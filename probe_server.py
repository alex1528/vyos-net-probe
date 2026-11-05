#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 出口分流探针后端服务  (probe_server.py)  v2.4
=====================================================================
 功能：
   - L1 DNS 解析：纯 socket 构造 DNS 查询包问本地代理 DNS（零 dig 依赖，等价 dig @IP；
     默认自动取 eth2/eth3 网卡 IP 作为 DNS 服务器，可用 PROBE_DNS 指定）
   - L2 出口探测：curl -4 取出口 IP；默认用 L1 解析结果 --resolve 直连(与 L1 同一台 DNS)，
     记录 DNS/建连/总耗时与 HTTP 状态码，失败时按 curl 退出码给出具体原因
   - L4 归属地：多源冗余查询(总预算 PROBE_GEO_BUDGET 秒)，按出口 IP 缓存(PROBE_GEO_CACHE_TTL)，失败时逐源给出原因；按出口通道配置预期归属地，
     不一致默认仅提示（PROBE_GEO_STRICT=1 可改为判失败）
   - 串线检测：某通道出口 IP 与其他通道相同 → 判失败（规则没命中、掉进兜底等）
   - L3 分流校验：海外出口 IP ≠ 国内出口 IP
   - PPTP/GRE：读 /proc/net/nf_conntrack 判断隧道状态（零 conntrack 依赖）
   - 历史趋势：每次探测落盘 history.jsonl，供曲线展示
 依赖：仅 Python3 标准库（VyOS 1.5.0 自带）。出口探测底层用系统 curl。
 监听：默认 127.0.0.1:8899（仅本地，由 nginx 反代对外）
---------------------------------------------------------------------
 API:
   GET /api/probe    → 执行全部探针，返回 JSON，并追加历史
   GET /api/history  → 返回最近 N 次历史（?n=50）
   GET /             → 看板页面（优先返回同目录 index.html）
   GET /healthz      → 健康检查
=====================================================================
"""
import json
import os
import re
import socket
import struct
import random
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------
# L1 DNS 服务器（v2.2）：等价 `dig <域名> @<IP>`
#   PROBE_DNS=auto(默认)         → 依次取 PROBE_DNS_IFACES 网卡的 IPv4，最后回退 127.0.0.1
#   PROBE_DNS=10.60.2.254         → 固定 IP（可逗号分隔多个，按顺序择优）
#   PROBE_DNS=eth2,eth3           → 直接写网卡名，运行时解析其 IPv4
#   启动/每 PROBE_DNS_SELECT_TTL 秒做一次快速探活，选第一个“有应答”的服务器供全部探针使用
PROBE_DNS_RAW = os.environ.get("PROBE_DNS", "auto").strip() or "auto"
DNS_IFACES = [x.strip() for x in os.environ.get("PROBE_DNS_IFACES", "eth2,eth3").split(",") if x.strip()]
DNS_SELECT_TTL = int(os.environ.get("PROBE_DNS_SELECT_TTL", "60"))
DNS_SERVER  = "127.0.0.1"   # 兜底值（兼容旧引用）；实际以 select_dns_server() 选出的为准
LISTEN_HOST = os.environ.get("PROBE_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("PROBE_PORT", "8899"))
CURL_TIMEOUT = 8
# L2 出口探测（v2.4）：域名解析来源
#   l1(默认)  → 用 L1 解析出的 IPv4 做 `curl --resolve host:80:IP`，与 L1 同一台 DNS；L1 失败时回退系统 DNS
#   system    → 不加 --resolve，走系统 DNS(/etc/resolv.conf)，即 v2.3 及以前行为
L2_RESOLVE = os.environ.get("PROBE_L2_RESOLVE", "l1").strip().lower() or "l1"
# L4 归属地查询总预算(秒，v2.4)：多源依次尝试，剩余时间不足 1s 则跳过后续源。
#   默认 10s，保证 L1(≤6s)+L2(≤8s)+L4 不超过 PROBE_HARD_TIMEOUT，失败原因才能完整回传
GEO_BUDGET = float(os.environ.get("PROBE_GEO_BUDGET", "10"))
# L4 归属地缓存(v2.4)：按 (出口IP, 源顺序) 缓存成功结果 PROBE_GEO_CACHE_TTL 秒(默认 3600，0=关闭)。
#   出口 IP 变化时键随之变化，自动重新查询；失败结果不缓存，下一轮重试。
#   同一轮内多个探针同一出口 IP 只查一次(并发去重)，其余探针等待复用。
GEO_CACHE_TTL = int(os.environ.get("PROBE_GEO_CACHE_TTL", "3600"))
GEO_CACHE_MAX = 256
PROBE_HARD_TIMEOUT = 25   # 单探针(L1+L2+L4)整体硬超时上限(秒)，超时判失败但不阻塞整体
# L1 DNS 解析调优（新增）：超时/重试/是否补查 AAAA，均可用环境变量覆盖
DNS_TIMEOUT    = float(os.environ.get("PROBE_DNS_TIMEOUT", "3"))   # 单次 DNS 查询超时(秒)
DNS_RETRIES    = int(os.environ.get("PROBE_DNS_RETRIES", "2"))     # UDP 丢包重试次数
DNS_QUERY_AAAA = os.environ.get("PROBE_DNS_AAAA", "1") not in ("0", "false", "False", "")  # A 无结果时补查 AAAA
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(BASE_DIR, "history.jsonl")
PPTP_HISTORY_FILE = os.path.join(BASE_DIR, "pptp_history.jsonl")
# 历史保留策略：按时间保留最近 N 天（不再用固定条数）
HISTORY_RETENTION_DAYS = 7
# 每天预期条数（用于估算硬上限行数，防止时钟异常/高频写入导致文件无限增长）
HISTORY_PER_DAY = 1440       # 出口探测约 60s 一次 → 1440/天
PPTP_PER_DAY    = 8640       # PPTP 轮询 10s 一次 → 8640/天
GRE_TIMEOUT_STATE = 47      # gre 协议号

# 探针清单：role=oversea 应走海外USPROXY / domestic 应走国内DIRECT
#   want: "!CN"=期望非中国出口 / "CN"=期望中国出口
# =====================================================================
# 探针清单：自动检测 mihomo 配置，动态切换两出口/三出口模式
# 检测逻辑：读 mihomo config.yaml → 若有 HKPROXY 代理组 → 三出口(美国+香港+国内)
#                                   → 若只有 USPROXY   → 两出口(海外+国内)

# 环境变量 MIHOMO_CONFIG_PATH 可指定配置路径(默认 /etc/mihomo/config.yaml)
# =====================================================================
MIHOMO_CONFIG_PATH = os.environ.get("MIHOMO_CONFIG_PATH", "/etc/mihomo/config.yaml")
# 三出口模式(USPROXY + HKPROXY + DIRECT)

PROBES_3EXIT = [
    # 美国出口（USPROXY，域名在 oversea.yaml）
    {"domain": "ifconfig.me",              "expect": "美国", "want": "!CN", "role": "us"},
    {"domain": "api.ip.sb",                "expect": "美国", "want": "!CN", "role": "us"},
    {"domain": "icanhazip.com",            "expect": "美国", "want": "!CN", "role": "us"},
    # 香港出口（HKPROXY，rules 显式或兜底 MATCH,HKPROXY）
    {"domain": "ifconfig.io",              "expect": "香港", "want": "!CN", "role": "hk"},
    {"domain": "ipecho.net/plain",         "expect": "香港", "want": "!CN", "role": "hk"},
    {"domain": "ident.me",                 "expect": "香港", "want": "!CN", "role": "hk"},
    # 国内出口（DIRECT，rules 显式）
    {"domain": "cip.cc",                   "expect": "国内", "want": "CN",  "role": "domestic"},
    {"domain": "ipinfo.io/ip",             "expect": "国内", "want": "CN",  "role": "domestic"},
    {"domain": "ifconfig.co",              "expect": "国内", "want": "CN",  "role": "domestic"},
]

# 两出口模式(USPROXY + DIRECT)
PROBES_2EXIT = [
    # 海外出口（USPROXY，域名在 oversea.yaml）
    {"domain": "ifconfig.me",    "expect": "海外", "want": "!CN", "role": "oversea"},
    {"domain": "api.ip.sb",      "expect": "海外", "want": "!CN", "role": "oversea"},
    {"domain": "icanhazip.com",  "expect": "海外", "want": "!CN", "role": "oversea"},
    # 国内出口（DIRECT，兜底 MATCH,DIRECT）
    {"domain": "cip.cc",         "expect": "国内", "want": "CN",  "role": "domestic"},
    {"domain": "ipinfo.io/ip",   "expect": "国内", "want": "CN",  "role": "domestic"},
    {"domain": "ifconfig.co",    "expect": "国内", "want": "CN",  "role": "domestic"},
]

def _detect_exit_mode():
    """检测 mihomo 配置中的出口模式：三出口(有HKPROXY) or 两出口(仅USPROXY)。
    返回 3 或 2。检测失败时默认 3（三出口,信息量更大）。"""
    try:
        with open(MIHOMO_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = f.read()
        if "name: HKPROXY" in cfg or "- HKPROXY" in cfg:
            return 3
        return 2
    except Exception:
        return 3
EXIT_MODE = _detect_exit_mode()
PROBES = PROBES_3EXIT if EXIT_MODE == 3 else PROBES_2EXIT

# ---------------------------------------------------------------------
# v2.3 出口通道 + 归属地预期
#   判定“是否走对出口”以通道为准：出口 IP 与其他通道相同 = 串线(失败)；
#   归属地只回答“这条线路在哪”，按通道配置预期，默认不一致仅提示。
#   PROBE_GEO_DIRECT / PROBE_GEO_HKPROXY / PROBE_GEO_USPROXY 取值：
#     CN | HK | CN,HK(任一) | !CN(非CN) | any(不检查)；未设置时沿用 PROBES 中的 want
#   PROBE_GEO_STRICT=1 → 归属地不一致也判失败（默认 0，仅提示）
# ---------------------------------------------------------------------
ROLE_CHANNEL = {"us": "USPROXY", "hk": "HKPROXY", "oversea": "USPROXY", "domestic": "DIRECT"}
GEO_STRICT = os.environ.get("PROBE_GEO_STRICT", "0") not in ("0", "false", "False", "")

def channel_of(role):
    return ROLE_CHANNEL.get(role, str(role).upper())

def _geo_spec(channel, want):
    """返回该通道的归属地预期原始串：环境变量优先，否则用探针 want。"""
    raw = os.environ.get(f"PROBE_GEO_{channel}", "").strip()
    return raw or (want or "any")

def geo_expect_label(spec):
    s = (spec or "any").strip()
    if s.lower() == "any":
        return "不限"
    if s.startswith("!"):
        return "非" + "/".join(x.strip().upper() for x in s[1:].split(",") if x.strip())
    return "/".join(x.strip().upper() for x in s.split(",") if x.strip())

def geo_match(cc, spec):
    """cc 是否符合预期。spec 为 any 时恒 True；cc 为空返回 None(无法判断)。"""
    s = (spec or "any").strip()
    if s.lower() == "any":
        return True
    if not cc:
        return None
    neg = s.startswith("!")
    codes = {x.strip().upper() for x in (s[1:] if neg else s).split(",") if x.strip()}
    hit = cc.upper() in codes
    return (not hit) if neg else hit
# PPTP VPN 服务器 IP（用于在 conntrack 中过滤 GRE 条目）
VPN_IPS = ["61.160.251.125", "36.154.11.187"]

def _detect_gateway_ips():
    """探测网关本机 IP（用于从客户端统计中排除网关自身）。
    默认用 UDP connect 技巧取主出口 IP，并支持环境变量 PROBE_GATEWAY_IPS 补充（逗号分隔）。"""
    ips = set(["127.0.0.1"])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    for x in os.environ.get("PROBE_GATEWAY_IPS", "").split(","):
        x = x.strip()
        if x:
            ips.add(x)
    return ips
# 网关自身 IP 集合（客户端去重时排除，避免把网关误算成客户端）
GATEWAY_IPS = _detect_gateway_ips()
IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
IPV4_FULL = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# =====================================================================
# L1：纯 socket DNS 解析（替代 dig，零外部依赖）—— v2.1 加固版
#   改进：TID+来源校验、RCODE 判别(NXDOMAIN/SERVFAIL/REFUSED)、
#        丢包重试、TC 截断回退 TCP、A 无结果补查 AAAA、记录解析耗时。
# =====================================================================
_DNS_RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
              3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

def _dns_build_query(domain, qtype):
    """构造 DNS 查询报文，返回 (tid, packet_bytes)。"""
    tid = random.randint(0, 0xffff)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)  # RD=1
    q = b""
    for part in domain.split("."):
        if not part:
            continue
        label = part.encode("ascii", "ignore")[:63]
        q += bytes([len(label)]) + label
    q += b"\x00" + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN
    return tid, header + q

def _dns_skip_name(data, idx):
    """跳过一个(可能被压缩的)域名，返回新偏移。"""
    while idx < len(data):
        length = data[idx]
        if length == 0:
            return idx + 1
        if length & 0xc0 == 0xc0:      # 压缩指针占 2 字节
            return idx + 2
        idx += length + 1
    return idx

def _dns_parse_answer(data, qtype):
    """从响应报文解析首个匹配 qtype 的地址字符串，无则 None。"""
    if len(data) < 12:
        return None
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        return None
    idx = _dns_skip_name(data, 12)   # 跳过 question 的 QNAME(QDCOUNT 固定 1)
    idx += 4                          # QTYPE + QCLASS
    for _ in range(ancount):
        if idx >= len(data):
            break
        idx = _dns_skip_name(data, idx)
        if idx + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[idx:idx+10])
        idx += 10
        if idx + rdlen > len(data):
            break
        if rtype == qtype:
            if qtype == 1 and rdlen == 4:
                return ".".join(str(b) for b in data[idx:idx+4])
            if qtype == 28 and rdlen == 16:
                try:
                    return socket.inet_ntop(socket.AF_INET6, data[idx:idx+16])
                except Exception:
                    return None
        idx += rdlen
    return None

def _dns_query_udp(packet, tid, qtype, server, port, timeout):
    """发一次 UDP 查询。返回 (rcode|None, addr|None, tc)。rcode=None=网络层失败。"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        deadline = time.time() + timeout
        while True:
            data, srcaddr = s.recvfrom(4096)
            if srcaddr[0] != server:                              # 来源地址校验
                if time.time() >= deadline:
                    return None, None, False
                continue
            if len(data) < 4 or data[:2] != struct.pack(">H", tid):  # TID 校验
                if time.time() >= deadline:
                    return None, None, False
                continue
            flags = struct.unpack(">H", data[2:4])[0]
            rcode = flags & 0x0F
            tc = bool(flags & 0x0200)
            addr = _dns_parse_answer(data, qtype) if rcode == 0 else None
            return rcode, addr, tc
    except socket.timeout:
        return None, None, False
    except Exception:
        return None, None, False
    finally:
        if s:
            s.close()

def _dns_query_tcp(packet, tid, qtype, server, port, timeout):
    """TC=1 截断时回退 TCP/53 重查。返回 (rcode|None, addr|None)。"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, port))
        s.sendall(struct.pack(">H", len(packet)) + packet)   # TCP 前置 2 字节长度
        ln = s.recv(2)
        if len(ln) < 2:
            return None, None
        resp_len = struct.unpack(">H", ln)[0]
        buf = b""
        while len(buf) < resp_len:
            chunk = s.recv(resp_len - len(buf))
            if not chunk:
                break
            buf += chunk
        if len(buf) < 4 or buf[:2] != struct.pack(">H", tid):
            return None, None
        flags = struct.unpack(">H", buf[2:4])[0]
        rcode = flags & 0x0F
        addr = _dns_parse_answer(buf, qtype) if rcode == 0 else None
        return rcode, addr
    except Exception:
        return None, None
    finally:
        if s:
            s.close()

def _dns_resolve_qtype(host, qtype, server, port, timeout, retries):
    """解析单一记录类型，含丢包重试与 TC→TCP 回退。返回 (rcode|None, addr|None)。"""
    last_rcode = None
    for _ in range(max(1, retries)):
        tid, packet = _dns_build_query(host, qtype)
        rcode, addr, tc = _dns_query_udp(packet, tid, qtype, server, port, timeout)
        if tc:                                   # 截断 → TCP 重查
            rcode, addr = _dns_query_tcp(packet, tid, qtype, server, port, timeout)
        if rcode is not None:                    # 拿到明确响应(含 NXDOMAIN 等)即返回
            return rcode, addr
        last_rcode = rcode                       # 仍为网络失败，继续重试
    return last_rcode, None

def dns_resolve(host, server=None, port=53, timeout=None, retries=None, want_aaaa=None):
    """结构化 DNS 解析（L1 核心）。返回:
       {ok, ip, ipv6, rcode, rtt_ms, error}
       - ok: 是否拿到 A 或 AAAA 地址
       - rcode: 文本化应答码(NOERROR/NXDOMAIN/SERVFAIL/REFUSED/...)，网络失败为 None
       - error: 失败归因(no_response=超时/不可达；其余为 rcode 文本)
    """
    timeout = DNS_TIMEOUT if timeout is None else timeout
    retries = DNS_RETRIES if retries is None else retries
    want_aaaa = DNS_QUERY_AAAA if want_aaaa is None else want_aaaa
    if not server:
        server = select_dns_server()["server"]
    out = {"ok": False, "ip": None, "ipv6": None, "server": server,
           "rcode": None, "rtt_ms": None, "error": None}
    t0 = time.time()
    rcode_a, ip = _dns_resolve_qtype(host, 1, server, port, timeout, retries)
    out["ip"] = ip
    out["rcode"] = _DNS_RCODE.get(rcode_a, rcode_a) if rcode_a is not None else None
    # A 有应答但无地址时才补查 AAAA；A 完全无应答(服务器不通)时补查无意义，直接跳过省一半耗时
    if want_aaaa and not ip and rcode_a is not None:
        rcode_6, ip6 = _dns_resolve_qtype(host, 28, server, port, timeout, retries)
        out["ipv6"] = ip6
        if ip6 and rcode_a is None:
            out["rcode"] = _DNS_RCODE.get(rcode_6, rcode_6)
    out["rtt_ms"] = int((time.time() - t0) * 1000)
    if out["ip"] or out["ipv6"]:
        out["ok"] = True
    elif rcode_a is None:
        out["error"] = "no_response"       # 超时/无响应/本地 DNS 不可达
    else:
        out["error"] = out["rcode"]        # NXDOMAIN / SERVFAIL / REFUSED / NOERROR(无A)
    return out

def dns_query_a(domain, server=None, port=53, timeout=None):
    """向后兼容包装：仅返回首个 IPv4（或 None）。内部走结构化 dns_resolve。"""
    return dns_resolve(domain, server=server, port=port,
                       timeout=timeout, want_aaaa=False)["ip"]

# ---------------------------------------------------------------------
# L1 DNS 服务器选择（v2.2）：网卡 IP 自动探测 + 探活择优 + 缓存
# ---------------------------------------------------------------------
def _iface_ipv4(ifname):
    """取网卡 IPv4：优先 ioctl(SIOCGIFADDR，零依赖)，失败回退 `ip -4 -o addr show dev X`。"""
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            req = struct.pack("256s", ifname[:15].encode("ascii", "ignore"))
            res = fcntl.ioctl(s.fileno(), 0x8915, req)   # SIOCGIFADDR
            return socket.inet_ntoa(res[20:24])
        finally:
            s.close()
    except Exception:
        pass
    rc, out = sh(["ip", "-4", "-o", "addr", "show", "dev", ifname], 3)
    m = re.search(r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", out or "")
    return m.group(1) if m else None

def dns_candidates():
    """按 PROBE_DNS 生成候选 [(ip, 来源)]，去重保序。"""
    cands, seen = [], set()
    def add(ip, why):
        if ip and ip not in seen:
            seen.add(ip)
            cands.append((ip, why))
    for tok in [t.strip() for t in PROBE_DNS_RAW.split(",") if t.strip()]:
        if tok.lower() == "auto":
            for ifn in DNS_IFACES:
                add(_iface_ipv4(ifn), f"iface:{ifn}")
            add("127.0.0.1", "loopback")
        elif IPV4_FULL.match(tok):
            add(tok, "static")
        else:                                   # 当作网卡名
            add(_iface_ipv4(tok), f"iface:{tok}")
    if not cands:
        add(DNS_SERVER, "fallback")
    return cands

_DNS_SEL = {"ts": 0.0, "result": None}
_DNS_SEL_LOCK = threading.Lock()

def select_dns_server(force=False):
    """探活择优：对每个候选发 1 次快速 A 查询，第一个“有应答”(任意 RCODE)的即选中。
       成功结果缓存 DNS_SELECT_TTL 秒；全部无应答时返回首个候选并标 ok=False。"""
    with _DNS_SEL_LOCK:
        r = _DNS_SEL["result"]
        if r and r["ok"] and not force and time.time() - _DNS_SEL["ts"] < DNS_SELECT_TTL:
            return r
    cands = dns_candidates()
    test_host = PROBES[0]["domain"].split("/")[0] if PROBES else "ifconfig.me"
    quick_to = min(DNS_TIMEOUT, 1.5)
    tried, chosen = [], None
    for ip, why in cands:
        t0 = time.time()
        rcode, _ = _dns_resolve_qtype(test_host, 1, ip, 53, quick_to, 1)
        tried.append({"server": ip, "source": why, "ok": rcode is not None,
                      "rtt_ms": int((time.time() - t0) * 1000)})
        if rcode is not None:
            chosen = (ip, why)
            break
    if chosen:
        res = {"server": chosen[0], "source": chosen[1], "ok": True, "tried": tried}
    else:
        first = cands[0] if cands else (DNS_SERVER, "fallback")
        res = {"server": first[0], "source": first[1], "ok": False, "tried": tried}
    with _DNS_SEL_LOCK:
        _DNS_SEL["ts"], _DNS_SEL["result"] = time.time(), res
    return res

def sh(cmd, timeout):
    """执行外部命令，返回 (rc, stdout_stripped)。"""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except Exception:
        return -1, ""
    
# =====================================================================
# L2：出口 IP 探测 + 延迟
# =====================================================================
# curl 退出码 → 失败原因（只列常见项，其余显示原码）
CURL_ERR = {
    5: "代理地址解析失败", 6: "域名解析失败", 7: "连接失败(拒绝/不可达)",
    18: "响应不完整", 28: "超时", 35: "TLS 握手失败", 47: "跳转过多",
    52: "服务器空响应", 55: "发送失败", 56: "接收失败(连接被重置)",
}
_L2_MARK = "\n__L2_METRICS__"

def _curl_fail_reason(rc, http_code, body_has_ip):
    """按 curl 退出码 / HTTP 状态码 / 返回内容归纳失败原因。返回 (code, 中文)。"""
    if rc == -1:
        return "exec", "curl 执行失败(未安装或被强制终止)"
    if rc not in (0, None):
        return f"curl_{rc}", CURL_ERR.get(rc, f"curl 错误 {rc}")
    if http_code and 300 <= http_code < 400:
        return f"http_{http_code}", f"HTTP {http_code} 跳转(探针不跟随跳转)"
    if http_code and http_code >= 400:
        return f"http_{http_code}", f"HTTP {http_code}"
    if http_code == 0:
        return "no_http", "无 HTTP 响应"
    if not body_has_ip:
        return "no_ip", "返回内容中无 IPv4"
    return None, None

def build_l2_cmd(domain, resolve_ip=None, timeout=None):
    """生成 L2 的 curl 命令（列表形式）。resolve_ip 存在时加 --resolve，与 L1 用同一解析结果。"""
    timeout = CURL_TIMEOUT if timeout is None else timeout
    host = domain.split("/")[0]
    cmd = ["curl", "-4", "-s", "--max-time", str(timeout),
           "-w", _L2_MARK + "%{http_code} %{time_namelookup} %{time_connect} %{time_total} %{remote_ip}"]
    if resolve_ip:
        cmd += ["--resolve", f"{host}:80:{resolve_ip}"]
    cmd.append("http://" + domain)
    return cmd

def l2_probe(domain, resolve_ip=None):
    """L2：curl 取出口 IP。返回结构化结果：
       {ip, latency, via, resolve_ip, http_code, t_dns_ms, t_connect_ms, t_total_ms,
        remote_ip, curl_rc, error, error_cn}
       latency 优先取 curl 自身 time_total（不含进程启动开销），取不到再用墙钟耗时。"""
    via = "l1" if resolve_ip else "system"
    cmd = build_l2_cmd(domain, resolve_ip)
    t0 = time.time()
    rc, out = sh(cmd, CURL_TIMEOUT + 2)
    wall = int((time.time() - t0) * 1000)
    body, metrics = (out or ""), ""
    if _L2_MARK.strip() in body:
        body, metrics = body.rsplit(_L2_MARK.strip(), 1)
    http_code = t_dns = t_conn = t_total = None
    remote_ip = None
    parts = metrics.split()
    try:
        if len(parts) >= 4:
            http_code = int(parts[0])
            t_dns = int(float(parts[1]) * 1000)
            t_conn = int(float(parts[2]) * 1000)
            t_total = int(float(parts[3]) * 1000)
            remote_ip = parts[4] if len(parts) >= 5 else None
    except ValueError:
        pass
    m = IPV4_RE.search(body)
    err, err_cn = _curl_fail_reason(rc, http_code, bool(m))
    res = {"ip": None, "latency": None, "via": via, "resolve_ip": resolve_ip,
           "http_code": http_code, "t_dns_ms": t_dns, "t_connect_ms": t_conn,
           "t_total_ms": t_total, "remote_ip": remote_ip or None, "curl_rc": rc,
           "error": err, "error_cn": err_cn}
    if err is None and m:
        res["ip"] = m.group(0)
        res["latency"] = t_total if t_total is not None else wall
    return res

def get_exit_ip(domain, resolve_ip=None):
    """向后兼容包装：返回 (ip 或 None, 延迟ms 或 None)。"""
    r = l2_probe(domain, resolve_ip)
    return r["ip"], r["latency"]

# =====================================================================
# L4：归属地查询（多源冗余，走国内直连）
# =====================================================================
# 常见国家两字母码 → 中文名映射（供 ipinfo.io 等只返回国码的接口显示友好名称）
CC_ZH = {
    "CN": "中国", "HK": "中国香港", "TW": "中国台湾", "MO": "中国澳门",
    "US": "美国", "JP": "日本", "KR": "韩国", "SG": "新加坡", "MY": "马来西亚",
    "GB": "英国", "DE": "德国", "FR": "法国", "NL": "荷兰", "RU": "俄罗斯",
    "CA": "加拿大", "AU": "澳大利亚", "IN": "印度", "BR": "巴西", "TH": "泰国",
    "VN": "越南", "ID": "印度尼西亚", "PH": "菲律宾", "TR": "土耳其",
    "IT": "意大利", "ES": "西班牙", "SE": "瑞典", "CH": "瑞士", "IE": "爱尔兰",
    "AE": "阿联酋", "ZA": "南非", "MX": "墨西哥", "PL": "波兰", "UA": "乌克兰",
}

_GEO_MARK = "__GEO_METRICS__"

def _curl_get(url, max_time):
    """通用 HTTP GET（L4 用）：返回 {body, http_code, ms, rc, error, error_cn}。"""
    cmd = ["curl", "-4", "-s", "--max-time", str(max_time),
           "-w", "\n" + _GEO_MARK + "%{http_code} %{time_total}", url]
    t0 = time.time()
    rc, out = sh(cmd, max_time + 2)
    wall = int((time.time() - t0) * 1000)
    body, http_code, ms = (out or ""), None, wall
    if _GEO_MARK in body:
        body, metrics = body.rsplit(_GEO_MARK, 1)
        parts = metrics.split()
        try:
            http_code = int(parts[0])
            ms = int(float(parts[1]) * 1000)
        except (IndexError, ValueError):
            pass
    err, err_cn = _curl_fail_reason(rc, http_code, True)
    if http_code == 429:
        err, err_cn = "http_429", "HTTP 429 限流"
    return {"body": body.strip(), "http_code": http_code, "ms": ms,
            "rc": rc, "error": err, "error_cn": err_cn}

def _geo_result(name, r, cc=None, country=None, error=None, error_cn=None):
    if cc and not error:
        return {"src": name, "ok": True, "cc": cc, "country": country,
                "ms": r["ms"], "error": None, "error_cn": None}
    return {"src": name, "ok": False, "cc": None, "country": None, "ms": r["ms"],
            "error": error or r["error"] or "no_country",
            "error_cn": error_cn or r["error_cn"] or "返回中无国家字段"}

def _geo_ipapi(ip, max_time=5):
    """ip-api.com（国内直连快，带中文国名）。免费限额约 45 次/分钟，超限返回 HTTP 429。"""
    r = _curl_get(f"http://ip-api.com/json/{ip}?fields=status,message,countryCode,country&lang=zh-CN", max_time)
    if r["error"]:
        return _geo_result("ip-api.com", r)
    try:
        d = json.loads(r["body"])
    except Exception:
        return _geo_result("ip-api.com", r, error="bad_json", error_cn="返回非 JSON")
    if d.get("status") != "success":
        msg = d.get("message") or "未知"
        return _geo_result("ip-api.com", r, error="api_fail", error_cn=f"接口返回失败({msg})")
    return _geo_result("ip-api.com", r, d.get("countryCode"), d.get("country"))

def _geo_baidu(ip, max_time=5):
    """百度企服（国内兜底）。"""
    r = _curl_get(f"https://qifu-api.baidubce.com/ip/geo/v1/district?ip={ip}", max_time)
    if r["error"]:
        return _geo_result("百度企服", r)
    m = re.search(r'"country":"([^"]*)"', r["body"])
    if not m or not m.group(1):
        return _geo_result("百度企服", r)
    country = m.group(1)
    return _geo_result("百度企服", r, "CN" if country == "中国" else "XX", country)

def _geo_ipinfo(ip, max_time=6):
    """ipinfo.io 公开接口（对海外 IP 判定权威）。country 为两字母码。"""
    r = _curl_get(f"https://ipinfo.io/{ip}/json", max_time)
    if r["error"]:
        return _geo_result("ipinfo.io", r)
    try:
        d = json.loads(r["body"])
    except Exception:
        return _geo_result("ipinfo.io", r, error="bad_json", error_cn="返回非 JSON")
    if d.get("bogon"):
        return _geo_result("ipinfo.io", r, error="bogon", error_cn="保留/内网地址")
    cc = d.get("country")
    return _geo_result("ipinfo.io", r, cc, CC_ZH.get(cc, cc) if cc else None)

_GEO_DEFAULT_TIMEOUT = {_geo_ipapi: 5, _geo_baidu: 5, _geo_ipinfo: 6}

def geo_lookup_detail(ip, prefer_oversea=False, budget=None):
    """多源归属地查询（结构化）。返回:
       {cc, country, source, tried:[{src, ok, cc, country, ms, error, error_cn}], error, error_cn}
       源顺序：代理通道 ipinfo.io → ip-api.com → 百度；DIRECT 通道 ip-api.com → 百度 → ipinfo.io。
       总预算 budget 秒（默认 GEO_BUDGET），剩余不足 1s 的源记为“预算用尽”跳过。"""
    budget = GEO_BUDGET if budget is None else budget
    order = (_geo_ipinfo, _geo_ipapi, _geo_baidu) if prefer_oversea else (_geo_ipapi, _geo_baidu, _geo_ipinfo)
    names = {_geo_ipinfo: "ipinfo.io", _geo_ipapi: "ip-api.com", _geo_baidu: "百度企服"}
    t0 = time.time()
    tried = []
    for fn in order:
        remain = budget - (time.time() - t0)
        if remain < 1:
            tried.append({"src": names[fn], "ok": False, "cc": None, "country": None, "ms": 0,
                          "error": "skipped", "error_cn": "预算用尽未查询"})
            continue
        r = fn(ip, max_time=max(1, min(_GEO_DEFAULT_TIMEOUT[fn], int(remain))))
        tried.append(r)
        if r["ok"]:
            return {"cc": r["cc"], "country": r["country"], "source": r["src"],
                    "tried": tried, "error": None, "error_cn": None}
    summary = " / ".join(f"{t['src']} {t['error_cn']}" for t in tried)
    return {"cc": None, "country": None, "source": None, "tried": tried,
            "error": "all_failed", "error_cn": summary}

_GEO_CACHE = {}       # (ip, prefer_oversea) -> (ts, result)
_GEO_INFLIGHT = {}    # (ip, prefer_oversea) -> {"ev": Event, "res": result|None}
_GEO_LOCK = threading.Lock()

def _geo_tag(r, cached, shared, age):
    out = dict(r)
    out["cached"], out["shared"], out["cache_age_s"] = cached, shared, age
    return out

def geo_lookup_cached(ip, prefer_oversea=False):
    """带缓存 + 并发去重的归属地查询。返回 geo_lookup_detail 的结构，另加:
       cached(命中缓存) / shared(复用同轮其他探针的查询) / cache_age_s(缓存年龄秒)"""
    key = (ip, bool(prefer_oversea))
    now = time.time()
    with _GEO_LOCK:
        hit = _GEO_CACHE.get(key)
        if hit and GEO_CACHE_TTL > 0 and now - hit[0] < GEO_CACHE_TTL:
            return _geo_tag(hit[1], True, False, int(now - hit[0]))
        slot = _GEO_INFLIGHT.get(key)
        leader = slot is None
        if leader:
            slot = {"ev": threading.Event(), "res": None}
            _GEO_INFLIGHT[key] = slot
    if not leader:
        # 同一出口 IP 已有探针在查：等待其结果（领头查询受 GEO_BUDGET 约束）
        if slot["ev"].wait(GEO_BUDGET + 1):
            if slot["res"] is not None:
                return _geo_tag(slot["res"], False, True, 0)
            # 领头查询异常退出 → 自己查一次
            return _geo_tag(geo_lookup_detail(ip, prefer_oversea), False, False, 0)
        return {"cc": None, "country": None, "source": None, "tried": [],
                "error": "wait_timeout", "error_cn": "等待同 IP 查询超时",
                "cached": False, "shared": True, "cache_age_s": None}
    r = None
    try:
        r = geo_lookup_detail(ip, prefer_oversea)
        if r["cc"] and GEO_CACHE_TTL > 0:
            with _GEO_LOCK:
                _GEO_CACHE[key] = (time.time(), r)
                if len(_GEO_CACHE) > GEO_CACHE_MAX:
                    oldest = min(_GEO_CACHE, key=lambda k: _GEO_CACHE[k][0])
                    _GEO_CACHE.pop(oldest, None)
        slot["res"] = r
    finally:
        slot["ev"].set()
        with _GEO_LOCK:
            _GEO_INFLIGHT.pop(key, None)
    return _geo_tag(r, False, False, 0)

def geo_cache_info():
    with _GEO_LOCK:
        now = time.time()
        live = sum(1 for ts, _ in _GEO_CACHE.values() if now - ts < GEO_CACHE_TTL)
        return {"ttl": GEO_CACHE_TTL, "size": len(_GEO_CACHE), "live": live}

def geo_lookup(ip, prefer_oversea=False):
    """向后兼容包装：返回 (国码, 国家中文名)，失败为 (None, None)。"""
    r = geo_lookup_detail(ip, prefer_oversea)
    return r["cc"], r["country"]

# =====================================================================
# PPTP/GRE 状态：读 /proc/net/nf_conntrack（零 conntrack 命令依赖）
# =====================================================================
def pptp_status():
    """
    返回 dict：gre_total / gre_replied / gre_unreplied / tcp1723 / ok / detail
    判定：gre_replied>0 → 隧道数据通(正常)；仅 UNREPLIED → 异常；无条目 → 未连接
    """
    result = {"gre_total": 0, "gre_replied": 0, "gre_unreplied": 0,
              "tcp1723": 0, "ok": None, "source": "", "detail": "", "entries": []}
    lines = []
    # 首选：/proc/net/nf_conntrack（无需任何命令）
    try:
        with open("/proc/net/nf_conntrack", "r") as f:
            lines = f.readlines()
        result["source"] = "/proc/net/nf_conntrack"
    except Exception:
        # 兜底：conntrack 命令
        rc, out = sh(["conntrack", "-L"], 6)
        if out:
            lines = out.splitlines()
            result["source"] = "conntrack -L"
    if not lines:
        result["detail"] = "无法读取 conntrack（/proc/net/nf_conntrack 不存在且无 conntrack 命令）"
        return result
    # 按客户端 IP 去重统计（关键修正）：
    #   conntrack 中 1 个客户端会产生多条记录（去程GRE + 回程GRE + TCP1723），
    #   直接累加"条目数"会导致三个数字天然不等且远大于真实客户端数。
    #   正确单位是"客户端"——取每行首个 src=（orig 发起方），排除 VPN 服务器 IP 与网关自身 IP 后去重。
    client_gre_replied = set()     # 有回包(隧道通)的客户端 IP
    client_gre_unreplied = set()   # 仅去程无回包的客户端 IP
    client_1723 = set()            # 建立了 1723 控制通道的客户端 IP

    def is_client(ip):
        # 真客户端 = 不是 VPN 服务器、不是网关自身、不是回环/组播
        if not ip:
            return False
        if ip in VPN_IPS or ip in GATEWAY_IPS:
            return False
        return True

    def client_ip_of(ln):
        # 关键修正：GRE 经 NAT 后，orig 方向 src= 是 VPN 服务器（被排除），
        #   真客户端 IP 出现在 reply 方向的第二个 src=。
        #   因此扫描本行所有 src=IP，返回第一个"非 VPN、非网关"的 IP（即真客户端）。
        for ip in re.findall(r'src=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ln):
            if is_client(ip):
                return ip
        return None

    def fmt_entry(ln):
        # 结构化精简 conntrack 行：提取协议 + 双向 src/dst + 状态，避免硬截断导致 IP 显示不全。
        proto = "GRE" if "gre" in ln.split()[:3] else ("TCP" if " tcp " in ln or "\ttcp\t" in ln else "?")
        pairs = re.findall(r'src=(\d+\.\d+\.\d+\.\d+) dst=(\d+\.\d+\.\d+\.\d+)', ln)
        ports = re.findall(r'sport=(\d+) dport=(\d+)', ln)
        state = "UNREPLIED" if "[UNREPLIED]" in ln else ("ASSURED" if "[ASSURED]" in ln else "")
        parts = [proto]
        if pairs:
            orig = f"{pairs[0][0]}→{pairs[0][1]}"
            if ports:
                orig += f":{ports[0][1]}"
            parts.append("orig " + orig)
        if len(pairs) > 1:
            reply = f"{pairs[1][0]}→{pairs[1][1]}"
            parts.append("reply " + reply)
        if state:
            parts.append("[" + state + "]")
        return "  ".join(parts)
    for ln in lines:
        fields = ln.split()
        is_gre = "gre" in fields[:3]
        # 是否与本 VPN 相关（含 VPN 服务器 IP 字面量）
        related_vpn = (not VPN_IPS) or any(ip in ln for ip in VPN_IPS)
        if is_gre:
            # 关键修正：GRE(协议47)在网关上几乎只有 PPTP 在用。
            #   经 NAT/MASQUERADE 后 GRE 的源/目的地址可能被改写，不再含 VPN_IP 字面量，
            #   若强制要求 related_vpn 会把已连通的 GRE 漏掉 → 误报"仅1723无GRE"。
            #   因此 GRE 一律统计（不强制 related_vpn），确保 VPN 连通时能数到 GRE 数据通道。
            result["gre_total"] += 1
            if "[UNREPLIED]" in ln:
                result["gre_unreplied"] += 1
            else:
                result["gre_replied"] += 1
            if len(result["entries"]) < 6:
                result["entries"].append(fmt_entry(ln))
            cip = client_ip_of(ln)
            if is_client(cip):
                if "[UNREPLIED]" in ln:
                    client_gre_unreplied.add(cip)
                else:
                    client_gre_replied.add(cip)
        # TCP 1723 控制通道：客户端直连不经 NAT 改写源，可用 related_vpn 精确过滤
        if ("sport=1723" in ln or "dport=1723" in ln) and related_vpn:
            result["tcp1723"] += 1
            cip = client_ip_of(ln)
            if is_client(cip):
                client_1723.add(cip)
    # 若某客户端既有 replied 又有 unreplied 记录，视为已连通（replied 优先）
    client_gre_unreplied -= client_gre_replied
    # 客户端级统计（仅供展示参考——NAT 环境下 GRE 源地址可能被改写，客户端归并为尽力而为）
    all_clients = client_gre_replied | client_gre_unreplied | client_1723
    result["clients_total"] = len(all_clients)
    result["clients_ok"] = len(client_gre_replied)
    result["clients_pending"] = len(client_gre_unreplied)
    result["clients_1723"] = len(client_1723)
    result["client_ips"] = sorted(all_clients)
    # ================== 判定逻辑（基于原始条目级 GRE 状态，可靠）==================
    # 关键修正：PPTP 是否正常 = 系统中是否存在 replied 的 GRE 条目，
    #   不依赖"GRE 能否归并到具体客户端"（NAT/MASQUERADE 会改写 GRE 源地址，
    #   导致按 client IP 关联失败，从而把已连通的 VPN 误报为"仅1723无GRE"）。
    # 判定优先级：有回包GRE → 正常；有GRE但全UNREPLIED → 异常；仅1723 → 协商中(中性)；无 → 空闲。
    has_replied_gre  = result["gre_replied"] > 0     # 原始条目级：存在双向 GRE
    has_any_gre      = result["gre_total"] > 0
    has_1723         = result["tcp1723"] > 0
    # 展示用"客户端数"兜底：若能归并到客户端就用客户端数，否则回退到"存在即为1"
    if result["clients_ok"] == 0 and has_replied_gre:
        result["clients_ok"] = 1          # GRE 通但源被NAT改写，按存在计为至少1个
    if result["clients_total"] == 0 and (has_any_gre or has_1723):
        result["clients_total"] = 1
    if has_replied_gre:
        result["ok"] = True
        result["detail"] = f"PPTP 隧道已打通（GRE 双向回包 replied={result['gre_replied']}）"
    elif has_any_gre and has_1723:
        # 有 GRE 出向 + 有控制通道，但 GRE 尚未见回包：短暂协商态，非硬故障
        result["ok"] = None
        result["detail"] = f"PPTP 连接中（控制通道已建，GRE 协商/回包确认中：GRE={result['gre_total']} UNREPLIED={result['gre_unreplied']}）"
    elif has_any_gre and not has_1723:
        # 有 GRE 出向但无 1723：可能控制通道刚关或 conntrack 时序差，仅当持续无回包才是真异常
        result["ok"] = False
        result["detail"] = f"GRE 出向无回包且无控制通道（GRE={result['gre_total']} UNREPLIED={result['gre_unreplied']}）——检查 route-exclude-address"
    elif has_1723 and not has_any_gre:
        # 只有 1723 没有任何 GRE：PPTP 协商初期正常现象，判为中性（不告警）
        result["ok"] = None
        result["detail"] = "PPTP 协商中（控制通道 TCP1723 已建，等待 GRE 数据通道建立）"
    else:
        result["ok"] = None
        result["detail"] = "当前无客户端拨入"
    return result

# =====================================================================
# 执行全部探针
# =====================================================================
def _probe_one(pcfg, dns_server=None):
    """单个探针的完整检测(L1解析 + L2出口 + L4归属地)。供并行调用。"""
    domain, expect, want, role = pcfg["domain"], pcfg["expect"], pcfg["want"], pcfg["role"]
    channel = channel_of(role)
    gspec = _geo_spec(channel, want)
    item = {"domain": domain, "expect": expect, "role": role, "channel": channel,
            "geo_expect": geo_expect_label(gspec), "geo_status": None,
            "geo_strict": GEO_STRICT, "crosstalk": None,
            "resolved": None, "dns_server": None, "dns_rcode": None, "dns_rtt": None, "dns_error": None,
            "exit_ip": None, "latency": None, "l2": None, "l2_error": None, "l2_error_cn": None,
            "cc": None, "country": None, "geo_ok": None, "ok": True,
            "geo_source": None, "geo_tried": None, "geo_error": None, "geo_error_cn": None,
            "geo_cached": False, "geo_shared": False, "geo_cache_age": None,
            "levels": {}}
    # L1: domain 可能带路径(如 ipinfo.io/ip)——DNS 解析只取主机名部分
    host = domain.split("/")[0]
    dnsr = dns_resolve(host, server=dns_server)
    resolved = dnsr["ip"] or dnsr["ipv6"]     # A 优先，回退 AAAA
    item["resolved"] = resolved
    item["dns_server"] = dnsr["server"]        # 实际使用的 DNS 服务器(等价 dig @IP)
    item["dns_rcode"] = dnsr["rcode"]          # 失败归因:NXDOMAIN/SERVFAIL/REFUSED/...
    item["dns_rtt"]   = dnsr["rtt_ms"]         # DNS 解析耗时(ms)，可作慢速早期告警
    item["dns_error"] = dnsr["error"]
    item["levels"]["L1"] = bool(resolved)
    if not resolved:
        item["ok"] = False
    # L2: 出口 IP + 延迟（v2.4：默认用 L1 的 IPv4 解析结果 --resolve，与 L1 同一台 DNS；L1 无 IPv4 时回退系统 DNS）
    rip = dnsr["ip"] if (L2_RESOLVE == "l1" and dnsr["ip"]) else None
    l2 = l2_probe(domain, resolve_ip=rip)
    exit_ip, latency = l2["ip"], l2["latency"]
    item["exit_ip"] = exit_ip
    item["latency"] = latency
    item["l2"] = l2
    item["l2_error"], item["l2_error_cn"] = l2["error"], l2["error_cn"]
    item["levels"]["L2"] = bool(exit_ip)
    if not exit_ip:
        item["ok"] = False
    # L4: 归属地——回答“这条线路在哪”，与通道预期比对；默认不一致仅提示
    if exit_ip:
        # 代理通道(非 DIRECT)优先 ipinfo.io，对海外 IP 判定更准（v2.3 修正：原仅 oversea 角色生效）
        g = geo_lookup_cached(exit_ip, prefer_oversea=(channel != "DIRECT"))
        cc, country = g["cc"], g["country"]
        item["cc"], item["country"] = cc, country
        item["geo_source"], item["geo_tried"] = g["source"], g["tried"]
        item["geo_error"], item["geo_error_cn"] = g["error"], g["error_cn"]
        item["geo_cached"], item["geo_shared"], item["geo_cache_age"] = g["cached"], g["shared"], g["cache_age_s"]
        m = geo_match(cc, gspec)
        if m is True:
            item["geo_ok"], item["geo_status"] = True, "match"
        elif m is False:
            item["geo_ok"], item["geo_status"] = False, "mismatch"
            if GEO_STRICT:
                item["ok"] = False
    else:
        item["geo_error"], item["geo_error_cn"] = "skipped", "L2 未取到出口，跳过"
    return item

def run_probes():
    exits = {}
    passed = failed = 0
    # L1：本轮先择优选出可用 DNS 服务器(eth2/eth3 IP → 127.0.0.1)，全部探针共用，避免每个探针各自超时
    dsel = select_dns_server()
    # 并行执行所有探针(每个探针含 curl 出口 + 归属地，串行累加会超 nginx 超时)
    # 并发后总耗时 ≈ 最慢的单个探针，而非所有探针之和；
    # 并对每个探针设硬超时上限(PROBE_HARD_TIMEOUT)，任一探针卡死不阻塞整体返回。
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from concurrent.futures import TimeoutError as _FutTimeout

    def _timeout_item(pcfg):
        # 探针整体超时时的兜底结果(视为该探针失败)
        ch = channel_of(pcfg["role"])
        return {"domain": pcfg["domain"], "expect": pcfg["expect"], "role": pcfg["role"],
                "channel": ch, "geo_expect": geo_expect_label(_geo_spec(ch, pcfg.get("want"))),
                "geo_status": None, "geo_strict": GEO_STRICT, "crosstalk": None,
                "resolved": None, "dns_server": dsel["server"], "dns_rcode": None, "dns_rtt": None, "dns_error": "timeout",
                "exit_ip": None, "latency": None, "l2": None,
                "l2_error": "timeout", "l2_error_cn": "探针整体超时",
                "cc": None, "country": None, "geo_ok": None, "ok": False,
                "levels": {"L1": False, "L2": False}, "timeout": True}
    results = [None] * len(PROBES)
    # 并发缺陷修复：原先用 `with ThreadPoolExecutor() as ex:`，退出时 shutdown(wait=True)
    #   会阻塞等待卡死线程真正结束；改为显式 try/finally + shutdown(wait=False)，
    #   并用 as_completed 设“整批”硬上限(PROBE_HARD_TIMEOUT)，任何未完成的槽位统一兜底。
    ex = ThreadPoolExecutor(max_workers=min(8, len(PROBES) or 1))
    try:
        futs = {ex.submit(_probe_one, pc, dsel["server"]): idx for idx, pc in enumerate(PROBES)}
        try:
            for fut in as_completed(futs, timeout=PROBE_HARD_TIMEOUT):
                idx = futs[fut]
                try:
                    results[idx] = fut.result()
                except Exception:
                    results[idx] = _timeout_item(PROBES[idx])
        except _FutTimeout:
            # 整批超过硬上限：已完成的保留，未完成的在下方统一兜底
            pass
        for idx, item in enumerate(results):
            if item is None:
                results[idx] = _timeout_item(PROBES[idx])
    finally:
        ex.shutdown(wait=False)   # 不等卡死线程，避免被退出处阻塞整体返回
    # v2.3 串线检测：出口 IP 与“其他通道”任一探针相同 → 该探针判失败
    #   仅凭 IP 无法断定哪一方走错，故相同的两侧都会标出（L3 同时报分流异常）
    ips_by_ch = {}
    for it in results:
        if it.get("exit_ip"):
            ips_by_ch.setdefault(it.get("channel") or channel_of(it["role"]), set()).add(it["exit_ip"])
    for it in results:
        ip = it.get("exit_ip")
        if not ip:
            continue
        mine = it.get("channel") or channel_of(it["role"])
        others = sorted(ch for ch, s in ips_by_ch.items() if ch != mine and ip in s)
        if others:
            it["crosstalk"] = others
            it["ok"] = False
    # 汇总(保持 PROBES 原始顺序，ex.map 有序返回)
    for item in results:
        if item["exit_ip"]:
            exits.setdefault(item["role"], item["exit_ip"])  # 同 role 首个成功出口
        if item["ok"]:
            passed += 1
        else:
            failed += 1
    # L3 分流校验(动态适配两/三出口:各出口IP互不相等=分流生效)
    exit_ips = {role: ip for role, ip in exits.items() if ip}
    split = {"exits": exit_ips, "ok": None, "msg": ""}
    if len(exit_ips) >= 2:
        unique_ips = set(exit_ips.values())
        if len(unique_ips) == len(exit_ips):
            split["ok"] = True
            labels = " / ".join(f"{channel_of(r)}={ip}" for r, ip in exit_ips.items())
            split["msg"] = f"分流生效：{len(exit_ips)} 个出口IP互不相同（{labels}）"
        else:
            split["ok"] = False
            labels = " / ".join(f"{channel_of(r)}={ip}" for r, ip in exit_ips.items())
            split["msg"] = f"分流异常：存在相同出口IP（{labels}），检查规则/oversea.yaml"
            failed += 1
    else:
        split["msg"] = f"跳过（仅取到 {len(exit_ips)} 个出口IP，不足对比）"
    pptp = pptp_status()
    total = passed + failed
    data = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dns": dsel["server"] + ("" if dsel["ok"] else "（无应答）"),
        "dns_select": dsel,
        "geo_cache": dict(geo_cache_info(),
                          hits=sum(1 for it in results if it.get("geo_cached")),
                          shared=sum(1 for it in results if it.get("geo_shared")),
                          lookups=sum(1 for it in results if it.get("geo_tried") and not it.get("geo_cached") and not it.get("geo_shared"))),
        "probes": results,
        "split": split,
        "pptp": pptp,
        "summary": {"passed": passed, "failed": failed, "total": total,
                    "all_ok": failed == 0 and total > 0},
    }
    append_history(data)
    return data

# =====================================================================
# 历史记录
# =====================================================================
def append_history(data):
    """把本次探测的精简摘要追加到 history.jsonl(动态适配两/三出口)。"""
    exits = data["split"].get("exits") or {}
    rec = {
        "ts": data["ts"],
        "exits": exits,
        "all_ok": data["summary"]["all_ok"],
        "split_ok": data["split"].get("ok"),
        "pptp_ok": data["pptp"].get("ok"),
    }
    roles = set(p["role"] for p in data["probes"])
    for role in roles:
        rec[f"{role}_latency"] = _avg_latency(data["probes"], role)
    try:
        with open(HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        _trim_by_age(HISTORY_FILE, per_day=HISTORY_PER_DAY)
    except Exception:
        pass

def _avg_latency(probes, role):
    vals = [p["latency"] for p in probes if p["role"] == role and p["latency"] is not None]
    return int(sum(vals) / len(vals)) if vals else None

def read_history(n=50):
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-n:]
        return [json.loads(x) for x in lines if x.strip()]
    except Exception:
        return []

def append_pptp_history(pp):
    """把每次 PPTP 轮询的精简状态追加到 pptp_history.jsonl（供状态趋势条）。"""
    # 客户端级口径为主，原始条目数保留供诊断
    rec = {"ts": pp.get("ts"), "ok": pp.get("ok"),
           "clients_total": pp.get("clients_total"), "clients_ok": pp.get("clients_ok"),
           "clients_pending": pp.get("clients_pending"), "clients_1723": pp.get("clients_1723"),
           # 兼容趋势条旧字段名（replied/unreplied 现表示"客户端数"）
           "replied": pp.get("clients_ok"), "unreplied": pp.get("clients_pending"),
           "total": pp.get("clients_total"), "tcp1723": pp.get("clients_1723")}
    try:
        with open(PPTP_HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        _trim_by_age(PPTP_HISTORY_FILE, per_day=PPTP_PER_DAY)
    except Exception:
        pass

def read_pptp_history(n=60):
    try:
        with open(PPTP_HISTORY_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-n:]
        return [json.loads(x) for x in lines if x.strip()]
    except Exception:
        return []
    
# =====================================================================
# HTTP 服务
# =====================================================================
class Handler(BaseHTTPRequestHandler):
    server_version = "ExitProbe/2.4"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            # 客户端(浏览器/nginx)已断开连接——常见于探测耗时超过 nginx proxy_read_timeout。
            # 属正常现象，静默忽略，不刷 Traceback 到 journal。
            pass

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        if path == "/healthz":
            self._send(200, "ok", "text/plain; charset=utf-8")
        elif path == "/api/probe":
            try:
                self._send(200, json.dumps(run_probes(), ensure_ascii=False))
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}, ensure_ascii=False))
        elif path == "/api/pptp":
            # 轻量端点：仅读 /proc/net/nf_conntrack 判定 PPTP/GRE，无 curl/dig，适合高频(10s)轮询
            try:
                pp = pptp_status()
                pp["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
                append_pptp_history(pp)
                self._send(200, json.dumps(pp, ensure_ascii=False))
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}, ensure_ascii=False))
        elif path == "/api/history":
            q = parse_qs(u.query)
            n = int(q.get("n", ["50"])[0])
            self._send(200, json.dumps({"history": read_history(n)}, ensure_ascii=False))
        elif path == "/api/pptp_history":
            q = parse_qs(u.query)
            n = int(q.get("n", ["60"])[0])
            self._send(200, json.dumps({"history": read_pptp_history(n)}, ensure_ascii=False))
        elif path == "/api/mode":
            # 返回当前出口模式、探针列表、检测到的配置路径(供调试/前端自适应)
            mode_info = {
                "exit_mode": EXIT_MODE,
                "mode_label": "三出口(美国+香港+国内)" if EXIT_MODE == 3 else "两出口(海外+国内)",
                "config_path": MIHOMO_CONFIG_PATH,
                "dns_config": PROBE_DNS_RAW,
                "dns_ifaces": DNS_IFACES,
                "dns_select": select_dns_server(),
                "channels": {r: channel_of(r) for r in sorted(set(p["role"] for p in PROBES))},
                "geo_expect": {channel_of(p["role"]): geo_expect_label(_geo_spec(channel_of(p["role"]), p.get("want"))) for p in PROBES},
                "geo_strict": GEO_STRICT,
                "l2_resolve": L2_RESOLVE,
                "geo_budget": GEO_BUDGET,
                "geo_cache": geo_cache_info(),
                "roles": sorted(set(p["role"] for p in PROBES)),
                "probes": PROBES,
            }
            self._send(200, json.dumps(mode_info, ensure_ascii=False))
        elif path in ("/", "/index.html"):
            idx = os.path.join(BASE_DIR, "index.html")
            if os.path.isfile(idx):
                with open(idx, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            else:
                self._send(200, "<h1>index.html not found</h1>", "text/html; charset=utf-8")
        else:
            self._send(404, json.dumps({"error": "not found"}, ensure_ascii=False))
# 软链周期自愈：防止 VyOS commit/升级重写 nginx 配置后，本站点软链失效
NGINX_SITE_LINK = "/etc/nginx/sites-enabled/vyos-net-probe"
NGINX_SITE_SRC  = "/etc/nginx/sites-available/vyos-net-probe"
# 自愈间隔秒(0=关闭)；默认 300s。VyOS 场景下建议保持开启。
SELF_HEAL_INTERVAL = int(os.environ.get("PROBE_SELF_HEAL_INTERVAL", "300"))

def _selfheal_symlink_loop():
    """后台守护：周期检查站点软链，缺失则重建并 reload nginx（幂等、静默）。"""
    import subprocess as _sp
    while True:
        try:
            time.sleep(SELF_HEAL_INTERVAL)
            # 源配置在、但软链丢失 → 重建 + reload
            if os.path.isfile(NGINX_SITE_SRC) and not os.path.islink(NGINX_SITE_LINK) \
               and not os.path.exists(NGINX_SITE_LINK):
                os.symlink(NGINX_SITE_SRC, NGINX_SITE_LINK)
                # 校验通过再 reload，避免影响现有 nginx
                if _sp.run(["nginx", "-t"], capture_output=True).returncode == 0:
                    _sp.run(["systemctl", "reload", "nginx"], capture_output=True)
                print("[self-heal] 站点软链丢失，已重建并 reload nginx")
        except Exception:
            # 守护线程绝不因异常退出（如无权限），静默continue
            pass

def main():
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"[probe_server v2.4] http://{LISTEN_HOST}:{LISTEN_PORT}  PROBE_DNS={PROBE_DNS_RAW} IFACES={','.join(DNS_IFACES)}")
    try:
        sel = select_dns_server(force=True)
        print(f"[probe_server] L1 DNS 选中 {sel['server']}({sel['source']}) ok={sel['ok']}  候选={[t['server'] for t in sel['tried']]}")
    except Exception as e:
        print(f"[probe_server] L1 DNS 择优失败：{e}")
    # 启动软链自愈守护线程（daemon，随主进程退出）
    if SELF_HEAL_INTERVAL > 0:
        import threading
        threading.Thread(target=_selfheal_symlink_loop, daemon=True).start()
        print(f"[probe_server] 软链自愈守护已启动（每 {SELF_HEAL_INTERVAL}s 检查）")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()

if __name__ == "__main__":
    main()
