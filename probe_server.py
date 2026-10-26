#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 出口分流探针后端服务  (probe_server.py)  v2.0
=====================================================================
 功能：
   - L1 DNS 解析：纯 socket 构造 DNS 查询包问本地代理 DNS（零 dig 依赖）
   - L2 出口探测：curl 取出口 IP + 测量延迟
   - L4 归属地：多源冗余查询（附加信息，不影响核心判定）
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
import time
from collections import deque
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------
DNS_SERVER  = os.environ.get("PROBE_DNS", "127.0.0.1")
LISTEN_HOST = os.environ.get("PROBE_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("PROBE_PORT", "8899"))
CURL_TIMEOUT = 8
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

def dns_resolve(host, server=DNS_SERVER, port=53, timeout=None, retries=None, want_aaaa=None):
    """结构化 DNS 解析（L1 核心）。返回:
       {ok, ip, ipv6, rcode, rtt_ms, error}
       - ok: 是否拿到 A 或 AAAA 地址
       - rcode: 文本化应答码(NOERROR/NXDOMAIN/SERVFAIL/REFUSED/...)，网络失败为 None
       - error: 失败归因(no_response=超时/不可达；其余为 rcode 文本)
    """
    timeout = DNS_TIMEOUT if timeout is None else timeout
    retries = DNS_RETRIES if retries is None else retries
    want_aaaa = DNS_QUERY_AAAA if want_aaaa is None else want_aaaa
    out = {"ok": False, "ip": None, "ipv6": None,
           "rcode": None, "rtt_ms": None, "error": None}
    t0 = time.time()
    rcode_a, ip = _dns_resolve_qtype(host, 1, server, port, timeout, retries)
    out["ip"] = ip
    out["rcode"] = _DNS_RCODE.get(rcode_a, rcode_a) if rcode_a is not None else None
    if want_aaaa and not ip:
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

def dns_query_a(domain, server=DNS_SERVER, port=53, timeout=None):
    """向后兼容包装：仅返回首个 IPv4（或 None）。内部走结构化 dns_resolve。"""
    return dns_resolve(domain, server=server, port=port,
                       timeout=timeout, want_aaaa=False)["ip"]

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
def get_exit_ip(domain):
    """curl 域名取出口 IP，返回 (ip 或 None, 延迟ms 或 None)。"""
    t0 = time.time()
    rc, out = sh(["curl", "-s", "--max-time", str(CURL_TIMEOUT), domain], CURL_TIMEOUT + 2)
    latency = int((time.time() - t0) * 1000)
    # 出口探测服务可能返回纯IP或含IP的文本，提取首个IPv4
    m = IPV4_RE.search(out or "")
    if m:
        return m.group(0), latency
    return None, None
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

def _geo_ipapi(ip):
    """ip-api.com（国内直连快，带中文国名）→ (cc, 中文名) 或 None。"""
    rc, out = sh(["curl", "-s", "--max-time", "5",
                  f"http://ip-api.com/json/{ip}?fields=status,countryCode,country&lang=zh-CN"], 7)
    if out and '"status":"success"' in out:
        try:
            d = json.loads(out)
            return d.get("countryCode"), d.get("country")
        except Exception:
            pass
    return None

def _geo_baidu(ip):
    """百度企服（国内兜底）→ (cc, 中文名) 或 None。"""
    rc, out = sh(["curl", "-s", "--max-time", "5",
                  f"https://qifu-api.baidubce.com/ip/geo/v1/district?ip={ip}"], 7)
    if out:
        m = re.search(r'"country":"([^"]*)"', out)
        if m:
            country = m.group(1)
            return ("CN" if country == "中国" else "XX"), country
    return None

def _geo_ipinfo(ip):
    """ipinfo.io 公开接口（对海外 IP 判定权威）→ (cc, 中文名) 或 None。country 为两字母码。"""
    rc, out = sh(["curl", "-s", "--max-time", "6", f"https://ipinfo.io/{ip}/json"], 8)
    if out:
        try:
            d = json.loads(out)
            cc = d.get("country")
            if cc:
                return cc, CC_ZH.get(cc, cc)  # 无映射则回退显示国码本身
        except Exception:
            pass
    return None

def geo_lookup(ip, prefer_oversea=False):
    """
    查询 IP 归属地，返回 (国码, 国家中文名)。多源冗余，任一成功即返回。
    源顺序按场景优化：
      - prefer_oversea=True（海外探针）：ipinfo.io 优先（对海外 IP 判定更权威），再 ip-api.com、百度兜底
      - prefer_oversea=False（国内探针）：ip-api.com 优先（国内直连快），再百度、ipinfo.io 兜底
    """
    if prefer_oversea:
        order = (_geo_ipinfo, _geo_ipapi, _geo_baidu)
    else:
        order = (_geo_ipapi, _geo_baidu, _geo_ipinfo)
    for src in order:
        r = src(ip)
        if r and r[0]:
            return r
    return None, None

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
def _probe_one(pcfg):
    """单个探针的完整检测(L1解析 + L2出口 + L4归属地)。供并行调用。"""
    domain, expect, want, role = pcfg["domain"], pcfg["expect"], pcfg["want"], pcfg["role"]
    item = {"domain": domain, "expect": expect, "role": role,
            "resolved": None, "dns_rcode": None, "dns_rtt": None, "dns_error": None,
            "exit_ip": None, "latency": None,
            "cc": None, "country": None, "geo_ok": None, "ok": True,
            "levels": {}}
    # L1: domain 可能带路径(如 ipinfo.io/ip)——DNS 解析只取主机名部分
    host = domain.split("/")[0]
    dnsr = dns_resolve(host)
    resolved = dnsr["ip"] or dnsr["ipv6"]     # A 优先，回退 AAAA
    item["resolved"] = resolved
    item["dns_rcode"] = dnsr["rcode"]          # 失败归因:NXDOMAIN/SERVFAIL/REFUSED/...
    item["dns_rtt"]   = dnsr["rtt_ms"]         # DNS 解析耗时(ms)，可作慢速早期告警
    item["dns_error"] = dnsr["error"]
    item["levels"]["L1"] = bool(resolved)
    if not resolved:
        item["ok"] = False
    # L2: 出口 IP + 延迟
    exit_ip, latency = get_exit_ip(domain)
    item["exit_ip"] = exit_ip
    item["latency"] = latency
    item["levels"]["L2"] = bool(exit_ip)
    if not exit_ip:
        item["ok"] = False
    # L4: 归属地(附加)
    if exit_ip:
        cc, country = geo_lookup(exit_ip, prefer_oversea=(role == "oversea"))
        item["cc"], item["country"] = cc, country
        if cc:
            if (want == "CN" and cc != "CN") or (want == "!CN" and cc == "CN"):
                item["geo_ok"] = False
                item["ok"] = False
            else:
                item["geo_ok"] = True
    return item

def run_probes():
    exits = {}
    passed = failed = 0
    # 并行执行所有探针(每个探针含 curl 出口 + 归属地，串行累加会超 nginx 超时)
    # 并发后总耗时 ≈ 最慢的单个探针，而非所有探针之和；
    # 并对每个探针设硬超时上限(PROBE_HARD_TIMEOUT)，任一探针卡死不阻塞整体返回。
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from concurrent.futures import TimeoutError as _FutTimeout

    def _timeout_item(pcfg):
        # 探针整体超时时的兜底结果(视为该探针失败)
        return {"domain": pcfg["domain"], "expect": pcfg["expect"], "role": pcfg["role"],
                "resolved": None, "dns_rcode": None, "dns_rtt": None, "dns_error": "timeout",
                "exit_ip": None, "latency": None,
                "cc": None, "country": None, "geo_ok": None, "ok": False,
                "levels": {"L1": False, "L2": False}, "timeout": True}
    results = [None] * len(PROBES)
    # 并发缺陷修复：原先用 `with ThreadPoolExecutor() as ex:`，退出时 shutdown(wait=True)
    #   会阻塞等待卡死线程真正结束；改为显式 try/finally + shutdown(wait=False)，
    #   并用 as_completed 设“整批”硬上限(PROBE_HARD_TIMEOUT)，任何未完成的槽位统一兜底。
    ex = ThreadPoolExecutor(max_workers=min(8, len(PROBES) or 1))
    try:
        futs = {ex.submit(_probe_one, pc): idx for idx, pc in enumerate(PROBES)}
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
            labels = " / ".join(f"{r}={ip}" for r, ip in exit_ips.items())
            split["msg"] = f"分流生效：{len(exit_ips)} 个出口IP互不相同（{labels}）"
        else:
            split["ok"] = False
            labels = " / ".join(f"{r}={ip}" for r, ip in exit_ips.items())
            split["msg"] = f"分流异常：存在相同出口IP（{labels}），检查规则/oversea.yaml"
            failed += 1
    else:
        split["msg"] = f"跳过（仅取到 {len(exit_ips)} 个出口IP，不足对比）"
    pptp = pptp_status()
    total = passed + failed
    data = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dns": DNS_SERVER,
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
    server_version = "ExitProbe/2.0"

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
    print(f"[probe_server v2.0] http://{LISTEN_HOST}:{LISTEN_PORT}  DNS={DNS_SERVER}")
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
