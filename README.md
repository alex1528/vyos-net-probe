# 出口分流监控看板

在 VyOS 网关上监控出口分流与 PPTP/GRE 隧道状态的**浏览器可视化看板**：集 DNS 解析、多出口探测（自动适配两出口/三出口）、归属地查询、分流校验于一体，通过 nginx 反代对外提供。

## 快速开始

**部署(VyOS 网关,root):**

```bash
sudo bash /tmp/vyos-net-probe/deploy.sh   # 装探针服务(probe) + nginx站点(listen 8080)
sudo systemctl restart probe
curl -s http://127.0.0.1:8899/healthz     # 验证 → ok
# 浏览器访问 http://<VyOS网关IP>:8080/
```

**git 提交(开发机 Git Bash/WSL):**

```bash
cd vyos-net-probe   # 进入项目目录
git init && git config core.hooksPath .githooks   # 首次:初始化并启用钩子
git add -A                                         # .gitignore 自动排除运行时产物
git commit -m "feat: 出口分流监控探针"             # pre-commit 校验 + post-commit 自动打 tag
```

> 完整的部署/运维/提交/排查命令见 [QUICKSTART.md](QUICKSTART.md)。

---

## 架构

```
浏览器 ──HTTP:80──> nginx(VyOS, 独立站点 /) ──proxy_pass──> probe_server.py (127.0.0.1:8899)
                                                          ├ socket 问本地 DNS  (L1 解析，结构化 rcode/rtt，零 dig 依赖)
                                                          ├ curl 出口探测    (L2 出口IP)
                                                          ├ 归属地查询       (L4 附加，三源冗余；海外探针 ipinfo.io 优先，国内探针 ip-api.com 优先)
                                                          └ 分流对比         (L3 校验)
                          index.html (探针服务自带前端) ───┘
```

- **零 pip 依赖**：`probe_server.py` 仅用 Python3 标准库（VyOS 自带），底层调用系统 `curl` 探测。
- **独立站点**：作为独立 nginx 站点部署（监听 **80**，根路径 `/`），不使用 default_server，**绝不触碰目标机自有的 `/etc/nginx/sites-enabled/default`**，与其零冲突。
- **判定分层**：核心结论（L1/L2/L3）不依赖外部归属地 API，归属地查询失败也能正确判定。

## 文件清单

| 文件 | 作用 |
|------|------|
| `probe_server.py` | 探针 HTTP 服务，提供 `/api/probe` JSON 与内置前端 |
| `index.html` | 暗色主题看板前端（零外部依赖） |
| `probe.service` | systemd 服务单元（含 ExecStartPre 引导 + 自愈间隔环境变量） |
| `ensure_nginx.sh` | nginx 引导脚本（软链自愈 + 智能共存，由 probe 服务开机调用） |
| `vyos-net-probe.conf` | 独立 nginx 站点配置（监听8080，根路径/） |
| `deploy.sh` | 一键部署脚本（安装文件 + 起服务 + 自检） |

## 部署（VyOS 上）

```bash
# 1. 上传整个 vyos-net-probe 目录到 VyOS，例如 /tmp/vyos-net-probe
# 2. 一键部署（安装探针服务）
sudo bash /tmp/vyos-net-probe/deploy.sh

# 3. 独立 nginx 站点由 deploy.sh 自动安装（独立端口8080、根路径/，规避80/443博弈，不碰VyOS配置）
#    如需手动安装：
#    sudo cp vyos-net-probe.conf /etc/nginx/sites-available/vyos-net-probe
#    sudo ln -sf /etc/nginx/sites-available/vyos-net-probe /etc/nginx/sites-enabled/vyos-net-probe
#    sudo nginx -t && sudo systemctl reload nginx

# 4. 浏览器访问
#    http://<VyOS网关IP>:8080/
```

## API

| 路径 | 说明 |
|------|------|
| `GET /api/probe` | 执行全部探针，返回 JSON |
| `GET /` | 看板页面 |
| `GET /healthz` | 健康检查，返回 `ok` |

## v2.0 新增能力

| 能力 | 说明 |
|------|------|
| **去 dig 依赖** | L1 解析改用纯 Python `socket` 构造 DNS 查询包直接问本地代理 DNS(53)，不再依赖 `dig`/`bind9-dnsutils` |
| **PPTP/GRE 状态** | 读 `/proc/net/nf_conntrack`（无需 `conntrack` 命令）统计 GRE replied/unreplied 与 TCP 1723，判定隧道是否打通 |
| **探针（自动适配·全纯IP）** | 自动检测 mihomo 配置切换两出口/三出口模式。三出口：美国(ifconfig.me/api.ip.sb/icanhazip.com) + 香港(ifconfig.io/ipecho.net/ident.me) + 国内(cip.cc/ipinfo.io/ip/ifconfig.co)；两出口：海外3+国内3 |
| **历史趋势** | 每次探测落盘 `history.jsonl`（**按时间保留最近 7 天**，自动滚动清理），`/api/history` + 前端纯 SVG 折线图展示海外/国内出口延迟与整体状态时间线 |

### PPTP/GRE 判定逻辑

- `gre_replied > 0` → 隧道双向已建立（✔ 正常）
- 仅 `UNREPLIED` → 出向有、回包无（✘ 未打通，对应 route-exclude-address 未生效）
- 无 GRE 条目 → 当前无客户端拨入（ⓘ 中性）

`probe_server.py` 顶部 `VPN_IPS` 用于在 conntrack 中过滤本 VPN 的 GRE 条目，按需修改。

## 新增 API

| 路径 | 说明 |
|------|------|
| `GET /api/history?n=50` | 返回最近 N 次探测摘要（出口IP、延迟、状态） |

历史文件 `history.jsonl`（出口探测）与 `pptp_history.jsonl`（PPTP/GRE 状态）均写在安装目录 `/opt/vyos-net-probe/`，systemd 的 `ReadWritePaths` 已放行。

### 历史保留策略（按时间滚动，防止文件无限增长）

- **保留窗口**：最近 **7 天**（`HISTORY_RETENTION_DAYS = 7`），超期记录每次写入时自动清理。
- **裁剪机制**：利用时间戳字典序快速定位 7 天分界；仅当行数超过「每天预期条数 × 7 × 1.1」硬上限时才真正解析裁剪，平时快速跳过——PPTP 每 10s 写入也无性能负担。
- **硬上限兜底**：即使时钟异常/回拨，也按硬上限强制截断，文件 size 恒定可控。
- 每天预期条数：出口 `HISTORY_PER_DAY=1440`（60s/次）、PPTP `PPTP_PER_DAY=8640`（10s/次）。7 天上限约 1.1 万 / 6.6 万行。

## v2.1 新增能力（L1 解析加固 + 调度并发修复）

本版聚焦把 L1 DNS 解析从“单发 UDP + 只看有无 A 记录”升级为工业级结构化解析，并修复探针调度的并发隐患。`dns_query_a()` 保留为向后兼容包装，现有看板字段（`resolved` / `levels.L1`）不变。

| 加固点 | 说明 |
|------|------|
| **RCODE 判别** | 解析失败显性化为 `NXDOMAIN`（域名不存在）/ `SERVFAIL`（DNS 服务故障）/ `REFUSED`（被拒）/ `no_response`（超时不可达），不再是笼统红叉 |
| **TID + 来源校验** | 校验响应的 Transaction ID 与来源 IP，杂包/伪造包不再被误接 |
| **丢包重试** | UDP 丢包不再直接判失败，默认重试 2 次 |
| **TC 截断回退 TCP** | 响应 TC=1 时自动改用 TCP/53 重查 |
| **补查 AAAA** | A 无结果时查 IPv6，兼容纯 IPv6 解析 |
| **解析耗时** | 新增 `dns_rtt`（ms），DNS 变慢可作早期告警 |
| **调度并发修复** | `run_probes` 改为 `try/finally` + `shutdown(wait=False)` + `as_completed(timeout=PROBE_HARD_TIMEOUT)`，单探针卡死不再阻塞整体返回 |

**探针结果新增字段（均为附加，不破坏兼容）：** `dns_rcode`、`dns_rtt`、`dns_error`。看板 L1 行已用上：失败显示中文化原因，成败均显示解析耗时。

**新增环境变量（均可选，有默认值）：**

| 环境变量 | 默认 | 说明 |
|------|------|------|
| `PROBE_DNS_TIMEOUT` | `3` | 单次 DNS 查询超时（秒） |
| `PROBE_DNS_RETRIES` | `2` | UDP 丢包重试次数 |
| `PROBE_DNS_AAAA` | `1` | A 无结果时是否补查 AAAA（0 关闭） |

> L1 解析失败的典型场景：本地代理 DNS（53）未启动/不可达（`no_response`）、域名不存在（`NXDOMAIN`）、上游解析器故障（`SERVFAIL`）、或整探针超过硬上限（`PROBE_HARD_TIMEOUT`，默认 25s）。

## v2.2 L1 DNS 服务器可指定（等价 `dig <域名> @<IP>`）

**问题**：mihomo 等本地代理 DNS 若只监听内网网卡 IP（如 eth2 的 `10.60.2.254`），而不监听 `127.0.0.1`，旧版固定问 `127.0.0.1` 会导致 L1 全部显示「✘ 无响应/超时 (≈12000ms)」——而 `dig ifconfig.me @10.60.2.254` 却正常。

**改进**：

- `PROBE_DNS` 默认改为 `auto`：依次取 `PROBE_DNS_IFACES`（默认 `eth2,eth3`）网卡的 IPv4，最后回退 `127.0.0.1`；每轮先对候选做一次快速探活（≤1.5s/个），选第一个有应答的服务器供全部探针共用（成功结果缓存 `PROBE_DNS_SELECT_TTL` 秒）。
- 也可固定指定：`PROBE_DNS=10.60.2.254`（等价 `dig @10.60.2.254`）、多个 `PROBE_DNS=10.60.2.254,10.60.3.254`、或直接写网卡名 `PROBE_DNS=eth2`。
- 网卡 IP 读取：优先 ioctl `SIOCGIFADDR`（零依赖），失败回退 `ip -4 -o addr show dev <网卡>`。
- A 记录完全无应答时不再补查 AAAA（服务器不通时补查无意义），失败耗时减半。
- 结果新增 `dns_server`（每个探针实际使用的 DNS）、`dns_select`（择优过程）；看板顶部「DNS：」显示选中服务器，悬停可看各候选是否应答及耗时；`/api/mode` 同步返回。

| 环境变量 | 默认 | 说明 |
|------|------|------|
| `PROBE_DNS` | `auto` | `auto` / IP（可逗号分隔多个）/ 网卡名 |
| `PROBE_DNS_IFACES` | `eth2,eth3` | `auto` 模式下取 IP 的网卡顺序 |
| `PROBE_DNS_SELECT_TTL` | `60` | 择优结果缓存秒数 |

> ⚠️ 升级需重新执行 `deploy.sh`（会覆盖 `/etc/systemd/system/probe.service` 并 daemon-reload），旧 service 中的 `PROBE_DNS=127.0.0.1` 会覆盖代码默认值。

## v2.3 出口通道判定 + 归属地预期可配置

**问题**：国内探针显示「L4 归属地 香港 (HK) ⚠不符」时，可能是两种完全不同的情况，旧版无法区分：

| 情况 | 原因 | 性质 |
|------|------|------|
| A. DIRECT 线路本身在香港 | WAN 口 IP 被归属地库判为 HK | 正常，只是“国内=CN”的预期不适合该环境 |
| B. 流量串到代理 | 没命中 DIRECT 规则，掉进 `MATCH,HKPROXY` | 真故障 |

**改进**：是否走对出口以「通道」判定，归属地只回答“线路在哪”。

- 卡片标签改为通道名：`DIRECT 通道` / `HKPROXY 通道` / `USPROXY 通道`；分组标题、L3 文案同步。
- **串线检测**：某探针出口 IP 与其他通道任一探针相同 → 判失败，L2 行显示 `✘ 串线：与 HKPROXY 相同`（仅凭 IP 无法断定哪方走错，相同的两侧都会标出，L3 同时报分流异常）。
- **归属地预期按通道配置**：`PROBE_GEO_DIRECT` / `PROBE_GEO_HKPROXY` / `PROBE_GEO_USPROXY`，取值 `CN`、`HK`、`CN,HK`（任一）、`!CN`（非 CN）、`any`（不检查）；未设置时沿用探针 `want`（DIRECT=CN，代理=!CN）。
- **不一致默认仅提示**：L4 行显示黄色 `ⓘ 线路所在地·预期 CN`，不计入失败；`PROBE_GEO_STRICT=1` 恢复为红色 `⚠不符` 并判失败。
- 修正：代理通道（含三出口模式的 us/hk）归属地查询优先 ipinfo.io（原仅 `oversea` 角色生效）。
- 结果新增字段：`channel`、`geo_expect`、`geo_status`(match/mismatch)、`geo_strict`、`crosstalk`；`/api/mode` 返回 `channels`、`geo_expect`、`geo_strict`。

| 环境变量 | 默认 | 说明 |
|------|------|------|
| `PROBE_GEO_DIRECT` | （沿用 want=CN） | DIRECT 通道预期归属地；DIRECT 线路在香港时设为 `HK` |
| `PROBE_GEO_HKPROXY` | （沿用 want=!CN） | HKPROXY 通道预期归属地 |
| `PROBE_GEO_USPROXY` | （沿用 want=!CN） | USPROXY 通道预期归属地 |
| `PROBE_GEO_STRICT` | `0` | `1` = 归属地不一致也判失败 |

> 判断是 A 还是 B：看国内探针与香港探针的 L2 出口 IP——不同为 A，相同为 B（v2.3 会直接显示串线）。

## 自定义探针

编辑 `probe_server.py` 顶部 `PROBES` 列表增减探测域名：

```python
# 三出口模式(自动检测 mihomo 配置含 HKPROXY 时启用)
PROBES_3EXIT = [
    # 美国出口(USPROXY，域名在 oversea.yaml)
    {"domain": "ifconfig.me",      "expect": "美国", "want": "!CN", "role": "us"},
    {"domain": "api.ip.sb",        "expect": "美国", "want": "!CN", "role": "us"},
    {"domain": "icanhazip.com",    "expect": "美国", "want": "!CN", "role": "us"},
    # 香港出口(HKPROXY，不在 oversea → 兜底)
    {"domain": "ifconfig.io",      "expect": "香港", "want": "!CN", "role": "hk"},
    {"domain": "ipecho.net/plain", "expect": "香港", "want": "!CN", "role": "hk"},
    {"domain": "ident.me",         "expect": "香港", "want": "!CN", "role": "hk"},
    # 国内出口(DIRECT，rules 显式)
    {"domain": "cip.cc",           "expect": "国内", "want": "CN",  "role": "domestic"},
    {"domain": "ipinfo.io/ip",     "expect": "国内", "want": "CN",  "role": "domestic"},
    {"domain": "ifconfig.co",      "expect": "国内", "want": "CN",  "role": "domestic"},
]
# ⚠️ 选域名原则：优先返回【纯IP】的服务，避免JSON/中文文本导致L2提取偏差
# 启动时自动检测 mihomo 配置(MIHOMO_CONFIG_PATH)决定两出口/三出口模式
```

改后 `sudo systemctl restart probe`。

## nginx 托管机制（不依赖 VyOS service https）

VyOS 靠 `config.boot` + `service_https.py` 驱动 nginx，不用 `systemctl enable nginx`。本项目**不依赖 VyOS 是否启用 `set service https`**，由 probe 服务自行保障 nginx 与站点软链，三层协同：

| 层 | 机制 | 时机 | 作用 |
|----|------|------|------|
| 开机引导 | `probe.service` 的 `ExecStartPre=+ensure_nginx.sh` | 每次 probe 启动（含开机，因 probe 已 `systemctl enable`） | 补软链 + 确保 nginx 运行 |
| 智能共存 | `ensure_nginx.sh` 判断 `systemctl is-active nginx` | 引导时 | nginx 已运行（VyOS 托管/已启动）则只 reload 不抢；未运行才 start |
| 运行时自愈 | `probe_server.py` 后台守护线程 | 每 `PROBE_SELF_HEAL_INTERVAL` 秒（默认 300，0=关闭） | 软链被 VyOS commit 覆盖后自动重建 + reload |

**权限**：`ExecStartPre` 用 `+` 前缀以完整 root 权限运行（豁免 `ProtectSystem=strict` 沙箱）；主进程自愈线程通过 `ReadWritePaths=... /etc/nginx/sites-enabled` 放行。

**效果**：`systemctl enable probe` 后，每次开机 probe 自启 → 拉起 nginx + 补软链 → 运行时守护保软链 → 看板 `http://<网关IP>:8080/` 始终可用，与 VyOS 是否启用 https 无关。

> ⚠️ 不做 `systemctl enable nginx` —— VyOS 用 config.boot 驱动 nginx，systemd enable 无意义且可能与 VyOS 管理冲突。

## 注意

- `probe_server.py` 只监听 `127.0.0.1:8899`，不直接对外，必须经 nginx 反代访问（根路径 `/`）。
- 独立站点默认只允许内网网段访问，按需调整 `allow/deny`。
- L1 解析为纯 Python `socket` 实现（零 `dig` 依赖）；解析失败时看板会显示具体原因（NXDOMAIN/SERVFAIL/REFUSED/无响应）与 DNS 耗时，便于区分“本地代理 DNS 不通”还是“域名解析不出”。
