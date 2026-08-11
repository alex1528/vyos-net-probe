# 出口分流监控看板

在 VyOS 网关上监控出口分流（海外/国内）与 PPTP/GRE 隧道状态的**浏览器可视化看板**：集 DNS 解析、双出口探测、归属地查询、分流校验于一体，通过 nginx 反代对外提供。

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
                                                          ├ dig @127.0.0.1  (L1 解析)
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
| **探针（各3个·全纯IP）** | 海外 ifconfig.me / api.ip.sb / icanhazip.com；国内 ifconfig.io / ip.3322.net / ipinfo.io/ip —— 均返回纯 IP，L2 提取零歧义，避免 JSON/中文文本域名导致误判 |
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

## 自定义探针

编辑 `probe_server.py` 顶部 `PROBES` 列表增减探测域名：

```python
PROBES = [
    # 海外各3个（应走 USPROXY，返回海外出口 IP）
    {"domain": "ifconfig.me",   "expect": "海外", "want": "!CN", "role": "oversea"},
    {"domain": "api.ip.sb",     "expect": "海外", "want": "!CN", "role": "oversea"},
    {"domain": "icanhazip.com", "expect": "海外", "want": "!CN", "role": "oversea"},
    # 国内各3个（应走 DIRECT，返回国内出口 IP）
    {"domain": "ifconfig.io",   "expect": "国内", "want": "CN",  "role": "domestic"},
    {"domain": "ip.3322.net",   "expect": "国内", "want": "CN",  "role": "domestic"},
    {"domain": "ipinfo.io/ip",  "expect": "国内", "want": "CN",  "role": "domestic"},
]
# ⚠️ 选域名原则：优先返回【纯IP】的服务，避免JSON(ipinfo.io)/中文文本(myip.ipip.net)导致L2提取或判定偏差
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
- 若 VyOS 无 `dig`，探针的 L1 解析会显示失败，但 L2 出口探测（curl）仍正常；可自行改用纯 curl 验证。
