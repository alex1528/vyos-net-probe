# vyos-net-probe 快速开始

> 出口分流监控探针 —— 在 VyOS 网关上监控出口分流（海外/国内）与 PPTP/GRE 隧道状态的可视化看板。

## 一图速览

```
浏览器 ──HTTP:8080──> nginx(VyOS 独立站点 /) ──反代──> probe_server.py (127.0.0.1:8899)
                                                      ├ L1 DNS 解析（socket 直连本地代理 DNS）
                                                      ├ L2 出口探测（curl 各探针取出口 IP + 延迟）
                                                      ├ L3 分流校验（海外≠国内出口 IP）
                                                      ├ L4 归属地（ip-api/百度/ipinfo.io 三源）
                                                      └ PPTP/GRE（读 /proc/net/nf_conntrack）
```

- **服务名**：`probe` · **探针端口**：`127.0.0.1:8899` · **nginx**：`listen 8080`（独立端口，规避 80/443 博弈）
- **安装目录**：`/opt/vyos-net-probe` · **绝不触碰** `/etc/nginx/sites-enabled/default`

---

## 一、部署（VyOS 网关，root）

```bash
# 1. 上传整个 vyos-net-probe 目录到网关（如 /tmp/vyos-net-probe）
# 2. 一键部署：装探针服务(probe) + 独立 nginx 站点(listen 8080)
sudo bash /tmp/vyos-net-probe/deploy.sh

# 3. 重启探针服务
sudo systemctl restart probe

# 4. 验证
systemctl status probe                                          # 服务状态
curl -s http://127.0.0.1:8899/healthz                           # 健康检查（返回 ok）
curl -s http://127.0.0.1:8899/api/pptp | python3 -m json.tool   # PPTP/GRE 接口

# 5. 浏览器访问
#    http://<VyOS网关IP>:8080/
```

> **防火墙放行 8080（如 VyOS 默认拦截入站）：** 在 VyOS 配置模式仅对内网放行：
> ```
> set firewall ipv4 name <入站规则集> rule <N> action accept
> set firewall ipv4 name <入站规则集> rule <N> destination port 8080
> set firewall ipv4 name <入站规则集> rule <N> protocol tcp
> set firewall ipv4 name <入站规则集> rule <N> source address 192.168.0.0/16
> commit; save
> ```

### 手动安装 nginx 站点（如不用 deploy.sh 自动安装）

```bash
sudo cp vyos-net-probe.conf /etc/nginx/sites-available/vyos-net-probe
sudo ln -sf /etc/nginx/sites-available/vyos-net-probe /etc/nginx/sites-enabled/vyos-net-probe
sudo nginx -t && sudo systemctl reload nginx
```

---

## 二、日常运维

```bash
systemctl status probe          # 查看状态
systemctl restart probe         # 重启（改配置/换探针域名后）
journalctl -u probe -f          # 实时日志
```

> **nginx 由 probe 服务托管**：`systemctl enable probe` 后，每次开机 probe 会自动拉起 nginx 并补站点软链（`ExecStartPre=ensure_nginx.sh`），运行时守护线程每 5 分钟自愈软链——不依赖 VyOS 是否启用 `service https`。已运行的 nginx 只 reload 不抢管理权。

### API 一览

| 路径 | 说明 |
|------|------|
| `GET /` | 看板页面 |
| `GET /api/probe` | 出口探针全量检测（出口 IP / 延迟 / 归属地 / 分流） |
| `GET /api/pptp` | PPTP/GRE 隧道状态（轻量，供 10s 高频轮询） |
| `GET /api/history?n=50` | 出口探测历史 |
| `GET /api/pptp_history?n=60` | PPTP 状态历史 |
| `GET /healthz` | 健康检查 |

---

## 三、自定义探针域名

编辑 `probe_server.py` 顶部 `PROBES`（增减后 `systemctl restart probe`）：

```python
PROBES = [
    # 海外（应走 USPROXY，返回海外出口 IP）
    {"domain": "ifconfig.me",   "expect": "海外", "want": "!CN", "role": "oversea"},
    {"domain": "api.ip.sb",     "expect": "海外", "want": "!CN", "role": "oversea"},
    {"domain": "icanhazip.com", "expect": "海外", "want": "!CN", "role": "oversea"},
    # 国内（应走 DIRECT，返回国内出口 IP）
    {"domain": "ifconfig.io",   "expect": "国内", "want": "CN",  "role": "domestic"},
    {"domain": "ip.3322.net",   "expect": "国内", "want": "CN",  "role": "domestic"},
    {"domain": "ipinfo.io/ip",  "expect": "国内", "want": "CN",  "role": "domestic"},
]
```

> 选域名原则：优先返回**纯 IP** 的服务，避免 JSON / 中文文本导致提取偏差。带路径域名（如 `ipinfo.io/ip`）已支持。

---

## 四、git 提交（开发机 Git Bash / WSL）

```bash
cd vyos-net-probe   # 进入项目目录

# 首次：初始化并启用 .githooks（提交时自动跑安全检查 + 打版本 tag）
git init
git config core.hooksPath .githooks

# 提交（.gitignore 已排除运行时产物 *.jsonl 等）
git add -A
git commit -m "feat: 出口分流监控探针"
#   → pre-commit  ：密钥检查 + Python 语法校验（失败则中止）
#   → post-commit ：自动打递增版本 tag（v0.0.1 → v0.0.2 → …）

git log --oneline -5    # 查看提交
git tag -l 'v*'         # 查看版本 tag
```

> 跳过钩子检查（谨慎）：`git commit --no-verify` · 跳过自动 tag：`SKIP_AUTO_TAG=1 git commit ...`

### 推送远端（可选）

```bash
git remote add origin <仓库地址>
git push -u origin main --tags
```

---

## 五、常见排查

| 现象 | 排查 |
|------|------|
| 页面打不开 | `systemctl status probe`、`nginx -t`、确认 80 端口未被占 |
| `/api/pptp` 报错 | 确认内核已加载 `nf_conntrack`（`lsmod \| grep conntrack`） |
| PPTP 显示异常但实际已连 | GRE 经 NAT 改写属正常，判定基于原始 GRE 条目回包状态；贴 `cat /proc/net/nf_conntrack \| grep -iE 'gre\|1723'` 核对 |
| 海外/国内出口 IP 相同 | 分流未生效，检查 mihomo `oversea.yaml` 分流规则 |
| 历史文件增长 | 已按 7 天滚动自动清理，无需手动干预 |

---

详细设计与全部功能说明见 [README.md](README.md)。
