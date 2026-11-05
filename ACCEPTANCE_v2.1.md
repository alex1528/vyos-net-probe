# vyos-net-probe v2.1 验收清单（部署后在 VyOS 网关上逐条核对）

> 范围：L1 DNS 解析加固 + 探针调度并发修复 + 看板 RCODE/耗时展示。
> 约定：`✅` = 符合预期；`❌` = 异常，记录现象后排查。探针端口 `127.0.0.1:8899`，看板 `http://<网关IP>:8080/`。

---

## 0. 部署与服务

| # | 步骤 | 命令 / 操作 | 预期 | 结果 |
|---|------|------------|------|------|
| 0.1 | 一键部署 | `sudo bash /tmp/vyos-net-probe/deploy.sh` | 末尾打印「部署完成」，无红色报错 | ☐ |
| 0.2 | 服务运行 | `systemctl is-active probe` | `active` | ☐ |
| 0.3 | 健康检查 | `curl -s http://127.0.0.1:8899/healthz` | 返回 `ok` | ☐ |
| 0.4 | 日志无异常 | `journalctl -u probe -n 30` | 无 Traceback | ☐ |

---

## 1. L1 正常路径（新增 rcode / rtt 字段）

| # | 步骤 | 命令 / 操作 | 预期 | 结果 |
|---|------|------------|------|------|
| 1.1 | 字段落地 | `curl -s http://127.0.0.1:8899/api/probe \| python3 -m json.tool \| grep -E 'resolved\|dns_rcode\|dns_rtt\|dns_error'` | 每个探针均出现 `dns_rcode`/`dns_rtt`/`dns_error` 三字段 | ☐ |
| 1.2 | 正常解析 | 同上，看一个国内探针（如 cip.cc） | `resolved` 有 IP、`dns_rcode=NOERROR`、`dns_rtt` 为正整数、`dns_error=null` | ☐ |
| 1.3 | 看板耗时 | 浏览器打开 `:8080/`，看探针卡片 **L1 解析** 行 | 成功项末尾显示 `(NN ms)` | ☐ |

---

## 2. L1 失败归因（RCODE 分支）

| # | 场景 | 构造方法 | 预期 `dns_rcode` / `dns_error` | 看板显示 | 结果 |
|---|------|---------|------------------------------|---------|------|
| 2.1 | 域名不存在 | 临时把某探针 domain 改为 `no-such-host-zzz9988.com` 后 `systemctl restart probe` | `dns_rcode=NXDOMAIN` | `✘ 域名不存在` | ☐ |
| 2.2 | 本地 DNS 不可达 | `PROBE_DNS=192.0.2.1 python3 /opt/vyos-net-probe/probe_server.py`（黑洞 IP，前台跑一次） | `dns_error=no_response` | `✘ 无响应/超时` | ☐ |
| 2.3 | 上游故障（可选） | 指向一个会返回 SERVFAIL 的解析器 | `dns_rcode=SERVFAIL` | `✘ DNS服务故障` | ☐ |

> 对照：`dig @127.0.0.1 no-such-host-zzz9988.com A +short` 应为空；用于核对 L1 判定与 dig 一致。

---

## 3. L1 重试 / IPv6 / 耗时

| # | 项 | 核对方法 | 预期 | 结果 |
|---|------|---------|------|------|
| 3.1 | 丢包重试 | 默认 `PROBE_DNS_RETRIES=2`；偶发丢包不应立刻判失败 | 瞬时丢包后仍能解析成功 | ☐ |
| 3.2 | AAAA 补查 | 对一个仅 IPv6 的域名观察（或设 `PROBE_DNS_AAAA=1`） | A 无结果时 `ipv6` 有值、`levels.L1=true` | ☐ |
| 3.3 | 关闭 AAAA | `PROBE_DNS_AAAA=0` 重启 | 不再补查 AAAA | ☐ |
| 3.4 | 超时可调 | `PROBE_DNS_TIMEOUT=1` 重启 | 慢 DNS 更快判 `no_response` | ☐ |

---

## 4. 探针调度并发修复（本次重点）

| # | 项 | 核对方法 | 预期 | 结果 |
|---|------|---------|------|------|
| 4.1 | 整体硬超时 | `time curl -s http://127.0.0.1:8899/api/probe >/dev/null` | 总耗时 ≤ `PROBE_HARD_TIMEOUT`(默认 25s)，通常数秒 | ☐ |
| 4.2 | 单探针卡死不阻塞 | 临时加一个指向黑洞的探针域名，重启后请求 | 其余探针正常返回，卡死项标 `timeout:true`，整体不被拖死 | ☐ |
| 4.3 | 不留僵尸线程 | 连续多次 `/api/probe` 后 `journalctl -u probe` | 无线程堆积 / 无异常增长 | ☐ |

---

## 5. 前端看板视觉核对（:8080/）

| # | 项 | 预期 | 结果 |
|---|------|------|------|
| 5.1 | L1 行成功态 | 显示解析 IP + ✔ + `(NN ms)` | ☐ |
| 5.2 | L1 行失败态 | 显示中文化原因（域名不存在 / DNS服务故障 / 被拒绝 / 无响应超时）+ ✘ | ☐ |
| 5.3 | 超时卡片 | 顶部有 `⏱ 超时` 标签，判失败 | ☐ |
| 5.4 | 旧字段兼容 | 老数据无新字段时回退显示「解析失败」不报错 | ☐ |

---

## 6. 回归（不受本次改动影响）

| # | 项 | 核对方法 | 预期 | 结果 |
|---|------|---------|------|------|
| 6.1 | L2 出口 | 看板各探针 L2 出口 IP | 正常取到出口 IP + 延迟 | ☐ |
| 6.2 | L3 分流 | 分流校验行 | 各出口 IP 互不相同 = 分流生效 | ☐ |
| 6.3 | L4 归属地 | 归属地行 | 正常显示国家（失败不影响判定） | ☐ |
| 6.4 | PPTP/GRE | `curl -s http://127.0.0.1:8899/api/pptp \| python3 -m json.tool` | 判定与改前一致 | ☐ |
| 6.5 | 历史趋势 | `/api/history?n=50` 与看板折线 | 正常落盘与展示 | ☐ |

---

## 7. git 提交核对（开发机 Git Bash）

| # | 步骤 | 命令 | 预期 | 结果 |
|---|------|------|------|------|
| 7.1 | 提交 | `cd /d/work/vyos/vyos-net-probe && bash commit.sh` | 按白名单提交，首行 `feat(probe): L1 DNS解析加固(v2.1) …` | ☐ |
| 7.2 | 白名单外文件未入库 | `git status -s` | 无临时/备份文件被提交 | ☐ |
| 7.3 | 打版本 tag（可选） | `git tag v2.1` | tag 建立 | ☐ |

---

## 8. v2.2 L1 DNS 服务器指定（等价 dig @IP）

| # | 项 | 命令 / 操作 | 预期 | 结果 |
|---|------|------------|------|------|
| 8.1 | 对照 dig | `dig ifconfig.me @10.60.2.254 +short` | 有解析结果 | ☐ |
| 8.2 | service 已更新 | `systemctl show probe -p Environment` | 含 `PROBE_DNS=auto`，不再是 `127.0.0.1` | ☐ |
| 8.3 | 启动择优日志 | `journalctl -u probe -n 20 \| grep "L1 DNS"` | `选中 10.60.2.254(iface:eth2) ok=True`（或 eth3） | ☐ |
| 8.4 | 探针使用的 DNS | `curl -s http://127.0.0.1:8899/api/probe \| python3 -m json.tool \| grep -E '"dns"\|dns_server'` | `dns` / `dns_server` 为 eth2 或 eth3 的 IP | ☐ |
| 8.5 | 看板 L1 | 浏览器 `:8080/` | L1 解析行 ✔ 显示 IP + 耗时(通常 <50ms)；顶部 DNS 悬停可见候选列表 | ☐ |
| 8.6 | 固定 IP 写法 | `PROBE_DNS=10.60.2.254` 重启 | 行为同上，`dns_select.source=static` | ☐ |
| 8.7 | 不通时耗时减半 | `PROBE_DNS=192.0.2.1` 前台跑一次 | `no_response`，`dns_rtt` ≈ 6000ms（旧版 ≈12000ms） | ☐ |

## 回滚方法（如需）

- 代码回滚：`git checkout <上一个提交> -- probe_server.py index.html` 后 `systemctl restart probe`。
- 临时关 AAAA / 调超时：改环境变量重启，无需改码。
