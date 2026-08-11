#!/bin/bash
#=====================================================================
#  出口分流探针看板 一键部署脚本 (VyOS 1.5.0)
#  作用：
#    1) 把探针服务 + 前端页面安装到 /opt/vyos-net-probe
#    2) 安装并启动 systemd 服务 probe（监听 127.0.0.1:8899）
#  幂等：可重复执行。
#=====================================================================
set -e

if [ -t 1 ]; then
  G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; B=$'\033[34m'; D=$'\033[2m'; N=$'\033[0m'
else
  G=''; Y=''; R=''; B=''; D=''; N=''
fi
info(){ printf "${B}[*]${N} %s\n" "$1"; }
ok(){   printf "${G}[✔]${N} %s\n" "$1"; }
warn(){ printf "${Y}[!]${N} %s\n" "$1"; }

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DST_DIR="/opt/vyos-net-probe"

[ "$(id -u)" -eq 0 ] || { printf "${R}请用 root 运行${N}\n"; exit 1; }

# 1) 依赖检查
info "检查依赖 (python3 / dig / curl)…"
for c in python3 dig curl; do
  if ! command -v "$c" >/dev/null 2>&1; then
    warn "缺少 $c —— dig 属 bind9-dnsutils；VyOS 若无请安装或改探针为纯curl"
  fi
done

# 2) 安装文件
info "安装到 ${DST_DIR}…"
mkdir -p "$DST_DIR"
cp -f "$SRC_DIR/probe_server.py" "$DST_DIR/"
cp -f "$SRC_DIR/index.html"      "$DST_DIR/"
chmod +x "$DST_DIR/probe_server.py"
ok "文件已同步"

# 3) 安装 systemd 服务
info "安装 systemd 服务 probe…"
cp -f "$SRC_DIR/probe.service" /etc/systemd/system/probe.service
systemctl daemon-reload
systemctl enable probe >/dev/null 2>&1 || true
systemctl restart probe
sleep 1
if systemctl is-active --quiet probe; then
  ok "探针服务已启动 (127.0.0.1:8899)"
else
  warn "探针服务未正常启动，查看：journalctl -u probe -n 30"
fi

# 4) 自检
info "本地自检 /api/probe …"
if curl -s --max-time 20 http://127.0.0.1:8899/healthz | grep -q ok; then
  ok "探针服务健康检查通过"
else
  warn "健康检查未通过，请查看服务日志"
fi

# 5) 安装独立 nginx 站点（独立端口8080，彻底规避80/443端口博弈；绝不触碰VyOS自有配置）
info "安装独立 nginx 站点 vyos-net-probe（端口 8080）…"
NGX_AVAIL="/etc/nginx/sites-available"
NGX_ENABLED="/etc/nginx/sites-enabled"
if [ -d "$NGX_AVAIL" ] && [ -d "$NGX_ENABLED" ]; then
    cp -f "$SRC_DIR/vyos-net-probe.conf" "$NGX_AVAIL/vyos-net-probe"
    ln -sf "$NGX_AVAIL/vyos-net-probe" "$NGX_ENABLED/vyos-net-probe"
    ok "已安装站点软链 $NGX_ENABLED/vyos-net-probe（未改动任何现有站点）"

    if nginx -t 2>/dev/null; then
        # nginx 运行中则 reload，未运行则 start（reload 对未运行的服务会报错）
        if systemctl is-active --quiet nginx; then
            systemctl reload nginx
            ok "独立站点已启用并重载 nginx（default 站点保持原样）"
        else
            warn "nginx 当前未运行，尝试启动…"
            if systemctl start nginx 2>/dev/null; then
                ok "nginx 已启动并加载独立站点"
            else
                warn "systemctl start nginx 失败。VyOS 上 nginx 可能由配置系统托管，"
                warn "请在 VyOS 配置模式启用 https 服务后再重载，例如："
                warn "    set service https listen-address <网关IP>"
                warn "    commit; save"
                warn "或临时直接启动：sudo nginx"
            fi
        fi
    else
        warn "nginx -t 校验未通过，请手动检查（未改动 default，可安全排查）："
        nginx -t || true
    fi
else
    warn "未找到 $NGX_AVAIL / $NGX_ENABLED（可能非标准 Debian nginx 布局）"
    warn "请手动将 vyos-net-probe.conf 放入你的 nginx 站点目录并 reload"
fi

printf "\n${Y}==== 完成 ====${N}\n"
cat <<EOF
浏览器访问：  http://<VyOS网关IP>:8080/
探针服务  ：  127.0.0.1:8899（仅本地，经 nginx 反代对外）
说明      ：  独立端口8080，不受VyOS 80/443及enable-http-redirect影响，未触碰VyOS自有配置
EOF

ok "部署完成"
