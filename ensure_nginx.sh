#!/bin/bash
#=====================================================================
#  ensure_nginx.sh —— probe 服务的 nginx 引导脚本（ExecStartPre 调用）
#  职责（模拟 VyOS 托管，不依赖 VyOS 是否启用 service https）：
#    1) 确保站点软链 sites-enabled/vyos-net-probe 存在（不在则重建）
#    2) nginx -t 校验通过后，确保 nginx 在运行（未运行则 start）
#    3) 智能共存：nginx 已在运行（无论谁启动的）则不抢管理权，仅补软链
#  幂等、静默容错——任何一步失败都不阻塞 probe 服务启动（exit 0）。
#=====================================================================
NGX_AVAIL="/etc/nginx/sites-available"
NGX_ENABLED="/etc/nginx/sites-enabled"
SITE="vyos-net-probe"
LOG_TAG="[ensure_nginx]"

log(){ printf '%s %s\n' "$LOG_TAG" "$1"; }

# ---- 1. 软链自愈：确保 sites-enabled/vyos-net-probe 存在 ----
if [ -f "$NGX_AVAIL/$SITE" ]; then
    if [ ! -L "$NGX_ENABLED/$SITE" ] && [ ! -e "$NGX_ENABLED/$SITE" ]; then
        ln -sf "$NGX_AVAIL/$SITE" "$NGX_ENABLED/$SITE" && log "软链缺失，已重建 $NGX_ENABLED/$SITE"
    fi
else
    log "警告：$NGX_AVAIL/$SITE 不存在（deploy.sh 未安装站点配置？），跳过"
    exit 0
fi

# ---- 2. nginx 配置校验（不通过则不动 nginx，避免影响现有服务）----
if ! command -v nginx >/dev/null 2>&1; then
    log "警告：未找到 nginx，跳过"
    exit 0
fi
if ! nginx -t >/dev/null 2>&1; then
    log "警告：nginx -t 校验未通过，跳过启动/重载（不影响 probe 服务）"
    exit 0
fi

# ---- 3. 智能共存：判断 nginx 是否已运行 ----
if systemctl is-active --quiet nginx; then
    # 已运行（可能由 VyOS service https 托管，也可能上次已启动）→ 不抢管理权，仅 reload 加载软链
    if systemctl reload nginx >/dev/null 2>&1; then
        log "nginx 已在运行，reload 加载本站点（未抢占管理权）"
    else
        log "nginx 已在运行，reload 失败（可忽略，站点软链已就位）"
    fi
else
    # 未运行 → 由本脚本启动（VyOS 未启用 service https 的场景，达到类托管效果）
    if systemctl start nginx >/dev/null 2>&1; then
        log "nginx 未运行，已启动并加载本站点"
    else
        log "警告：systemctl start nginx 失败（可能 VyOS 托管冲突或配置问题），不阻塞 probe"
    fi
fi

exit 0
