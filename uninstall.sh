#!/usr/bin/env bash
# ==============================================================
#  卸载 Surfshark 轮换方案，恢复到干净状态
#
#      sudo bash uninstall.sh            卸载并保留配置备份
#      sudo bash uninstall.sh --purge    连 /opt 目录一起删掉
# ==============================================================
set -euo pipefail

BASE="/opt/surfshark-rotate"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

c_ok() { printf '\033[32m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "请用 root 运行"; exit 1; }

step "1/4  停止并取消开机自启"
systemctl disable --now surfshark-rotate.timer 2>/dev/null || true
systemctl disable --now surfshark-watchdog.timer 2>/dev/null || true
systemctl stop surfshark-rotate.service 2>/dev/null || true
systemctl disable mihomo.service 2>/dev/null || true
systemctl stop mihomo.service 2>/dev/null || true
c_ok "  ✓ 服务已停"

step "2/4  清理可能残留的策略路由"
if [ -x "$BASE/cleanup-routes.sh" ]; then
    "$BASE/cleanup-routes.sh"
    c_ok "  ✓ 路由已清理"
else
    while ip rule del lookup 2022 2>/dev/null; do :; done
    ip route flush table 2022 2>/dev/null || true
    c_ok "  ✓ 路由已清理（使用内置命令）"
fi

step "3/4  移除 systemd 单元"
rm -f /etc/systemd/system/mihomo.service \
      /etc/systemd/system/surfshark-rotate.service \
      /etc/systemd/system/surfshark-rotate.timer
      /etc/systemd/system/surfshark-watchdog.service
      /etc/systemd/system/surfshark-watchdog.timer
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true
c_ok "  ✓ 单元已移除"

step "4/4  处理安装目录"
if [ "$PURGE" -eq 1 ]; then
    # 【--purge 是「彻底删除」，就不该留一份密钥在盘上】
    # 早先这里把 config.yaml 复制到 /root/surfshark-config-<日期>.yaml
    # 「以防万一」—— 而那个文件里有 4 处 Surfshark WireGuard 私钥，
    # 与 purge 的语义完全相反，且没有任何提示。
    # 备份是**默认**路径（不 purge）就已经在做的事；真要彻底删就别留。
    if [ -f "$BASE/config.yaml" ]; then
        c_warn "  注意：config.yaml 里有 Surfshark 私钥，--purge 将**不保留**备份。"
        printf '  确实要删？输入 PURGE 确认（其它任意键取消）：'
        read -r _ans
        if [ "$_ans" != "PURGE" ]; then
            c_err "  已取消。$BASE 保留，可重新运行本脚本不带 --purge。"
            exit 1
        fi
    fi
    rm -rf "$BASE"
    c_ok "  ✓ $BASE 已删除"
else
    c_ok "  保留 $BASE（含配置与日志回溯信息）"
    c_ok "  如需彻底删除：sudo bash uninstall.sh --purge"
fi

printf '\n'
c_ok "卸载完成。SSH 现在完全不受影响。"
echo "  确认：systemctl is-active mihomo.service   # 应显示 inactive"
echo "  确认：ip rule show | grep 2022              # 应无输出"