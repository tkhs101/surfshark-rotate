#!/usr/bin/env bash
# ==============================================================
#  Surfshark 轮换 —— 状态速查
#  故意不用 set -e：诊断脚本里任何一项查不到都不该中断后面���查。
# ==============================================================
set -uo pipefail

BASE="/opt/surfshark-rotate"
CFG="$BASE/config.yaml"

c_ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
c_warn() { printf '\033[33m%s\033[0m\n' "$*"; }
c_err()  { printf '\033[31m%s\033[0m\n' "$*"; }
line()   { printf '\n\033[1;36m── %s ──\033[0m\n' "$*"; }

if [ "$(id -u)" -ne 0 ]; then
    c_warn "建议用 root 运行，读取部分文件需要权限"
fi

# ------------------------------------------------------------
line "服务"
# ------------------------------------------------------------
for u in mihomo.service surfshark-rotate.timer surfshark-rotate.service; do
    # systemctl is-active 在非 active 时会往 stdout 打印状态，同时以非零码退出。
    # 因此不能写成 `|| echo unknown` —— 那样 $st 会变成两行
    # （先 "inactive" 再 "unknown"），输出里就会多出一行看不懂的东西。
    st="$(systemctl is-active "$u" 2>/dev/null | head -1)"
    st="${st:-未安装}"
    case "$u" in
        *rotate.service) st="$st（单次任务，跑完退出即正常）" ;;
    esac
    case "$st" in
        active*)  printf '  %-28s \033[32m%s\033[0m\n' "$u" "$st" ;;
        failed*)  printf '  %-28s \033[31m%s\033[0m\n' "$u" "$st" ;;
        *)        printf '  %-28s \033[33m%s\033[0m\n' "$u" "$st" ;;
    esac
done

line "轮换定时器"
# ------------------------------------------------------------
systemctl --no-pager list-timers surfshark-rotate.timer 2>/dev/null | sed 's/^/  /'
echo
LAST="$(systemctl show surfshark-rotate.service -p ExecMainStatus --value 2>/dev/null || echo '?')"
if [ "$LAST" = "0" ]; then
    c_ok "  上一轮轮换结果：成功"
elif [ "$LAST" = "?" ] || [ -z "$LAST" ]; then
    c_warn "  上一轮轮换结果：暂无记录（服务可能还没跑过）"
else
    c_err "  上一轮轮换结果：失败（退出码 $LAST）"
    c_err "  看原因：journalctl -u surfshark-rotate.service -n 30"
fi

line "分流验证"
# ------------------------------------------------------------
DIRECT="$(curl -fsS --max-time 15 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || echo '(取不到)')"
PROXY="$(curl -fsS --max-time 20 --proxy socks5h://127.0.0.1:7897 \
          https://ip.sb/ip 2>/dev/null | tr -d '[:space:]' || echo '(取不到)')"
echo "  直连出口（应为本机/VPS 真实 IP）：$DIRECT"
echo "  代理出口（应为 Surfshark 节点 IP）：$PROXY"
if [ "$PROXY" = "(取不到)" ]; then
    c_err "  取不到代理出口 —— 隧道可能没建起来，或出站 UDP 被拦"
    c_err "  排查：journalctl -u mihomo -n 40 | grep -i -E 'wireguard|handshake|error'"
elif [ "$DIRECT" = "$PROXY" ]; then
    c_warn "  两者相同 —— 分流可能没生效，检查 config.yaml 的 rules"
else
    c_ok "  分流正常：只有 opencode.ai / ip.sb 走代理"
fi

line "轮换器内部状态"
# ------------------------------------------------------------
if [ -f "$BASE/rotate.py" ]; then
    # 从配置里取密钥，不写死在脚本里
    SECRET="$(sed -n 's/^secret:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' "$CFG" 2>/dev/null | head -1)"
    ROTATE_SECRET="$SECRET" python3 "$BASE/rotate.py" --status 2>&1 | sed 's/^/  /'
else
    c_err "  找不到 $BASE/rotate.py"
fi

line "最近 10 轮轮换"
# ------------------------------------------------------------
journalctl -u surfshark-rotate.service -n 40 --no-pager 2>/dev/null \
    | grep -E '完成|失败|异常|!!' | tail -10 | sed 's/^/  /' || echo "  (暂无记录)"
echo
c_warn "  看完整日志：journalctl -u surfshark-rotate.service -n 50 --no-pager"