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
#  降级横幅
#  必须在所有其它检查之前打：降级时下面的「分流验证」会给出误导性的结论
#  （代理出口 == 直连出口），先看到横幅才不会照着错误方向去排查。
# ------------------------------------------------------------
BASE_SECRET="$(sed -n 's/^secret:[[:space:]]*"\{0,1\}\([^"#]*\)"\{0,1\}[[:space:]]*$/\1/p' "$CFG" 2>/dev/null | head -1)"
AF_NOW=""
if [ -n "$BASE_SECRET" ]; then
    AF_NOW="$(curl -fsS --max-time 5 -H "Authorization: Bearer $BASE_SECRET" \
              http://127.0.0.1:9097/proxies/AUTOFALL 2>/dev/null \
              | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("now") or "")
except Exception: pass' 2>/dev/null)"
fi
if [ "$AF_NOW" = "DIRECT" ]; then
    printf '\n\033[1;41m\033[97m  ⚠ 降级中：节点不可用，opencode.ai 未走代理  \033[0m\n'
    c_err  "  opencode.ai 已退到直连（脚本连续 2 轮取不到出口 IP，且控制面也探测不到节点）—— 还能用，但出口是本机（$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null)），"
    c_err  "  IP 轮换已停摆，而轮换正是这个项目存在的理由。"
    c_err  "  常见原因：Surfshark WireGuard 私钥到期 / 被吊销 / 续费后换了新私钥没更新。"
    c_err  "  恢复：换新私钥 → sudo systemctl restart mihomo（钩子会自动启回轮换定时器）"
    c_warn "  若 2 分钟内没自动恢复，手工执行：sudo systemctl start surfshark-rotate.timer"
    echo
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
    # 这两种情况表面上完全一样（代理出口 == 直连出口），但排查方向相反：
    #   · 降级了  → 该查私钥 / 节点健康，不是 rules 写错了
    #   · 没降级  → rules 确实没生效，该查规则匹配
    # 原实现在这里一律提示「检查 config.yaml 的 rules」，降级时会把人引向
    # 完全错误的方向 —— 而这恰恰是最容易发生的那种情况。
    if [ "$AF_NOW" = "DIRECT" ]; then
        c_warn "  两者相同 —— 因为已降级到直连（见顶部横幅）。规则本身没问题，别去查 rules。"
        c_warn "  该查的是私钥：journalctl -u mihomo -n 40 | grep -i 'dial PROXY'"
    else
        c_warn "  两者相同，且未降级 —— 分流确实没生效，检查 config.yaml 的 rules"
        c_warn "  排查：journalctl -u mihomo -n 40 | grep -i opencode"
    fi
else
    c_ok "  分流正常：只有 opencode.ai / ip.sb 走代理"
fi

line "轮换器内部状态"
# ------------------------------------------------------------
if [ -f "$BASE/rotate.py" ]; then
    # 复用上面降级横幅已经取过的密钥，不在这里再取一遍 ——
    # 同一个值两处独立解析，改一处忘一处就会出现两个真相来源。
    ROTATE_SECRET="$BASE_SECRET" python3 "$BASE/rotate.py" --status 2>&1 | sed 's/^/  /'
else
    c_err "  找不到 $BASE/rotate.py"
fi

line "最近 10 轮轮换"
# ------------------------------------------------------------
journalctl -u surfshark-rotate.service -n 40 --no-pager 2>/dev/null \
    | grep -E '完成|失败|异常|!!' | tail -10 | sed 's/^/  /' || echo "  (暂无记录)"
echo
c_warn "  看完整日志：journalctl -u surfshark-rotate.service -n 50 --no-pager"