#!/usr/bin/env bash
# ==============================================================
#  Surfshark 轮换 —— 状态速查
#  故意不用 set -e：诊断脚本里任何一项查不到都不该中断后面的检查。
# ==============================================================
set -uo pipefail

BASE="/opt/surfshark-rotate"
CFG="$BASE/config.yaml"
STATE="$BASE/.rotate_state.json"
PY3="$(command -v python3 || true)"

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
# 必须容忍 secret: 前的缩进 —— rotate.py 与 install.sh 的解析都容忍，
# 而这里不容忍。三处不一致的后果是 config 里缩进一格就同时废掉
# 「钩子恢复」与「降级横幅」，变成永久泄漏且没有任何信号。
BASE_SECRET="$(sed -n 's/^[[:space:]]*secret:[[:space:]]*"\{0,1\}\([^"#]*\)"\{0,1\}[[:space:]]*$/\1/p' "$CFG" 2>/dev/null | head -1)"
AF_NOW=""
if [ -n "$BASE_SECRET" ]; then
    AF_NOW="$(curl -fsS --max-time 5 -H "Authorization: Bearer $BASE_SECRET" \
              http://127.0.0.1:9097/proxies/AUTOFALL 2>/dev/null \
              | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("now") or "")
except Exception: pass' 2>/dev/null)"
fi
# 从状态文件读降级起始时刻。永久泄漏最怕的不是发生，是没人知道它已经持续了
# 两天 —— 一个只有「是/否」的状态无法区分「刚降级 40 秒」和「已经漏了三天」。
DEG_AT=""
DEG_AGE=""
if [ -n "$PY3" ] && [ -f "$STATE" ]; then
    DEG_AT="$("$PY3" -c '
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    print(d.get("degraded_at") or "")
except Exception:
    print("")' "$STATE" 2>/dev/null)"
fi
if [ -n "$DEG_AT" ]; then
    DEG_AGE="$("$PY3" -c '
import datetime, sys
try:
    t0 = datetime.datetime.strptime(sys.argv[1], "%Y-%m-%d %H:%M:%S")
except Exception:
    sys.exit(0)
d = int((datetime.datetime.now() - t0).total_seconds())
if d < 3600:
    print("%d 分钟" % max(0, d // 60))
else:
    print("%d 小时 %d 分" % (d // 3600, (d % 3600) // 60))' "$DEG_AT" 2>/dev/null)"
fi
if [ "$AF_NOW" = "DIRECT" ]; then
    if [ -n "$DEG_AGE" ]; then
        printf '\n\033[1;41m\033[97m  ⚠ 降级中 %s：节点不可用，opencode.ai 未走代理  \033[0m\n' "$DEG_AGE"
    else
        printf '\n\033[1;41m\033[97m  ⚠ 降级中：节点不可用，opencode.ai 未走代理  \033[0m\n'
    fi
    c_err  "  opencode.ai 已退到直连（脚本连续 2 轮取不到出口 IP，且控制面也探测不到节点）—— 还能用，但出口是本机（$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null)），"
    c_err  "  IP 轮换已停摆，而轮换正是这个项目存在的理由。"
    c_err  "  常见原因：Surfshark WireGuard 私钥到期 / 被吊销 / 续费后换了新私钥没更新。"
    c_err  "  恢复：换新私钥 → sudo systemctl restart mihomo（钩子会自动启回轮换定时器）"
    c_warn "  若 9 分钟内没自动恢复，手工执行：sudo systemctl start surfshark-rotate.timer"
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

# ------------------------------------------------------------
#  停摆判据：唯一会打印误导性绿字的组合
# ------------------------------------------------------------
# 定时器 inactive 的原因通常是降级 —— 那是设计如此，横幅已经解释过。
# 但只要 AUTOFALL 不在 DIRECT、状态文件也没有降级标记，「定时器停着」就意味着：
# 轮换停了，而紧接着下面那一节会显示「上一轮轮换结果：成功」——
# 唯一的产出为零，信号却是绿的。手工 stop、systemd-run 失败、单元被 masked
# 都会落到这里。这里补一条红字，把这种组合从暗处搬到明处。
TIMER_ST="$(systemctl is-active surfshark-rotate.timer 2>/dev/null | head -1)"
DEG_FLAG=""
if [ -n "$PY3" ] && [ -f "$STATE" ]; then
    DEG_FLAG="$("$PY3" -c '
import json, sys
try:
    print("true" if json.load(open(sys.argv[1], encoding="utf-8")).get("degraded") else "false")
except Exception:
    print("")' "$STATE" 2>/dev/null)"
fi
if [ "$TIMER_ST" != "active" ] && [ "$AF_NOW" != "DIRECT" ] && [ "$DEG_FLAG" != "true" ]; then
    printf '\n\033[1;41m\033[97m  ⚠ 轮换已停摆且不处于降级态  \033[0m\n'
    c_err  "  定时器状态是「$TIMER_ST」，但降级标记为「否」—— 按设计，停表只会因为降级而发生。"
    c_err  "  opencode.ai 仍走代理（没有泄漏），但 IP 已不会更新，轮换产出为零。"
    c_err  "  恢复：sudo systemctl start surfshark-rotate.timer"
    echo
fi

# ------------------------------------------------------------
#  分流规则异常（跨连接的，不会因为连接断开而消失）
# ------------------------------------------------------------
# 上面那条连接侧检测有个实测出来的软肋：连接是瞬态的，没有流量时查不到。
# 这一条是确定性的 —— rotate.py 每次热重载后都会核对 mihomo **已加载**的规则，
# 不符就退出码 3（ExecMainStatus 变红）并在这里留下记录。它不需要任何流量。
ROUTE_BAD=""
if [ -n "$PY3" ] && [ -f "$STATE" ]; then
    ROUTE_BAD="$("$PY3" -c '
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit
if d.get("routing_bad_at"):
    print(d.get("routing_bad_at") + " | " + (d.get("routing_bad_reason") or ""))' \
        "$STATE" 2>/dev/null)"
fi
ROUTE_UNK=""
if [ -n "$PY3" ] && [ -f "$STATE" ]; then
    ROUTE_UNK="$("$PY3" -c '
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit
if d.get("routing_unknown_at"):
    print(d.get("routing_unknown_at") + " | " + (d.get("routing_unknown_reason") or ""))'         "$STATE" 2>/dev/null)"
fi
if [ -n "$ROUTE_UNK" ]; then
    printf '
[1;43m[30m  ? 分流规则无法核对（判据本身失效，不是已确认的泄漏）  [0m
'
    c_warn  "  最近一次：$ROUTE_UNK"
    c_warn  "  这一刻既没有泄漏证据，也没有「规则正常」的证据 —— 两者都不能推断。"
    c_warn  "  等 mihomo API 恢复，或手工核对：/rules"
    echo
fi

if [ -n "$ROUTE_BAD" ]; then
    printf '\n\033[1;41m\033[97m  ⚠ 分流规则异常：opencode.ai 不走 AUTOFALL  \033[0m\n'
    c_err  "  最近一次核对：$ROUTE_BAD"
    c_err  "  mihomo 已加载的规则里 opencode.ai 不指向 AUTOFALL —— 它会走直连，"
    c_err  "  把本机 IP 泄漏出去。降级逻辑此时完全正常，所以横幅不会亮。"
    c_err  "  排查：sudo /opt/surfshark-rotate/mihomo -t -d /opt/surfshark-rotate \\"
    c_err  "        -f /opt/surfshark-rotate/config.yaml"
    c_err  "        再用 curl -H 'Authorization: Bearer <secret>' \\"
    c_err  "             http://127.0.0.1:9097/rules 看实际生效的目标"
    echo
fi

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
    # 【这条绿字只断言了 ip.sb】上面两次探测走的是 ip.sb（域名型 socks5h），
    # 所以它证明的只有「ip.sb 经代理出去」。
    # 早先这里写的是「分流正常：只有 opencode.ai / ip.sb 走代理」——
    # **顺带断言了它没验证过的东西**，而 sniffer 失效（域名没被还原、
    # 纯 IP 建连落进 MATCH,DIRECT）恰好**不改变** ip.sb 的结果，
    # 因为 ip.sb 走的是域名型代理。于是这正是 L3 类泄漏下的「假全绿」：
    # opencode.ai 正在直连，而这一行是绿的。
    # opencode.ai 那一路现在由上面的「泄漏检测」单独断言（阳性检测）。
    c_ok "  分流正常：ip.sb 经代理出去（这是本段唯一验证过的那一路）"
    c_warn "  提醒：本段不验证 opencode.ai —— 它走上面的阳性检测（connections 的 chains）"
fi

line "泄漏检测"
# ------------------------------------------------------------
# 阳性检测：直接读 mihomo 已建立的连接，看 opencode.ai 实际走了哪条链。
#
# 【为什么不自己实现一份】早先这里内嵌了一份 python，与 rotate.py 的
# direct_leaks() 是同一套判据的第二份实现（继探针 URL、secret 解析、
# DEGRADED_KEYS 之后又一次），而且零测试覆盖 —— 改 rotate.py 那份时
# 这份不会跟着改，且永远不会有人发现。
# 现在改成调 rotate.py：判据只有一份，且那条路径有 5 个测试。
#
# 降级期间出现 DIRECT 是设计如此，不算泄漏，所以只在「未降级」时报。
# 另外连接是瞬态的：没有流量时查不到 —— 这条检测的是正在发生的泄漏，
# 不是历史。跨连接的那条判据在下面「分流规则异常」里。
# 契约：stdout 是一个十进制非负整数，或字面量 skip。**不用退出码承载** ——
# `|| echo skip` 会把 echo 的输出也收进变量（实测变成两行 skip），
# 而 case 的 skip 模式匹配不上，于是「读不到」被当成泄漏条数。
# `*[!0-9]*` 是最后一道防线：rotate.py 崩掉时 log() 走 stdout，
# 变量会是多行日志 + skip，必须归为「读不到」而不是条数。
LEAK_RAW="$("$PY3" "$BASE/rotate.py" --leak-count 2>/dev/null)"
# 契约：stdout 是「十进制非负整数[ ok|noip]」，或字面量 skip。
# **不用退出码承载** —— `|| echo skip` 会把 echo 的输出也收进变量
# （实测变成两行 skip），而 skip 的 case 模式匹配不上，
# 于是「读不到」被当成泄漏条数。
#
# 先按空格切成两个字段，**再**校验第一个是不是纯数字 ——
# 顺序反了的话 "0 ok" 会因为整串含空格与字母而被当成多行日志。
LEAK_N=skip
LEAK_IP=ok
if [ "$LEAK_RAW" != "skip" ] && [ -n "$LEAK_RAW" ]; then
    _LEAK_NUM="${LEAK_RAW%% *}"          # 第一字段：条数
    _LEAK_TAG="${LEAK_RAW##* }"          # 第二字段：ok / noip
    case "$_LEAK_NUM" in
        # 非纯数字 -> rotate.py 崩了，它的 log() 走 stdout，
        # 变量会是多行日志 + 条数，必须归为「读不到」而不是条数。
        ''|*[!0-9]*) LEAK_N=skip ;;
        *)            LEAK_N="$_LEAK_NUM"; LEAK_IP="$_LEAK_TAG" ;;
    esac
fi
case "$LEAK_N" in
    skip|"")
        c_warn "  读不到，跳过（mihomo API 可能不通，或 rotate.py 不可用）" ;;
    0)
        if [ "$LEAK_IP" = "off" ]; then
            # 【半盲时不给绿字】sniffer 失效正是这条检测要覆盖的场景，
            # 而按 IP 反查不可用时它退化成「只按域名匹配」——
            # 也就是对它自己的目标失明。在这种状态下说「未发现」是在骗人。
            c_warn "  未发现 opencode.ai 走直连，**但本次判定是半盲的**"
            c_warn "    （按 IP 反查不可用，只按域名匹配；sniffer 失效正是要覆盖的场景）"
        else
            c_ok   "  未发现 opencode.ai 走直连"
        fi ;;
    *)
        # 门用状态文件的 degraded 标记，与 rotate.py --status 保持一致。
        # 早先这里用 AF_NOW，于是「degraded=true 但 AUTOFALL 已切回 PROXY」
        # 这个**钩子恢复窗口**里，本页会说「正在泄漏」而下一段说「降级期间
        # 属预期」，同一屏自相矛盾。实测过。
        if [ "$DEG_FLAG" = "true" ]; then
            c_warn "  有 $LEAK_N 条 opencode.ai 连接走 DIRECT —— 降级期间属预期"
        else
            printf '
[1;41m[97m  ⚠ 正在泄漏：opencode.ai 走直连，但系统未判定降级  [0m
'
            c_err  "  有 $LEAK_N 条 opencode.ai 的连接正在走 DIRECT。"
            c_err  "  但状态文件的降级标记是「${DEG_FLAG:-读不到}」、AUTOFALL=${AF_NOW:-未知}"
            c_err  "  对端看到的就是这台 VPS 的公网 IP（$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null)）。"
            c_err  "  最可能：分流规则被改动，或 sniffer 失效导致域名没被还原、落进 MATCH,DIRECT。"
            echo
        fi ;;
esac
echo

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