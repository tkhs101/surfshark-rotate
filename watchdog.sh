#!/usr/bin/env bash
# 看门狗：只出声，不修复。
#
# 【为什么不直接读状态文件自己判断】状态文件是 rotate.py 的 schema，字段会演进。
# 这里复用 rotate.py 已经算好的结论（`--status` 的输出），而不是再实现一遍判据 ——
# 再实现一遍就是第二个 owner，两边迟早漂移（这个项目已经吃过一次亏：
# BROAD 集合用 YAML 拼写而 /rules 返回 CamelCase）。
#
# 【怎么被外部接走】ALERT 文件是纯文本，第一行是 ISO 时间戳，其余是原因行。
# 有 Telegram/邮件/短信通道的话，写个脚本读它即可，不必改本项目。
set -uo pipefail
BASE="$(cd "$(dirname "$0")" && pwd)"
PY3="$(command -v python3 || echo /usr/bin/python3)"
ALERT="$BASE/.alert"
STATE="$BASE/.watchdog_state"

say() { printf '[watchdog] %s\n' "$1"; }

STATUS="$("$PY3" "$BASE/rotate.py" --status 2>&1)"
rc=$?

reasons=()
[ "$rc" -ne 0 ] && reasons+=("rotate.py --status 退出码 $rc")

# 去掉颜色码再匹配；只认「真正需要注意」的那几类
clean="$(printf '%s' "$STATUS" | sed 's/\x1b\[[0-9;]*m//g')"

# 【每条模式都必须对得上 --status 的真实输出】
# 上一版有三条永远不可能命中：我照着 status.sh 的文案写，却去 grep --status 的
# 输出 ——「正在泄漏」「分流规则异常」「无法核对」只在 status.sh 里出现。
# 现在 rotate.py --status 直接报全（它是状态文件的解释 owner），
# 下面的模式与它一一对应，并由 TestWatchdogPatternsMatchRealOutput 守着。
grep -q '降级状态 : 是' <<< "$clean" && reasons+=("处于降级态：opencode.ai 正在走直连（出口是本机 IP）")
grep -q '!! 分流规则异常' <<< "$clean" && reasons+=("分流规则异常：opencode.ai 不走 AUTOFALL")
grep -q '分流规则无法核对' <<< "$clean" && reasons+=("分流规则无法核对：判据本身失效，此刻无法判断")
grep -q '重摇仍撞上' <<< "$clean" && reasons+=("重摇用尽仍撞上窗口内用过的地址")
# 【这条我写错过两次】真实输出是
#   ⚠ 泄漏检测 : 有 2 条 opencode.ai 连接正在走 DIRECT！
# 带 ⚠ 前缀、且是「连接**正在**走」。先前写成 `!! 有 N 条 …连接走 DIRECT`，
# 同样打不中 —— 而我加的测试只锁了最初那三个死模式，所以没报出来。
# **这正是「锁死已知死模式」这种测试的盲区：新的死模式它一律看不见。**
grep -qE '泄漏检测 : 有 [0-9]+ 条' <<< "$clean" && reasons+=("检测到 opencode.ai 的连接走直连")
# 这一行曾被评审的实验注入覆盖成 `探测通道固定走 PROXY`，并被我随后的提交收进
# HEAD。那是个只在**降级态**才打印的串，于是半盲告警在该响时不响、
# 降级时误响、而理由还写着「按 IP 反查不可用」。已改回。
grep -q 'IP 反查  : 不可用' <<< "$clean" && reasons+=("泄漏检测半盲：按 IP 反查不可用，只按域名匹配")
grep -q '轮换停摆' <<< "$clean" && reasons+=("轮换停摆：定时器没在跑，或 AUTOFALL 卡住")
# 反向矩阵扫出来的真漏：--status 在 API 读不到时会打 `!! mihomo API 不通`
# 然后直接 return —— 也就是说**后面所有检查都没跑**。这种「判据来源失效」
# 必须喊出来，否则 watchdog 会把「什么都没检查」当成「一切正常」。
grep -q 'mihomo API 不通' <<< "$clean" && reasons+=("判据失效：mihomo API 不通，--status 后续检查全部未执行")
# 状态文件丢失/损坏时：AUTOFALL 卡在 DIRECT，但没人再负责切回来。
grep -q '状态不一致' <<< "$clean" && reasons+=("状态不一致：AUTOFALL 停在 DIRECT 但状态文件说没降级（多半是状态文件丢了）")
grep -q '12h 预算' <<< "$clean" || reasons+=("读不到 12h 预算 —— 判据来源可能失效")
# 「池子抽干」只在确实轮换过、且 now 无 spare 时才算数。
# 早先无条件 grep 那句，全新安装（只有 1 条记录、last_ip=None）时
# spare 为空集 -> **刚装好的机器第一轮就喊「地址池已抽干」**。
# 「已换过」不能只做子串匹配 —— 全新安装时输出是「已换过 **0** 轮」，
# 仍然含「已换过」，于是上一版那个守卫在场景 H（刚装好、只有 1 条记录）
# 依然会命中，「第一轮就喊池子抽干」并没有真正修掉。必须要求轮次 > 0。
if grep -q '已经没有任何未用过的地址' <<< "$clean"    && grep -qE '已换过 [1-9][0-9]* 轮' <<< "$clean"; then
    reasons+=("出口地址池已抽干，12h 内无法再取到未用过的地址")
fi

now="$(date -Is)"

if [ "${#reasons[@]}" -eq 0 ]; then
    if [ -f "$ALERT" ]; then
        say "已恢复正常，清除告警标记"
        rm -f "$ALERT"
    fi
    printf '%s\n' "$now" > "$STATE"
    exit 0
fi

{
    printf '%s\n' "$now"
    printf 'surfshark-rotate 需要人工关注（watchdog 只报不修）：\n'
    for r in "${reasons[@]}"; do printf '  · %s\n' "$r"; done
    printf '\n查看详情： sudo /opt/surfshark-rotate/status.sh\n'
} > "$ALERT"

# 只在「原因集合变了」时才喊进 journal，否则每 5 分钟刷一次同样的内容
prev="$(cat "$STATE" 2>/dev/null || true)"
# 用换行连接而不是直接拼：printf '%s' 拼接会让 [ab,c] 与 [a,bc] 得到同一个值，
# 于是「原因变了但 prev==cur」而静默不报。
cur="$(printf '%s
' "${reasons[@]}")"
if [ "$prev" != "$cur" ]; then
    say "⚠ 需要人工关注："
    for r in "${reasons[@]}"; do say "  · $r"; done
    say "标记已写入 $ALERT"
fi
printf '%s\n' "$cur" > "$STATE"
exit 0