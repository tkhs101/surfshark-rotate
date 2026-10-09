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

grep -q '^.*降级状态 : 是' <<< "$clean" && reasons+=("处于降级态：opencode.ai 正在走直连（出口是本机 IP）")
grep -q '正在泄漏' <<< "$clean" && reasons+=("检测到 opencode.ai 的连接走直连")
grep -q '分流规则异常' <<< "$clean" && reasons+=("分流规则异常：opencode.ai 不走 AUTOFALL")
grep -q '无法核对' <<< "$clean" && reasons+=("分流规则无法核对：判据本身失效，此刻无法判断")
grep -q '停摆' <<< "$clean" && reasons+=("轮换停摆：定时器没在跑，或 AUTOFALL 卡住")
grep -q 'IP 反查  : 不可用' <<< "$clean" && reasons+=("泄漏检测半盲：按 IP 反查不可用，只按域名匹配")
grep -q '池子抽干' <<< "$clean" && reasons+=("出口地址池已抽干，12h 内无法再取到未用过的地址")
grep -q '重摇 [0-9]* 次仍撞上' <<< "$clean" && reasons+=("重摇用尽仍撞上窗口内用过的地址")

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
cur="$(printf '%s' "${reasons[@]}")"
if [ "$prev" != "$cur" ]; then
    say "⚠ 需要人工关注："
    for r in "${reasons[@]}"; do say "  · $r"; done
    say "标记已写入 $ALERT"
fi
printf '%s\n' "$cur" > "$STATE"
exit 0