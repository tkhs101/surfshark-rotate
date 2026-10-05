#!/usr/bin/env bash
# ==============================================================
#  实测各节点延迟，并打印可直接粘贴的 TIERS 分档
#
#  TIERS 决定「拿不到新 IP 时降级到哪个节点」。分档顺序应当按**你所在的
#  机房**的实际延迟排，而不是照抄别人的。区域内延迟差异可能差好几倍：
#  同一台机器上，JP 是 2ms 而 SG 是 77ms，照抄就等于平时用最差的节点。
#
#  用法：
#      bash measure-nodes.sh
#
#  把输出里的 TIERS 代码块粘进 rotate.py 即可。
# ==============================================================
set -uo pipefail

# 节点显示名 -> Surfshark 域名。顺序与 config.yaml 中的定义保持一致。
NODES=(
    "JP 日本-东京:jp-tok"
    "KR 韩国-首尔:kr-seo"
    "TW 台湾-台北:tw-tai"
    "SG 新加坡:sg-sng"
)
PING_COUNT="${1:-5}"

c_ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
c_warn() { printf '\033[33m%s\033[0m\n' "$*"; }
c_err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }

if ! command -v ping >/dev/null; then
    c_err "缺少 ping 命令"
    exit 1
fi

printf '\n  每个节点测 %d 次 ICMP（衡量到 Surfshark 入口的往返时延）\n\n' "$PING_COUNT"
printf '  %-18s %-12s %s\n' "节点" "中位 RTT" "丢包"
printf '  %-18s %-12s %s\n' "------------------" "------------" "------------"

declare -a ORDER=()
declare -a RESULTS=()

for entry in "${NODES[@]}"; do
    name="${entry%%:*}"
    host="${entry##*:}.prod.surfshark.com"

    if ! getent hosts "$host" >/dev/null 2>&1; then
        printf '  %-18s %-12s %s\n' "$name" "解析失败" "-"
        continue
    fi

    # -q 模式下输出两行摘要：丢包率一行、rtt 一行。
    # 必须整段保存后分别提取，只取 tail -1 只会拿到 rtt 行，丢包列就全是 ?。
    raw="$(ping -c "$PING_COUNT" -W 2 -q "$host" 2>/dev/null)"
    line="$(tail -1 <<< "$raw")"
    if [ -z "$line" ]; then
        printf '  %-18s %-12s %s\n' "$name" "不可达" "-"
        continue
    fi

    med="$(awk -F'= ' '/= /{split($2,a,"/"); print a[2]}' <<< "$line")"
    loss="$(grep -oE '[0-9]+% packet loss' <<< "$raw" | grep -oE '^[0-9]+' || true)"
    [ -n "$loss" ] || loss="?"

    if [ -z "$med" ]; then
        printf '  %-18s %-12s %s\n' "$name" "解析失败" "$loss%"
        continue
    fi

    printf '  %-18s %-12s %s\n' "$name" "${med} ms" "${loss}%"
    ORDER+=("$med|$name")
done

if [ "${#ORDER[@]}" -eq 0 ]; then
    c_err "  所有节点都不可达，先确认出网正常：ping -c 3 1.1.1.1"
    exit 1
fi

# 数值升序排序（用 awk 做浮点比较，避免 sort 按字典序）
sorted="$(printf '%s\n' "${ORDER[@]}" | awk -F'|' '{print $1"\t"$2}' | sort -n -k1,1)"

mapfile -t LINES <<< "$sorted"
n="${#LINES[@]}"

printf '\n  按延迟从低到高：'
for l in "${LINES[@]}"; do printf '%s ' "${l#*$'\t'}"; done
printf '\n\n'

# 分档规则：
#   第 1 档 = 前 2 个（延迟最低，日常轮换在这两档间进行）
#   第 2 档起 = 其余各一个，按延迟顺序（谁快谁先降级过去）
# 只有 1 个节点可用时，全部放同一档。
#
# 用数组收集而不是拼字符串：拼字符串时多行内容只有首行能带上 heredoc 的前缀缩进，
# 输出就会变成首行多缩进、其余行少缩进，粘回源码里很难看。
TIER_LINES=()
if [ "$n" -le 1 ]; then
    TIER_LINES+=("[\"${LINES[0]#*$'\t'}\"],")
elif [ "$n" -eq 2 ]; then
    TIER_LINES+=("[\"${LINES[0]#*$'\t'}\", \"${LINES[1]#*$'\t'}\"],")
else
    TIER_LINES+=("[\"${LINES[0]#*$'\t'}\", \"${LINES[1]#*$'\t'}\"],")
    for ((i = 2; i < n; i++)); do
        TIER_LINES+=("[\"${LINES[$i]#*$'\t'}\"],")
    done
fi

printf '\n  粘贴到 rotate.py，替换掉原来的 TIERS = [...] 整块：\n\n'
printf '  ─────────────────────────────────────────────────\n'
printf '  TIERS = [\n'
for t in "${TIER_LINES[@]}"; do printf '    %s\n' "$t"; done
printf '  ]\n'
printf '  ─────────────────────────────────────────────────\n\n'

if [ "$n" -lt 4 ]; then
    c_warn "  只有 $n 个节点可用，TIERS 将只包含这些。查原因：出网被限 / DNS 异常 / 节点下线。"
fi
