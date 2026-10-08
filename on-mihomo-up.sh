#!/usr/bin/env bash
# ==============================================================
#  mihomo 启动钩子（mihomo.service 的 ExecStartPost）
#
#  职责：机器处于降级态时，把停掉的轮换定时器启回来。
#
#  【为什么挂在 mihomo.service 上】
#  换 Surfshark WireGuard 私钥必然要 systemctl restart mihomo 才生效，
#  所以「mihomo 重启」就是最精确的恢复触发点 —— 不需要轮询，
#  也不需要监视配置文件有没有被改。正常运行时本脚本立刻返回，零开销。
#
#  【和谁配合】
#  · rotate.py 检测到节点全挂时，会 systemctl stop surfshark-rotate.timer
#    并在 .rotate_state.json 里写 degraded=true（详见 rotate.py 的 mark_degraded）
#  · mihomo 侧的 AUTOFALL（fallback 组）会在节点恢复后自动切回 PROXY，
#    但那只是数据面 —— 没人把定时器启回来，轮换不会自己复活。
#    本脚本补的就是这一环。
#
#  设计原则：永远返回 0。
#  ExecStartPost 一旦非零退出，systemd 会把 mihomo.service 判为 failed，
#  而 Restart=always 会因此反复重启一个内核完全健康的服务。
#  本脚本查不到东西、状态不对、API 没起来，都只是「什么都不做」。
# ==============================================================
set -uo pipefail

BASE="/opt/surfshark-rotate"
CFG="$BASE/config.yaml"
STATE="$BASE/.rotate_state.json"
TIMER="surfshark-rotate.timer"
PY3="$(command -v python3 || true)"

# 复查的间隔与上限。
# 间隔：换新私钥 + restart mihomo 之后，WireGuard 要重新握手，给它一点时间。
# 上限：复查是有限次的。早先这里每 90 秒无条件重排自己一次，只要没人修私钥
# 就永远存在，既持续写 journal，也和本脚本「正常运行时立刻返回」的说明矛盾。
# 超限后明确交给人，并说明重启即可重新计数。
RECHECK_DELAY=90
RECHECK_MAX=6      # 6 × 90s ≈ 9 分钟

say() { printf '[on-mihomo-up] %s\n' "$*"; }

# ---- 不在降级态：什么都不做，立刻返回（正常启动走的就是这条）----
# 顺序有讲究：先确认 python3 和状态文件都在，再去问「是不是降级态」。
# 反过来写的话，python3 缺失时会把 "-c" 当成命令去执行。
[ -z "$PY3" ] && exit 0

# 状态文件只有两种情况要继续往下走：
#   · 明确写着 degraded        → 正常降级，检查是否恢复
#   · 缺失 / 损坏 / 读不出来   → 仍要往下走，理由见下
#
# 【为什么后者不能直接 exit 0】降级时 AUTOFALL 是被我们设成 DIRECT 的，
# 而 mihomo 会把这个 select 组的选择持久化到 cache.db。若此刻状态文件被删
# 或损坏，degraded 标记就没了，但数据面上 opencode.ai 仍在用本机 IP 出网，
# 而定时器早就被 mark_degraded 停掉了 —— 谁都不会再去看它一眼。
# 早先这里直接 exit 0，等于让这种状态永久泄漏且无人察觉。
# 所以读不出状态时继续往下走，改用数据面本身（AUTOFALL 实际指向谁）来判断。
# 三态判定，用 case 写而不是 && / || —— 退出码的语义必须一眼可见：
#   0 = 明确处于降级态 -> 继续往下走
#   1 = 明确没有在降级 -> 立刻返回（正常启动走的就是这条，零开销）
#   2 = 状态文件读不出来 -> 继续往下走，改用数据面判断
# 早先写成 `"$PY3" -c ... && exit 0`，把语义整个反转了：已降级反而立刻退出，
# 于是恢复路径完全失灵 —— 而降级路径不受影响，只测降级根本发现不了。
STATE_UNKNOWN=0
if [ -f "$STATE" ]; then
    "$PY3" -c 'import json,sys
try:
    sys.exit(0 if json.load(open(sys.argv[1])).get("degraded") else 1)
except Exception:
    sys.exit(2)' "$STATE" 2>/dev/null
    case "$?" in
        0) ;;
        1) exit 0 ;;
        *) STATE_UNKNOWN=1 ;;
    esac
else
    STATE_UNKNOWN=1
fi

if [ "$STATE_UNKNOWN" = "1" ]; then
    say "状态文件缺失或损坏，改用数据面判断是否处于降级态…"
fi

[ -r "$CFG" ] || exit 0
SECRET="$(sed -n 's/^secret:[[:space:]]*"\{0,1\}\([^"#]*\)"\{0,1\}[[:space:]]*$/\1/p' "$CFG" 2>/dev/null | head -1)"
case "$SECRET" in
    ""|*@*) exit 0 ;;
esac

# 等 API 起来（首次启动还要下载 MMDB，最多等 30 秒）
READY=0
for _ in $(seq 1 30); do
    if curl -fsS --max-time 2 -H "Authorization: Bearer $SECRET" \
            http://127.0.0.1:9097/version >/dev/null 2>&1; then
        READY=1; break
    fi
    sleep 1
done
[ "$READY" -eq 1 ] || { say "控制接口 30 秒内没起来，本次不处理"; exit 0; }

# ---- 节点是否真的活了 ----
#
# 【为什么不能看 AUTOFALL 现在选的是谁】AUTOFALL 已经改成 select 组，
# 由 rotate.py 显式切换，降级期间它就是 DIRECT —— 那是**我们自己的选择**，
# 不是内核的判断。拿它判断恢复会自证循环：DIRECT 意味着「我们判定降级了」，
# 不意味着「节点还没好」。
#
# 这里走控制面的 /proxies/<节点>/delay，完全不经过 AUTOFALL 与数据面。
# 它回答的是一个独立问题：节点本身现在通不通。
#
# 输出 "<当前节点> <延迟毫秒>" 表示活着；输出空串表示还没活。
#
# 连续采样 HEALTH_PROBES 次（中间隔 HEALTH_GAP 秒），全健康才算恢复 ——
# 与 rotate.py 的 RECOVER_AFTER_HEALTHY 对称。单次侥幸成功不足以证明
# 「真的修好了」：那次成功的对象是 cp.cloudflare.com，不是我们要保的出口。
# 两次之间任何一个失败就整体作废，避免对着一台还在抖的隧道下结论。
HEALTH_PROBES=2
HEALTH_GAP=8
RESULT="$("$PY3" - "$HEALTH_PROBES" "$HEALTH_GAP" <<'PY' 2>/dev/null
import json, re, sys, time, urllib.parse, urllib.request
cfg = open("/opt/surfshark-rotate/config.yaml", encoding="utf-8").read()
sec = re.search(r'(?m)^secret:\s*"?([^"#\s]+)"?\s*$', cfg)
if not sec:
    sys.exit(0)
H = {"Authorization": "Bearer " + sec.group(1)}
API = "http://127.0.0.1:9097"
WANT = int(sys.argv[1]); GAP = int(sys.argv[2])


def get(path, timeout=15):
    req = urllib.request.Request(API + path, headers=H)
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def probe(node):
    q = urllib.parse.quote(node, safe="")
    u = urllib.parse.quote("http://cp.cloudflare.com/", safe="")
    try:
        d = get("/proxies/%s/delay?timeout=8000&url=%s" % (q, u), timeout=20)
        dl = d.get("delay")
        return dl if isinstance(dl, int) and dl > 0 else None
    except Exception:
        return None


try:
    node = get("/proxies/PROXY").get("now") or ""
    if not node:
        sys.exit(0)
    last = None
    for i in range(WANT):
        if i:
            time.sleep(GAP)
        last = probe(node)
        if last is None:
            sys.exit(0)          # 任一次失败 -> 整体作废
    print("%s %d" % (node, last))
except Exception:
    pass
PY
)"

NODE_ALIVE="${RESULT%% *}"
DELAY_MS="${RESULT##* }"

if [ -z "$NODE_ALIVE" ]; then
    # 节点此刻还没活，起一次复查。
    #
    # 【复查次数必须有上限】早先这里每 90 秒无条件重排自己一次，只要没人去修
    # 私钥就永远存在：既持续往 journal 里写，也和本脚本开头「正常运行时立刻
    # 返回、零开销」的说法自相矛盾。计数存在状态文件里，所以走的是 rotate.py
    # 的原子写，不会和轮换那一侧撞车。
    #
    # 上限的意义不是「等够了就放弃」，而是把等待变成有限次的、看得见的等待 ——
    # 超限时明确告诉人现在是什么状态、要做什么，而不是让人以为系统还在自己
    # 努力。再往后想恢复，只需要 restart mihomo 一次，计数会重置。
    TRIES="$("$PY3" -c '
import json, sys, os
p = sys.argv[1]
try:
    print(int(json.load(open(p)).get("recheck_tries") or 0))
except Exception:
    print(0)' "$STATE" 2>/dev/null || echo 0)"
    NEXT=$((TRIES + 1))

    if [ "$NEXT" -gt "$RECHECK_MAX" ]; then
        say "已复查 $TRIES 次仍未恢复，停止自动复查（不会有人来修的）"
        say "  现在是降级态：opencode.ai 走直连还能用，但出口是本机 IP，轮换已停摆。"
        say "  修好之后二选一：sudo systemctl restart mihomo（计数重置，重新自动复查）"
        say "            或直接 sudo systemctl start $TIMER"
        exit 0
    fi

    say "控制面探测节点失败，${RECHECK_DELAY}s 后复查（第 $NEXT/$RECHECK_MAX 次）"
    # 计数由 rotate.py 落盘：它走 flock + 原子写，是状态 schema 的唯一 owner。
    # 钩子里再手写一份读-改-写，就多一个能把它写坏的版本 —— 实测手写那份
    # 确实没写进去，而计数没落盘会让上限永远不生效。
    GOT="$("$PY3" "$BASE/rotate.py" --recheck-tried 2>/dev/null || echo "$NEXT")"
    [ "$GOT" = "$NEXT" ] || say "⚠ 复查计数写入异常（期望 $NEXT，实得 $GOT）"

    if command -v systemd-run >/dev/null; then
        systemd-run --quiet --unit=surfshark-rotate-resume \
            --on-active="${RECHECK_DELAY}" \
            /bin/bash "$BASE/on-mihomo-up.sh" >/dev/null 2>&1 \
            || say "复查起不来，等下次 mihomo 重启或手工 systemctl start $TIMER"
    else
        say "systemd-run 不可用，请手工执行 systemctl start $TIMER"
    fi
    exit 0
fi

# ---- 已恢复：切回代理、启回定时器并清标记 ----
if systemctl start "$TIMER" 2>/dev/null; then
    # 降级痕迹交给 rotate.py 清，不在这里再写一份 key 列表 ——
    # 两个写入方各维护一份清单，迟早会漏掉某个键，而漏掉的恰恰是
    # 「标记已恢复」这类语义最重的键。顺带把复查计数一并归零。
    "$PY3" "$BASE/rotate.py" --clear-degraded >/dev/null 2>&1

    # 顺手把 AUTOFALL 切回 PROXY。降级时是我们自己把它设成 DIRECT 的，
    # 光清状态不够 —— 否则要等到下一轮轮换（最多 5 分钟）才纠正回来，
    # 这段时间 opencode.ai 仍在用本机 IP 出网，正是这个项目要避免的事。
    #
    # 提示语必须由这一步的真实结果决定：说「已切回」而实际没切成，
    # 是整个系统里最不该发生的一类误导 —— 它会让运维以为泄漏已经堵上了。
    if "$PY3" - <<'PYHOOK' 2>/dev/null
import json, re, sys, urllib.request
cfg = open("/opt/surfshark-rotate/config.yaml", encoding="utf-8").read()
sec = re.search(r'(?m)^secret:\s*"?([^"#\s]+)"?\s*$', cfg)
if not sec:
    sys.exit(1)
req = urllib.request.Request(
    "http://127.0.0.1:9097/proxies/AUTOFALL",
    method="PUT", data=json.dumps({"name": "PROXY"}).encode(),
    headers={"Authorization": "Bearer " + sec.group(1),
             "Content-Type": "application/json"})
urllib.request.urlopen(req, timeout=10).read()
sys.exit(0)
PYHOOK
    then
        say "节点已恢复（$NODE_ALIVE 连续 2 次探测健康，延迟 ${DELAY_MS}ms），已重新启用 $TIMER"
        say "AUTOFALL 已切回 PROXY，opencode.ai 恢复走轮换 IP"
    else
        say "节点已恢复（$NODE_ALIVE 连续 2 次探测健康，延迟 ${DELAY_MS}ms），已重新启用 $TIMER"
        say "⚠ AUTOFALL 未能切回 PROXY —— opencode.ai 可能仍在直连，请手工确认："
        say "  sudo python3 $BASE/rotate.py --status"
    fi
else
    say "启用 $TIMER 失败，请手工执行：systemctl start $TIMER"
fi
exit 0