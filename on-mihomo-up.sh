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
# 由 rotate.py 在连续 2 次控制面探测健康后切回 PROXY —— 恢复判据走控制面，
# 不看 AUTOFALL 当前指向谁（那正是我们自己设的，用它判断会自证循环）。
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
# --resume 表示这是**链式复查**自己调起来的；不带参数则是人工/开机触发的首次。
#
# 必须区分：链式复查每次都重新执行本脚本，若每次都归零计数，上限就永远触发不了，
# 于是又变回无限重排。而人工重试必须归零 —— 早先的提示语写「restart mihomo
# （计数重置）」是错的：除了真的恢复，没有任何地方会清这个计数，
# 它能一直停在上限值上，于是人工重试照样一次都不查。
# --resume 表示「我是链上叫起来的」；$2 是**本链已经完成的跳数**。
#
# 计数为什么要搬进 argv：它本来记在状态文件里，于是「状态文件丢失」时
# 计数无处可记 —— NEXT 恒为 1、单元名恒为 resume-1，复查链在第 1 跳就死。
# 而那条路径正是「状态丢了也能自愈」的兜底，兜底只剩一跳。
# 搬进 argv 之后，计数由**这一跳携带**，不再从共享文件重新推导，
# 状态文件丢了照样能跑满 6 跳；状态文件里的 recheck_tries 退化成跨链的
# 全局上限（重启机器不会被重置）。两条信号分工，而不是二选一。
RESUMED=0
[ "${1:-}" = "--resume" ] && RESUMED=1
HOP="${2:-}"

STATE_UNKNOWN=0
if [ -f "$STATE" ]; then
    "$PY3" -c 'import json,sys
try:
    sys.exit(0 if json.load(open(sys.argv[1], encoding="utf-8")).get("degraded") else 1)
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

# 复查计数归零 —— 位置很重要，必须在闸门**之后**。
#
# 早先放在闸门之前，于是无论状态如何都先跑一次 `rotate.py --reset-recheck`，
# 而它会走 update_state -> load_state -> _write_atomic，把**不存在的状态文件
# 凭空创建出来**（内容是一份默认状态）。紧接着闸门读这个新建的文件：文件存在
# 于是走 case 0/1 分支，degraded 键不存在 -> case 1) exit 0。
# 于是「状态文件丢失 -> 钩子应当改用数据面判断」这条恢复路径**永远走不到**，
# 而 AUTOFALL 还停在 DIRECT —— 上机实测确认：钩子零输出、退出码 0、永久泄漏。
# 同样是那一次改动引入的：我为了修「重启 mihomo 不重置计数」，把更早的
# 「状态丢失可自修」又打了回去。
#
# 现在只在确认处于降级态之后才归零；状态读不出来时**一个字都不写**，
# 既不物化文件，也不覆盖损坏文件（覆盖会销毁唯一的证据）。
if [ "$STATE_UNKNOWN" = "0" ] && [ "$RESUMED" = "0" ]; then
    "$PY3" "$BASE/rotate.py" --reset-recheck >/dev/null 2>&1
fi

if [ "$STATE_UNKNOWN" = "1" ]; then
    say "状态文件缺失或损坏，改用数据面判断是否处于降级态…"
fi

[ -r "$CFG" ] || exit 0
# 必须容忍 secret: 前的缩进 —— rotate.py 与 install.sh 的解析都容忍，
# 而这里不容忍。三处不一致的后果是 config 里缩进一格就同时废掉
# 「钩子恢复」与「降级横幅」，变成永久泄漏且没有任何信号。
SECRET="$(sed -n 's/^[[:space:]]*secret:[[:space:]]*"\{0,1\}\([^"#]*\)"\{0,1\}[[:space:]]*$/\1/p' "$CFG" 2>/dev/null | head -1)"
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
# 「真的修好了」：那次成功打通的只是某个探针站点，不是我们要保的那个出口。
# 两次之间任何一个失败就整体作废，避免对着一台还在抖的隧道下结论。
HEALTH_PROBES=2
HEALTH_GAP=8
# 探测逻辑归 rotate.py 所有（--probe-node）。钩子早先是内嵌一份 python 副本，
# 连探针 URL 都在那里硬编码了一遍 —— 同一套判据两份实现，迟早漂移，而漂移的
# 方向恰好是「钩子这份还写着一个已经废弃的 URL」，表现为恢复永远判不健康、
# 机器安静地一直直连。
#
# 探针端点集合与「任一成功即算健康」的判据都在 rotate.py 的
# NODE_HEALTH_URLS —— 那不是宽容：误判隧道死会泄漏（本项目头号问题），
# 误判隧道活只是让 opencode.ai 撞一次失败的代理，不泄漏且下一轮纠正。
RESULT="$("$PY3" "$BASE/rotate.py" --probe-node \
            --probes "$HEALTH_PROBES" --gap "$HEALTH_GAP" 2>/dev/null || true)"

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
    print(int(json.load(open(p, encoding="utf-8")).get("recheck_tries") or 0))
except Exception:
    print(0)' "$STATE" 2>/dev/null || echo 0)"
    # 算术展开遇到非数字是致命错误，会让 ExecStartPost 非零退出 ->
    # mihomo 判 failed + Restart=always。先净化再算。
    case "$TRIES" in (''|*[!0-9]*) TRIES=0 ;; esac
    case "$HOP"   in (''|*[!0-9]*) HOP=""  ;; esac
    # 链内跳以 argv 为准（不依赖状态文件，这是它最大的好处）；
    # 首次排程以状态文件为准（跨链累计，重启机器不会被重置）。
    if [ -n "$HOP" ]; then NEXT=$((HOP + 1)); else NEXT=$((TRIES + 1)); fi

    if [ "$NEXT" -gt "$RECHECK_MAX" ]; then
        say "已复查 $TRIES 次仍未恢复，停止自动复查（不会有人来修的）"
        say "  现在是降级态：opencode.ai 走直连还能用，但出口是本机 IP，轮换已停摆。"
        say "  修好之后：sudo systemctl restart mihomo"
        say "            这一条会把复查计数归零、重新开始自动复查。"
        say "  只想手工启回轮换：sudo systemctl start $TIMER"
        say "            但它**不**重置计数 —— 节点若仍不通，五分钟后本脚本"
        say "            会再次停掉定时器，且不再自动复查。重启 mihomo 才会重来。"
        exit 0
    fi

    say "控制面探测节点失败，${RECHECK_DELAY}s 后复查（第 $NEXT/$RECHECK_MAX 次）"
    # 先排复查，成功了才记这一跳。
    #
    # 【单元名必须每跳唯一】早先固定用 --unit=surfshark-rotate-resume。
    # systemd 的 --on-active 会建**两个**瞬态单元（.timer 与 .service），
    # 而第 2 跳的进程本身就是 surfshark-rotate-resume.service、此刻正在运行，
    # 再申请同名直接失败。实测：第 1 跳 rc=0，第 2 跳报
    # 「Unit surfshark-rotate-resume.timer was already loaded」、rc=1。
    # 于是复查链只能走一跳，RECHECK_MAX 从第二跳起就是装饰。
    #
    # 计数放在排成功之后：排不上就说明这一跳根本没发生，记它等于白烧配额。
    if command -v systemd-run >/dev/null; then
        # 排之前先看有没有**别的**复查链在飞。
        #
        # mihomo 崩溃循环时（Restart=always + RestartSec=5s），每一次人工重启
        # 都会在本文件开头把计数清零，于是反复申请同一个 --unit=...-1；
        # 而 5 秒前排的那个还在飞 -> systemd-run 失败。早先这里直接说
        # 「停止自动复查」，等于把本来在正常走的链**连带弄断**，
        # 而提示还让人再做一遍同样的操作 —— 那是自己制造自己。
        #
        # 有在飞的链恰恰说明链还活着，此时正确做法是什么都不做。
        #
        # 【必须按状态过滤，这不是洁癖】list-units --all 列的是**所有已装载
        # 单元**。而 oneshot timer 一触发就回到 inactive：我们这一跳运行时，
        # 它的父 timer surfshark-rotate-resume-N.timer 正是那个「刚触发完、
        # 还没被 GC 回收」的单元。把它算成「有别的链在飞」，
        # 每一跳都会因为看见自己而拒绝重排 —— 实测复查链在第 2 跳就终止，
        # RECHECK_MAX 从此再也不会触发，而提示还谎称「已有一条链在飞」。
        #
        # 只认 active：正在等下一跳的链才会挡住本次重排。
        # inactive 的不挡（自己的父 timer、已触发完的旧链）；
        # failed 的不挡（要 reset-failed 才卸载，一个残留会让复查永久无法重排）。
        #
        # --collect 救不了：它是 --property=CollectMode=inactive-or-failed 的
        # 快捷方式，落在瞬态 **service** 上，而我们 glob 的是 **timer** ——
        # 它并没有被设上 CollectMode，只能等 GC，而 GC 对刚被引用过的单元
        # 有回收宽限窗口。父 timer 刚被 job 引用完，正好落在窗口里。
        INFLIGHT=""
        if command -v systemctl >/dev/null; then
            INFLIGHT="$(systemctl list-units --type=timer --state=active \
                        --no-legend --plain \
                        'surfshark-rotate-resume-*.timer' 2>/dev/null \
                        | awk '{print $1}' | head -3)"
        fi
        if [ -n "$INFLIGHT" ]; then
            say "已有一条自动复查链在飞，本次不重排："
            for u in $INFLIGHT; do say "    $u"; done
            say "  （mihomo 反复重启时会出现：计数被清零导致申请同一个单元名）"
            exit 0
        fi
        if ! systemd-run --quiet --collect \
                --unit="surfshark-rotate-resume-$NEXT" \
                --on-active="${RECHECK_DELAY}" \
                /bin/bash "$BASE/on-mihomo-up.sh" --resume "$NEXT" \
                >/dev/null 2>&1; then
            say "复查排不起来（systemd 拒绝），停止自动复查"
            say "  修好之后请手工重试：sudo systemctl restart mihomo"
            exit 0
        fi
        # 计数由 rotate.py 落盘：它走 flock + 原子写，是状态 schema 的唯一 owner。
        # 钩子里再手写一份读-改-写，就多一个能把它写坏的版本。
        GOT="$("$PY3" "$BASE/rotate.py" --recheck-tried 2>/dev/null)"
        # 这里**不能**写 || echo "$NEXT" —— 那会让 GOT 恒等于 NEXT，于是
        # 「写失败」的告警永远不触发；而写失败恰恰意味着上限永不生效
        # （rotate.py 坏掉时必然发生），也就正是最需要上限的时候。
        # 这里**不**因为计数没落盘就停掉复查 —— 复查在上一行的 systemd-run
        # 已经排上去了，说「停止」与行为相反。
        if [ -z "$GOT" ]; then
            say "· 复查计数无处可记（状态文件不存在或损坏）—— rotate.py 按设计不写"
            say "  一个读不出来的状态文件。复查本身继续，上限由本链自己数。"
        elif [ "$GOT" != "$NEXT" ]; then
            say "⚠ 复查计数未能落盘（期望 $NEXT，实得 '$GOT'）—— 跨链上限可能失效"
            say "  多半是 rotate.py 不可用。复查本身继续；修好之后手工重试。"
        fi
    else
        say "systemd-run 不可用，请手工执行 systemctl start $TIMER"
    fi
    exit 0
fi

# ---- 已恢复：切回代理、启回定时器并清标记 ----
if systemctl start "$TIMER" 2>/dev/null; then
    # 顺手把 AUTOFALL 切回 PROXY。降级时是我们自己把它设成 DIRECT 的，
    # 光清状态不够 —— 否则要等到下一轮轮换（最多 5 分钟）才纠正回来，
    # 这段时间 opencode.ai 仍在用本机 IP 出网，正是这个项目要避免的事。
    #
    # 提示语必须由这一步的真实结果决定：说「已切回」而实际没切成，
    # 是整个系统里最不该发生的一类误导 —— 它会让运维以为泄漏已经堵上了。
    if "$PY3" - <<'PYHOOK' 2>/dev/null
import json, re, sys, urllib.request
cfg = open("/opt/surfshark-rotate/config.yaml", encoding="utf-8").read()
sec = re.search(r'(?m)^\s*secret:\s*"?([^"#\s]+)"?\s*$', cfg)
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
        # 顺序要紧：先确认路由真的切回来了，才清降级标记。
        # 反过来的话 PUT 失败时标记已经被销毁，钩子下次启动会在「明确未降级」
        # 分支直接 exit 0，再也不会重试这一步 —— 钩子把自己的补救机会先烧掉了。
        #
        # 降级痕迹交给 rotate.py 清，不在这里再写一份 key 列表。
        if "$PY3" "$BASE/rotate.py" --clear-degraded >/dev/null 2>&1; then
            say "节点已恢复（$NODE_ALIVE 连续 $HEALTH_PROBES 次探测健康，延迟 ${DELAY_MS}ms），已重新启用 $TIMER"
            say "AUTOFALL 已切回 PROXY，opencode.ai 恢复走轮换 IP"
        else
            say "节点已恢复（$NODE_ALIVE 连续 $HEALTH_PROBES 次探测健康，延迟 ${DELAY_MS}ms），已重新启用 $TIMER"
            say "AUTOFALL 已切回 PROXY，opencode.ai 恢复走轮换 IP"
            say "⚠ 降级标记未能清除（状态文件仍显示降级）。下一轮轮换会重试；"
            say "  若一直不好请手工执行：sudo python3 $BASE/rotate.py --clear-degraded"
        fi
    else
        say "节点已恢复（$NODE_ALIVE 连续 $HEALTH_PROBES 次探测健康，延迟 ${DELAY_MS}ms），已重新启用 $TIMER"
        say "⚠ AUTOFALL 未能切回 PROXY —— opencode.ai 可能仍在直连，请手工确认："
        say "  sudo python3 $BASE/rotate.py --status"
        say "  降级标记已保留，下次 mihomo 重启时钩子会再试这一步"
    fi
else
    say "启用 $TIMER 失败，请手工执行：systemctl start $TIMER"
fi
exit 0