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

# 二次复查的延迟（秒）。要给 mihomo 的健康检查留出至少一个 interval，
# 否则节点可能刚好还没被判定为恢复。
RECHECK_DELAY=90

say() { printf '[on-mihomo-up] %s\n' "$*"; }

# ---- 不在降级态：什么都不做，立刻返回（正常启动走的就是这条）----
# 顺序有讲究：先确认 python3 和状态文件都在，再去问「是不是降级态」。
# 反过来写的话，python3 缺失时会把 "-c" 当成命令去执行。
[ -z "$PY3" ] && exit 0
[ -f "$STATE" ] || exit 0

"$PY3" -c 'import json,sys
try:
    sys.exit(0 if json.load(open(sys.argv[1])).get("degraded") else 1)
except Exception:
    sys.exit(1)' "$STATE" 2>/dev/null || exit 0

say "检测到降级态，检查节点是否已恢复…"

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

# ---- 查 AUTOFALL 当前选的是谁 ----
NOW="$("$PY3" - <<'PY' 2>/dev/null
import json, re, sys, urllib.request
cfg = open("/opt/surfshark-rotate/config.yaml", encoding="utf-8").read()
m = re.search(r'(?m)^secret:\s*"?([^"#\s]+)"?\s*$', cfg)
if not m:
    sys.exit(0)
req = urllib.request.Request("http://127.0.0.1:9097/proxies/AUTOFALL",
                             headers={"Authorization": "Bearer " + m.group(1)})
try:
    print(json.load(urllib.request.urlopen(req, timeout=5)).get("now") or "")
except Exception:
    pass
PY
)"

if [ -z "$NOW" ]; then
    # 老版本 config.yaml 没有 AUTOFALL 组 —— 无从判断是否恢复，留给人工。
    say "读不到 AUTOFALL 组（config.yaml 版本较旧？），本次不处理"
    exit 0
fi

if [ "$NOW" = "DIRECT" ]; then
    # mihomo 的健康检查还没跑到，节点此刻确实还没被判定为恢复。
    # 起一个一次性复查：到点再判断一次，成功就把定时器启回来。
    # 用 systemd-run 而不是常驻 timer —— 平时根本不存在这个东西。
    say "AUTOFALL 仍是 DIRECT，${RECHECK_DELAY}s 后复查一次"
    if command -v systemd-run >/dev/null; then
        systemd-run --quiet --unit=surfshark-rotate-resume \
            --on-active="${RECHECK_DELAY}" \
            /bin/bash "$BASE/on-mihomo-up.sh" >/dev/null 2>&1 \
            || say "一次性复查起不来，等下次 mihomo 重启或手工 systemctl start $TIMER"
    else
        say "systemd-run 不可用，请手工执行 systemctl start $TIMER"
    fi
    exit 0
fi

# ---- 已恢复：启回定时器并清标记 ----
if systemctl start "$TIMER" 2>/dev/null; then
    "$PY3" -c 'import json,sys
p = sys.argv[1]
try:
    d = json.load(open(p))
    for k in ("degraded", "degraded_reason", "degraded_at", "fail_streak"):
        d.pop(k, None)
    json.dump(d, open(p, "w"), ensure_ascii=False, indent=2)
except Exception:
    pass' "$STATE" 2>/dev/null
    say "节点已恢复（AUTOFALL=$NOW），已重新启用 $TIMER"
else
    say "启用 $TIMER 失败，请手工执行：systemctl start $TIMER"
fi
exit 0