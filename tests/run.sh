#!/usr/bin/env bash
# 跑测试套件，并且**检查它真的跑了**。
#
# 【为什么不能用 exit code】`python3 tests/test_rotate.py` 在文件末尾的
# `if __name__ == "__main__":` 块丢失时，会 **exit=0、零输出** ——
# 退出码是成功的，但一个用例都没跑。
#
# 这不是假设：我在删除重复测试类时把那一块一起删掉了，随后照惯例检查
# 「exit=0 且 grep FAILED 计数为 0」，把一个**根本没运行的套件的绿灯**
# 写进了提交信息。套件内部的任何测试都发现不了这件事 ——
# 它们自己也在那个没被调起的文件里。
#
# 所以防线必须放在套件外面：断言输出里有 `Ran N tests`，而不只是退出码。
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

python3 "$HERE/test_rotate.py" "$@" > "$OUT" 2>&1
rc=$?

# 「出现过 Ran N」**不够** —— 评审实测：伪造一个只打印 `Ran 999 tests` + `OK`、
# 零用例的套件，旧版 run.sh 会 exit=0 并打印 OK。那与「套件没跑」是同形漏洞。
# 所以 N 必须与下限比较。
MIN_TESTS=50

if ! grep -qE '^Ran [0-9]+ tests?' "$OUT"; then
    echo "!! 测试套件**没有运行**：输出里没有任何用例计数。" >&2
    echo "   （exit=$rc，输出 $(wc -c < "$OUT") 字节）" >&2
    echo "   多半是 tests/test_rotate.py 末尾的 __main__ 块丢了。" >&2
    sed -n '1,20p' "$OUT" >&2
    exit 2
fi

ran="$(grep -oE '^Ran [0-9]+' "$OUT" | head -1 | grep -oE '[0-9]+')"
if [ "${ran:-0}" -lt "$MIN_TESTS" ]; then
    echo "!! 测试套件只跑了 ${ran:-0} 个用例（下限 $MIN_TESTS）。" >&2
    echo "   「出现了 Ran N」不等于「跑全了」——套件可能被截断或大部分没收集到。" >&2
    exit 3
fi

if grep -qE '^(FAILED|OK)' "$OUT" && grep -q '^FAILED' "$OUT"; then
    echo "!! 测试有失败：" >&2
    grep -E '^(FAIL|ERROR):' "$OUT" >&2
    exit 1
fi

grep -E '^Ran |^OK$' "$OUT"
exit 0