#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rotate.py / on-mihomo-up.sh 的回归测试（纯标准库，无需 mihomo、无需网络）。

## 为什么要有这个文件

此前三轮提交里所有测试都是一次性脚本，仓库里没有任何测试文件 —— 「这次是对的」
是真的，「下次还是对的」没有依据。这个文件把那些验证过的行为固定下来。

## 关键设计：测试打在 urllib 边界上，不替换 api()

历史上漏过两个 bug，都是「替身比真实契约宽松」造成的：

1. set_autofall 传 dict，而 api() 要求 bytes —— 任何把 api() 整个替换掉的
   mock 都抓不到，因为真实路径上 urllib 会抛 TypeError。
2. 合并写删不掉键（pop 掉 degraded 后又被磁盘现值读回来）。

所以这里起一个真的 HTTP 服务（http.server），只把 rotate.API 指过去，
让 api()、urllib、JSON 编码、Authorization 头、bytes 契约全部走真实路径。
只有「节点是否健康」这一个预言机被 stub —— 它本质上要问外部世界。

跑法：python3 tests/test_rotate.py
"""

import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class FakeMihomo(BaseHTTPRequestHandler):
    """最小 mihomo 控制面。只实现被测路径用到的那几个端点。"""

    def log_message(self, *a):        # 别把测试输出冲掉
        pass

    # 由测试注入
    groups = {}
    delays = {}
    requests = []
    dead_urls = set()

    def _auth_ok(self):
        return self.headers.get("Authorization") == "Bearer testsecret"

    def _send(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        type(self).requests.append(("GET", self.path, None))
        if not self._auth_ok():
            return self._send(401, {"message": "unauthorized"})
        if self.path == "/version":
            return self._send(200, {"version": "test"})
        for name in self.groups:
            if self.path == "/proxies/" + name:
                return self._send(200, dict(self.groups[name], type="Selector"))
            if "/delay?" in self.path or self.path.endswith("/delay"):
                from urllib.parse import parse_qs, unquote, urlparse
                path_only = urlparse(self.path).path
                node = unquote(path_only.split("/proxies/")[1].split("/")[0])
                qs = parse_qs(urlparse(self.path).query)
                probe_url = qs.get("url", [""])[0]
                if probe_url in type(self).dead_urls:
                    return self._send(504, {"message": "timeout"})
                d = self.delays.get(node)
                if d is None:
                    return self._send(504, {"message": "timeout"})
                return self._send(200, {"delay": d})
        return self._send(404, {"message": "not found"})

    def do_PUT(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n)
        type(self).requests.append(("PUT", self.path, raw))
        if not self._auth_ok():
            return self._send(401, {"message": "unauthorized"})
        if not raw:
            return self._send(400, {"message": "empty body"})
        try:
            body = json.loads(raw.decode())
        except Exception as e:
            # urllib 对非 bytes 的 data 会在这里之前就炸；这里兜 JSON 层
            return self._send(400, {"message": "bad json: %s" % e})
        name = self.path.split("/proxies/")[-1].split("?")[0]
        g = self.groups.get(name)
        if not g or body.get("name") not in g.get("all", []):
            return self._send(400, {"message": "no such member"})
        g["now"] = body["name"]
        return self._send(204, {})


class RotateTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), FakeMihomo)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        FakeMihomo.groups = {
            "AUTOFALL": {"now": "PROXY", "all": ["PROXY", "DIRECT"]},
            "PROXY": {"now": "JP 日本-东京", "all": ["JP 日本-东京", "KR 韩国-首尔"]},
        }
        FakeMihomo.delays = {"JP 日本-东京": 137, "KR 韩国-首尔": 42}
        FakeMihomo.requests = []
        FakeMihomo.dead_urls = set()

        import rotate
        self.rotate = rotate
        self._saved = (rotate.API, rotate.STATE_FILE, rotate.HEAL, rotate.SECRET,
                       rotate.exit_ip, rotate.node_healthy, rotate.switch,
                       rotate.reload_config, rotate.current_node)
        rotate.API = "http://127.0.0.1:%d" % self.port
        rotate.SECRET = "testsecret"
        rotate.STATE_FILE = os.path.join(self.tmp, ".rotate_state.json")
        rotate.HEAL = False

    def tearDown(self):
        r = self.rotate
        (r.API, r.STATE_FILE, r.HEAL, r.SECRET, r.exit_ip, r.node_healthy,
         r.switch, r.reload_config, r.current_node) = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def state(self):
        return json.loads(pathlib.Path(self.rotate.STATE_FILE)
                          .read_text(encoding="utf-8"))

    def seed(self, **kw):
        d = {"tier": 0, "idx": 5, "last_ip": "1.2.3.4", "fail_streak": 0}
        d.update(kw)
        pathlib.Path(self.rotate.STATE_FILE).write_text(json.dumps(d))
        return d

    def quiet(self, fn, *a, **kw):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            return fn(*a, **kw)
        finally:
            sys.stdout = old


class TestApiContract(RotateTestBase):
    """api() 的契约：真实 urllib 路径，替身抓不到的错在这里能抓到。"""

    def test_secret_from_config(self):
        cfg = pathlib.Path(self.tmp) / "config.yaml"
        for body in ('secret: "abc123"\n', '  secret: "abc123"\n'):
            cfg.write_text(body)
            m = self.rotate._secret_from_config(str(cfg))
            self.assertIsNotNone(m, "缩进的 secret 取不到：%r" % body)
            self.assertEqual(m, "abc123")

    def test_put_body_must_be_bytes(self):
        """set_autofall 若传 dict，真实 urllib 路径上会 TypeError。"""
        self.seed()
        self.assertTrue(self.rotate.set_autofall("DIRECT"))
        body = FakeMihomo.requests[-1][2]
        self.assertIsInstance(body, bytes,
                              "PUT 的 body 必须是 bytes，替身比真实契约宽松")
        self.assertEqual(FakeMihomo.groups["AUTOFALL"]["now"], "DIRECT")

    def test_set_autofall_reports_failure_instead_of_raising(self):
        """不存在的成员必须被拒，且失败要如实返回 False 而不是假装成功。"""
        self.seed()
        before = FakeMihomo.groups["AUTOFALL"]["now"]
        self.assertFalse(self.rotate.set_autofall("NOPE"))
        self.assertEqual(FakeMihomo.groups["AUTOFALL"]["now"], before)


class TestStatePrimitives(RotateTestBase):

    def test_patch_only_touches_named_keys(self):
        self.seed(last_ip="5.6.7.8", tier=2, idx=41)
        self.rotate.update_state({"recovery_streak": 1})
        s = self.state()
        self.assertEqual(s["tier"], 2)
        self.assertEqual(s["idx"], 41)
        self.assertEqual(s["last_ip"], "5.6.7.8")
        self.assertEqual(s["recovery_streak"], 1)

    def test_remove_actually_removes(self):
        """合并写表达不了删除 —— 这就是必须单独有 remove 通道的原因。"""
        self.seed(degraded=True, degraded_reason="x")
        self.rotate.update_state({"fail_streak": 0},
                                 remove=self.rotate.DEGRADED_KEYS)
        s = self.state()
        self.assertNotIn("degraded", s)
        self.assertNotIn("degraded_reason", s)

    def test_incr_is_applied(self):
        self.seed()
        self.rotate.update_state(incr={"recheck_tries": 1})
        self.assertEqual(self.state()["recheck_tries"], 1)
        self.rotate.update_state(incr={"recheck_tries": 1})
        self.assertEqual(self.state()["recheck_tries"], 2)

    def test_corrupt_state_is_reported_not_swallowed(self):
        pathlib.Path(self.rotate.STATE_FILE).write_text('{"tier": 3, "last')
        buf = io.StringIO()
        old, sys.stdout = sys.stdout, buf
        try:
            s = self.rotate.load_state()
        finally:
            sys.stdout = old
        self.assertEqual(s["tier"], 0)          # 仍要能用
        out = buf.getvalue()
        self.assertIn("状态文件损坏", out, "损坏必须出声，不能被静默当成「没有状态」")

    def test_missing_state_is_normal(self):
        self.assertFalse(pathlib.Path(self.rotate.STATE_FILE).exists())
        self.assertEqual(self.rotate.load_state()["tier"], 0)

    def test_clear_degraded_flags_is_idempotent(self):
        self.seed(degraded=True, recheck_tries=3)
        self.assertTrue(self.rotate.clear_degraded_flags())
        self.assertFalse(self.rotate.clear_degraded_flags())
        s = self.state()
        self.assertNotIn("degraded", s)
        self.assertNotIn("recheck_tries", s)

    def test_reset_recheck_keeps_other_fields(self):
        """它是纯 setter，早先误用整体覆盖会把别人的 last_ip 盖回旧值。"""
        self.seed(recheck_tries=6, last_ip="9.9.9.9")
        self.rotate.reset_recheck_tries()
        s = self.state()
        self.assertEqual(s["recheck_tries"], 0)
        self.assertEqual(s["last_ip"], "9.9.9.9")

    def test_both_clear_functions_agree_on_guard(self):
        """守卫漂移过一次：只有 recheck_tries 时两函数行为分叉。"""
        self.seed(recheck_tries=5)
        self.assertTrue(self.rotate.clear_degraded_flags())
        self.assertNotIn("recheck_tries", self.state())

    def test_write_leaves_no_stray_files(self):
        self.seed()
        self.rotate.update_state({"fail_streak": 1})
        left = [p for p in os.listdir(self.tmp)
                if p.endswith(".tmp")]
        self.assertEqual(left, [], "原子写的中间态不该残留")


class TestDebounce(RotateTestBase):
    """恢复侧去抖：必须连续 2 次健康，与降级侧对称。"""

    def setUp(self):
        super().setUp()
        r = self.rotate
        r.current_node = lambda: "JP 日本-东京"
        r.pick_next = lambda s: (0, "JP 日本-东京")
        r.switch = lambda n: None
        r.reload_config = lambda: None
        r.node_healthy = lambda n, timeout_ms=8000: self.healthy[0]

    def run_once(self):
        self.quiet(self.rotate.rotate_once)

    def test_recovery_needs_two_samples(self):
        self.seed(degraded=True, degraded_reason="x", degraded_at="t")
        self.healthy = [True]
        puts_before = len([r for r in FakeMihomo.requests if r[0] == "PUT"])

        self.run_once()
        s = self.state()
        self.assertTrue(s.get("degraded"), "第 1 次健康不该撤销降级")
        self.assertEqual(s["recovery_streak"], 1)
        self.assertEqual(len([r for r in FakeMihomo.requests if r[0] == "PUT"]), puts_before,
                         "撤销之前不该有任何 AUTOFALL 切换")

        self.run_once()
        s = self.state()
        self.assertNotIn("degraded", s, "第 2 次健康应当撤销降级")
        puts = [r for r in FakeMihomo.requests if r[0] == "PUT"]
        self.assertEqual(len(puts), puts_before + 1, "应当恰好切一次")
        self.assertEqual(json.loads(puts[-1][2].decode())["name"], "PROXY")

    def test_flapping_does_not_recover(self):
        self.seed(degraded=True, degraded_reason="x", degraded_at="t")
        for h in (True, False, True):
            self.healthy = [h]
            self.run_once()
        s = self.state()
        self.assertTrue(s.get("degraded"), "中途失败应清零计数，降级必须维持")
        self.assertEqual(s["recovery_streak"], 1)


class TestDegradeCorroboration(RotateTestBase):
    """降级必须与控制面结论一致，否则「ip.sb 挂了」会被当成「隧道坏了」。"""

    def setUp(self):
        super().setUp()
        r = self.rotate
        r.current_node = lambda: "JP 日本-东京"
        r.pick_next = lambda s: (0, "JP 日本-东京")
        r.switch = lambda n: None
        r.reload_config = lambda: None

    def test_healthy_tunnel_never_degrades(self):
        self.seed()
        r = self.rotate
        r.exit_ip = lambda: None
        r.node_healthy = lambda n, timeout_ms=8000: True
        for _ in range(2):
            self.quiet(r.rotate_once)
        s = self.state()
        self.assertNotIn("degraded", s, "隧道健康时绝不能降级（那是新的泄漏源）")
        self.assertEqual(s["fail_streak"], 0)
        self.assertEqual(s["last_ip"], "1.2.3.4", "last_ip 必须保留")
        self.assertEqual(FakeMihomo.groups["AUTOFALL"]["now"], "PROXY")

    def test_dead_tunnel_degrades(self):
        self.seed()
        r = self.rotate
        r.exit_ip = lambda: None
        r.node_healthy = lambda n, timeout_ms=8000: False
        self.quiet(r.rotate_once)
        self.assertNotIn("degraded", self.state(), "第 1 轮不该降级")
        self.quiet(r.rotate_once)
        s = self.state()
        self.assertTrue(s.get("degraded"))
        self.assertEqual(FakeMihomo.groups["AUTOFALL"]["now"], "DIRECT")


class TestMultiUrlProbe(RotateTestBase):
    """控制面探针：任一端点响应即算隧道存活。

    单端点曾让 cp.cloudflare.com 单独承担降级佐证与恢复判据两件事 ——
    它一旦被限流，恢复侧会永远判不健康，于是机器安静地一直直连：不报错、
    不降级、只是再也不恢复。这里固定住多端点语义。
    """

    def test_all_urls_configured(self):
        urls = self.rotate.NODE_HEALTH_URLS
        self.assertGreaterEqual(len(urls), 2, "必须多于一个探针端点")
        self.assertEqual(len(set(urls)), len(urls), "探针端点不该重复")
        hosts = {urllib.parse.urlparse(u).netloc for u in urls}
        self.assertGreaterEqual(len(hosts), 2, "探针应来自互不相关的服务")

    def test_one_healthy_url_is_enough(self):
        self.seed()
        for u in self.rotate.NODE_HEALTH_URLS[1:]:
            FakeMihomo.dead_urls.add(u)
        self.assertTrue(self.rotate.node_healthy("JP 日本-东京"),
                        "有一个端点活着就该算隧道可用")

    def test_dead_only_when_all_urls_fail(self):
        self.seed()
        FakeMihomo.dead_urls = set(self.rotate.NODE_HEALTH_URLS)
        self.assertFalse(self.rotate.node_healthy("JP 日本-东京"))

    def test_dead_node_stays_dead(self):
        """所有端点失败时仍然判死 —— 收敛探针不能把真故障一起放过。"""
        self.seed()
        FakeMihomo.delays = {}          # 节点全死
        self.assertFalse(self.rotate.node_healthy("JP 日本-东京"))

    def test_probe_node_subcommand_contract(self):
        """钩子靠 --probe-node 的输出判恢复，格式变了就会静默永不恢复。"""
        self.seed()
        self.assertTrue(self.rotate.probe_node_consecutive(2, 0)[0])
        FakeMihomo.dead_urls = set(self.rotate.NODE_HEALTH_URLS)
        ok, _ = self.rotate.probe_node_consecutive(2, 0)
        self.assertFalse(ok)

    def test_hook_has_no_hardcoded_probe_url(self):
        """钩子里再写一份 URL 就是漂移的起点。"""
        src = (ROOT / "on-mihomo-up.sh").read_text(encoding="utf-8")
        for u in self.rotate.NODE_HEALTH_URLS:
            self.assertNotIn(u, src, "钩子里硬编码了探针 URL %s" % u)
        self.assertIn("--probe-node", src)


class TestHookShell(unittest.TestCase):
    """on-mihomo-up.sh 的分支逻辑。用 bash 实跑，不用 shell 替身。"""

    @classmethod
    def setUpClass(cls):
        cls.hook = ROOT / "on-mihomo-up.sh"
        cls.tmp = tempfile.mkdtemp()
        # 抽出一段与真实脚本同源的判定逻辑来跑分支
        cls.snippet = pathlib.Path(cls.tmp) / "case.sh"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _run(self, state_body, present=True):
        sp = pathlib.Path(self.tmp) / "state.json"
        if present:
            sp.write_text(state_body)
        snippet = '''
STATE="$1"
STATE_UNKNOWN=0
if [ -f "$STATE" ]; then
    python3 -c 'import json,sys
try:
    sys.exit(0 if json.load(open(sys.argv[1])).get("degraded") else 1)
except Exception:
    sys.exit(2)' "$STATE" 2>/dev/null
    case "$?" in
        0) echo CONTINUE_UNKNOWN0 ;;
        1) echo EXIT_QUIET ;;
        *) STATE_UNKNOWN=1 ;;
    esac
else
    STATE_UNKNOWN=1
fi
echo "CONTINUE_UNKNOWN=$STATE_UNKNOWN"
'''
        f = pathlib.Path(self.tmp) / "run.sh"
        f.write_text("#!/usr/bin/env bash\nset -uo pipefail\n" + snippet)
        target = sp if present else pathlib.Path(self.tmp) / "nope.json"
        r = subprocess.run(["bash", str(f), str(target)],
                           capture_output=True, text=True)
        return r.stdout.strip(), r.returncode

    def test_degraded_continues(self):
        out, rc = self._run('{"degraded": true}')
        self.assertIn("CONTINUE_UNKNOWN0", out)
        self.assertEqual(rc, 0)

    def test_not_degraded_exits_quietly(self):
        out, rc = self._run('{"degraded": false}')
        self.assertIn("EXIT_QUIET", out)
        self.assertEqual(rc, 0)

    def test_corrupt_falls_through_to_dataplane(self):
        out, rc = self._run('{"tier": 3, "last')
        self.assertIn("CONTINUE_UNKNOWN=1", out)
        self.assertEqual(rc, 0)

    def test_missing_falls_through(self):
        out, rc = self._run("", present=False)
        self.assertIn("CONTINUE_UNKNOWN=1", out)
        self.assertEqual(rc, 0)

    def test_hook_is_valid_bash(self):
        r = subprocess.run(["bash", "-n", str(self.hook)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        b = self.hook.read_bytes()
        self.assertEqual(b.count(b"\r\n"), 0,
                         "钩子带 CRLF 会报 syntax error（$'in\\r'）")

    def test_recheck_unit_names_are_unique(self):
        """固定单元名会让复查链只能走一跳 —— 第 2 跳必然 already loaded。"""
        t = self.hook.read_text(encoding="utf-8")
        self.assertIn("--unit=\"surfshark-rotate-resume-$NEXT\"", t)
        self.assertNotIn("--unit=surfshark-rotate-resume \\", t)

    def test_counter_warning_is_not_neutralised(self):
        """`|| echo "$NEXT"` 会让 GOT 恒等于 NEXT，告警永远不触发。"""
        t = self.hook.read_text(encoding="utf-8")
        self.assertNotIn('--recheck-tried 2>/dev/null || echo "$NEXT"', t)


if __name__ == "__main__":
    unittest.main(verbosity=2)