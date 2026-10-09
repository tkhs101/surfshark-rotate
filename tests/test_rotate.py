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

CRLF_BYTES = bytes([13, 10])
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
    connections = []
    rules = []

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
        if self.path == "/rules":
            return self._send(200, {"rules": type(self).rules})
        if self.path == "/connections":
            return self._send(200, {"connections": type(self).connections,
                                    "uploadTotal": 0, "downloadTotal": 0})
        for name in self.groups:
            if self.path == "/proxies/" + name:
                g = self.groups[name]
                payload = dict(g, type=g.get("type", "Selector"))
                if "all" not in payload:
                    payload["all"] = []
                return self._send(200, payload)
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
    """【为什么提供 patch() 而不是直接赋值】

    直接 `r.pick_next = lambda ...` 会**永久**改掉模块属性 —— 而测试之间
    共享同一个模块实例，于是这个补丁会漏到后面的测试类里去。实测就是这么
    发现的：TestDegradeCorroboration 把 pick_next 打成 lambda 且从不还原，
    导致后面新写的轮询测试在**被污染的模块**上运行。
    而且 lambda 的签名会随真实 API 演进而悄悄过时。

    patch() 用 addCleanup 保证还原，跑测顺序就不再影响结果。
    """

    def patch(self, obj, name, value):
        old = getattr(obj, name)
        self.addCleanup(setattr, obj, name, old)
        setattr(obj, name, value)
        return value

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
            "AUTOFALL": {"now": "PROXY", "all": ["PROXY", "DIRECT"],
                         "type": "Selector"},
            "PROXY": {"now": "JP 日本-东京", "all": ["JP 日本-东京", "KR 韩国-首尔"]},
        }
        FakeMihomo.delays = {"JP 日本-东京": 137, "KR 韩国-首尔": 42}
        FakeMihomo.requests = []
        FakeMihomo.dead_urls = set()
        FakeMihomo.connections = []
        FakeMihomo.rules = [
            {"type": "DomainSuffix", "payload": "opencode.ai", "proxy": "AUTOFALL"},
            {"type": "DomainSuffix", "payload": "ip.sb", "proxy": "PROXY"},
            {"type": "Match", "payload": "", "proxy": "DIRECT"},
        ]

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
        self.patch(r, "pick_next", lambda s, skip=0: "JP 日本-东京")
        self.patch(r, "switch", lambda n: None)
        self.patch(r, "reload_config", lambda: None)
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
        self.patch(r, "pick_next", lambda s, skip=0: "JP 日本-东京")
        self.patch(r, "switch", lambda n: None)
        self.patch(r, "reload_config", lambda: None)

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
        ok, _, _ = self.rotate.probe_node_consecutive(2, 0)
        self.assertFalse(ok)

    def test_hook_has_no_hardcoded_probe_url(self):
        """钩子里再写一份 URL 就是漂移的起点。"""
        src = (ROOT / "on-mihomo-up.sh").read_text(encoding="utf-8")
        for u in self.rotate.NODE_HEALTH_URLS:
            self.assertNotIn(u, src, "钩子里硬编码了探针 URL %s" % u)
        self.assertIn("--probe-node", src)


class TestRealHookGate(unittest.TestCase):
    """**执行真实的 on-mihomo-up.sh**，而不是它的手抄片段。

    上一版的 TestHookShell 跑的是把闸门逻辑手抄出来的一段 run.sh，而手抄的
    片段漏掉了同一次提交里新增的几行。于是两个用例（损坏/缺失状态）一路绿，
    而真实脚本在这两种情况下根本走不到数据面回退 —— 也就是那条永久泄漏链。
    判据很简单：**要么跑真脚本，要么别测它**。文本断言（assertIn/assertNotIn）
    只能证明「这行字打对了」，不能证明「行为对」。
    """

    def _sandbox(self, state_body):
        tmp = pathlib.Path(tempfile.mkdtemp())
        (tmp / ".rotate_state.json").write_text(state_body, encoding="utf-8")
        # 钩子的 BASE 是硬编码的绝对路径，这里不改仓库、只在副本上跑：
        # 用 sed 把 BASE 指向沙箱，其余逻辑一行不动。
        hook = (tmp / "on-mihomo-up.sh")
        src = (ROOT / "on-mihomo-up.sh").read_text(encoding="utf-8")
        src = src.replace('BASE="/opt/surfshark-rotate"', 'BASE="%s"' % tmp)
        hook.write_text(src, encoding="utf-8")
        # 桩：任何子命令都成功返回，且往 stdout 里吐点东西 ——
        # 钩子必须能在子命令输出被污染时仍正确解析自己的结果。
        # 桩：任何子命令都成功返回，且往 stdout 里吐点东西 ——
        # 钩子必须能在子命令输出被污染时仍正确解析自己的结果。
        stub = chr(10).join([
            "import sys, pathlib",
            "log = pathlib.Path(__file__).with_name('stub-calls.log')",
            "with log.open('a', encoding='utf-8') as f:",
            "    f.write(' '.join(sys.argv[1:2]) + chr(10))",
            "sys.exit(0)", ""])
        (tmp / "rotate.py").write_text(stub, encoding="utf-8")
        return tmp, hook

    def _calls(self, tmp):
        f = tmp / "stub-calls.log"
        return f.read_text(encoding="utf-8") if f.exists() else ""

    def _run(self, state_body, args=()):
        tmp, hook = self._sandbox(state_body)
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        r = subprocess.run(["bash", str(hook), *args],
                           capture_output=True, text=True, timeout=60)
        return tmp, r

    def test_degraded_state_resets_counter(self):
        """确认处于降级态时，计数必须被归零 —— 这是人工重试能重新开始复查的唯一途径。"""
        tmp, r = self._run('{"degraded": true, "recheck_tries": 6}')
        self.assertEqual(r.returncode, 0)
        self.assertIn("--reset-recheck", self._calls(tmp))

    def test_not_degraded_exits_without_writing_anything(self):
        """明确未降级 = 正常路径，必须零写入、零子命令调用。"""
        tmp, r = self._run('{"degraded": false, "tier": 2}')
        st = json.loads((tmp / ".rotate_state.json").read_text(encoding="utf-8"))
        self.assertEqual(st, {"degraded": False, "tier": 2},
                         "明确未降级时必须是零写入，状态文件不能被动过")
        self.assertEqual(self._calls(tmp), "", "零开销路径不该调用任何子命令")

    def test_resume_flag_does_not_reset_counter(self):
        """链式复查不能归零 —— 每次都归零的话上限永远触发不了。"""
        tmp, r = self._run('{"degraded": true, "recheck_tries": 3}', args=("--resume",))
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("--reset-recheck", self._calls(tmp))

    def test_missing_state_file_is_not_recreated(self):
        """L1 回归的精确守卫。

        钩子曾在闸门之前调 --reset-recheck，把不存在的状态文件凭空创建出来，
        于是闸门读到一份没有 degraded 键的默认状态、判定「明确未降级」直接返回，
        数据面回退永远走不到 —— AUTOFALL 停在 DIRECT 不动，永久泄漏。
        """
        tmp, hook = self._sandbox("{}")
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        (tmp / ".rotate_state.json").unlink()
        r = subprocess.run(["bash", str(hook)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertFalse((tmp / ".rotate_state.json").exists(),
                         "状态文件缺失时绝不能被物化出来")
        self.assertNotIn("--reset-recheck", self._calls(tmp),
                         "读不出状态时不该去写它 —— 那正是 L1 的成因")

    def test_corrupt_state_file_is_not_overwritten(self):
        """L2：覆盖坏文件会销毁唯一的证据，也让 STATE_UNKNOWN 失效。"""
        tmp, hook = self._sandbox("{}")
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        raw = '{"tier": 3, "last'
        (tmp / ".rotate_state.json").write_text(raw, encoding="utf-8")
        r = subprocess.run(["bash", str(hook)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertEqual((tmp / ".rotate_state.json").read_text(encoding="utf-8"), raw,
                         "损坏的状态文件是唯一证据，不能被覆盖")


class TestLeakDetection(RotateTestBase):
    """阳性泄漏检测：读 mihomo 已建立的连接，看 opencode.ai 实际走了哪条链。

    它覆盖的是唯一一个没有任何其它信号能看见的失效：分流规则被外部改动或
    sniffer 失效，落进 MATCH,DIRECT —— 此时没有探测失败、没有降级、status 全绿。
    """

    def _conn(self, host, chains):
        return {"metadata": {"host": host, "destinationIP": "1.2.3.4",
                             "sniffHost": host},
                "chains": chains, "upload": 10, "download": 20}

    def test_no_leak_when_autofall_chain_is_used(self):
        self.seed()
        FakeMihomo.connections = [
            self._conn("api.opencode.ai", ["KR 韩国-首尔", "PROXY", "AUTOFALL"])]
        self.assertEqual(self.rotate.direct_leaks(), [])

    def test_detects_opencode_going_direct(self):
        self.seed()
        FakeMihomo.connections = [
            self._conn("api.opencode.ai", ["KR 韩国-首尔", "PROXY", "AUTOFALL"]),
            self._conn("api.opencode.ai", ["DIRECT"]),
        ]
        hits = self.rotate.direct_leaks()
        self.assertEqual(len(hits), 1, "必须认出 chains[0]==DIRECT 的那条")

    def test_ignores_other_hosts(self):
        self.seed()
        FakeMihomo.connections = [
            self._conn("ip.sb", ["DIRECT"]),          # ip.sb 规则本身挂 PROXY，
            self._conn("www.google.com", ["DIRECT"])]  # 其它 MATCH,DIRECT 属正常
        self.assertEqual(self.rotate.direct_leaks(), [])

    def test_matches_sniffed_host_and_bare_domain(self):
        self.seed()
        FakeMihomo.connections = [
            {"metadata": {"host": "", "sniffHost": "opencode.ai",
                          "destinationIP": "104.18.1.1"},
             "chains": ["DIRECT"]}]
        self.assertEqual(len(self.rotate.direct_leaks()), 1,
                         "sniffer 还原出的域名也要认 —— 那正是失效模式本身")

    def _fake_leak_ip(self):
        """注入一个确定的 opencode.ai IP，让匹配逻辑的测试不依赖真 DNS。

        `_leak_ips` 是带 TTL 的缓存，直接把缓存填掉即可 —— 我们测的是
        `direct_leaks()` 拿 IP 去比的那一步，不是 DNS 本身。
        """
        ip = "203.0.113.77"          # RFC 5737 文档保留段，真实路由不到
        self.rotate._IP_CACHE.update(at=float("inf"), ips={ip}, ok=True)
        return ip

    def test_sniffer_failure_is_detected_by_ip(self):
        """**这是这条检测被写出来要覆盖的失效模式本身。**

        sniffer 失效的后果恰恰是 metadata 里一个域名都没有 —— host 空、
        sniffHost 空，只剩 destinationIP。早先的实现拿域名做子串匹配，
        于是对它自己的目标失明：实测返回 []。必须按 IP 反查才能抓到。
        """
        self.seed()
        real_ip = self._fake_leak_ip()
        FakeMihomo.connections = [
            {"metadata": {"host": "", "sniffHost": "", "destinationIP": real_ip},
             "chains": ["DIRECT"]}]
        hits = self.rotate.direct_leaks()
        self.assertEqual(len(hits), 1,
                         "无域名、纯 IP、chains[0]=DIRECT —— 必须按 IP 认出")
        self.assertEqual(hits[0][2], "by-ip")

    def test_proxied_connection_not_flagged_even_with_bare_ip(self):
        """反向误报检查：走代理的同 IP 连接不该被报成泄漏。"""
        self.seed()
        FakeMihomo.connections = [
            {"metadata": {"host": "", "sniffHost": "",
                          "destinationIP": self._fake_leak_ip()},
             "chains": ["JP 日本-东京", "PROXY", "AUTOFALL"]}]
        self.assertEqual(self.rotate.direct_leaks(), [])

    def test_real_dns_resolution_actually_works(self):
        """**集成检查**，会因环境而 skip —— 所以它刻意与上面两条分开。

        上面两条测的是 `direct_leaks()` 的**匹配逻辑**，不需要真 DNS；
        早先它们直接调 `_leak_ips()`，于是离线环境下唯一覆盖
        「sniffer 失效」这条最危险检测路径的用例会 skipTest ——
        而「测试全绿」在离线环境里并不等于覆盖到了它。
        """
        ips = self.rotate._leak_ips()
        if not ips:
            self.skipTest("本机解析不到 opencode.ai（这是集成检查，环境所致）")
        self.assertTrue(all(isinstance(x, str) for x in ips))
        for ip in ips:
            self.assertIsInstance(self.rotate.socket.inet_aton(ip), bytes)

    def test_returns_none_when_api_unreachable(self):
        self.seed()
        saved = self.rotate.API
        self.rotate.API = "http://127.0.0.1:1"     # 必然连不上
        try:
            self.assertIsNone(self.rotate.direct_leaks(),
                              "读不到要返回 None，不能当成「没有泄漏」")
        finally:
            self.rotate.API = saved


class TestRoutingInvariants(RotateTestBase):
    """热重载后核对 mihomo **已加载**的规则。

    config.yaml 是我们的意图，/rules 是它实际在跑的东西。两者不一致时只有后者
    说明真相 —— 而这正是最难发现的一类泄漏：没有探测失败、没有降级、status 全绿。
    """

    def test_ok_when_rules_match(self):
        self.seed()
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "OK", "正常配置不该报错：%s" % problems)

    def test_detects_opencode_pointed_at_direct(self):
        """本次评审要求抓的核心失效。"""
        self.seed()
        for r in FakeMihomo.rules:
            if r["payload"] == "opencode.ai":
                r["proxy"] = "DIRECT"
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "VIOLATION")
        self.assertTrue(any("opencode.ai" in m for m in problems), problems)

    def test_detects_missing_rule(self):
        """规则被删掉 -> 落进 MATCH,DIRECT，同样是泄漏。"""
        self.seed()
        FakeMihomo.rules = [r for r in FakeMihomo.rules if r["payload"] != "opencode.ai"]
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "VIOLATION")
        self.assertTrue(any("找不到" in m for m in problems), problems)

    def test_detects_ip_sb_probe_misrouting(self):
        """ip.sb 挂错会让出口 IP 探测走错通道，降级判据随之失真。"""
        self.seed()
        for r in FakeMihomo.rules:
            if r["payload"] == "ip.sb":
                r["proxy"] = "AUTOFALL"
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "VIOLATION", "ip.sb 挂在 AUTOFALL 上必须能检出")

    def test_unreadable_is_not_treated_as_ok(self):
        """无法判定不等于通过 —— 把不确定当确定是典型的静默失败。"""
        self.seed()
        saved = self.rotate.API
        self.rotate.API = "http://127.0.0.1:1"
        try:
            verdict, problems = self.rotate.check_routing_invariants()
            self.assertEqual(verdict, "UNKNOWN",
                             "读不到 /rules 是「无法判定」，既不是通过也不是违规")
            self.assertTrue(problems)
        finally:
            self.rotate.API = saved


class TestInvariantBypasses(RotateTestBase):
    """三条实测可绕过的不变量检查，全部来自对抗评审。

    之前 44 例全绿而检查可被绕过 —— 假服务的规则表只覆盖了「正确」形态。
    """

    def test_geosite_rule_shadowing_is_caught(self):
        """加一条 GEOSITE,opencode,DIRECT 排在前面就能完全遮蔽。"""
        self.seed()
        FakeMihomo.rules = [
            {"type": "GeoSite", "payload": "opencode", "proxy": "DIRECT"},
            {"type": "DomainSuffix", "payload": "opencode.ai", "proxy": "AUTOFALL"},
            {"type": "DomainSuffix", "payload": "ip.sb", "proxy": "PROXY"},
        ]
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "VIOLATION", "遮蔽必须被发现")
        self.assertTrue(any("遮蔽" in m for m in problems), problems)

    def test_domain_suffix_ai_shadowing_is_caught(self):
        """最可能被人手写出来的遮蔽：DOMAIN-SUFFIX,ai,DIRECT。

        早先 BROAD 写的是 YAML 拼写，DomainSuffix.upper() 之后是 DOMAINSUFFIX
        而不是 DOMAIN-SUFFIX，于是**这一条原本是漏检的**，而测试夹具当时也用了
        同样的错拼写，所以一路绿灯。
        """
        self.seed()
        FakeMihomo.rules = [
            {"type": "DomainSuffix", "payload": "ai", "proxy": "DIRECT"},
            {"type": "DomainSuffix", "payload": "opencode.ai", "proxy": "AUTOFALL"},
            {"type": "DomainSuffix", "payload": "ip.sb", "proxy": "PROXY"},
        ]
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "VIOLATION",
                         "DOMAIN-SUFFIX,ai,DIRECT 是最现实的遮蔽，必须能抓到")
        self.assertTrue(any("遮蔽" in m for m in problems), problems)

    def test_in_type_direct_is_not_a_false_shadow(self):
        """IN-TYPE,HTTP,DIRECT 合法且无害，不该被报成遮蔽。

        报成遮蔽 -> VIOLATION -> 退出码 3 -> 轮换停摆 + 谎报泄漏。
        一个假的 VIOLATION 代价不比真的小。
        """
        self.seed()
        FakeMihomo.rules = [
            {"type": "InType", "payload": "HTTP", "proxy": "DIRECT"},
            {"type": "DomainSuffix", "payload": "opencode.ai", "proxy": "AUTOFALL"},
            {"type": "DomainSuffix", "payload": "ip.sb", "proxy": "PROXY"},
        ]
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "OK", "误报会停掉唯一产出并谎报泄漏：%s" % problems)

    def test_broad_set_uses_mihomo_spelling_not_yaml(self):
        """BROAD 字面量里必须是 /rules 的 Type，不是 config.yaml 的写法。

        只查 BROAD 那个字面量，不扫整个文件 —— 注释里正是在解释这个坑，
        把说明文字当成违规会把这条测试自己搞坏。

        契约来自真机实测：/rules 的 type 取值是 DomainSuffix / DstPort / Match。
        """
        import rotate as _r
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        i = src.index("BROAD = {")
        j = src.index("}", i)
        broad = src[i:j]
        # GEOSITE / GEOIP 是**对的**：mihomo 返回 GeoSite / GeoIP，
        # .upper() 正好对上。真正死掉的只有带连字符的那几个。
        for bad in ('"IP-CIDR"', '"DOMAIN-SUFFIX"', '"DOMAIN-KEYWORD"',
                    '"DOMAIN-REGEX"', '"RULE-SET"', '"IP-CIDR6"',
                    '"IN-TYPE"', '"PROCESS-NAME"', '"IN-NAME"'):
            self.assertNotIn(bad, broad,
                             "BROAD 里混进了 config.yaml 的 YAML 拼写 %s" % bad)
        for good in ("DOMAINSUFFIX", "IPCIDR", "RULESET"):
            self.assertIn(good, broad, "BROAD 缺少 %s" % good)

    def test_ip_cidr_shadowing_is_caught(self):
        self.seed()
        FakeMihomo.rules = [
            {"type": "IPCIDR", "payload": "104.18.1.0/24", "proxy": "DIRECT"},
            {"type": "DomainSuffix", "payload": "opencode.ai", "proxy": "AUTOFALL"},
            {"type": "DomainSuffix", "payload": "ip.sb", "proxy": "PROXY"},
        ]
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "VIOLATION")
        self.assertTrue(any("遮蔽" in m for m in problems), problems)

    def test_autofall_members_without_proxy_is_caught(self):
        """规则指向 AUTOFALL「完全正确」，但组被掏空成只剩 DIRECT。"""
        self.seed()
        FakeMihomo.groups["AUTOFALL"]["all"] = ["DIRECT"]
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "VIOLATION")
        self.assertTrue(any("缺少 PROXY" in m for m in problems), problems)

    def test_autofall_type_must_be_selector(self):
        """类型不是 select 的话内核会自行翻组，降级归属失效。"""
        self.seed()
        FakeMihomo.groups["AUTOFALL"]["type"] = "Fallback"
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "VIOLATION")
        self.assertTrue(any("Selector" in m for m in problems), problems)

    def test_harmless_leading_rule_does_not_false_alarm(self):
        """前面有指向 PROXY/AUTOFALL 的规则不该被报成遮蔽。"""
        self.seed()
        FakeMihomo.rules = [
            {"type": "GeoIP", "payload": "cn", "proxy": "DIRECT"},
            {"type": "DomainSuffix", "payload": "opencode.ai", "proxy": "AUTOFALL"},
            {"type": "DomainSuffix", "payload": "ip.sb", "proxy": "PROXY"},
        ]
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "VIOLATION")   # GeoIP,cn 排在前面确实会遮蔽，应当报
        self.assertTrue(any("遮蔽" in m for m in problems), problems)

        FakeMihomo.rules = [
            {"type": "DstPort", "payload": "22", "proxy": "DIRECT"},
            {"type": "DomainSuffix", "payload": "opencode.ai", "proxy": "AUTOFALL"},
            {"type": "DomainSuffix", "payload": "ip.sb", "proxy": "PROXY"},
        ]
        verdict, problems = self.rotate.check_routing_invariants()
        self.assertEqual(verdict, "OK", "SSH 规则在前面是无害的：%s" % problems)


class TestTriStateVerdict(unittest.TestCase):
    """三态的**语义**本身要测，而不只是各分支返回什么字符串。

    背景：早先把「确认违规」与「无法判定」塞进同一条路径，于是 /rules 返回一次
    500 也会写出 routing_bad_at，而 status.sh 把那条记录翻译成
    「把本机 IP 泄漏出去」——在零泄漏证据的情况下说出这句话。
    """

    def _hook_text(self):
        return (ROOT / "status.sh").read_text(encoding="utf-8")

    def test_unknown_never_writes_the_leak_field(self):
        """UNKNOWN 分支不得写 routing_bad_at。"""
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        i = src.index('if verdict == "UNKNOWN":')
        blk = src[i:src.index('if verdict == "VIOLATION":')]
        self.assertIn("routing_unknown_at", blk)
        self.assertNotIn("routing_bad_at", blk,
                         "UNKNOWN 分支写 routing_bad_at 会造出假的泄漏告警")

    def test_violation_raises_exit_3(self):
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        i = src.index('if verdict == "VIOLATION":')
        self.assertIn("raise SystemExit(3)", src[i:i + 700])

    def test_status_banner_wording_distinguishes_verdicts(self):
        """status.sh 必须能区分「确认违规」与「无法判定」两种文案。"""
        t = self._hook_text()
        self.assertIn("routing_bad_at", t)
        self.assertIn("正在泄漏", t)
        # 无法判定的措辞必须是「无法核对」而不是「泄漏」
        if "routing_unknown_at" in t:
            seg = t[t.index("routing_unknown_at"):]
            seg = seg[:seg.index(chr(10) + "fi")]
            self.assertNotIn("泄漏", seg,
                             "无法判定的横幅里不该出现「泄漏」字样")

    def test_leak_gate_uses_state_not_autofall(self):
        """泄漏判定的门必须与 rotate.py 一致，用状态文件的降级标记。"""
        t = self._hook_text()
        # 从**第二个** case（真正决定颜色那一个）起算 ——
        # 前面还有一个把原始输出归一化的转换块。
        i = t.index('case "$LEAK_N" in')
        seg = t[i:t.index("esac", i)]
        self.assertIn('DEG_FLAG" = "true"', seg,
                      "门必须用 DEG_FLAG；用 AF_NOW 会在钩子恢复窗口里自相矛盾")


class TestNoMaterialisation(RotateTestBase):
    """**读不到状态就别写。** 物化的危险在 update_state 本身。

    早先守卫只加在 reset_recheck_tries 上，兄弟路径 bump_recheck_tries 没有 ——
    于是同一个 P0 泄漏链照样成立：钩子一边打印「状态文件缺失，改用数据面判断」，
    一边把这个判断的前提凭空创建出来；下一次运行闸门读到那份新建的（没有
    degraded 键的）文件，判定「明确未降级」直接 exit 0，「状态丢失 -> 自修」
    永久失效，AUTOFALL 停在 DIRECT 不动。评审用真实钩子端到端复现过。
    """

    def test_incr_does_not_create_missing_file(self):
        self.assertFalse(pathlib.Path(self.rotate.STATE_FILE).exists())
        self.assertIsNone(self.rotate.bump_recheck_tries())
        self.assertFalse(pathlib.Path(self.rotate.STATE_FILE).exists(),
                         "--recheck-tried 不得凭空创建状态文件")

    def test_reset_does_not_create_missing_file(self):
        self.rotate.reset_recheck_tries()
        self.assertFalse(pathlib.Path(self.rotate.STATE_FILE).exists())

    def test_corrupt_file_is_not_overwritten_by_either(self):
        raw = '{"tier": 3, "last'
        pathlib.Path(self.rotate.STATE_FILE).write_text(raw, encoding="utf-8")
        self.rotate.bump_recheck_tries()
        self.rotate.reset_recheck_tries()
        self.assertEqual(pathlib.Path(self.rotate.STATE_FILE).read_text(encoding="utf-8"),
                         raw, "损坏文件是唯一证据，不能被任何子命令覆盖")

    def test_default_does_not_create_file(self):
        """默认**不**物化 —— 物化必须显式申请。

        这是「谁有资格物化状态文件」改成策略之后的锁：
        update_state 在没有 require_existing=False 时，永远不会创建状态文件。
        """
        self.assertFalse(pathlib.Path(self.rotate.STATE_FILE).exists())
        self.rotate.update_state({"tier": 0, "last_ip": "1.1.1.1"})
        self.assertFalse(pathlib.Path(self.rotate.STATE_FILE).exists(),
                         "默认策略已改为不物化")

    def test_explicit_authorisation_still_creates_file(self):
        """显式授权仍然能创建 —— 否则全新安装的轮换状态无处落盘。"""
        self.assertFalse(pathlib.Path(self.rotate.STATE_FILE).exists())
        self.rotate.update_state({"tier": 0, "last_ip": "1.1.1.1"},
                                 require_existing=False)
        self.assertTrue(pathlib.Path(self.rotate.STATE_FILE).exists())

    def test_observation_accounting_never_materialises(self):
        """分流核对的记账是观测，不是轮换证据 —— 一律不许物化。

        这正是上一个 P0 的残余：物化点从 --dry-run 挪到了核对的第一笔记账，
        而它排在切换/重载/验 IP 之前，于是任何一次中途失败的轮换都会留下
        一份空壳，而闸门把它当成权威。
        """
        self.assertFalse(pathlib.Path(self.rotate.STATE_FILE).exists())
        self.rotate.update_state({"routing_bad_at": "2026-01-01 00:00:00",
                                  "routing_bad_reason": "x"})
        self.rotate.update_state({}, remove=("routing_unknown_at",))
        self.rotate.update_state({"routing_unknown_at": "t",
                                  "routing_unknown_reason": "y"})
        self.assertFalse(pathlib.Path(self.rotate.STATE_FILE).exists(),
                         "观测性记账不得物化")

    def test_only_two_call_sites_authorised(self):
        """锁住「只有轮换记账那两处有资格物化」这个不变量。"""
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        code = chr(10).join(l for l in src.split(chr(10))
                            if not l.strip().startswith("#"))
        # 去掉注释里的那一处
        n = code.count("require_existing=False")
        self.assertEqual(n, 2, "授权点必须恰好两个：fail_streak 首记 + 主记账")

    def test_recovery_actually_removes_keys(self):
        """置空串会让「曾经坏过」看起来像从未发生 —— 必须真删。"""
        self.seed(routing_bad_at="2026-01-01 00:00:00", routing_bad_reason="x")
        self.rotate.update_state({}, remove=("routing_bad_at", "routing_bad_reason"))
        s = self.state()
        self.assertNotIn("routing_bad_at", s)
        self.assertNotIn("routing_bad_reason", s)


class TestDryRunWritesNothing(RotateTestBase):
    """--dry-run 必须是只读的。

    install.sh 的第 8 步跑的就是它。人在「状态丢了、AUTOFALL 停在 DIRECT」时
    最自然的动作就是重跑安装 —— 而一次「试运行」凭空写出状态文件，
    写出的那份没有 degraded 键，钩子闸门据此判「明确未降级」直接 exit 0，
    自修路径被自己的验证步骤毁掉。守卫当初要防的那条链，从另一扇门走回来。
    """
    def test_dry_run_does_not_create_state_file(self):
        self.assertFalse(pathlib.Path(self.rotate.STATE_FILE).exists())
        r = self.rotate.rotate_once(dry_run=True)
        self.assertTrue(r)
        self.assertFalse(pathlib.Path(self.rotate.STATE_FILE).exists(),
                         "--dry-run 不得凭空写出状态文件")

    def test_dry_run_still_reports_verdict(self):
        self.seed()          # 不预置降级：降级分支会先短路返回，那是本该如此
        for x in FakeMihomo.rules:
            if x["payload"] == "opencode.ai":
                x["proxy"] = "DIRECT"
        buf = io.StringIO(); old = sys.stdout; sys.stdout = buf
        try:
            with self.assertRaises(SystemExit) as cm:
                self.rotate.rotate_once(dry_run=True)
        finally:
            sys.stdout = old
        self.assertEqual(cm.exception.code, 3,
                         "dry-run 遇到确认违规也要退出 3 —— install.sh 靠它阻断安装")


class TestLeakCountContract(RotateTestBase):
    """--leak-count 的输出契约。

    早先失败时 print("skip") 且 return 1，而调用方写的是
    `$(rotate.py --leak-count || echo skip)` —— `||` 会把 echo 的输出也收进
    变量，于是变量变成两行 skip，case 的 skip 模式匹配不上，落进 *) 被当成
    **泄漏条数**。也就是说 mihomo API 一挂，页面就喊「正在泄漏」。
    正是上一轮刚消灭的「零证据说泄漏」从另一扇门回来了。
    """

    def test_direct_leaks_none_means_unknown_not_zero(self):
        """读不到必须是 None（无法判定），不是 0（没有泄漏）。"""
        self.seed()
        saved = self.rotate.API
        self.rotate.API = "http://127.0.0.1:1"
        try:
            self.assertIsNone(self.rotate.direct_leaks())
        finally:
            self.rotate.API = saved

    def test_rotate_never_uses_exit_code_for_this(self):
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        i = src.index("if args.leak_count:")
        j = src.index("if args.", i + 10)          # 到下一个子命令为止
        # 只看代码行 —— 注释里正是在引用旧的错误写法。
        blk = chr(10).join(l for l in src[i:j].split(chr(10))
                        if not l.strip().startswith("#"))
        self.assertIn("return 0", blk, "判据失效也必须 exit 0")
        self.assertNotIn("return 1", blk, "契约不得用退出码承载")
        self.assertIn('print("skip")', blk)
        self.assertIn("_leak_ip_lookup_ok()", blk,
                      "判据失效时也必须报 skip，且带可用性标记")

    def test_consumer_treats_non_numeric_as_skip(self):
        """消费端必须把任何非纯数字归为「读不到」，而不是条数。"""
        t = (ROOT / "status.sh").read_text(encoding="utf-8")
        self.assertNotIn("--leak-count 2>/dev/null || echo skip", t,
                         "`|| echo skip` 会把 echo 的输出也收进变量")
        i = t.index('LEAK_RAW="$("$PY3"')
        seg = t[i:t.index("fi", i)]
        self.assertIn("*[!0-9]*)", seg,
                      "缺了非数字防线：rotate.py 崩掉时 log() 走 stdout，"
                      "变量会是多行日志 + skip")
        # 必须先切字段再校验数字：顺序反了 "0 ok" 会被整串含非数字而误判
        self.assertLess(seg.index('${LEAK_RAW%% *}'), seg.index("*[!0-9]*"),
                        "先切字段再校验，否则 '0 ok' 会被当成多行日志")
        self.assertIn("noip", seg, "契约需携带「按 IP 反查是否可用」")


class TestLeakIpTtl(RotateTestBase):
    """解析失败时 TTL 不能失效，也不能静默把检测器变瞎。"""

    def test_timestamp_updates_even_when_resolution_fails(self):
        import socket as _s
        self.rotate._IP_CACHE.update(at=0.0, ips=set(), ok=False)
        calls = []
        real = _s.getaddrinfo
        def boom(*a, **k):
            calls.append(1)
            raise _s.gaierror("boom")
        _s.getaddrinfo = boom
        try:
            for _ in range(4):
                self.rotate._leak_ips()
        finally:
            _s.getaddrinfo = real
        # 一次 _leak_ips 调用会按 AF_INET / AF_INET6 各试一次，所以是 2 次；
        # 4 次调用若每次都重试就会是 8 次。关键是「不随调用次数增长」。
        self.assertLessEqual(len(calls), 2,
                             "持续失败时每轮重试 DNS —— TTL 对失败路径失效了")

    def test_keeps_previous_good_cache_on_failure(self):
        import socket as _s
        self.rotate._IP_CACHE.update(at=0.0, ips={"1.2.3.4"}, ok=True)
        real = _s.getaddrinfo
        _s.getaddrinfo = lambda *a, **k: (_ for _ in ()).throw(_s.gaierror())
        try:
            ips = self.rotate._leak_ips()
        finally:
            _s.getaddrinfo = real
        self.assertIn("1.2.3.4", ips, "一次解析失败不该把缓存清空")

    def test_status_reports_when_by_ip_is_unavailable(self):
        """检测器对它自己的目标静默失明，必须在**两处**说出来。

        早先只在 rotate.py --status 里说了，而 status.sh 走的是 --leak-count，
        那条绿字完全不披露检测器是否半盲 —— 在半盲状态下说「未发现」是在骗人。
        """
        r = (ROOT / "rotate.py").read_text(encoding="utf-8")
        self.assertIn("IP 反查", r, "--status 需披露按 IP 反查不可用")
        i = r.index("if args.leak_count:")
        blk = r[i:r.index("if args.", i + 10)]
        self.assertIn("noip", blk, "--leak-count 必须在 stdout 上带可用性标记")

        s = (ROOT / "status.sh").read_text(encoding="utf-8")
        self.assertIn("半盲", s, "status.sh 必须在检测器半盲时改变措辞")
        self.assertIn('LEAK_IP', s)


class TestRecheckCounterCarrier(unittest.TestCase):
    """复查计数搬进 argv：状态文件丢了也要能跑满 6 跳。

    旧实现把计数记在状态文件里，于是「状态文件丢失」时计数无处可记 ——
    NEXT 恒为 1、单元名恒为 resume-1，复查链在第 1 跳就死。而那条路径
    正是「状态丢了也能自愈」的兜底，兜底只剩一跳。
    队友已实跑确认过搬进 argv 后连跑 8 跳正常收口；这里锁住形状。
    """

    def _src(self):
        return (ROOT / "on-mihomo-up.sh").read_text(encoding="utf-8")

    def test_hop_argument_is_read(self):
        self.assertIn('HOP="${2:-}"', self._src())

    def test_hop_takes_precedence_over_state_file(self):
        src = self._src()
        i = src.index('case "$HOP"')
        blk = src[i:i + 400]
        self.assertIn('[ -n "$HOP" ]', blk,
                      "链内跳必须以 argv 为准，否则状态文件丢失时又回到只剩一跳")

    def test_next_is_passed_to_the_next_hop(self):
        self.assertIn('--resume "$NEXT"', self._src(),
                      "每一跳必须把计数传给下一跳")

    def test_unit_name_stays_unique_per_hop(self):
        self.assertIn('--unit="surfshark-rotate-resume-$NEXT"', self._src())

    def test_dirty_values_cannot_reach_arithmetic(self):
        """$(( )) 里的语法错误是致命的（即使没有 set -e、即使 2>/dev/null）。

        整脚本非零退出 -> ExecStartPost 非零 -> mihomo 判 failed + Restart=always。
        """
        src = self._src()
        for v in ("TRIES", "HOP"):
            self.assertIn('case "$%s"' % v, src,
                          "%s 必须先净化再进算术展开" % v)

    def test_inflight_hint_is_not_stale(self):
        """计数搬进 argv 后「计数被清零」那句话已失效。

        计数不再从状态文件读，不会被清零 —— 留着会让人按错误的因果去排查。
        """
        src = self._src()
        # 只看 say 行 —— 注释里正是在引用这句旧归因来说明历史。
        says = [l for l in src.split(chr(10))
                if "say " in l and "计数被清零" in l]
        self.assertEqual(says, [],
                         "计数由 argv 携带，不会被清零；这句归因已失效：%s" % says)

    def test_empty_counter_does_not_stop_rechecking(self):
        """计数没落盘时复查已经排上去了，不能说「停止自动复查」。"""
        src = self._src()
        i = src.index('if [ -z "$GOT" ]; then')
        blk = src[i:i + 500]
        self.assertNotIn("停止自动复查", blk,
                         "空计数时复查已排上，说停止与行为相反")
        self.assertNotIn("rotate.py 不可用", blk.split("elif")[0],
                         "守卫正确地拒绝写入，归因不该说成 rotate.py 坏了")


class TestHookBudget(unittest.TestCase):
    """钩子最坏耗时 vs mihomo.service 的 TimeoutStartSec。

    这个耦合早先只存在于一段注释里，而那段注释的数字在改完超时后就已经过时
    —— 也就是说「还剩多少余量」没有任何东西在守着。越线的后果不是「少查一次」，
    而是钩子被 systemd 杀掉 -> mihomo 判 failed -> Restart=always 反复重启
    一台内核完全健康的服务。

    本轮实测值 199s（队友第四轮独立实测也是 199s，两边吻合）。
    """

    def _timeout_start_sec(self):
        txt = (ROOT / "mihomo.service").read_text(encoding="utf-8")
        m = __import__("re").search(r"TimeoutStartSec=(\d+)", txt)
        self.assertIsNotNone(m, "mihomo.service 必须显式声明 TimeoutStartSec")
        return int(m.group(1))

    def test_current_budget_fits(self):
        import rotate as _r
        worst = _r.hook_worst_case_seconds()
        limit = self._timeout_start_sec()
        self.assertLess(worst, limit * 0.9,
                        "钩子最坏 %.0fs 逼近 TimeoutStartSec=%ds" % (worst, limit))

    def test_hook_probes_default_matches_rotate(self):
        """钩子显式传的 --probes/--gap 必须与 rotate.py 的默认值一致。

        不一致的话预算算的是两个不同的数，这个测试也就失去意义。
        """
        import rotate as _r
        hook = (ROOT / "on-mihomo-up.sh").read_text(encoding="utf-8")
        import re
        probes = re.search(r"HEALTH_PROBES=(\d+)", hook)
        gap = re.search(r"HEALTH_GAP=(\d+)", hook)
        self.assertIsNotNone(probes)
        self.assertIsNotNone(gap)
        sig = __import__("inspect").signature(_r.hook_worst_case_seconds)
        self.assertEqual(int(probes.group(1)), sig.parameters["probes"].default,
                         "钩子的 HEALTH_PROBES 与预算函数默认值不一致")
        self.assertEqual(int(gap.group(1)), sig.parameters["gap"].default,
                         "钩子的 HEALTH_GAP 与预算函数默认值不一致")

    def test_adding_endpoints_is_caught(self):
        """加端点导致预算越线时，这条测试必须变红。"""
        import rotate as _r
        base = _r.NODE_HEALTH_URLS
        try:
            _r.NODE_HEALTH_URLS = tuple("http://x%d/" % i for i in range(10))
            self.assertGreater(_r.hook_worst_case_seconds(),
                               self._timeout_start_sec() * 0.9,
                               "10 个端点应该越过 0.9 安全线；"
                               "若没有，说明预算公式没跟着端点数走")
        finally:
            _r.NODE_HEALTH_URLS = base

    def test_budget_is_monotonic_in_probe_count(self):
        import rotate as _r
        vals = [_r.hook_worst_case_seconds(probes=n) for n in (1, 2, 3, 4, 5)]
        self.assertEqual(vals, sorted(vals), "预算必须随采样次数单调不减")

    def test_subcommand_reports_the_number(self):
        import rotate as _r
        n = int(_r.hook_worst_case_seconds() + 0.999)
        self.assertGreater(n, 0)
        self.assertEqual(n, int(_r.hook_worst_case_seconds() + 0.999))


class TestInstallGuards(unittest.TestCase):
    """install.sh 第 8 步的三段判据必须真的能命中。

    早先写成 `grep 轮换开始 && grep 告警`：而分流核对是**无条件前置**的，
    VIOLATION 会在打印「轮换开始」**之前**就 exit 3 —— 两个条件永远不能同时
    满足，于是 VIOLATION 落进「无法通过 API 认证」（报错方向完全错），
    UNKNOWN 走 dry-run 的另一句文案、grep 不到，照样打印绿色「认证正常」。
    评审实测三种情况后改的，这里把结论锁住。
    """

    def _install(self):
        return (ROOT / "install.sh").read_text(encoding="utf-8")

    def test_violation_guard_does_not_require_progress_line(self):
        src = self._install()
        # 只看 if 那几行本身 —— 上面的注释里正是在引用「轮换开始」
        # 来说明为什么不能拿它当条件。
        i = src.index("分流规则异常")
        line_start = src.rfind(chr(10), 0, i) + 1
        cond = src[line_start:src.find(chr(10), i)]
        self.assertNotIn("轮换开始", cond,
                         "VIOLATION 时「轮换开始」压根没打印，加这个条件守卫必然落空")
        self.assertIn("grep -q", cond)

    def test_unknown_guard_matches_the_dry_run_wording(self):
        src = self._install()
        self.assertIn("分流核对：UNKNOWN", src,
                      "dry-run 打印的是这句，不是非 dry-run 的「无法核对」")

    def test_three_cases_are_mutually_exclusive(self):
        """**真的执行 install.sh 的判据**，不是在测试里抄一份 if/elif。

        上一版这里构造一个字典、然后在自己抄的 if/elif 链上断言抄对了 ——
        一个同义反复：把 install.sh 的三段判据整个删掉，它照样绿。
        现在把 install.sh 里那几行判据**抽出来当代码执行**。
        """
        src = self._install()
        # 抽出 install.sh 那三段判据里 grep 的字符串（按文件里的出现顺序）
        conds, rest = [], src
        while True:
            a = rest.find("grep -q '")
            if a < 0:
                break
            rest = rest[a + 9:]
            b = rest.find("'")
            conds.append(rest[:b])
            rest = rest[b:]
        self.assertGreaterEqual(len(conds), 3, "install.sh 里应有三段 grep 判据")
        self.assertEqual(conds[:3], ["分流规则异常", "分流核对：UNKNOWN", "轮换开始"],
                         "三段判据的内容或顺序变了")

        def classify(output):
            """按 install.sh 那三段的真实顺序判定。"""
            for cond, verdict in zip(conds[:3], ("die", "warn", "ok")):
                if cond in output:
                    return verdict
            return "auth-fail"

        self.assertEqual(classify("!! 分流规则异常：opencode.ai 指向 DIRECT"), "die")
        self.assertEqual(classify("(dry-run) 分流核对：UNKNOWN  <- 读不到"), "warn")
        self.assertEqual(classify("--- 轮换开始 | 当前节点=JP"), "ok")
        self.assertEqual(classify("HTTP Error 401: Unauthorized"), "auth-fail")

    def test_guard_order_puts_violation_first(self):
        """三段判据的**顺序**就是优先级：违规必须最先判。

        顺序错了就会出现「VIOLATION 被当成认证失败」——
        那正是第六轮发现、第八轮修掉的那个 bug。
        """
        src = self._install()
        a = src.index("grep -q '分流规则异常'")
        b = src.index("grep -q '分流核对：UNKNOWN'")
        c = src.index("grep -q '轮换开始'")
        self.assertLess(a, b, "违规判据必须在 UNKNOWN 之前")
        self.assertLess(b, c, "UNKNOWN 判据必须在「认证正常」之前")


class TestUninstallPurge(unittest.TestCase):
    """--purge 的语义是「彻底删除」，就不该留一份含私钥的 config 在盘上。"""

    def _purge_block(self):
        """取**真正执行 purge 的那一段**，不是文件头注释里的第一处 --purge。"""
        src = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        i = src.index('if [ "$PURGE" -eq 1 ]; then')
        blk = src[i:src.index("else", i)]
        # 只看代码行 —— 注释里正是在引用旧文件名来说明改了什么
        return chr(10).join(l for l in blk.split(chr(10))
                            if not l.strip().startswith("#"))

    def test_purge_does_not_copy_config_with_private_keys(self):
        blk = self._purge_block()
        self.assertNotIn("surfshark-config-", blk,
                         "把含 4 处 WireGuard 私钥的 config 复制到 /root 永久保留，"
                         "与 purge 的语义完全相反")
        txt = (ROOT / "docs/adr/0001-degradation-owner.md").read_text(encoding="utf-8")
        self.assertNotIn("replace=True", txt, "save_state/replace= 已被 update_state 取代")
        self.assertNotIn("save_state", txt)

    def test_config_has_no_fallback_era_claims(self):
        cfg = (ROOT / "config.yaml").read_text(encoding="utf-8")
        # 「自动切回/自动选中」是 fallback 组时代的说法
        for bad in ("恢复后自动切回", "自动退到直连"):
            self.assertNotIn(bad, cfg,
                             "config.yaml 仍写着 %r —— AUTOFALL 是 select 组，"
                             "恢复只由 rotate.py 显式切换" % bad)


class TestRotationOutputHonesty(unittest.TestCase):
    """--status 不得拿实时探测去比 last_ip。

    每次**成功**轮换之后 last_ip 就是当前出口 IP，所以那句「本轮与上次相同」
    **在健康路径上也会亮**；而「累计」取的是轮换记录的 same_ip_streak，
    于是会出现「本轮与上次相同（累计 0）」这种自相矛盾的行。
    真信号只有 same_ip_streak 一个。
    """

    def test_status_does_not_compare_live_probe_with_last_ip(self):
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        i = src.index("def show_status")
        blk = src[i:src.index("def main(", i)]
        code = chr(10).join(l for l in blk.split(chr(10))
                            if not l.strip().startswith("#"))
        self.assertNotIn("== st[\"last_ip\"]", code,
                         "拿实时探测比 last_ip 在健康路径上必然为真 —— 是假告警")
        self.assertNotIn("本轮与上次相同", code)

    def test_streak_is_the_only_signal(self):
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        i = src.index("def show_status")
        blk = src[i:src.index("def main(", i)]
        self.assertIn("same_ip_streak", blk, "唯一的信号是轮换自己记的 streak")


class TestHookInvariants(unittest.TestCase):
    """只保留**执行真实脚本**或**断言行为**的用例。

    原先这里还有一个 TestHookShell，跑的是把三态闸门手抄出来的 run.sh。
    那份片段是在真实钩子之外另写的一份实现，且从未随钩子更新 ——
    它声称「用 bash 实跑，不用 shell 替身」，实际跑的是替身，而文档字符串
    一直在说谎。TestRealHookGate（跑真脚本）加入后它本该被删掉，却因为
    两者互不干扰而一直绿着。同一件事有两种测法、一种是真的一种是假的，
    假的那份提供的是虚假信心。已删除。
    """

    def test_hook_is_valid_bash(self):
        r = subprocess.run(["bash", "-n", str(ROOT / "on-mihomo-up.sh")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        b = (ROOT / "on-mihomo-up.sh").read_bytes()
        self.assertEqual(b.count(CRLF_BYTES), 0,
                         "钩子带 CRLF 会报 syntax error（$'in\\r'）")

    def test_probe_endpoints_live_in_rotate_only(self):
        """探针 URL 只允许出现在 rotate.py 一处。

        这条不是纯文本洁癖：钩子里硬编码过一个已废弃的 URL，表现为恢复永远
        判不健康、机器安静地一直直连。判据取「钩子里不许出现任何一个端点」，
        而不是「某行必须这么写」—— 后者只证明这行字打对了。
        """
        import rotate as _r
        src = (ROOT / "on-mihomo-up.sh").read_text(encoding="utf-8")
        for u in _r.NODE_HEALTH_URLS:
            self.assertNotIn(u, src, "钩子里硬编码了探针 URL %s" % u)
        self.assertIn("--probe-node", src)

    def test_counter_warning_not_neutralised_by_or_else(self):
        """`|| echo "$NEXT"` 会让 GOT 恒等于 NEXT，告警永远不触发。

        早先的版本正是这么写的，而紧挨着的注释还写着「计数没落盘会让上限
        永远不生效」—— 那个 || 恰好废掉了自己刚加的告警。
        """
        src = (ROOT / "on-mihomo-up.sh").read_text(encoding="utf-8")
        self.assertNotIn('--recheck-tried 2>/dev/null || echo "$NEXT"', src)


class TestSnifferCoverageNeverSkips(unittest.TestCase):
    """「最危险的检测路径」不得因环境而消失。

    sniffer 失效（无域名、纯 IP 落进 MATCH,DIRECT）是这条检测被写出来要覆盖的
    失效模式本身。早先覆盖它的两条用例直接调 `_leak_ips()`，于是离线或受限
    网络下会 skipTest —— 而「测试全绿」在那种环境里**并不等于**覆盖到了它。
    典型场景：CI、容器、还没联网的新机器。
    """

    def _method_src(self, name):
        src = (ROOT / "tests/test_rotate.py").read_text(encoding="utf-8")
        i = src.index("def %s(self)" % name)
        j = src.find(chr(10) + "    def ", i + 1)
        return src[i:j if j > 0 else len(src)]

    def test_sniffer_detection_tests_do_not_skip(self):
        for name in ("test_sniffer_failure_is_detected_by_ip",
                     "test_proxied_connection_not_flagged_even_with_bare_ip"):
            blk = self._method_src(name)
            self.assertNotIn("skipTest", blk,
                             "%s 覆盖的是最危险的检测路径，不许因环境而跳过" % name)

    def test_they_inject_the_ip_instead_of_resolving(self):
        for name in ("test_sniffer_failure_is_detected_by_ip",
                     "test_proxied_connection_not_flagged_even_with_bare_ip"):
            blk = self._method_src(name)
            self.assertNotIn("_leak_ips()", blk,
                             "%s 不该依赖真 DNS" % name)

    def test_real_dns_check_is_labelled_as_integration(self):
        """真实解析那条保留为集成检查，且必须自我标注。"""
        src = (ROOT / "tests/test_rotate.py").read_text(encoding="utf-8")
        self.assertIn("test_real_dns_resolution_actually_works", src)
        blk = self._method_src("test_real_dns_resolution_actually_works")
        self.assertIn("集成检查", blk,
                      "允许 skip 的那条必须明确标注自己是集成检查")


class TestRunnerOrder(unittest.TestCase):
    """测试类必须定义在 runner **之前**，否则从未执行。

    我把一个类追加到文件末尾时踩过：它在 `unittest.main()` 调用**之后**才定义，
    于是收集时不存在 —— **看起来有测试，实际没有**，比同义反复更隐蔽：
    连 `FAILED` 都不会有，一直是全绿。
    """

    def test_no_test_class_is_defined_after_the_runner(self):
        src = (ROOT / "tests/test_rotate.py").read_text(encoding="utf-8")
        # 用 rindex：文件里 TestRunnerOrder 自己的断言字符串也含这段文本，
        # index() 会命中那个字面量而不是真 runner（我自己踩过）。
        runner = src.rindex('if __name__ == "__main__":')
        tail = src[runner:]
        import re as _r
        classes = _r.findall(r"^class (Test\w+)", tail, _r.M)
        self.assertEqual(classes, [],
                         "这些测试类定义在 runner 之后，从未执行：%s" % classes)

    def test_every_class_is_discoverable(self):
        """确认套件里真的装得下这些类（防止类名写错而静默不收）。"""
        import unittest as _u
        loader = _u.TestLoader()
        suite = loader.discover(str(pathlib.Path(__file__).parent),
                                pattern="test_rotate.py")
        names = set()
        def walk(s):
            for t in s:
                if isinstance(t, _u.TestSuite):
                    walk(t)
                else:
                    names.add(type(t).__name__)
        walk(suite)
        src = (ROOT / "tests/test_rotate.py").read_text(encoding="utf-8")
        import re as _r
        declared = set(_r.findall(r"^class (Test\w+)", src, _r.M))
        missing = declared - names
        self.assertEqual(missing, set(),
                         "这些测试类没有被 loader 收集到：%s" % sorted(missing))



class TestRotationStrategy(unittest.TestCase):
    """12 小时内不重复：扁平轮询 + recent 记忆 + 撞重复换节点重摇。

    实测 48h/181 周期：JP 90 / KR 91 / **SG 0 / TW 0**，相邻两次相同 **0 次**
    -> 旧结构的 tier 恒为 0，整套分档是死代码，而它让人以为备用节点是活的。
    """

    def setUp(self):
        import rotate as _r
        self.r = _r

    def test_all_four_nodes_are_in_rotation(self):
        self.assertEqual(len(self.r.NODES), 4, "SG/TW 必须在轮询里，否则一次也用不上")
        for n in ("JP", "KR", "SG", "TW"):
            self.assertTrue(any(x.startswith(n) for x in self.r.NODES),
                            "%s 不在 NODES 里" % n)

    def test_pick_next_cycles_through_all_nodes(self):
        st = {"idx": 0}
        seen = []
        for _ in range(len(self.r.NODES) * 2):
            seen.append(self.r.pick_next(st))
            st["idx"] += 1
        self.assertEqual(len(set(seen[:4])), 4, "一个完整周期必须经过四个节点")
        self.assertEqual(seen[:4], seen[4:], "第二个周期应完全重复")

    def test_skip_moves_to_a_different_pool(self):
        """重摇**必须换节点** —— 原地重摇实测接受率 0/9。"""
        st = {"idx": 0}
        base = self.r.pick_next(st)
        self.assertNotEqual(self.r.pick_next(st, skip=1), base,
                            "skip 不换节点 = 原地重摇，实测永远抽到用过的地址")

    def test_recent_window_expires(self):
        now = 1700000000
        fresh = self.r.remember_ip({"recent": []}, "1.2.3.4", now=now)
        self.assertEqual(self.r.recent_ips({"recent": fresh}, now=now + 60), {"1.2.3.4"})
        later = now + (self.r.RECENT_WINDOW_H + 1) * 3600
        self.assertEqual(self.r.recent_ips({"recent": fresh}, now=later), set(),
                         "超过窗口的地址必须被忘掉，否则集合只增不减")

    def test_recent_dedupes_same_ip(self):
        now = 1700000000
        s = {"recent": self.r.remember_ip({"recent": []}, "9.9.9.9", now=now)}
        s["recent"] = self.r.remember_ip(s, "9.9.9.9", now=now + 30)
        self.assertEqual(len(s["recent"]), 1, "同一个 IP 只留最新一条")

    def test_budget_arithmetic_is_achievable(self):
        """12h 需要的不同地址数必须 <= 实测池并集，否则数学上不可能达标。"""
        need = 720 // self.r.ROUND_INTERVAL_MIN
        pools = {"JP 日本-东京": 47, "KR 韩国-首尔": 32,
                 "SG 新加坡": 17, "TW 台湾-台北": 13}
        union = sum(pools[n] for n in self.r.NODES if n in pools)
        self.assertLessEqual(need, union,
                             "间隔 %d 分钟 -> 12h 需 %d 个不同地址，"
                             "而实测池并集只有 %d —— 数学上不可能不重复"
                             % (self.r.ROUND_INTERVAL_MIN, need, union))

    def test_five_minute_interval_is_now_infeasible(self):
        """5 分钟是这个配置的边界之外 —— 必须被显式承认。"""
        need = 720 // 5
        union = 47 + 32 + 17 + 13
        self.assertGreater(need, union,
                           "若这条不再成立（池子变大），可以重新评估间隔")

    def test_dead_tier_keys_are_gone(self):
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        code = chr(10).join(l for l in src.split(chr(10))
                            if not l.strip().startswith("#"))
        self.assertNotIn('state["tier"]', code)
        self.assertNotIn("same_ip_streak", code,
                         "只在「与上次完全相同」时递增，实测 181 周期 0 次触发")


class TestIntervalMatchesBudget(unittest.TestCase):
    """定时器间隔与 12h 预算必须一致 —— 这两处以前没有任何东西关联着。"""

    def test_timer_interval_matches_rotate_constant(self):
        import rotate as _r
        unit = (ROOT / "surfshark-rotate.timer").read_text(encoding="utf-8")
        import re
        m = re.search(r"OnUnitActiveSec=(\d+)min", unit)
        self.assertIsNotNone(m, "定时器应显式声明分钟间隔")
        self.assertEqual(int(m.group(1)), _r.ROUND_INTERVAL_MIN,
                         "定时器间隔与 rotate.py 的 ROUND_INTERVAL_MIN 不一致 —— "
                         "预算算的是另一个数")

    def test_five_minutes_is_rejected_by_the_budget(self):
        """5 分钟是边界之外。若哪天池子变大，这条会红，那是重新评估的信号。"""
        import rotate as _r
        union = 47 + 32 + 17 + 13
        self.assertGreater(720 // 5, union)


class TestStatusHasNoFalseAlarm(unittest.TestCase):
    """--status 不得报「当前 IP 在记忆里」—— 它本来就应该在。

    与上一轮修掉的 same_ip_streak 假告警同一个毛病，只换了张脸：
    当前 IP 是最近一次轮换记进去的，拿它去问「是不是用过的」必然为真。
    """

    def test_status_excludes_current_and_last_from_spare(self):
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        i = src.index("def show_status")
        blk = src[i:src.index("def main(", i)]
        code = chr(10).join(l for l in blk.split(chr(10))
                            if not l.strip().startswith("#"))
        self.assertNotIn("ip in used", code,
                         "拿当前 IP 去问「是不是用过」必然为真 —— 每轮都会假告警")
        self.assertIn("spare", code)

    def test_warns_only_when_pool_is_exhausted(self):
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        i = src.index("def show_status")
        blk = src[i:src.index("def main(", i)]
        code = chr(10).join(l for l in blk.split(chr(10))
                            if not l.strip().startswith("#"))
        self.assertIn("len(spare) <= 0", code,
                      "该出声的场合是「池子抽干」，不是「刚用过这个」")


class TestRedrawPathActuallyRuns(RotateTestBase):
    """重摇路径必须被**真的执行**过，不能只测 pick_next / remember_ip。

    我写完重摇逻辑时，测试只覆盖了 pick_next 与 recent 这两个纯函数，
    `switch_and_reload` 在整个测试文件里**零引用** —— 于是它第一次上机
    执行就崩：`TypeError: can't concat str to bytes`（给 api() 传了 dict），
    04:39 那轮整轮崩溃，recent 没更新、idx 没推进。
    「看起来测过了」与「跑过了」之间隔着一次真实调用。
    """

    def test_api_encodes_dict_body(self):
        """api() 必须自己处理编码，而不是要求每个调用点记得 encode。

        真机崩过：重摇路径给 api() 传了 dict -> `TypeError: can't concat str
        to bytes`，而且崩在**隧道已经切换之后**，状态文件还没记账。
        这里直接断言「传进去的 data 是 bytes」，不经过 HTTP 桩 ——
        桩的 400/401 会掩盖真正要测的东西。
        """
        import urllib.request as _u
        r = self.rotate
        seen = {}
        real = _u.urlopen

        def spy(req, timeout=None):
            seen["data"] = req.data
            seen["headers"] = dict(req.headers)
            raise RuntimeError("stop-here")

        self.patch(_u, "urlopen", spy)
        self.patch(r, "SECRET", "x")
        for body in ({"name": "JP 日本-东京"},
                     '{"name": "JP 日本-东京"}',
                     json.dumps({"name": "JP 日本-东京"}).encode("utf-8")):
            seen.clear()
            try:
                r.api("/proxies/PROXY", "PUT", body)
            except RuntimeError:
                pass
            self.assertIsInstance(seen.get("data"), bytes,
                                  "传 %s 时 data 应为 bytes，实际 %r"
                                  % (type(body).__name__, type(seen.get("data"))))
            self.assertIn("name", json.loads(seen["data"].decode("utf-8")))


    def test_switch_and_reload_hits_the_real_api(self):
        self.seed()
        FakeMihomo.groups["PROXY"]["now"] = "JP 日本-东京"
        r = self.rotate
        self.patch(r, "SECRET", "testsecret")
        import time as _t
        self.patch(r, "reload_config", lambda: _t.sleep(0))   # 只免掉那 5 秒
        ok, err = r.switch_and_reload("KR 韩国-首尔")
        self.assertTrue(ok, "switch_and_reload 失败：%s" % err)
        puts = [r for r in FakeMihomo.requests
                if r[0] == "PUT" and r[1].endswith("/proxies/PROXY")]
        self.assertTrue(puts, "必须真的 PUT 过 /proxies/PROXY")
        last = puts[-1][2]
        if isinstance(last, bytes):
            last = last.decode("utf-8")
        # json.dumps 默认转义非 ASCII，所以要解析后比而不是子串匹配
        self.assertEqual(json.loads(last).get("name"), "KR 韩国-首尔",
                         "PUT /proxies/PROXY 的 body 必须是节点名")

    def test_full_rotation_runs_the_redraw_branch(self):
        """整条 rotate_once 在「撞到用过的地址」时必须跑通，而不是崩。

        真机上这一段崩过：`TypeError: can't concat str to bytes`，
        而且崩在**隧道已经切换之后** —— 状态文件还没记账。
        """
        self.seed()
        r = self.rotate
        seen = []
        self.patch(r, "SECRET", "testsecret")
        self.patch(r, "current_node", lambda: "JP 日本-东京")
        self.patch(r, "reload_config", lambda: None)
        self.patch(r, "exit_ip", lambda: "9.9.9.9")     # 固定成已用过的地址
        self.patch(r, "recent_ips", lambda state, now=None: {"9.9.9.9"})
        self.patch(r, "switch_and_reload",
                   lambda n: (seen.append(n), (True, ""))[1])
        self.quiet(r.rotate_once)
        self.assertTrue(seen, "应该至少重摇一次（撞到窗口内用过的地址）")
        self.assertLessEqual(len(seen), r.MAX_REDRAW, "重摇次数必须有上限")


class TestStatusHasNoFalseAlarm(unittest.TestCase):
    """--status 不得报「当前 IP 在记忆里」—— 它本来就应该在。

    与上一轮修掉的 same_ip_streak 假告警同一个毛病，只换了张脸：
    当前 IP 是最近一次轮换记进去的，拿它去问「是不是用过的」必然为真。
    """

    def test_status_excludes_current_and_last_from_spare(self):
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        i = src.index("def show_status")
        blk = src[i:src.index("def main(", i)]
        code = chr(10).join(l for l in blk.split(chr(10))
                            if not l.strip().startswith("#"))
        self.assertNotIn("ip in used", code,
                         "拿当前 IP 去问「是不是用过」必然为真 —— 每轮都会假告警")
        self.assertIn("spare", code)

    def test_warns_only_when_pool_is_exhausted(self):
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        i = src.index("def show_status")
        blk = src[i:src.index("def main(", i)]
        code = chr(10).join(l for l in blk.split(chr(10))
                            if not l.strip().startswith("#"))
        self.assertIn("len(spare) <= 0", code,
                      "该出声的场合是「池子抽干」，不是「刚用过这个」")



class TestSuiteItselfRuns(unittest.TestCase):
    """这个文件必须真的会跑。

    我在删重复测试类时把文件末尾的 `if __name__ == "__main__": unittest.main()`
    一起删掉了。于是 `python3 tests/test_rotate.py` 变成 **exit=0、零输出**，
    而我照惯例检查「exit=0、grep FAILED 计数为 0」—— **绿灯来自一个根本没运行的套件**，
    并且我把这个假绿灯写进了提交信息。

    早先的 `TestRunnerOrder` 只检查「runner 之后不应有类」，
    查不出「runner 根本不存在」。这一条查那个。
    """

    def test_main_block_exists(self):
        src = (ROOT / "tests/test_rotate.py").read_text(encoding="utf-8")
        self.assertIn('if __name__ == "__main__":', src,
                      "没有 __main__ 块 -> 直接运行本文件一个测试都不会跑，"
                      "而 exit 仍是 0")
        self.assertIn("unittest.main(", src)

    def test_runner_is_actually_wired_up(self):
        """用一个**不存在**的用例名运行：快，且能证明 runner 真的接好了。

        早先那版是「直接运行本文件」，结果它会把整个套件再跑一遍 ——
        套件套自己，300 秒都跑不完。这版只验证接线，不执行任何用例。
        """
        import subprocess
        r = subprocess.run(
            [sys.executable, str(ROOT / "tests/test_rotate.py"),
             "TestSuiteItselfRuns.test_definitely_not_a_real_test"],
            capture_output=True, text=True, timeout=120)
        out = (r.stdout or "") + (r.stderr or "")
        import re as _r
        m = _r.search(r"Ran (\d+) test", out)
        self.assertIsNotNone(m,
                             "runner 没接上 —— 直接运行本文件没有任何用例计数"
                             "（exit=%s，输出 %d 字节）"
                             % (r.returncode, len(out)))
        self.assertLessEqual(int(m.group(1)), 5,
                             "探针不该真的跑整个套件（跑了 %s 个）" % m.group(1))

    def test_declared_classes_match_collected(self):
        """声明的类数必须与 loader 收集到的类数一致。"""
        import unittest as _u
        suite = _u.TestLoader().discover(str(ROOT / "tests"),
                                          pattern="test_rotate.py")
        got = set()

        def walk(s):
            for t in s:
                if isinstance(t, _u.TestSuite):
                    walk(t)
                else:
                    got.add(type(t).__name__)
        walk(suite)
        src = (ROOT / "tests/test_rotate.py").read_text(encoding="utf-8")
        import re as _r
        declared = set(_r.findall(r"^class (Test\w+)", src, _r.M))
        self.assertEqual(declared - got, set(),
                         "这些类声明了但没被收集：%s" % sorted(declared - got))


class TestReadmeMatchesReality(unittest.TestCase):
    """README 里的间隔与时间尺度必须与代码一致。

    我把间隔从 5 分钟改成 10 分钟时只改了 timer 与 ADR，README 里的 4 处
    「每 5 分钟」原封不动 —— 而降级判据那行「约 10 分钟」也跟着错了
    （2 轮 × 10 分钟 = 20 分钟）。这类陈述不会让任何测试变红。
    """

    def _readme(self):
        return (ROOT / "README.md").read_text(encoding="utf-8")

    def test_no_stale_five_minute_claims(self):
        self.assertNotIn("每 5 分钟", self._readme(),
                         "间隔已改为 10 分钟，README 仍在说 5 分钟")
        self.assertNotIn("每 5 分钟自动换", self._readme())

    def test_declared_interval_matches_timer(self):
        import rotate as _r
        self.assertIn("每 %d 分钟" % _r.ROUND_INTERVAL_MIN, self._readme(),
                      "README 应按代码里的 ROUND_INTERVAL_MIN 表述")

    def test_degrade_window_math_matches(self):
        """降级是「连续 N 轮」，换算成时间要乘间隔。"""
        import rotate as _r
        minutes = _r.DEGRADE_AFTER_FAILS * _r.ROUND_INTERVAL_MIN
        self.assertIn("约 %d 分钟" % minutes, self._readme(),
                      "降级需要 %d 轮 × %d 分钟 = %d 分钟，README 应这么写"
                      % (_r.DEGRADE_AFTER_FAILS, _r.ROUND_INTERVAL_MIN, minutes))


class TestRepeatRateIsHonest(unittest.TestCase):
    """「12h 不重复」是承诺，但只有跑满 12 小时才算验证过。

    用 recent 算重复率会把重复吃掉 —— recent 对同一 IP 只留最新一条，
    所以它永远没有重复。需要一个**每轮都记**的 rot_log 才能算出来。
    """

    def test_rot_log_records_every_round_including_repeats(self):
        import rotate as _r
        st = {"rot_log": [], "recent": []}
        now = 1700000000
        for ip in ("1.1.1.1", "1.1.1.1", "2.2.2.2"):
            st["rot_log"] = _r.prune_recent(st.get("rot_log"), now)
            st["rot_log"].append((now, ip))
        hist = [ip for _, ip in st["rot_log"]]
        self.assertEqual(len(hist), 3, "rot_log 必须记下每一轮，重复也要记")
        self.assertEqual(len(hist) - len(set(hist)), 1, "能算出 1 次重复")

    def test_recent_alone_would_hide_the_repeat(self):
        """这正是不能用 recent 算重复率的原因。"""
        import rotate as _r
        st = {"recent": []}
        now = 1700000000
        for ip in ("1.1.1.1", "1.1.1.1"):
            st["recent"] = _r.remember_ip(st, ip, now=now)
        self.assertEqual(len(_r.recent_ips(st, now=now)), 1,
                         "recent 去重后看不出发生过两次")

    def test_status_states_that_the_window_must_fill_first(self):
        src = (ROOT / "rotate.py").read_text(encoding="utf-8")
        i = src.index("def show_status")
        blk = src[i:src.index("def main(", i)]
        self.assertIn("承诺要到 12 小时后才算数", blk,
                      "窗口没跑满时不能让人以为已经达标")


if __name__ == "__main__":
    unittest.main(verbosity=2)
