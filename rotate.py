#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Surfshark 出口 IP 轮换器（Linux / VPS 版）

轮换逻辑（与 Windows 版一致，已实测验证）：
    1. 切到下一个节点        → 新连接走新节点，旧连接继续留在原节点上跑完
    2. PUT /configs 热重载   → 重建隧道，新连接拿到全新出口 IP
    3. 检测 IP 是否变化      → 没变就降到下一优先级档位

实测结论（决定了为什么没有「排空等待」这一步）：
    · 切换节点   不会中断已有连接
    · 热重载配置 不会中断已有连接（直连与代理连接各验证过）
    旧连接天然就是排空语义，不需要等待，更不能超时强杀。

相对 Windows 版移除了什么：
    · _find_runtime_config()  扫描 C:\\ProgramData\\clash-verge-service\\users\\<hash>
                               （Clash Verge 服务模式专属路径，VPS 上不存在）
    · _read_path_file()       为绕开 schtasks /TR 的 260 字符上限而存在的路径文件
    · os.name == "nt" 分支    pythonw 专用的 CREATE_NO_WINDOW
    · GUI 相关的一切

相对 Windows 版新增了什么：
    · 出口 IP 探测改为纯标准库 SOCKS5，不依赖 curl（精简 VPS 镜像常常没有 curl）
    · 自愈：mihomo API 不通时自动 systemctl restart mihomo
      （本机有 Clash Verge 兜底，VPS 上没有，必须自己兜）
    · 日志走 stdout，由 journald 收集和轮转

用法：
    python3 rotate.py                轮换一次
    python3 rotate.py --loop 300     每 300 秒轮换一次（Ctrl+C 停止）
    python3 rotate.py --status       只看当前状态
    python3 rotate.py --dry-run      只演示不实际切换
"""

import argparse
import json
import os
import re
import subprocess
import sys
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

# flock 只在 Unix 上有。本项目跑在 Linux VPS 上，那里一定有；
# 这里做守卫是为了让模块在别处也能 import（本地测试、语法检查），
# 拿不到 fcntl 时退化成「只有原子写、没有锁」，与改动前行为一致。
try:
    import fcntl
except ImportError:            # pragma: no cover - 非 Unix 环境
    fcntl = None

# ============================================================
#  需要和 config.yaml 保持一致
# ============================================================
API = "http://127.0.0.1:9097"        # external-controller
MIXED_PORT = 7897                     # mixed-port
MIXED_HOST = "127.0.0.1"
IP_PROBE_HOST = "ip.sb"               # 必须在分流规则内，否则测到的是本机真实 IP

# 降级链。config.yaml 里 AUTOFALL 是 **select** 组，成员 [PROXY, DIRECT]，
# 由本模块通过 PUT /proxies/AUTOFALL 显式切换 —— 内核不参与判断。
# （早先是 fallback 组，靠内核健康检查自动翻，详见 ADR 0001 记录的
#   废弃理由：单样本布尔裁决，隧道抖一下就把 opencode.ai 送去直连。）
# 也就是说「密钥到期 → opencode.ai 连不上」这个故障由本模块消掉，
# 本模块同时负责控制面：发现降级、停掉没意义的轮换、把状态告诉人。
AUTOFALL = "AUTOFALL"
DEGRADED_TO = "DIRECT"

# 连续多少轮取不到出口 IP 就判定为节点全挂。
# 不能是 1：单轮取不到可能只是某个 CDN 边缘节点抖动。
# 也不能太大：定时器 5 分钟一轮，3 轮就是 15 分钟无谓的空转。
SAME_IP_WARN = 3            # 连续 3 轮出口 IP 不变 -> 产出为零，开始出声
DEGRADE_AFTER_FAILS = 2

# 恢复侧的去抖次数。
#
# 降级要求连续 2 次失败，恢复曾一度只要 1 次成功 —— 两边的迟滞不对称，
# 结果是对着 cp.cloudflare.com 的一次侥幸成功就撤销降级、把 AUTOFALL 切回
# PROXY，opencode.ai 立刻硬失败，再攒两轮又降级，来回抖。
# 方向上不算危险（PROXY 是安全的那一侧），但会让出口 IP 和定时器状态
# 无意义地反复变化。要求连续 2 次健康采样，与降级侧对称。
RECOVER_AFTER_HEALTHY = 2

MIHOMO_SERVICE = "mihomo.service"     # 自愈时重启的目标
ROTATE_TIMER = "surfshark-rotate.timer"   # 降级时停掉；由 on-mihomo-up.sh 钩子启回
HEAL = os.environ.get("ROTATE_HEAL", "1") != "0"   # --no-heal 可临时关掉

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("ROTATE_CONFIG_PATH") or os.path.join(BASE, "config.yaml")


def _secret_from_config(path):
    """从 config.yaml 读 secret，让配置只有一个真相来源。

    密钥由 install.sh 随机生成后写进 config.yaml。若在这里再写一份
    （哪怕是占位符），两处迟早会不一致 —— 实测就踩过：
    install.sh 替换了 config.yaml 里的占位符，rotate.py 里的那份没被替换，
    于是每轮轮换都收到 HTTP 401，并且被误判成「内核挂了」而触发多余的重启。
    """
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r'^\s*secret:\s*"?([^"#\s]+)"?\s*$', line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return ""


SECRET = os.environ.get("ROTATE_SECRET") or _secret_from_config(CONFIG_PATH)

# 优先级分档：先在第一档内轮换，拿不到新 IP 才降档。
#
# 【这一项跟机器强相关】分档顺序必须按**部署目标机**的实际延迟排。
# 各区域差异极大：同一台机器上 JP 可能是 2ms 而 SG 是 77ms，
# 照抄别处的顺序等于平时就在用最差的节点。
#
# 换机器或换机房后，用同目录的 measure-nodes.sh 重测并把结果粘回来：
#     bash measure-nodes.sh
TIERS = [
    ["JP 日本-东京", "KR 韩国-首尔"],
    ["TW 台湾-台北"],
    ["SG 新加坡"],
]
# ============================================================

STATE_FILE = os.path.join(BASE, ".rotate_state.json")

_IP_RE = re.compile(r"^[0-9a-fA-F:.]+$")


def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def api(path, method="GET", body=None, timeout=15):
    h = {"Authorization": f"Bearer {SECRET}"}
    if body is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(API + path, method=method, data=body, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


# ------------------------------------------------------------
#  出口 IP 探测：纯标准库 SOCKS5 + TLS + HTTP
#  不依赖 curl，因为精简版 VPS 镜像经常没装
# ------------------------------------------------------------
def _recv_exact(sock, n, timeout):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"连接提前关闭（已收 {len(buf)}/{n} 字节）")
        buf += chunk
    return buf


def _socks5_probe(host, port, path="/ip", timeout=25):
    """socks5h 语义：域名直接交给代理解析，本地不做 DNS。"""
    import socket
    import ssl

    s = socket.create_connection((MIXED_HOST, MIXED_PORT), timeout=timeout)
    s.settimeout(timeout)
    try:
        # 1) 握手：只声明「无认证」一种方法
        s.sendall(b"\x05\x01\x00")
        if _recv_exact(s, 2, timeout) != b"\x05\x00":
            raise RuntimeError("SOCKS5 协商失败（mixed-port 可能不对，或被要求认证）")

        # 2) CONNECT，地址类型 0x03 = 域名
        hb = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + port.to_bytes(2, "big"))
        rep = _recv_exact(s, 4, timeout)
        if rep[1] != 0x00:
            raise RuntimeError(f"SOCKS5 CONNECT 被拒绝，reply code={rep[1]}")

        # 3) 读掉 BND.ADDR / BND.PORT
        atyp = rep[3]
        if atyp == 0x01:
            _recv_exact(s, 4, timeout)
        elif atyp == 0x03:
            _recv_exact(s, _recv_exact(s, 1, timeout)[0], timeout)
        elif atyp == 0x04:
            _recv_exact(s, 16, timeout)
        else:
            raise RuntimeError(f"未知地址类型 {atyp}")
        _recv_exact(s, 2, timeout)

        # 4) 隧道内做 TLS + HTTP GET
        ctx = ssl.create_default_context()
        ts = ctx.wrap_socket(s, server_hostname=host)
        try:
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: rotate-probe\r\nAccept: text/plain\r\n"
                   f"Connection: close\r\n\r\n")
            ts.sendall(req.encode())
            chunks = []
            while True:
                d = ts.recv(4096)
                if not d:
                    break
                chunks.append(d)
        finally:
            ts.close()
        raw = b"".join(chunks).decode("utf-8", "replace")
        head, _, body = raw.partition("\r\n\r\n")
        if not head.startswith("HTTP/1.1 2"):
            status = head.splitlines()[0] if head else "(空响应)"
            raise RuntimeError(f"ip.sb 返回异常：{status}")
        return body
    finally:
        try:
            s.close()
        except OSError:
            pass


def _curl_probe(timeout=25):
    r = subprocess.run(
        ["curl", "-s", "-m", str(timeout),
         "--proxy", f"socks5h://{MIXED_HOST}:{MIXED_PORT}",
         f"https://{IP_PROBE_HOST}/ip"],
        capture_output=True, text=True, timeout=timeout + 5)
    # 必须检查返回码：curl 失败时 stdout 为空，
    # 若不报错就会静默走到「取不到 IP」，无人值守时无从排查。
    if r.returncode != 0:
        raise RuntimeError(f"curl 退出码 {r.returncode}：{r.stderr.strip()[:200] or '(无 stderr)'}")
    return r.stdout


def exit_ip():
    """返回当前经代理的出口 IP，取不到返回 None。

    必须用 ip.sb —— 它在分流规则内会走代理；其它域名会被 MATCH,DIRECT
    直连，测出来的是本机真实 IP，看起来就像「轮换没生效」。
    """
    for probe, name in ((lambda: _socks5_probe(IP_PROBE_HOST, 443), "socks5"),
                        (lambda: _curl_probe(), "curl")):
        try:
            text = probe()
        except Exception as e:
            log(f"    出口 IP 探测（{name}）失败：{type(e).__name__}: {e}")
            continue
        for tok in (text or "").split():
            tok = tok.strip().strip('"').rstrip(".")
            if _IP_RE.match(tok) and any(c.isdigit() for c in tok):
                return tok
    return None


# ------------------------------------------------------------
#  控制 API 的薄封装
# ------------------------------------------------------------
def current_node():
    return api("/proxies/PROXY")["now"]


def switch(node):
    api("/proxies/PROXY", "PUT", json.dumps({"name": node}).encode())
    time.sleep(1)


def reload_config():
    if not os.path.exists(CONFIG_PATH):
        raise RuntimeError(f"配置文件不存在：{CONFIG_PATH}")
    try:
        api("/configs", "PUT", json.dumps({"path": CONFIG_PATH}).encode(), timeout=30)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(
            f"热重载被拒绝 (HTTP {e.code})：{body}\n"
            f"提示：mihomo 只允许重载启动目录（-d）内的配置，"
            f"该路径必须位于 {BASE} 之下。") from None
    time.sleep(5)


# 分流不变量：opencode.ai 必须走 AUTOFALL，ip.sb 必须走 PROXY。
#
# 为什么要查 **已加载** 的规则而不是读 config.yaml：config.yaml 是我们的意图，
# mihomo 的 /rules 是它**实际**在跑的东西。两者不一致时，只有后者说明真相 ——
# 而「不一致」正是最难发现的那种故障：没有探测失败、没有降级、status 全绿，
# 而 opencode.ai 正在用本机 IP 出网。
#
# 这条检查是确定性的：不需要任何流量，配合每次热重载自然发生。
# 连接侧的阳性检测（direct_leaks）作为补充，它还能看到 rules 检查看不见的一类
# —— sniffer 失效导致域名没被还原、纯 IP 建连落进 MATCH,DIRECT。
def check_routing_invariants():
    """核对 mihomo 实际加载的规则是否符合分流不变量。

    返回 ("OK" | "VIOLATION" | "UNKNOWN", 说明文字列表)。

    三态而不是布尔：「确认违规」与「无法判定」必须分开。读不到 /rules、
    读不到组成员表，都属于 UNKNOWN —— 无法判定既不该被当成通过，
    更不该被当成泄漏。后者更糟：它会让 status.sh 在零证据的情况下
    说出「正在泄漏」。
    """
    problems = []
    unknown = []
    try:
        rules = (api("/rules") or {}).get("rules") or []
    except Exception as e:
        return "UNKNOWN", [f"读不到 /rules：{type(e).__name__}: {e}"]
    if not rules:
        return "UNKNOWN", ["/rules 返回空规则表"]

    # mihomo 的求值是**第一条命中即生效**，所以这里必须按顺序取第一条，
    # 而不是「任意一条 payload 含该子串的规则」。早先的实现遍历全部规则、
    # 返回第一条子串匹配，于是任何排在前面、payload 不含该字面量的规则
    # 都能遮蔽真正生效的那条 —— 实测三条绕过：
    #   GEOSITE,opencode,DIRECT   / IP-CIDR,104.18.1.0/24,DIRECT
    #   / DOMAIN,opencode.ai,DIRECT
    # 而「加一条 GEOSITE 规则」是很自然的动作。
    def target_of(needle):
        for r in rules:
            if not isinstance(r, dict):
                continue
            if needle in str(r.get("payload") or ""):
                return r.get("proxy")
        return None

    # 早于本规则命中、且把流量送去 DIRECT 的规则 —— 它们会遮蔽本配置。
    # 只看**宽匹配器**：DST-PORT,22 排在前面是无害的（opencode.ai 走 443，
    # 那条永远不匹配），把它算成遮蔽就是误报。
    BROAD = {"MATCH", "GEOSITE", "GEOIP", "IP-CIDR", "IP-CIDR6",
             "RULE-SET", "DOMAIN", "DOMAIN-KEYWORD", "DOMAIN-SUFFIX",
             "DOMAIN-REGEX", "IN-NAME", "IN-TYPE", "PROCESS-NAME"}
    def earlier_direct_rules(idx_of):
        hits = []
        for r in rules[:idx_of]:
            if not isinstance(r, dict):
                continue
            if str(r.get("proxy") or "") != "DIRECT":
                continue
            if str(r.get("type") or "").upper() not in BROAD:
                continue
            hits.append("%s,%s" % (r.get("type"), r.get("payload")))
        return hits

    for host, want, tag in (("opencode.ai", AUTOFALL, "opencode.ai"),
                            ("ip.sb", "PROXY", "出口 IP 探测")):
        idx, got = None, None
        for i, r in enumerate(rules):
            if isinstance(r, dict) and host in str(r.get("payload") or ""):
                idx, got = i, r.get("proxy")
                break
        if got is None:
            problems.append(f"{host} 的分流规则在已加载的规则表里找不到"
                            f"（tag={tag}）—— 它会落进 MATCH,DIRECT，直接泄漏")
            continue
        if got != want:
            problems.append(f"{host} 已加载的规则指向 {got}，应为 {want}"
                            f"（tag={tag}）")
        # 前面的 DIRECT 规则会遮蔽它：mihomo 取第一条命中，压根走不到这条。
        shadow = earlier_direct_rules(idx)
        if shadow:
            problems.append(
                f"{host} 前面有 {len(shadow)} 条指向 DIRECT 的规则会遮蔽它"
                f"（mihomo 取第一条命中）：{'、'.join(shadow[:3])}"
                f" —— 实际生效的是 DIRECT")

    # AUTOFALL 组本身必须仍然含 PROXY。规则指向 AUTOFALL「完全正确」，
    # 但若成员被掏空成只剩 DIRECT，AUTOFALL 就等于直连，而上面那条检查
    # 读不到这一点 —— 实测这就是一条绕过路径。
    try:
        grp = api("/proxies/" + urllib.parse.quote(AUTOFALL, safe="")) or {}
        members = grp.get("all") or []
        if "PROXY" not in members:
            problems.append(f"{AUTOFALL} 组成员缺少 PROXY（当前 {members}）—— "
                            f"即使规则指向它，opencode.ai 也会走直连")
        if str(grp.get("type")) != "Selector":
            problems.append(f"{AUTOFALL} 的类型是 {grp.get('type')} 而不是 Selector —— "
                            f"内核会自行判断分组，降级归属将失效")
    except Exception as e:
        unknown.append(f"读不到 {AUTOFALL} 的成员表：{type(e).__name__}: {e}")

    # 三态而不是布尔：「确认违规」与「无法判定」必须分开。
    # 早先把两者塞进同一个 problems，于是 /rules 返回一次 500 也会写出
    # routing_bad_at，而 status.sh 会把那条记录翻译成「把本机 IP 泄漏出去」——
    # 在零泄漏证据的情况下说出这句话。这正是本函数 docstring 反对的
    # 「把不确定当确定」，自己却犯了。
    if problems:
        return "VIOLATION", problems
    if unknown:
        return "UNKNOWN", unknown
    return "OK", []


# 需要盯的流量。opencode.ai 是唯一「泄漏即严重」的目标：它直连时，
# 对端看到的就是这台 VPS 自己的 GCP 机房 IP。
LEAK_HOST = "opencode.ai"


def direct_leaks():
    """当前是否有 opencode.ai 的连接正在走 DIRECT。

    **阳性检测，不是推断。** 其它所有信号都是「探测失败 -> 猜是不是该降级」；
    这一条直接读 mihomo 已经建立的连接，看它实际走了哪条链。

    为什么要它：有一个失效模式其它信号全都看不见 —— 降级逻辑完全正常、
    AUTOFALL 好好指着 PROXY，但分流规则被外部改动（opencode.ai 那条规则改了
    目标、或 sniffer 失效导致域名没被还原）而落进 MATCH,DIRECT。
    此时没有探测失败、没有降级、status.sh 一片绿，**而 opencode.ai 正在直连**。
    这是「无信号泄漏」里最隐蔽的一种。

    chains 的形状实测为 ["KR 韩国-首尔", "PROXY", "AUTOFALL"]，
    chains[0] 才是真正承载流量的出站。

    降级期间（AUTOFALL=DIRECT）出现 DIRECT 是**设计如此**，不算泄漏；
    调用方负责区分，否则每次降级都会报一个假警。
    """
    try:
        data = api("/connections")
    except Exception:
        return None
    hits = []
    # sniffer 失效时 metadata 里一个域名都没有，只剩 destinationIP ——
    # 而「sniffer 失效」正是这条检测被写出来要覆盖的失效模式之一。
    # 所以必须同时按 IP 反查，否则它对它自己的目标失明（实测过）。
    ip_pool = _leak_ips()
    for c in (data.get("connections") or []):
        if not isinstance(c, dict):
            continue
        md = c.get("metadata") or {}
        chains = c.get("chains") or []
        if not (chains and chains[0] == "DIRECT"):
            continue                      # 先判链路，省掉后面的字符串拼接
        host = md.get("host") or ""
        sniff = md.get("sniffHost") or ""
        dst = md.get("destinationIP") or ""
        by_name = LEAK_HOST in host or LEAK_HOST in sniff
        by_ip = bool(dst) and dst in ip_pool
        if by_name or by_ip:
            hits.append((host or sniff or dst, dst, "by-ip" if by_ip and not by_name
                         else "by-name"))
    return hits


_IP_CACHE = {"at": 0.0, "ips": set()}


def _leak_ips(ttl=900):
    """opencode.ai 当前解析到的 IP 集合，带 TTL 缓存。

    Cloudflare 前端，地址会变，所以带 TTL 而不是写死。但缓存是为了不每轮
    都去做一次 DNS —— 15 分钟一次足够，而一条连接通常活不过几分钟。
    解析失败时返回上一份缓存而不是空集：宁可多看几条，也不要因为
    一次解析失败就把正在泄漏的连接全判成无关。
    """
    now = time.time()
    if now - _IP_CACHE["at"] < ttl:
        return _IP_CACHE["ips"]
    ips = set()
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                for r in socket.getaddrinfo(LEAK_HOST, 443, fam):
                    ips.add(r[4][0])
            except OSError:
                pass
    except Exception:
        pass
    if ips:
        _IP_CACHE["ips"] = ips
        _IP_CACHE["at"] = now
    return _IP_CACHE["ips"]


def conns_on(node):
    """经过指定节点的活跃连接数（仅用于状态观测）"""
    try:
        data = api("/connections")
    except Exception:
        return -1
    return sum(1 for c in (data.get("connections") or [])
               if isinstance(c, dict) and node in (c.get("chains") or []))


# ------------------------------------------------------------
#  降级状态
# ------------------------------------------------------------
def autofall_now():
    """AUTOFALL 组当前选中的出站。

    返回 "DIRECT" 表示节点全挂、已降级到直连。
    老版本 config.yaml 没有 AUTOFALL 组，返回 None —— 调用方按「未降级」处理。
    """
    try:
        return api("/proxies/" + AUTOFALL)["now"]
    except Exception:
        return None


def set_autofall(target):
    """把 AUTOFALL 组显式切到 PROXY 或 DIRECT。

    AUTOFALL 是 select 组，没有健康检查，因此**永不自行翻转** ——
    降级与恢复只可能由本脚本的这一次调用造成。这就是瞬时泄漏归零的
    结构保证：实测 17 小时内内核自行翻转 5 次、其中 1 次让 opencode.ai
    用本机机房 IP 出网，改成 select 之后这种情况一次都不会再发生。
    """
    try:
        # api() 把 body 原样交给 urllib，必须是 bytes —— 与 switch() 同一写法
        api("/proxies/" + AUTOFALL, "PUT", json.dumps({"name": target}).encode())
        return True
    except Exception as e:
        log("!! 切换 AUTOFALL 到 %s 失败：%s" % (target, e))
        return False


# 节点健康探测用的 URL。只经由控制面的 /proxies/<节点>/delay 端点使用，
# 不参与分流规则，所以与出口 IP 探测（ip.sb，经数据面）是两条独立通道。
# 控制面健康信号用的探针端点。**必须保持多个且互相独立。**
#
# 之前只有 cp.cloudflare.com 一个。它一旦对该机房 IP 限流，node_healthy() 就
# 恒为 False —— 而这个信号同时是「降级佐证」和「恢复判据」：
#   · 降级侧：exit_ip() 也失败时，会被判定为隧道已死 -> 误降级 -> 泄漏
#   · 恢复侧：探测永远失败 -> 恢复卡住 -> 泄漏持续
# 第二种更要命：它不会报错、不会降级，只是**永远不再恢复**，机器安静地一直直连。
#
# 判据取「任一端点响应即视为隧道存活」而不是「全部响应」，这不是宽容，
# 是因为两个方向的错误代价相反：误判隧道死会泄漏（本项目的头号问题），
# 误判隧道活只是让 opencode.ai 撞一次失败的代理，不泄漏且下一轮就会纠正。
# 用两三家互不相关的服务，把「误判隧道死」的概率压到需要三方同时出事。
NODE_HEALTH_URLS = (
    "http://cp.cloudflare.com/",          # Cloudflare
    "http://www.gstatic.com/generate_204",  # Google
    "http://detectportal.firefox.com/success.txt",  # Mozilla
)
NODE_HEALTH_TIMEOUT_MS = 4000           # 单个端点；任一成功即短路返回
# 钩子的最坏耗时必须远低于 mihomo.service 的 TimeoutStartSec，否则 systemd 会
# 在钩子跑完前把它杀掉 —— 后果不是「少查一次」，而是 mihomo 被判 failed 配上
# Restart=always 反复重启，恢复路径永远跑不完。端点数从 1 扩到 3 时最坏耗时
# 从 128s 涨到 188s，正好越过了 systemd 默认的 90s，所以这里显式收窄客户端超时，
# 并且在 mihomo.service 里显式声明 TimeoutStartSec —— 不依赖默认值算术。
NODE_HEALTH_CLIENT_SLACK = 3


def node_healthy(node, timeout_ms=NODE_HEALTH_TIMEOUT_MS):
    """探测某个节点本身是否可用。任一端点响应即算可用。

    【为什么不用 AUTOFALL 判断恢复】降级时 AUTOFALL 正是我们自己设成
    DIRECT 的，拿它判断恢复会自证循环。这里走控制面的
    /proxies/<name>/delay —— 完全不经过 AUTOFALL，也不经过数据面，
    所以 AUTOFALL 当前指向谁都不影响这个结论。
    """
    q = urllib.parse.quote(node, safe="")
    # 顺序尝试、任一成功即短路返回：健康情况下只花一个请求，
    # 只有「全挂」才付满 N × timeout 的代价。
    for raw in NODE_HEALTH_URLS:
        u = urllib.parse.quote(raw, safe="")
        try:
            d = api("/proxies/%s/delay?timeout=%d&url=%s"
                    % (q, timeout_ms, u), timeout=timeout_ms / 1000.0 + NODE_HEALTH_CLIENT_SLACK)
            delay = d.get("delay")
            if isinstance(delay, int) and delay > 0:
                return True
        except Exception:
            continue
    return False


def probe_node_consecutive(want, gap):
    """连续 want 次探测当前节点，全健康才返回 (True, 延迟)。给钩子用。

    为什么归本模块所有：钩子早先是内嵌一份 python 副本，连探针 URL 都在那里
    硬编码了一遍。同一套判据两份实现，迟早漂移 —— 而漂移的方向恰好是
    「钩子那份还写着一个已经废弃的 URL」，表现为恢复永远判不健康。
    中途任何一次失败即整体作废，避免对着一台还在抖的隧道下结论。
    """
    node = api("/proxies/PROXY").get("now") or ""
    if not node:
        return False, None, ""
    last = None
    for i in range(max(1, want)):
        if i:
            time.sleep(gap)
        if not node_healthy(node):
            return False, None, node
        try:                      # 只为把延迟显示在日志里，失败无所谓
            u = urllib.parse.quote(NODE_HEALTH_URLS[0], safe="")
            q = urllib.parse.quote(node, safe="")
            d = api("/proxies/%s/delay?timeout=%d&url=%s"
                    % (q, NODE_HEALTH_TIMEOUT_MS, u),
                    timeout=NODE_HEALTH_TIMEOUT_MS / 1000.0
                    + NODE_HEALTH_CLIENT_SLACK)
            last = d.get("delay")
        except Exception:
            pass
    return True, last, node


def mark_degraded(state, reason):
    """进入降级态：切 AUTOFALL 到直连、记状态、停掉没意义的轮换定时器。

    停定时器是对的：此时切节点、热重载、探测出口 IP 全都做不出结果，
    每 5 分钟重试一次只是空转。恢复由 on-mihomo-up.sh 钩子负责 ——
    换私钥必然要 restart mihomo，钩子会在那里复查节点是否真的活了。
    """
    was = state.get("degraded")
    # 复查计数归零：这是一次全新的降级，不该继承上一次故障用掉的配额。
    # 否则「上次卡在 6 次上限」会让这次故障一进钩子就零次自动复查。
    state.pop("recheck_tries", None)
    state["degraded"] = True
    state["degraded_reason"] = reason
    state["degraded_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    update_state({"degraded": True, "degraded_reason": reason,
                  "degraded_at": state["degraded_at"]},
                 remove=("recheck_tries",))

    if was is not True:
        log("!! 进入降级态：%s" % reason)
        if set_autofall(DEGRADED_TO):
            log("   AUTOFALL 已切到 %s，opencode.ai 会退到直连（还能用，但出口变回本机）"
                % DEGRADED_TO)
        log("   IP 轮换已停摆 —— 这是本项目唯一的产出，现在等于空转")
    if os.path.exists("/run/systemd/system"):
        r = subprocess.run(["systemctl", "stop", ROTATE_TIMER],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            log("   已停掉定时器 %s" % ROTATE_TIMER)
        else:
            log("   ⚠ 停定时器失败（%s）：%s" % (ROTATE_TIMER, (r.stderr or "").strip()[:160]))
    log("   恢复步骤：")
    log("     1. 换新的 Surfshark WireGuard 私钥（config.yaml 里 private-key，4 处共用同一个）")
    log("     2. sudo systemctl restart mihomo")
    log("        钩子会在 mihomo 起来后用控制面探测节点是否真的活了，是则自动恢复")
    log("     3. 若 1 分钟内没自动恢复，手工执行：sudo systemctl start %s" % ROTATE_TIMER)
    return False


def clear_degraded(state):
    """取到出口 IP 后清掉降级痕迹，并把日志说准确。

    两种情况必须分开说：
      · 真的进过降级态（AUTOFALL 落到 DIRECT，定时器已被停掉）
      · 只是探测失败计数被清零，从没进过降级态
    早先两者共用一句「已退出降级态」。实测遇到过「单轮探测失败
    fail_streak 1/2 就恢复了」的情况，那句话把严重程度夸大了。
    """
    was_degraded = bool(state.get("degraded"))
    streak = int(state.get("fail_streak") or 0)
    if not has_degraded_marks(state):
        return
    for k in DEGRADED_KEYS:
        state.pop(k, None)
    state["fail_streak"] = 0
    # 增删都在 update_state 的锁内完成，且只碰列出来的键。
    # 早先这里是 load_state + replace 写：读在锁外，而且守卫条件与
    # clear_degraded_flags() 那份不一致，已经漂移过一次（漏 recheck_tries）。
    update_state({"fail_streak": 0}, remove=DEGRADED_KEYS)

    if not was_degraded:
        log(f"    出口 IP 已恢复（此前连续 {streak} 轮取不到），轮换继续")
        return

    # 非降级态必须让 AUTOFALL 指回 PROXY —— 它是我们自己设成 DIRECT 的。
    # mihomo 会把 select 组的选择写进 cache.db 并跨重启保留，
    # 所以这里显式纠正，防止任何异常残留把 opencode.ai 永远钉在直连上。
    if set_autofall("PROXY"):
        log("    AUTOFALL 已切回 PROXY，opencode.ai 恢复走轮换 IP")

    # mark_degraded 停掉了定时器，所以「轮换恢复」这句话成立的前提是
    # 定时器真的还活着。而恢复有两条路径，只有钩子那条会顺带 systemctl start：
    #   · 换私钥 → restart mihomo → on-mihomo-up.sh 起定时器
    #   · 手工跑一轮 rotate.py（本函数的调用点）→ 钩子根本不触发
    # 第二条路径下定时器仍然是停的，而轮换正是这个项目唯一的产出 ——
    # 实测出现过：换回私钥、重启过、也手工跑过一轮，定时器还是 inactive，
    # 轮换从此静默停摆，日志却一切正常。
    # 所以这里主动把定时器启回来，而不是只提醒一句「需要手工执行」。
    if not os.path.exists("/run/systemd/system"):
        log("    已退出降级态（非 systemd 环境，定时器由人管）")
        return
    r = subprocess.run(["systemctl", "start", ROTATE_TIMER],
                       capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        log("    已退出降级态，并已启回 %s —— 轮换恢复" % ROTATE_TIMER)
    else:
        log(f"    已退出降级态，但启回 {ROTATE_TIMER} 失败：{(r.stderr or '').strip()[:160]}")
        log(f"    请手工执行：sudo systemctl start {ROTATE_TIMER}")


def heal_mihomo():
    """mihomo 挂了就把它拉起来。VPS 上没有 Clash Verge 兜底，这一步是必需的。"""
    if not HEAL:
        log("    自愈已关闭（ROTATE_HEAL=0）")
        return False
    if not os.path.exists("/run/systemd/system"):
        log("    不是 systemd 环境，跳过自愈")
        return False
    log(f"    自愈：systemctl restart {MIHOMO_SERVICE}")
    try:
        subprocess.run(["systemctl", "restart", MIHOMO_SERVICE],
                       capture_output=True, text=True, timeout=90)
    except Exception as e:
        log(f"    自愈失败：{type(e).__name__}: {e}")
        return False
    for i in range(30):
        time.sleep(2)
        try:
            current_node()
            log(f"    自愈成功（等待 {2*(i+1)} 秒）")
            return True
        except Exception:
            pass
    log("    自愈后 API 仍不通")
    return False


# ------------------------------------------------------------
#  状态与分档
# ------------------------------------------------------------
def load_state():
    """读状态。文件缺失是正常的（首次运行），文件损坏不是 —— 要出声。

    早先两者都返回一份全新的默认状态，于是损坏会被「当成没有降级」：
    钩子守卫在明确没降级时直接 exit 0，标记一丢就再也不会把 AUTOFALL 切回
    PROXY、也不会启回定时器 —— 而数据面还在直连，正是 ADR 里点名的静默泄漏。
    原子写已经让「读到半个文件」不可能，所以剩下的触发面只有外部删改、
    旧版本残留的坏文件、磁盘错误；这几种都必须看得见。
    """
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"tier": 0, "idx": 0, "last_ip": None}
    except Exception as e:
        log(f"!! 状态文件损坏（{type(e).__name__}: {e}）—— 按「没有状态」处理")
        log("   如果此刻明明是降级态，轮换不会再自动恢复，请手工确认：")
        log("   sudo python3 %s --status" % os.path.join(BASE, "rotate.py"))
        return {"tier": 0, "idx": 0, "last_ip": None}


def update_state(patch=None, remove=(), incr=None):
    """在同一个锁内完成「读 -> 改 -> 写」，并返回磁盘上的最终状态。

    【为什么是独立原语】读-改-写必须整体在同一个锁内，
    中间任何一步都可能踩进另一个写入方。而且更隐蔽的是：调用方通常传的是
    load_state() 拿到的**整份快照**，于是「合并写」会把这份快照里所有键都盖回
    磁盘 —— 包括调用方这一轮根本没打算动、但已经过时的那些。实测过一个**无并发**
    也会发生的例子：钩子刚用 replace=True 删掉 degraded，rotate.py 随后拿陈旧
    快照写回 recovery_streak，顺手把 degraded=true 又带回来了；而钩子此时已经
    启回了定时器、切回了 PROXY，状态却显示降级 —— 轮换静默停摆。

    patch 只写它列出的键，remove 只删它列出的键，两者都不碰其余字段。
    """
    def _apply():
        cur = load_state()
        if not isinstance(cur, dict):
            cur = {}
        for k in remove:
            cur.pop(k, None)
        if patch:
            cur.update(patch)
        for k, step in (incr or {}).items():
            cur[k] = int(cur.get(k) or 0) + step
        return cur

    if fcntl is None:
        final = _apply()
        _write_atomic(final)
        return final
    lock_path = STATE_FILE + ".lock"
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        final = _apply()
        _write_atomic(final)
        return final
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            final = _apply()
            _write_atomic(final)      # 同样必须在临界区内
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
    return final


def _write_atomic(s):
    tmp = STATE_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_FILE)
        # 【必须 fsync 父目录】os.replace 的持久性靠的是父目录项落盘，
        # 只 fsync 文件不够：断电后改名可能回退，读者会看到旧内容。
        # 而在这个项目里「旧内容」恰好是最坏的内容 —— mark_degraded 写完
        # degraded=true、紧接着 systemctl stop 定时器之后掉电且改名回退，
        # 就是「标记丢失 + AUTOFALL 已是 DIRECT + 定时器已停」的静默泄漏。
        try:
            dfd = os.open(os.path.dirname(STATE_FILE) or ".", os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass          # 某些文件系统不支持目录 fsync，不影响原子改名本身
    except OSError as e:
        log(f"    状态文件写入失败：{e}")
        try:
            os.unlink(tmp)
        except OSError:
            pass


# 「降级痕迹」是哪些键，和「清理时删掉哪些键」是同一件事 ——
# 所以只维护一份。早先两处各写一份 for k in (...) 列表，守卫条件又各写一份，
# 结果已经漂移过一次：只有 recheck_tries 时，clear_degraded 守卫早退而
# clear_degraded_flags 却清了。两份列表漂移至少还 grep 得到，守卫漂移查不出来。
DEGRADED_KEYS = ("degraded", "degraded_reason", "degraded_at",
                 "direct_seen", "recovery_streak", "recheck_tries")


def has_degraded_marks(s):
    return any(s.get(k) for k in DEGRADED_KEYS) or bool(s.get("fail_streak"))


def clear_degraded_flags():
    """清掉全部降级痕迹，只动这批键，不碰 tier/idx/last_ip。

    on-mihomo-up.sh 通过 `rotate.py --clear-degraded` 调用它，而不是自己
    再写一份 key 列表 —— 两个写入方各带一份硬编码清单，迟早会漏掉某个键，
    而漏掉的恰恰是「标记已恢复」这一类语义最重的键。

    增删都走 update_state：读-改-写在同一个锁内，且只碰列出来的键。
    早先这里是 load_state + replace 写，读在锁外；而且守卫条件与
    clear_degraded() 的那份不一致，已经漂移过一次。
    """
    if not has_degraded_marks(load_state()):
        return False
    update_state({"fail_streak": 0}, remove=DEGRADED_KEYS)
    return True


def bump_recheck_tries():
    """复查计数 +1，返回新值。给 on-mihomo-up.sh 用。

    计数同样归本模块所有：钩子里再手写一份读-改-写，就得重复原子写与加锁的
    逻辑，重复一次就多一个能把它写坏的版本。增也在锁内完成 —— 读加写分开
    的话，两个并发调用会拿到同一个新值。
    """
    return int(update_state(incr={"recheck_tries": 1}).get("recheck_tries") or 0)


def reset_recheck_tries():
    """复查计数归零。人工重试前调用。

    这里是一次纯 setter（只把 recheck_tries 置 0，没有任何删除），
    早先却用了 replace=True 整体覆盖 —— 别人刚写的 last_ip 会被整块盖回旧值。

    **状态文件不存在时什么都不做。** 早先无条件 update_state，结果把不存在的
    文件凭空创建成一份默认状态；而钩子在闸门之前调它，于是新建的文件里没有
    degraded 键，闸门据此判定「明确未降级」直接返回 —— 状态丢失后的数据面恢复
    路径永远走不到，AUTOFALL 停在 DIRECT 不动。上机实测确认过这条泄漏链。
    写一个状态文件不是「无害的准备工作」，它会改变下游的判读。
    """
    if not os.path.exists(STATE_FILE):
        return
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            json.load(f)          # 损坏就别覆盖 —— 那是唯一的证据
    except Exception:
        return
    update_state({"recheck_tries": 0})


def pick_next(state):
    """按优先级挑下一个节点：档内循环，降档后继续"""
    tier = state.get("tier", 0) % len(TIERS)
    nodes = TIERS[tier]
    return tier, nodes[state.get("idx", 0) % len(nodes)]


# ------------------------------------------------------------
#  轮换主流程
# ------------------------------------------------------------
def rotate_once(dry_run=False):
    state = load_state()

    try:
        live = current_node()
    except urllib.error.HTTPError as e:
        # 认证失败不是「内核挂了」。实测踩过：密钥不一致时每轮都收到 401，
        # 而早先的版本把它当成连接失败，触发自愈去重启一个完全健康的核心 ——
        # 结果是每 5 分钟白重建一次隧道、断掉连接、白白换一次 IP。
        if e.code in (401, 403):
            log(f"!! mihomo API 拒绝认证 (HTTP {e.code})")
            log(f"   密钥取自 {CONFIG_PATH} 的 secret 字段，与内核实际值不一致")
            log("   重连解决不了认证问题，不触发自愈")
            return False
        log(f"!! mihomo API 返回 HTTP {e.code}")
        if heal_mihomo():
            live = current_node()
        else:
            log("   放弃本次轮换")
            return False
    except Exception as e:
        log(f"!! 无法连接 mihomo API ({API})：{type(e).__name__}: {e}")
        if heal_mihomo():
            live = current_node()
        else:
            log("   放弃本次轮换")
            return False

    tier, target = pick_next(state)

    # 降级态下的唯一出路是节点真的恢复。判据走控制面（节点 delay 探测），
    # 不用 AUTOFALL 的当前选择 —— 那正是我们自己设成 DIRECT 的，
    # 拿它判断恢复会自证循环。
    #
    # 恢复后不立刻做本轮轮换：刚恢复的节点可能还不稳，此刻重建隧道
    # 等于用一个说不清的 IP 去记基线。干净退出，让下一轮正常轮换去建立基线。
    if state.get("degraded"):
        # 同样要求连续 RECOVER_AFTER_HEALTHY 次健康，与降级侧对称。
        # 单次侥幸成功不足以证明「真的修好了」—— 那次成功的对象是
        # cp.cloudflare.com，不是我们要保的那个出口。
        rec = int(state.get("recovery_streak") or 0)
        if node_healthy(live):
            rec += 1
            state["recovery_streak"] = rec
            update_state({"recovery_streak": rec})   # 补丁，不是整份快照
            if rec < RECOVER_AFTER_HEALTHY:
                log(f"    控制面探测健康，第 {rec}/{RECOVER_AFTER_HEALTHY} 次 —— "
                    f"再确认一次才撤销降级")
                return False
            log(f"    连续 {rec} 次探测健康，撤销降级")
            # 不在这里再调 set_autofall —— clear_degraded() 内部会切回 PROXY。
            # 两处都调会产生两次重复的 PUT（评审 Minor 项 M3）。
            clear_degraded(state)
            log("--- 本轮不做轮换，让下一轮重新建立基线 ---")
        else:
            state["recovery_streak"] = 0
            update_state({"recovery_streak": 0})
            log("    节点仍不可用（控制面探测失败），维持降级")
        return False

    # 非降级态就该走代理。mihomo 会把 select 组的选择持久化到 cache.db，
    # 任何异常残留（例如手工改过、或降级中途被强杀）都要在这里纠正回来，
    # 否则 opencode.ai 会被永久钉在直连上而无人察觉。
    if autofall_now() not in (None, "PROXY"):
        log("    发现 AUTOFALL 异常指向 %s，纠正回 PROXY" % autofall_now())
        set_autofall("PROXY")

    old_ip = state.get("last_ip")
    log(f"--- 轮换开始 | 当前节点={live} | 档位={tier+1}/{len(TIERS)} "
        f"({TIERS[tier][0]}...) ---")

    # 1) 切换节点 —— 实测不中断已有连接
    if target != live:
        log(f"    切换 {live} -> {target}")
        if not dry_run:
            try:
                switch(target)
            except Exception as e:
                log(f"!! 切换失败：{e}")
                return False
    else:
        log(f"    已在 {target}，跳过切换")

    # 2) 热重载重建隧道 —— 实测同样不中断已有连接
    #
    # 这里不做「排空等待」，也不做强杀。Windows 版曾经有这两步，
    # 建立在「热重载会杀连接」这个错误前提上；实测推翻后，那套逻辑的
    # 超时强杀分支反而成了 45% 轮换发生中断的唯一来源。
    log("    热重载配置以重建隧道…")
    if not dry_run:
        try:
            reload_config()
        except Exception as e:
            log(f"!! 重载失败：{e}")
            if heal_mihomo():
                log("    自愈后重试一次热重载…")
                try:
                    switch(target)
                    reload_config()
                except Exception as e2:
                    log(f"!! 重试仍失败：{e2}")
                    return False
            else:
                return False
        # 重载后选择可能被重置，确保回到目标节点
        try:
            if current_node() != target:
                switch(target)
        except Exception:
            pass

    # 2b) 核对已加载的分流规则
    #
    # 放在热重载**之后**：重载才是可能让 mihomo 实际生效的规则发生变化的时刻。
    # 此刻读 /rules 问的是「它现在到底在跑什么」，而磁盘上的 config.yaml 只是
    # 我们的意图 —— 两者不一致时只有前者说明真相。
    #
    # 不符合就退出非零：这是确定性的配置错误，不是网络抖动。退出码非零会让
    # ExecMainStatus 变红 —— 那是唯一一个「不需要用户做任何事就能看到」的信号。
    verdict, details = check_routing_invariants()
    if verdict == "UNKNOWN":
        # 无法判定：**不**升级成泄漏告警，只留痕说明判据此刻失效。
        for m in details:
            log(f"?? 分流规则无法核对：{m}")
        log("   这一刻没有泄漏证据，也没有「规则正常」的证据。人工核对：/rules")
        update_state({"routing_unknown_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                      "routing_unknown_reason": "; ".join(details)})
    else:
        update_state({}, remove=("routing_unknown_at", "routing_unknown_reason"))
    if verdict == "VIOLATION":
        for m in details:
            log(f"!! 分流规则异常：{m}")
        log("!! 这会让 opencode.ai 走直连，把本机 IP 泄漏出去，且没有任何其它信号能看见。")
        log("   权威来源是 mihomo 的 /rules，不是磁盘上的 config.yaml。请人工核对。")
        update_state({"routing_bad_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                      "routing_bad_reason": "; ".join(details)})
        raise SystemExit(3)
    if state.get("routing_bad_at"):
        # 之前坏过、现在好了 —— 清掉标记，但记一条「曾异常过」的字样，
        # 免得「曾经坏过」在状态里看起来像从未发生
        update_state({"routing_bad_at": "", "routing_bad_reason": ""})
        log("    分流规则已恢复正常（此前记录到异常）")

    # 3) 验证 IP
    if dry_run:
        log("    (dry-run，跳过 IP 检测)")
        return True

    new_ip = exit_ip()

    # ---- 取不到出口 IP ----
    # 这条分支必须单独处理。原实现在这里是 new_ip=None 落进 else 分支，
    # 然后照样打印「完成」并 return True —— 隧道早就死了，日志却写着成功，
    # 定时器每 5 分钟空转一次，没有任何告警。
    # 失败方向是「无事发生」，比「连不上」更难察觉。
    if new_ip is None:
        streak = int(state.get("fail_streak") or 0) + 1
        state["fail_streak"] = streak
        log(f"    出口IP：{old_ip or '(未知)'} -> (取不到)   连续第 {streak} 次失败")
        # last_ip 必须保留上一次已知的正常出口。
        # 写成 None 的话，等密钥换好之后 old_ip 为空，
        # 「IP 没变就降档」的判断会被跳过，分档逻辑整个失准。
        state["last_ip"] = old_ip

        if streak >= DEGRADE_AFTER_FAILS:
            # 【必须用第二个信号佐证，否则降级会变成新的泄漏源】
            # 上面那个失败只说明「ip.sb 这条探测通道没给出结果」，它与隧道
            # 健康无关 —— ip.sb 限流、5xx、边缘拦截、TLS 抖动，全都落在同一个
            # 分支里。实测 ip.sb 挂 5~10 分钟就能攒够 2 次，届时会把一条
            # **完全健康**的隧道切到直连：opencode.ai 于是用本机 GCP 机房 IP
            # 出网，正是这个项目要避免的事，而且比原来内核那次瞬时翻转更糟
            # （那个 <1 秒，这个是两整轮、期间所有连接都算）。
            #
            # 所以降级必须与控制面结论一致：只有隧道本身也不通时才算降级。
            # 这也符合「泄漏比失败更糟」的优先级 —— 隧道好着就不该降级，
            # ip.sb 的问题下一轮自然就好了。
            # 注意探的是 target 不是 live：此刻已经切换并热重载过，
            # 当前生效的是 target，live 是刚被切走的旧节点。
            if node_healthy(target):
                log(f"    控制面判定节点仍可用 —— 隧道没坏，是探测通道（ip.sb）的问题，不降级")
                log(f"    fail_streak 清零，last_ip 保留为 {old_ip or '(未知)'}")
                state["fail_streak"] = 0
                update_state({"fail_streak": 0, "last_ip": old_ip})
                log(f"--- 结束 | 节点={target} | 出口IP=(取不到，但隧道健康) | "
                    f"未降级 ---")
                return False
            return mark_degraded(state, f"连续 {streak} 轮取不到出口 IP，且控制面也探测不到节点")

        update_state({"fail_streak": streak, "last_ip": old_ip})
        log(f"--- 结束 | 节点={target} | 出口IP=(取不到) | "
            f"连续失败 {streak}/{DEGRADE_AFTER_FAILS} ---")
        return False

    # 取到了：任何降级痕迹都清掉
    if state.get("degraded") or state.get("fail_streak"):
        clear_degraded(state)

    log(f"    出口IP：{old_ip or '(未知)'} -> {new_ip}")

    if old_ip and new_ip == old_ip:
        log("    IP 未变化 → 降到下一档备用节点")
        state["tier"] = tier + 1
        state["idx"] = 0
        # 连续「取到了出口 IP、但和上次一样」的次数。
        # 这是一个**产出为零但全绿**的状态：每轮都打印「完成」、退出码 0，
        # 而项目唯一的存在理由（换 IP）没有任何进展。数据本来就在手里，
        # 只差记一下让 status.sh 能看见。
        unchanged = int(state.get("same_ip_streak") or 0) + 1
        state["same_ip_streak"] = unchanged
        if unchanged >= SAME_IP_WARN:
            log(f"    ⚠ 连续 {unchanged} 轮取到的出口 IP 与上次相同 —— "
                f"轮换产出为零。检查 status.sh 或换节点/换私钥。")
    else:
        state["same_ip_streak"] = 0
        state["idx"] = state.get("idx", 0) + 1
        if tier > 0 and new_ip:
            # 备用档成功换到新 IP，就逐步升回低延迟档
            state["tier"] = tier - 1
            log(f"    备用档成功 → 升回第 {state['tier']+1} 档")

    state["last_ip"] = new_ip
    update_state({"last_ip": new_ip, "idx": state["idx"],
                  "tier": state["tier"],
                  "same_ip_streak": state.get("same_ip_streak", 0)})
    log(f"--- 完成 | 节点={target} | IP={new_ip} | 档位={state['tier']+1} ---")
    return True


def show_status():
    try:
        node = current_node()
    except Exception as e:
        log(f"!! mihomo API 不通：{type(e).__name__}: {e}")
        log("   试试：systemctl status mihomo.service")
        return
    st = load_state()
    now = autofall_now()
    degraded = (now == DEGRADED_TO) or bool(st.get("degraded"))
    ip = exit_ip()

    log(f"降级状态 : {'是' if degraded else '否'}"
        + (f"  —— {st.get('degraded_reason') or now}（AUTOFALL={now}）" if degraded else ""))
    log(f"当前节点 : {node}")
    if degraded:
        # ip.sb 现在固定挂在 PROXY 上（不在降级链里），所以降级时探测它
        # 必然失败、返回「取不到」—— 这本身就是「当前没走代理」的直接证据。
        # 早先这里写的是「测回来的就是本机公网 IP」，那是 ip.sb 还挂在
        # AUTOFALL 上时的行为，改规则后已经不成立了，留着会教错排查方向。
        log(f"出口 IP  : (取不到)  ← 探测通道固定走 PROXY，隧道不通，"
            f"这是「当前确实没走代理」的证据")
        log(f"停摆于   : {st.get('degraded_at') or '(未知)'}")
    else:
        log(f"出口 IP  : {ip or '(取不到)'}")
    log(f"上次 IP  : {st.get('last_ip') or '(无记录)'}")
    streak = int(st.get("same_ip_streak") or 0)
    if streak >= SAME_IP_WARN:
        log(f"⚠ 轮换产出 : 连续 {streak} 轮出口 IP 与上次相同 —— "
            f"在换节点但没换到不同出口。项目唯一产出为零。")
    elif ip and st.get("last_ip") and ip == st["last_ip"]:
        log(f"轮换产出 : 本轮与上次相同（累计 {streak}，满 {SAME_IP_WARN} 轮告警）")
    else:
        log(f"轮换产出 : 正常（本轮 {ip or '(未知)'}）")
    log(f"该节点连接 : {conns_on(node)}")
    # 未降级却出现 opencode.ai 走 DIRECT = 正在泄漏，且没有任何其它信号能看见
    leaks = direct_leaks()
    if leaks is None:
        log("泄漏检测 : 读不到 /connections（mihomo API 不通），跳过")
    elif leaks and not degraded:
        log(f"⚠ 泄漏检测 : 有 {len(leaks)} 条 {LEAK_HOST} 连接正在走 DIRECT！")
        for h, dst, _how in leaks[:3]:
            log(f"    {h} {dst}")
        log(f"  但降级标记为「否」、AUTOFALL={now} —— 按设计不该出现这种情况。")
        log("  最可能：config.yaml 里 opencode.ai 的分流规则被改动，"
            "或 sniffer 失效导致域名没被还原、落进 MATCH,DIRECT。")
        log("  排查：sudo bash %s/status.sh" % BASE)
    elif leaks:
        log(f"泄漏检测 : {len(leaks)} 条走 DIRECT —— 降级期间属预期，非异常")
    else:
        log(f"泄漏检测 : 未发现 {LEAK_HOST} 走直连")
    log(f"当前档位 : {st.get('tier', 0)+1} / {len(TIERS)}")
    log(f"配置路径 : {CONFIG_PATH} ({'存在' if os.path.exists(CONFIG_PATH) else '不存在'})")


def main():
    ap = argparse.ArgumentParser(description="Surfshark 出口 IP 轮换器（VPS 版）")
    ap.add_argument("--loop", type=int, metavar="秒", help="按间隔持续轮换")
    ap.add_argument("--status", action="store_true", help="显示当前状态")
    ap.add_argument("--dry-run", action="store_true", help="只演示不实际切换")
    ap.add_argument("--no-heal", action="store_true", help="mihomo 挂了不自愈（调试用）")
    ap.add_argument("--clear-degraded", action="store_true",
                    help="只清降级痕迹（供 on-mihomo-up.sh 调用）")
    ap.add_argument("--leak-count", action="store_true",
                    help="打印当前正在走直连的 opencode.ai 连接数（供 status.sh 调用）")
    ap.add_argument("--probe-node", action="store_true",
                    help="探测当前节点连续健康（供 on-mihomo-up.sh 调用）")
    ap.add_argument("--probes", type=int, default=2, help="--probe-node 的采样次数")
    ap.add_argument("--gap", type=int, default=8, help="--probe-node 的采样间隔秒")
    ap.add_argument("--recheck-tried", action="store_true",
                    help="复查计数 +1 并打印（供 on-mihomo-up.sh 调用）")
    ap.add_argument("--reset-recheck", action="store_true",
                    help="复查计数归零（供 on-mihomo-up.sh 调用）")
    args = ap.parse_args()

    if args.no_heal:
        globals()["HEAL"] = False

    # on-mihomo-up.sh 曾经自带一份硬编码的 key 列表来清状态，于是状态 schema
    # 有两个写入方、各维护一份清单，迟早会漏掉某个键 —— 而漏掉的恰恰是
    # 「标记已恢复」这类语义最重的键。改成调用本函数，让 schema 只有一个 owner。
    if args.leak_count:
        hits = direct_leaks()
        if hits is None:
            print("skip"); return 1
        print(len(hits))
        return 0

    if args.probe_node:
        ok, delay, live = probe_node_consecutive(args.probes, args.gap)
        if ok:
            # 不要再调一次 /proxies/PROXY 取名字：那一跳失败会让 RESULT 变空，
            # 于是「节点其实健康」被当成没活，白排一次复查；而若 PROXY 恰好
            # 在这中间换掉，名字与延迟会来自两个不同节点。
            print("%s %d" % (live, delay or 0))
        return 0                 # 无论结果如何都返回 0：钩子必须永远返回 0

    if args.recheck_tried:
        print(bump_recheck_tries())
        return 0

    if args.reset_recheck:
        reset_recheck_tries()
        return 0

    if args.clear_degraded:
        changed = clear_degraded_flags()
        print("降级痕迹已清除" if changed else "没有降级痕迹")
        return 0

    # main() 的返回值就是进程退出码，必须往下传。
    # 不传的话，无论成功、降级、还是取不到出口 IP，systemd 记的都是
    # ExecMainStatus=0，status.sh 于是永远显示「上一轮轮换结果：成功」——
    # 故障明明已经写进日志，状态页却说成功。
    # 这与本模块要解决的「失败方向是无事发生」是同一类问题。
    if args.status:
        show_status()
        return 0

    if args.loop:
        log(f"=== 轮换器启动，间隔 {args.loop}s，Ctrl+C 停止 ===")
        try:
            while True:
                rotate_once()
                log(f"... 等待 {args.loop}s ...")
                time.sleep(args.loop)
        except KeyboardInterrupt:
            log("=== 已停止 ===")
        return 0

    return 0 if rotate_once(dry_run=args.dry_run) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:
        # 由 systemd 调用时没有终端，异常必须打到 journal 才看得到
        log(f"!! 未捕获异常：{type(e).__name__}: {e}")
        raise