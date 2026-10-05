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
import time
import urllib.error
import urllib.request

# ============================================================
#  需要和 config.yaml 保持一致
# ============================================================
API = "http://127.0.0.1:9097"        # external-controller
MIXED_PORT = 7897                     # mixed-port
MIXED_HOST = "127.0.0.1"
IP_PROBE_HOST = "ip.sb"               # 必须在分流规则内，否则测到的是本机真实 IP

MIHOMO_SERVICE = "mihomo.service"     # 自愈时重启的目标
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


def conns_on(node):
    """经过指定节点的活跃连接数（仅用于状态观测）"""
    try:
        data = api("/connections")
    except Exception:
        return -1
    return sum(1 for c in (data.get("connections") or [])
               if isinstance(c, dict) and node in (c.get("chains") or []))


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
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"tier": 0, "idx": 0, "last_ip": None}


def save_state(s):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=2)
    except OSError as e:
        log(f"    状态文件写入失败：{e}")


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

    # 3) 验证 IP
    if dry_run:
        log("    (dry-run，跳过 IP 检测)")
        return True

    new_ip = exit_ip()
    log(f"    出口IP：{old_ip or '(未知)'} -> {new_ip or '(取不到)'}")

    if old_ip and new_ip and new_ip == old_ip:
        log("    IP 未变化 → 降到下一档备用节点")
        state["tier"] = tier + 1
        state["idx"] = 0
    else:
        state["idx"] = state.get("idx", 0) + 1
        if tier > 0 and new_ip:
            # 备用档成功换到新 IP，就逐步升回低延迟档
            state["tier"] = tier - 1
            log(f"    备用档成功 → 升回第 {state['tier']+1} 档")

    state["last_ip"] = new_ip
    save_state(state)
    log(f"--- 完成 | 节点={target} | IP={new_ip} | 档位={state['tier']+1} ---")
    return True


def show_status():
    try:
        node = current_node()
    except Exception as e:
        log(f"!! mihomo API 不通：{type(e).__name__}: {e}")
        log("   试试：systemctl status mihomo.service")
        return
    ip = exit_ip()
    st = load_state()
    log(f"当前节点 : {node}")
    log(f"出口 IP  : {ip or '(取不到)'}")
    log(f"上次 IP  : {st.get('last_ip') or '(无记录)'}")
    log(f"该节点连接 : {conns_on(node)}")
    log(f"当前档位 : {st.get('tier', 0)+1} / {len(TIERS)}")
    log(f"配置路径 : {CONFIG_PATH} ({'存在' if os.path.exists(CONFIG_PATH) else '不存在'})")


def main():
    ap = argparse.ArgumentParser(description="Surfshark 出口 IP 轮换器（VPS 版）")
    ap.add_argument("--loop", type=int, metavar="秒", help="按间隔持续轮换")
    ap.add_argument("--status", action="store_true", help="显示当前状态")
    ap.add_argument("--dry-run", action="store_true", help="只演示不实际切换")
    ap.add_argument("--no-heal", action="store_true", help="mihomo 挂了不自愈（调试用）")
    args = ap.parse_args()

    if args.no_heal:
        globals()["HEAL"] = False

    if args.status:
        show_status()
        return

    if args.loop:
        log(f"=== 轮换器启动，间隔 {args.loop}s，Ctrl+C 停止 ===")
        try:
            while True:
                rotate_once()
                log(f"... 等待 {args.loop}s ...")
                time.sleep(args.loop)
        except KeyboardInterrupt:
            log("=== 已停止 ===")
    else:
        rotate_once(dry_run=args.dry_run)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        # 由 systemd 调用时没有终端，异常必须打到 journal 才看得到
        log(f"!! 未捕获异常：{type(e).__name__}: {e}")
        raise