#!/usr/bin/env bash
# ==============================================================
#  Surfshark 出口 IP 轮换 —— VPS 一键安装
#
#  用法：把本目录整个上传到 VPS，然后
#      cd <目录> && sudo bash install.sh
#
#  设计原则：宁可装失败，也不能把你自己锁在服务器外面。
#  所有会影响网络拓扑的动作都发生在最后，且每一步都有可回退手段。
# ==============================================================
set -euo pipefail

BASE="/opt/surfshark-rotate"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIHOMO_VERSION="${MIHOMO_VERSION:-v1.19.32}"

c_ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
c_warn() { printf '\033[33m%s\033[0m\n' "$*"; }
c_err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }
step()   { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die()    { c_err "✗ $*"; exit 1; }

# ==============================================================
step "0/9  环境自检"
# ==============================================================
[ "$(id -u)" -eq 0 ] || die "必须用 root 运行（创建 TUN 设备需要 CAP_NET_ADMIN）。请 sudo bash install.sh"
c_ok "  ✓ root"

command -v systemctl >/dev/null || die "没有 systemd，这个安装脚本不适用"
c_ok "  ✓ systemd"

PY3="$(command -v python3 || true)"
[ -n "$PY3" ] || die "缺少 python3。Debian/Ubuntu: apt-get install -y python3"
c_ok "  ✓ python3 ($PY3)"

# TUN 设备：没有它整套方案不成立，且很多 VPS 商家不给开
if [ ! -c /dev/net/tun ]; then
    c_warn "  /dev/net/tun 不存在，尝试加载 tun 模块…"
    modprobe tun 2>/dev/null || true
fi
[ -c /dev/net/tun ] || die "/dev/net/tun 不可用。
  OpenVZ / 部分 LXC / 精简商家镜像不给 TUN 设备，mihomo 无法工作。
  换一台 KVM 或 支持 TUN 的商家，或联系客服开启。"
c_ok "  ✓ /dev/net/tun"

# DNS 解析能力（轮换要靠它把 Surfshark 节点域名解析出来）
for h in jp-tok.prod.surfshark.com kr-seo.prod.surfshark.com; do
    getent hosts "$h" >/dev/null 2>&1 || die "无法解析 $h，请检查 VPS 的 DNS 和出网能力"
done
c_ok "  ✓ 外网 DNS 正常"

# ==============================================================
step "1/9  打印应急恢复方式（先看这个，再往下）"
# ==============================================================
cat <<'RECOVERY'

  ┌────────────────────────────────────────────────────────────┐
  │  如果装到中途 SSH 断开（极小概率，但有可能）              │
  │                                                            │
  │  用 VPS 商家控制台的 VNC / 串口 / Web Terminal 登录，然后：│
  │                                                            │
  │      systemctl stop mihomo surfshark-rotate.timer          │
  │      /opt/surfshark-rotate/cleanup-routes.sh              │
  │      systemctl disable mihomo surfshark-rotate.timer       │
  │                                                            │
  │  之后 SSH 会立即恢复。控制台不需要密码，随时可用。         │
  └────────────────────────────────────────────────────────────┘

RECOVERY

# ==============================================================
step "2/9  准备目录"
# ==============================================================
[ -d "$BASE" ] && { c_warn "  $BASE 已存在，备份原配置到 $BASE/config.yaml.bak-$(date +%Y%m%d-%H%M%S)"; }
mkdir -p "$BASE"
[ -f "$BASE/config.yaml" ] && cp -a "$BASE/config.yaml" "$BASE/config.yaml.bak-$(date +%Y%m%d-%H%M%S)"

install -m 0755 "$SRC/rotate.py"          "$BASE/rotate.py"
install -m 0755 "$SRC/cleanup-routes.sh"  "$BASE/cleanup-routes.sh"
# 状态速查与卸载脚本也必须落到 $BASE。安装完成的提示里让用户直接跑
# status.sh，而它并不在上传目录里 —— 交付时漏装，用户照着提示执行会得到
# "No such file or directory"。实测踩过。
install -m 0755 "$SRC/status.sh"          "$BASE/status.sh"
install -m 0755 "$SRC/uninstall.sh"       "$BASE/uninstall.sh"
install -m 0755 "$SRC/measure-nodes.sh"   "$BASE/measure-nodes.sh"
c_ok "  ✓ 脚本已就位"

# ==============================================================
step "3/9  下载 mihomo 内核 $MIHOMO_VERSION"
# ==============================================================
case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    i386|i686)     ARCH=386  ;;
    *) die "不支持的 CPU 架构：$(uname -m)" ;;
esac
c_ok "  架构：$ARCH"

# 下载并验证一个新副本，不直接覆盖正在运行的二进制。
# 返回码：10=下载失败 11=解压失败 12=无法执行
download_and_verify() {
    local suffix="$1"
    local url="https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/mihomo-linux-${ARCH}${suffix}-${MIHOMO_VERSION}.gz"
    c_warn "  下载：$(basename "$url")"
    curl -fsSL --retry 3 --connect-timeout 20 -o "$BASE/mihomo.gz" "$url" || return 10
    gunzip -c "$BASE/mihomo.gz" > "$BASE/mihomo.new" || return 11
    chmod +x "$BASE/mihomo.new"
    # 必须真跑一次才算装成功：glibc 版本不符会在这里暴露。
    # 用 .new 这个新 inode 验证，不能直接写 $BASE/mihomo ——
    # 重装时旧内核进程还在执行那个文件，对它写入会 ETXTBSY（Text file busy）。
    "$BASE/mihomo.new" -v >/dev/null 2>&1 || return 12
}

if ! download_and_verify ""; then
    c_warn "  常规构建不可用（多为 glibc 版本过老），改用 compatible 构建"
    if ! download_and_verify "-compatible"; then
        rm -f "$BASE/mihomo.gz" "$BASE/mihomo.new"
        die "mihomo 安装失败。
  · 下载不通 → 检查出网能力 / GitHub 可达性
  · 下载通了但跑不起来 → 多半是 glibc 过老，可指定 MIHOMO_VERSION 换一个更旧的内核版本"
    fi
fi

# 原子替换：rename(2) 不打开目标文件，因此旧内核仍在运行也能覆盖成功。
# 旧进程继续跑着旧 inode，到第 6 步 systemctl restart 才切到新内核，全程无中断。
mv -f "$BASE/mihomo.new" "$BASE/mihomo"
rm -f "$BASE/mihomo.gz"
c_ok "  ✓ mihomo $("$BASE/mihomo" -v 2>&1 | head -1)"

# ==============================================================
step "4/9  生成配置（密钥 + SSH 保护地址）"
# ==============================================================
# 复用已有配置里的密钥。重装时如果换新密钥，而内核尚未重启，
# 就会出现「磁盘上的配置」与「内存中运行的内核」不一致：
# rotate.py 从文件读到新密钥，内核却还在用旧密钥认证 → 每轮都 401。
# 重装不应该让一个正在正常工作的实例失效。
OLD_SECRET=""
if [ -f "$BASE/config.yaml" ]; then
    OLD_SECRET="$(sed -n 's/^[[:space:]]*secret:[[:space:]]*"\{0,1\}\([^"#]*\)"\{0,1\}[[:space:]]*$/\1/p' \
                  "$BASE/config.yaml" | head -1)"
    # 首次安装失败时 config.yaml 里可能还留着未替换的占位符，
    # 那种值不能当作已有密钥复用，否则会把占位符当密钥写回去。
    case "$OLD_SECRET" in
        *@*) OLD_SECRET="" ;;
    esac
fi
if [ -n "$OLD_SECRET" ]; then
    SECRET="$OLD_SECRET"
    c_ok "  ✓ 复用已有密钥（重装不改变已部署实例的认证）"
else
    SECRET="$("$PY3" -c 'import secrets; print(secrets.token_urlsafe(32))')"
    c_ok "  ✓ 已生成随机密钥"
fi

# ---- WireGuard 私钥 ----
# 私钥是 Surfshark 账号的真实凭据，4 个节点共用同一个，绝不能进版本库。
# 因此 config.yaml 里只有 @@WG_PRIVATE_KEY@@ 占位符，由这里注入。
# 取值优先级：
#   1) 环境变量 SURFSHARK_WG_KEY
#   2) 与本脚本同目录的 surfshark.key（单行，已在 .gitignore 中）
#   3) 复用已部署实例 $BASE/config.yaml 里的现有私钥（重装时保持一致）
WG_KEY=""
if [ -n "${SURFSHARK_WG_KEY:-}" ]; then
    WG_KEY="$SURFSHARK_WG_KEY"
    c_ok "  ✓ WireGuard 私钥来自环境变量 SURFSHARK_WG_KEY"
elif [ -f "$SRC/surfshark.key" ]; then
    WG_KEY="$(tr -d '[:space:]' < "$SRC/surfshark.key")"
    c_ok "  ✓ WireGuard 私钥来自 surfshark.key"
else
    OLD_WG=""
    if [ -f "$BASE/config.yaml" ]; then
        OLD_WG="$(sed -n 's/^[[:space:]]*private-key:[[:space:]]*"\{0,1\}\([^"#]*\)"\{0,1\}[[:space:]]*$/\1/p' \
                   "$BASE/config.yaml" | head -1)"
        case "$OLD_WG" in
            *@*|'') OLD_WG="" ;;
        esac
    fi
    if [ -n "$OLD_WG" ]; then
        WG_KEY="$OLD_WG"
        c_ok "  ✓ 复用已部署实例的 WireGuard 私钥（重装不改变已部署配置）"
    else
        die "缺少 WireGuard 私钥。
  私钥不存放在本仓库里（config.yaml 只有 @@WG_PRIVATE_KEY@@ 占位符）。请提供其一：
    · 把私钥写进 $SRC/surfshark.key（单行，已在 .gitignore 中）
    · 或设置环境变量 SURFSHARK_WG_KEY=<私钥>
  私钥可在 Surfshark 官网手动 WireGuard 配置里获取，形如 base64 的 44 字符。
  注意：这台机器若已装过本方案，私钥应已存在于 $BASE/config.yaml，此时会自动复用。"
    fi
fi

case "$WG_KEY" in
    *' '*|*'	'*) die "WireGuard 私钥里混入了空白字符，请确认 surfshark.key 只有一行且无空格" ;;
esac
# surfshark.key 存在但内容为空是很常见的踩法（touch 完忘了填），
# tr 之后 WG_KEY 会是空串。不挡住的话会装出一个私钥为空的废配置，
# 表现为隧道连不上、轮换每次都降档，排查起来毫无头绪。
[ -n "$WG_KEY" ] || die "WireGuard 私钥为空。
  surfshark.key 存在但没有内容，或 SURFSHARK_WG_KEY 设置成了空值。
  请写入形如 XXXX= 的 44 字符 base64 私钥，或删掉 surfshark.key 后重新提供。"

# 一次探测产出两样东西：SSH 保护地址列表（stdout）和本机应使用的 MTU（临时文件）。
# 关键：SSH 连的如果是公网 IP 而内核里是私有 IP（NAT 场景很常见），
# 只排除本机地址是不够的，必须把公网出口 IP 也算进去。
# 另外 route-exclude-address 只接受 CIDR，裸 IP 会被内核拒绝，必须补 /32。
MTU_FILE="$(mktemp)"
EXCLUDE_BLOCK="$("$PY3" - "$MTU_FILE" <<'PY'
import ipaddress, pathlib, re, subprocess, sys
mtu_out = pathlib.Path(sys.argv[1])
ips, notes = set(), []

def add(v):
    """只收 IPv4，排除 loopback。私有地址必须收 —— NAT 场景下 SSH 连的是公网 IP，
    而内核里只有私有地址，两者都要在列表里才保得住连接。"""
    try:
        a = ipaddress.IPv4Address(v)
    except ValueError:
        return
    # 198.18.0.0/15 是 mihomo 的 TUN 默认段（含 fake-ip 段），
    # 那是代理自己的地址，不是这台机器的。
    if a.is_loopback or a in ipaddress.ip_network("198.18.0.0/15"):
        return
    ips.add(str(a))

def run(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    except Exception as e:
        notes.append(f"{' '.join(cmd)} -> {type(e).__name__}")
        return ""

for line in run("ip", "-4", "-o", "addr", "show", "scope", "global").splitlines():
    parts = line.split()
    # 跳过 mihomo 自己的 TUN 网卡。重装时内核已在运行，会把它虚拟网卡的地址
    # （默认 198.18.0.1）当成"本机地址"收进 SSH 保护列表 —— 那是代理自己，
    # 不是这台机器，把自己的地址排除出自己属于自指，且每重装一次就多一条。
    if len(parts) > 1 and parts[1].lower() in ("mihomo", "clash", "tun0", "utun0"):
        continue
    if "inet" in parts:
        add(parts[parts.index("inet") + 1].split("/")[0])

# 不能用 `ip route get 1.1.1.1` 取源地址：TUN 启用后这条查询会返回
# `via 198.18.0.2 dev Mihomo src 198.18.0.1`，即 TUN 自己的地址。
# 真实在用的是主表默认路由上的 src，重装（内核已在跑）时只有它是对的。
m = re.search(r"\bsrc (\S+)", run("ip", "-4", "route", "show", "default"))
if m:
    add(m.group(1))

pub = run("curl", "-fsS", "--max-time", "8", "https://api.ipify.org").strip()
if pub:
    add(pub)
else:
    notes.append("公网出口 IP 探测失败（可能还没出网）")

# ---- 当前活跃 SSH 会话的对端 ----
#
# 【为什么必须加进排除列表】server 回给 client 的包，目的端口是 client 的
# 随机临时端口，不是 22。所以 rules 里那条 DST-PORT,22,DIRECT 只在**出站方向**
# 成立；回包方向靠的是「同一条连接已被判定为 DIRECT」这一连接跟踪结果，
# 而不是规则本身。也就是说它并不是独立于内核进程的第二道保险：
# mihomo 一旦停掉或崩了，内核里残留的 TUN 路由仍在，SSH 回包会被吞掉。
#
# 写进 route-exclude-address 之后，内核在路由阶段就绕开 TUN，
# 完全不经过 mihomo 的任何代码 —— 与本机地址、元数据网段享受同等级的保证。
# 本方案的设计原则是「宁可装失败，也不能把自己锁在服务器外面」，
# 而 SSH 恰恰是最不能出问题的那条连接。
#
# 注意 ss 的列序会随过滤器而变：
#   ss -tn                                   → State Recv-Q Send-Q Local Peer  （对端 = 第 5 列）
#   ss -tn state established '( sport = :22 )' →       Recv-Q Send-Q Local Peer  （对端 = 第 4 列）
# 带 state 过滤器时 ss 会省掉 State 列。用无过滤器的列序去取对端会拿到本机地址，
# 等于什么都没加 —— 这里两种写法都实测过，按带过滤器的 4 列来取。
for line in run("ss", "-tn", "state", "established", "( sport = :22 )").splitlines()[1:]:
    parts = line.split()
    if len(parts) >= 4:
        add(parts[3].rsplit(":", 1)[0])

# 云厂商元数据地址：被 TUN 劫持会导致取不到实例凭据
CIDRS = [
    "169.254.0.0/16",       # AWS / GCP / Azure
    "100.100.100.200/32",   # 阿里云
    "192.0.0.192/32",       # Oracle Cloud
]

# ---- MTU ----
# 按本机实际网卡 MTU 推算，不能写死。写死的值换个机器就可能超网卡 MTU：
#   外层包 = 内层 MTU + WireGuard 开销(60) 必须 <= 网卡 MTU
# 各云厂商网卡 MTU 差异很大（1500 / 1460 / 1400 都有），所以必须现场测。
WG_OVERHEAD = 60          # IPv4(20) + UDP(8) + WireGuard 数据头(32)

def nic_mtu():
    """返回 (网卡 MTU, 说明文字)"""
    m = re.search(r"\bdefault via \S+ dev (\S+)", run("ip", "-4", "route", "show", "default"))
    if m:
        dev = m.group(1)
        mm = re.search(r"\bmtu (\d+)", run("ip", "link", "show", "dev", dev))
        if mm:
            return int(mm.group(1)), f"网卡 {dev}"
    # 兜底：取所有接口里最小的 MTU，宁可保守也不能超
    vals = [int(x) for x in re.findall(r"\bmtu (\d+)", run("ip", "link", "show"))]
    if vals:
        return min(vals), "多网卡取最小值"
    return 1500, "未探测到，按 1500 估算"

NIC_MTU, NIC_DESC = nic_mtu()
MTU = max(1280, min(NIC_MTU - WG_OVERHEAD, 1500))   # 下限 1280 保 IPv6 可用，上限 1500

out = [f"    - {ip}/32" for ip in sorted(ips)]
out += [f"    - {c}" for c in CIDRS]
print("\n".join(out))
mtu_out.write_text(f"{MTU}\n{NIC_DESC}\n{WG_OVERHEAD}\n", encoding="utf-8")
for n in notes:
    print(f"# {n}", file=sys.stderr)
PY
)"

MTU="$(sed -n 1p "$MTU_FILE")"
MTU_DESC="$(sed -n 2p "$MTU_FILE")"
# WG_OVERHEAD 只定义在上面的 Python 里，shell 侧没有这个变量。
# 直接在 shell 里写 $WG_OVERHEAD 会被 set -u 当成未绑定变量而中止脚本 ——
# 实测踩过：全新安装时死在这一行，config 已写好但后续步骤全没执行。
WG_OVERHEAD="$(sed -n 3p "$MTU_FILE")"
rm -f "$MTU_FILE"
[ -n "$MTU" ] || die "未能探测出本机 MTU，拒绝安装。诊断：ip link show"

if [ -z "$EXCLUDE_BLOCK" ]; then
    die "没能收集到任何本机地址，拒绝安装。
  装上去会威胁 SSH 连通性。诊断命令：ip -4 -o addr show scope global"
fi

"$PY3" - "$SRC/config.yaml" "$BASE/config.yaml" "$SECRET" "$EXCLUDE_BLOCK" "$WG_KEY" "$MTU" <<'PY'
import re, sys, pathlib
src, dst, secret, exclude, wg_key, mtu = sys.argv[1:7]
text = pathlib.Path(src).read_text(encoding="utf-8")
text = (text.replace("@@SECRET@@", secret)
            .replace("@@ROUTE_EXCLUDE@@", exclude)
            .replace("@@WG_PRIVATE_KEY@@", wg_key)
            .replace("@@MTU@@", mtu))
# 兜底：配置里不允许残留任何 @@ 占位符序列，也不允许私钥为空串。
# 装上一个带 @@ 的废配置，表现为隧道连不上、每轮轮换都降档，排查起来毫无头绪。
leftover = re.findall(r"@@[A-Z_]+@@", text)
if leftover:
    sys.exit(f"占位符 {sorted(set(leftover))} 未能替换，拒绝安装")
if 'private-key: ""' in text:
    sys.exit("WireGuard 私钥为空，拒绝安装")
pathlib.Path(dst).write_text(text, encoding="utf-8")
PY

# config.yaml 里含 WireGuard 私钥，只允许 root 读。
# mihomo 以 root 运行，读 600 不受影响；rotate.py 也是 root 调用。
chmod 600 "$BASE/config.yaml"

# 先用内核自己的语法检查过一遍，再落盘生效
"$BASE/mihomo" -t -d "$BASE" -f "$BASE/config.yaml" >/dev/null 2>&1 \
    || die "配置语法检查未通过，详见：$BASE/mihomo -t -d $BASE -f $BASE/config.yaml"

sed 's/^/  /' <<< "$EXCLUDE_BLOCK"
c_ok "  ✓ MTU 自动推算：$MTU（${MTU_DESC} − WireGuard 开销 $WG_OVERHEAD，上限 1500 下限 1280）"
c_ok "  ✓ 配置已生成并通过语法检查（密钥为随机生成，不落日志）"

# ==============================================================
step "5/9  安装 systemd 单元"
# ==============================================================
install -m 0644 "$SRC/mihomo.service"              /etc/systemd/system/mihomo.service
install -m 0644 "$SRC/surfshark-rotate.service"    /etc/systemd/system/surfshark-rotate.service
install -m 0644 "$SRC/surfshark-rotate.timer"      /etc/systemd/system/surfshark-rotate.timer
install -m 0644 "$SRC/README.md"                   "$BASE/README.md" 2>/dev/null || true

systemctl daemon-reload
systemctl enable mihomo.service >/dev/null
c_ok "  ✓ 单元已安装并设为开机自启"

# ==============================================================
step "6/9  启动 mihomo"
# ==============================================================
# 此刻起整机流量开始经过 TUN。SSH 保护依赖上一步填入的 route-exclude-address。
systemctl restart mihomo.service

# 首次启动会下载 MMDB 地理数据库（约 30 秒，实测本机 27.8 秒），
# 这期间进程是 running 但控制接口还没起来。
# 所以这里不能用「睡几秒再判断」的写法，必须循环等 API，
# 同时在循环里盯着服务有没有真的失败。
API_OK=0
for i in $(seq 1 90); do
    if ! systemctl is-active --quiet mihomo.service; then
        c_err "  mihomo 启动失败，日志："
        journalctl -u mihomo.service -n 30 --no-pager || true
        systemctl stop mihomo.service || true
        "$BASE/cleanup-routes.sh" || true
        die "已自动停止并清理路由，SSH 不受影响。诊断：journalctl -u mihomo -n 50"
    fi
    if curl -fsS --max-time 3 -H "Authorization: Bearer $SECRET" \
            http://127.0.0.1:9097/version >/dev/null 2>&1; then
        API_OK=1
        [ "$i" -gt 3 ] && c_warn "  （首次启动需下载 MMDB，等待 ${i}s）"
        break
    fi
    sleep 1
done

if [ "$API_OK" -ne 1 ]; then
    c_err "  控制接口 9097 在 90 秒内没有响应"
    journalctl -u mihomo.service -n 40 --no-pager || true
    systemctl stop mihomo.service || true
    "$BASE/cleanup-routes.sh" || true
    die "已自动停止并清理路由，SSH 不受影响"
fi
c_ok "  ✓ mihomo 运行中，控制接口正常"

# ==============================================================
step "7/9  验证隧道与分流"
# ==============================================================
# 出口 IP 必须能取到；取不到说明 WireGuard 隧道没建起来
# （最常见原因是商家限制了出站 UDP 51820）
PROXY_IP=""
for _ in $(seq 1 10); do
    PROXY_IP="$(curl -fsS --max-time 20 \
        --proxy socks5h://127.0.0.1:7897 https://ip.sb/ip 2>/dev/null | tr -d '[:space:]' || true)"
    [ -n "$PROXY_IP" ] && break
    sleep 2
done

if [ -z "$PROXY_IP" ]; then
    c_err "  ✗ 取不到代理出口 IP —— 隧道没有建起来"
    c_err "    最可能原因：VPS 商家限制或封锁了出站 UDP 51820。"
    c_err "    验证方法：nc -vzu jp-tok.prod.surfshark.com 51820"
    journalctl -u mihomo.service -n 30 --no-pager || true
    die "隧道不通，未启动轮换定时器。mihomo 保持运行但不会换 IP。"
fi
c_ok "  ✓ 代理出口 IP：$PROXY_IP"

DIRECT_IP="$(curl -fsS --max-time 15 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || echo '(取不到)')"
c_ok "  直连出口 IP：$DIRECT_IP"
if [ "$DIRECT_IP" = "$PROXY_IP" ]; then
    c_warn "  ⚠ 直连与代理出口 IP 相同，代理通路可能整体失效"
fi

# ---- 真正验证「opencode.ai 命中域名规则并走了代理」----
#
# 只对比直连出口与代理出口是否不同，是不够的：那只证明了代理通路本身可用。
# 即使 opencode.ai 100% 直连，那一步也会打印「✓ 分流生效」——
# 本项目最核心的目的（opencode.ai 走代理，IP 轮换才有意义）一次都没被验证过。
# 这正是「分流静默失效却一路绿灯装完」的原因。
#
# 改为发起真实请求的同时轮询 /connections，看是否存在
#   host 以 opencode.ai 结尾、且 chains 含 PROXY/FAST 的条目。
# /connections 是瞬时快照，单次查询极易错过，因此用「后台请求 + 短轮询」。
IPS="$(getent ahostsv4 opencode.ai 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
HIT=""
for _try in $(seq 1 8); do
    curl -fs --max-time 10 -o /dev/null https://opencode.ai/ >/dev/null 2>&1 &
    _cpid=$!
    for _ in $(seq 1 25); do
        HIT="$("$PY3" - "$SECRET" "$IPS" <<'PY'
import json, sys, urllib.request
sec, ips = sys.argv[1], set(sys.argv[2].split())
req = urllib.request.Request("http://127.0.0.1:9097/connections",
                             headers={"Authorization": "Bearer " + sec})
try:
    data = json.load(urllib.request.urlopen(req, timeout=3))
except Exception:
    sys.exit(0)
for c in data.get("connections") or []:
    md = c.get("metadata") or {}
    host, dip = md.get("host") or "", md.get("destinationIP") or ""
    chains = c.get("chains") or []
    if host.endswith("opencode.ai"):
        print("PROXY" if any(x in ("PROXY", "FAST") for x in chains) else "DIRECT")
        break
    # host 为空且目标 IP 属于 opencode.ai = 以纯 IP 建连且规则没命中（被绕过）
    if not host and dip in ips:
        print("BYPASS")
        break
PY
)"
        [ -n "$HIT" ] && break
        sleep 0.1
    done
    # curl 失败是正常的（站点可能返回非 2xx），与本检查无关。
    # 不加 || true 的话 set -e 会在 curl 非 0 退出时直接中止整个安装。
    wait "$_cpid" 2>/dev/null || true
    [ -n "$HIT" ] && break
done

case "$HIT" in
    PROXY)
        c_ok "  ✓ 分流生效：opencode.ai 已命中域名规则并走代理"
        ;;
    DIRECT|BYPASS)
        die "opencode.ai 未走代理（判定=$HIT），域名规则没有生效。
  典型原因：应用解析绕开了 mihomo（DNS 缓存命中 / 自带 DoH、DoT /
  系统解析器落在 route-exclude-address 的排除网段内），内核内存里没有
  该域名的 IP->域名映射，纯 IP 建连直接落到 MATCH,DIRECT 静默直连。
  确认 config.yaml 的 sniffer 段已启用，且 parse-pure-ip: true。
  已启动的 mihomo 仍可手工修好：改完 config.yaml 后 systemctl restart mihomo"
        ;;
    *)
        die "未能观测到 opencode.ai 的连接，无法确认分流是否生效。
  排查：curl -v --max-time 15 https://opencode.ai/ 看是否连通；
        journalctl -u mihomo -n 50 --no-pager | grep -i opencode"
        ;;
esac

# ---- 能力校验：纯 IP 建连能不能命中域名规则 ----
#
# 上面的运行时检查证明的是「此刻 opencode.ai 走的是代理」，但它证明不了
# 「纯 IP 建连也能命中域名规则」。这两件事不等价，实测过：
# 把 sniffer 关掉后重跑同一个检查，它照样返回 PROXY ——
# 因为它自己那条 curl 会做一次正常 DNS 解析，该查询经 dns-hijack 进了
# mihomo，重新建立了 IP->域名映射，于是规则又命中了。
# 也就是说「sniffer 根本没生效」这个故障可以完全躲过运行时检查。
#
# 所以这里再补一个确定性的能力校验：直接检查刚生成、且已通过 mihomo -t
# 语法检查的 config.yaml 里 sniffer 段是否真的开着。config.yaml 是本脚本
# 从同目录的 config.yaml 生成的，不存在「用户手改了一份另一套」的可能。
SNIFF="$("$PY3" - "$BASE/config.yaml" <<'PY'
import re, sys, pathlib
t = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
m = re.search(r'(?ms)^sniffer:[ \t]*\n((?:[ \t]+.*\n|[ \t]*\n)*)', t)
if not m:
    print("NO_SNIFFER"); raise SystemExit
blk = m.group(1)
def flag(name):
    r = re.search(r'(?m)^[ \t]+' + name + r':[ \t]*(\S+)', blk)
    return r.group(1).strip('"\'') if r else None
print("OK" if flag("enable") == "true" and flag("parse-pure-ip") == "true" else "WEAK")
PY
)"
if [ "$SNIFF" = "OK" ]; then
    c_ok "  ✓ 域名嗅探能力已启用（纯 IP 建连也能命中 DOMAIN 规则）"
else
    die "config.yaml 的 sniffer 段未正确启用（判定=$SNIFF）。
  enhanced-mode: redir-host 下，纯 IP 建连只能靠 sniffer 从 SNI/Host 还原域名，
  否则 DOMAIN 规则静默失效、流量落到 MATCH,DIRECT —— 表现为「代理不报错但没走代理」，
  而 IP 轮换只对走 PROXY 的流量有意义，那样等于空转。
  诊断：grep -n -A14 '^sniffer:' $BASE/config.yaml"
fi

# ==============================================================
step "8/9  验证轮换器能通过 API 认证"
# ==============================================================
# 这一步专门抓「内核起来了，但轮换脚本连不上」这类问题。
# 实测踩过：install.sh 替换了 config.yaml 里的密钥占位符，
# rotate.py 里那份却没被替换，于是每轮轮换都收 401，
# 还被误判成内核故障而反复重启一个完全健康的核心。
# 放在启用定时器之前，避免把「每 5 分钟失败一次」留在机器上。
VERIFY_OUT="$("$PY3" "$BASE/rotate.py" --dry-run 2>&1 || true)"
printf '%s\n' "$VERIFY_OUT" | sed 's/^/  /'
if printf '%s\n' "$VERIFY_OUT" | grep -q '轮换开始'; then
    c_ok "  ✓ 轮换器认证正常"
else
    die "轮换器无法通过 API 认证，原因见上方输出。
  常见原因：config.yaml 的 secret 与内核实际加载的值不一致。"
fi

# ==============================================================
step "9/9  启用轮换定时器"
# ==============================================================
systemctl enable --now surfshark-rotate.timer >/dev/null
c_ok "  ✓ 定时器已启用，每 5 分钟一轮"

printf '\n'
systemctl --no-pager --lines=0 status surfshark-rotate.timer 2>/dev/null | sed 's/^/  /' || true
printf '\n'

cat <<DONE

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   装好了。下一轮轮换：$("$PY3" -c "
import datetime
print((datetime.datetime.now()+datetime.timedelta(minutes=5)).strftime('%H:%M:%S'))") 左右
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  常用命令：
    $BASE/status.sh                       查看节点 / 出口 IP / 定时器状态
    journalctl -u surfshark-rotate.timer -n 20     看最近几轮轮换日志
    journalctl -u mihomo -f                       跟踪内核日志
    systemctl status mihomo                       内核状态
    systemctl restart mihomo                      手动重启内核（会短暂断流）
    $BASE/rotate.py --status                      手动看状态
    $BASE/rotate.py                               手动轮换一次

  卸载：
    sudo bash $BASE/uninstall.sh            保留配置
    sudo bash $BASE/uninstall.sh --purge    连 $BASE 一起删（配置备份到 /root/）

  应急恢复（如果 SSH 突然连不上）：
    systemctl stop mihomo surfshark-rotate.timer
    /opt/surfshark-rotate/cleanup-routes.sh

  ⚠ 防火墙：如果你开了 ufw / firewalld 且默认 DROP，需要放行出站 UDP：
      ufw allow out 51820/udp
    否则隧道会在防火墙层被静默丢弃。

DONE