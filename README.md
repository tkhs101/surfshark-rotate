# Surfshark 出口 IP 轮换 —— VPS 版

在一台 Linux VPS 上，用 mihomo + Surfshark WireGuard 隧道做**整机分流**，并**每 10 分钟自动换一个出口 IP**。
无 GUI、systemd 托管、开机自启，适合长期挂机跑。

默认分流规则（改 `config.yaml` 即可调整）：

```
整机流量
   ├─ opencode.ai / ip.sb ──→ TUN ──→ PROXY 组 ──→ WireGuard ──→ Surfshark 节点
   │                                                    （每 10 分钟换一次出口 IP）
   └─ 其他所有（含 SSH）───→ DIRECT ─────────────────→ 物理网卡
```

**自包含**：私钥不进仓库、MTU 按本机网卡自动推算、节点优先级可用脚本实测生成。
换一台机器 clone 下来装一次即可，不需要手工调任何参数。

⚠️ **合规提示**：请自行确认所在地法律与 Surfshark 服务条款允许此类用途，并遵守目标网站的服务条款。

---

## 架构

```
VPS 整机流量
   │
   ├─ opencode.ai ──→ TUN ──→ AUTOFALL ──┬─（rotate.py 判定正常）→ PROXY 组 → WireGuard → Surfshark JP/KR
   │                                      │                              （每 10 分钟换一次出口 IP）
   │                                      └─（连续 2 轮探测失败）→ DIRECT ────→ 物理网卡
   ├─ ip.sb ──→ TUN ──→ PROXY ────────────┴─→ WireGuard    （测量通道，故意不进降级链）
   └─ 其他所有（含 SSH）───→ DIRECT ─────────────────────────────→ 物理网卡
```

三个 systemd 单元：

| 单元 | 作用 |
|---|---|
| `mihomo.service` | 内核常驻，`Restart=always` |
| `surfshark-rotate.timer` | **那个 24 小时循环**，每 10 分钟触发一次 `surfshark-rotate.service` |
| `surfshark-watchdog.timer` | **看门狗**，每 5 分钟一次，**只出声不修复**。有需要关注的状态就写 `.alert` 文件并在 journal 出声 |
| （降级时会临时起一个一次性单元） | 节点恢复后的复查，见[降级与恢复](#降级与恢复) |

**AUTOFALL 是降级链**：节点不可用时 `opencode.ai` 会退到直连（还能用，只是出口变回本机），
而不是直接连不上。没有它的话，私钥一过期整个项目就静默停摆。
它是一个 `select` 组，由 `rotate.py` 显式切换 —— 详见[降级与恢复](#降级与恢复)
与 [ADR 0001](docs/adr/0001-degradation-owner.md)。

---

## 前置条件

| 条件 | 说明 |
|---|---|
| systemd | 脚本基于 systemctl，非 systemd 环境不适用 |
| `/dev/net/tun` | **必须**。OpenVZ / 部分 LXC 商家不给，需要换机器 |
| 出站 UDP 51820 | 必须。部分商家限速或封 UDP，装完第 7 步会验证 |
| root | 建 TUN 设备需要 `CAP_NET_ADMIN` |
| python3 | 轮换脚本用，仅标准库，无需 pip |
| Surfshark WireGuard 私钥 | **本仓库不含私钥**，见下 |

---

## 提供私钥（必须）

`config.yaml` 里 `private-key` 是占位符 `@@WG_PRIVATE_KEY@@`——**你的 Surfshark 账号私钥不在这个仓库里**。
4 个节点共用同一个私钥，提交进 git 等于把它永久公开（删掉也留在历史记录里）。

部署前提供其一：

```bash
# 方式 A：写成文件（推荐，已在 .gitignore 中）
echo -n '<你的私钥>' > surfshark.key

# 方式 B：环境变量
export SURFSHARK_WG_KEY='<你的私钥>'
```

`install.sh` 的取值优先级：环境变量 → `surfshark.key` → 复用该机器上已部署实例 `config.yaml` 里的现有私钥。
三者都没有就直接拒绝安装，不会装出一个带 `@@` 的废配置。

私钥在 Surfshark 官网的手动 WireGuard 配置里，形如 44 字符 base64（`XXXX=`，结尾带等号）。

**装了私钥的机器上**，`/opt/surfshark-rotate/config.yaml` 权限为 `600`。

---

## 部署

```bash
# 把整个 surfshark-vps 目录传到 VPS
scp -r surfshark-vps user@your-vps:/tmp/

ssh user@your-vps
cd /tmp/surfshark-vps
sudo bash install.sh
```

`install.sh` 的 9 个步骤：环境自检 → 打印应急恢复方式 → 下载内核 → 生成配置（密钥 / SSH 保护地址 / MTU）→ 装单元 → 启动 → 验证隧道与分流 → 验证轮换器认证 → 启用定时器。

**任何一步失败都会自动停止 mihomo 并清理路由**，SSH 不受影响。

安装位置：`/opt/surfshark-rotate/`

### 装完建议做一件事

`rotate.py` 里的 `TIERS`（节点降级优先级）默认按开发时那台机器的延迟排的，**跟你的机房不一定匹配**。
实测一下并把结果贴回去：

```bash
bash /opt/surfshark-rotate/measure-nodes.sh
```

它会打印一段可直接粘贴的 `TIERS = [...]`，覆盖 `rotate.py` 里原来的那一块。
延迟差异常常很大——同区域可能 2ms，跨区域能到 80ms+，顺序错了等于长期用最差的节点。

---

## 日常运维

```bash
/opt/surfshark-rotate/status.sh                              # 状态速查（最常用）

journalctl -u surfshark-rotate.timer -n 20                  # 最近几轮轮换
journalctl -u mihomo -f                                    # 跟踪内核日志
journalctl -u mihomo -n 50 | grep -i handshake              # 看隧道握手

systemctl restart mihomo                                    # 手动重启内核（短暂断流）
/opt/surfshark-rotate/rotate.py --status                    # 手动看状态
/opt/surfshark-rotate/rotate.py                             # 手动轮换一次
/opt/surfshark-rotate/rotate.py --dry-run                   # 只演算不执行

bash /opt/surfshark-rotate/measure-nodes.sh                 # 重测节点延迟并生成 TIERS
```

轮换间隔改 `surfshark-rotate.timer` 里的 `OnUnitActiveSec=5min`，然后 `systemctl daemon-reload`。

---

## 降级与恢复

私钥到期、续费后换了新私钥、或者节点全挂时，**不要指望它报错**。没有 AUTOFALL 时
opencode.ai 会直接连不上，日志里只有一行 `dial PROXY ... context deadline exceeded`。

现在分两层处理：

### 数据面：自动退到直连（脚本层决策，内核不参与）

`AUTOFALL` 是 `select` 组，成员 `[PROXY, DIRECT]`，**由 `rotate.py` 通过
`PUT /proxies/AUTOFALL` 显式切换**：

| 状态 | `AUTOFALL` 选中 | opencode.ai |
|---|---|---|
| 节点正常 | `PROXY` | 走 Surfshark 节点，IP 正常轮换 |
| 节点全挂 | `DIRECT` | 走本机直连，**还能用**，但出口变回 VPS 自己的 IP |

**为什么不用 `fallback` 组**：mihomo 的 `fallback` 判定是单样本布尔查表 ——
`fallback.go` 的 `findAliveProxy()` 顺序遍历成员、返回第一个
`AliveForTestUrl()==true` 的，`Now()` 直接调它，中间**没有任何计数器、迟滞或冷却**。
隧道抖一下，下一条连接立刻走直连。实测 17 小时内内核自行翻转 5 次，其中一次
（01:20:25，当时无轮换在跑）让两条 opencode.ai 的连接以 `AUTOFALL[DIRECT]` 发出，
即用本机 GCP 机房 IP 出网。

对本项目而言泄漏比失败更糟 —— 失败只是断一次，泄漏是把机房 IP 送到对方面前，
而暴露机房 IP 恰恰是这个项目要避免的事。其它开关也压不住：
`max-failed-times` 只作用于 `onDialFailed`（拨号失败路径），周期健康检查不走它；
`fixed` 钉选成员仍被存活检查覆盖；`relay` 已移除；`fallback-filter` 是 DNS 字段。

`select` 组没有健康检查，**永不自行翻转**。降级需要**两个独立信号同时成立**：

1. 连续 2 轮取不到出口 `IP`（间隔 10 分钟，约 20 分钟）—— 要求故障持续至少一个完整轮换周期
2. 控制面 `/proxies/<节点>/delay` 也探测不到节点

第 2 条不可省。只看第 1 条会把「ip.sb 限流或宕机」误判成「隧道坏了」，
从而把一条**完全健康**的隧道切到直连 —— 那就成了一个新的泄漏源，而且比内核
那次瞬时翻转更糟（那个 <1 秒，这个是两整轮、期间所有连接都算）。

### 一个必须知道的失效方向

脚本是降级的**唯一**决策方，所以 rotate.py 本身坏掉时不会降级（fail-closed）。
方向上比泄漏安全，但代价是 opencode.ai 会一直连不上而不出现降级横幅。
这种情况由 `status.sh` 的 `ExecMainStatus` 标红，以及 `rotate.py --status` 暴露。

### 控制面：轮换自动停摆（脚本层）

降级时继续轮换毫无意义，所以 `rotate.py` 会：

1. 连续 2 轮取不到出口 IP，且控制面也探测不到节点
2. 把 `AUTOFALL` 切到 `DIRECT`、记下降级状态、**停掉 `surfshark-rotate.timer`**
3. 在日志里打出完整的恢复步骤

所以看到 `surfshark-rotate.timer` 是 inactive 时，**先别当成故障** —— 看 `status.sh` 顶部有没有降级横幅。

### 恢复

换新私钥（`config.yaml` 里 `private-key`，4 处共用同一个）之后：

```bash
sudo systemctl restart mihomo
```

`mihomo.service` 的 `ExecStartPost` 钩子（`on-mihomo-up.sh`）会自动复查。
判据是**控制面的 `/proxies/<节点>/delay`** —— 节点本身现在通不通，
完全不经过 `AUTOFALL` 与数据面（降级时 `AUTOFALL` 是我们**自己**设成 `DIRECT` 的，
拿它判断恢复会自证循环）。要求**连续 2 次健康**才判定恢复，与降级侧的迟滞对称：
单次侥幸成功不足以证明修好了：探测打通的只是探针站点，不是我们要保的那个出口。
探针是**多个互不相关的端点**（见 `rotate.py` 的 `NODE_HEALTH_URLS`），任一响应即视为
隧道存活 —— 这不是宽容，而是两个方向的错误代价相反：误判隧道死会泄漏（本项目头号
问题），误判隧道活只是让 opencode.ai 撞一次失败的代理，不泄漏且下一轮就纠正。
单端点曾让 `cp.cloudflare.com` 独自承担降级佐证与恢复判据：它一旦被限流，恢复侧会
永远判不健康，于是机器**不报错、不降级、只是再也不恢复**，安静地一直直连。

确认恢复后钩子把 `AUTOFALL` 切回 `PROXY`、启回定时器并清掉降级标记。
提示语由切换的真实结果决定 —— 切不回去时会明确说「可能仍在直连」并给出确认命令。

若节点此刻还没活，钩子会起一次复查（`systemd-run --on-active=90`），
**最多 6 次**（约 9 分钟）。超限后明确交给你，并说明重启即可重新计数：

```bash
sudo systemctl restart mihomo      # 重新自动复查
# 或直接
sudo systemctl start surfshark-rotate.timer
```

> 另有一条恢复路径：不重启 mihomo、手工跑一轮 `rotate.py`。钩子不在这条路径上，
> 所以 `clear_degraded()` 会主动把定时器启回来。

### 确认当前状态

```bash
sudo /opt/surfshark-rotate/status.sh      # 顶部横幅 + 分流验证
```

降级时横幅会直接写明「未走代理」和出口 IP。别看「代理出口 == 直连出口」就
去查 `rules` —— 那是降级造成的，规则本身没问题。

---

## 应急恢复

**如果 SSH 突然连不上**（极小概率，但不是零）：

用 VPS 商家控制台的 **VNC / 串口 / Web Terminal** 登录（不需要密码），然后：

```bash
systemctl stop mihomo surfshark-rotate.timer
/opt/surfshark-rotate/cleanup-routes.sh
systemctl disable mihomo surfshark-rotate.timer
```

SSH 立即恢复。

设计上有三层防御，所以这一步几乎不会用上：

1. `route-exclude-address` —— VPS 自身地址根本不进 TUN（内核层面，进程挂了也不受影响）
2. `DST-PORT,22,DIRECT` 规则 —— 第二道保险
3. `cleanup-routes.sh` 作为 `ExecStopPost` —— mihomo 被 OOM/SIGKILL 后自动清理残留策略路由

---

## 卸载

```bash
sudo bash /opt/surfshark-rotate/uninstall.sh            # 保留配置
sudo bash /opt/surfshark-rotate/uninstall.sh --purge    # 连 /opt 一起删（配置会备份到 /root/）
```

---

## 设计取舍

几个不看代码会疑惑的地方：

**TUN 栈用 `system` 而不是 `gvisor`**
Linux 有原生协议栈，官方文档明确 system 栈"更稳定、资源占用更低"。gVisor 是 Windows TUN 驱动栈下的取舍，Linux 上不必沿用。

**为什么有 `route-exclude-address` 和 `DST-PORT,22` 两条保 SSH 的规则**
TUN 接管整机流量后，配置稍有偏差就可能把自己的 SSH 一起代理进去，连接断在外面只能靠商家控制台救。
第一道防线是 `route-exclude-address`——把本机地址、公网出口 IP、云厂商元数据地址排除在 TUN 之外，
这些流量**根本不进 mihomo 进程**，即使内核崩了也不受影响。第二道是 `DST-PORT,22,DIRECT` 规则兜底。
`install.sh` 会现场探测这些地址并填入，不写死。

**轮换时不做「排空等待」也不强杀连接**
切换节点和热重载都**不会**中断已有连接（实测四种路径均存活）。所以旧连接天然就是排空语义，
不需要等，更不能超时强杀——早期版本加过这套逻辑，结果长连接往往永不自然结束，
必然等满超时后被强杀，253 次轮换里 113 次因此中断。已整段移除。

**出口 IP 探测用纯标准库 SOCKS5 而不是 curl**
精简 VPS 镜像常常没装 curl。纯标准库版本为主，curl 存在时作回退。
探测域名固定用 `ip.sb`——它必须在分流规则内，否则会被 `MATCH,DIRECT` 直连，
测出来的是本机真实 IP，看起来就像「轮换没生效」。

**systemd timer 而不是常驻 `--loop` 进程**
`Persistent=true` 让停机/休眠期间错过的触发在开机后补跑；单次执行即使卡死也不影响下一次触发；
日志走 journald，自带轮转和容量上限。

---

## 排错

### 隧道建不起来 / 出口 IP 取不到

```bash
nc -vzu jp-tok.prod.surfshark.com 51820        # 出站 UDP 是否被拦
journalctl -u mihomo -n 50 | grep -i -E 'wireguard|handshake|error'
```

最常见原因：**商家限制出站 UDP**。安装脚本第 7 步会明确报出来。

### 装了 ufw / firewalld

防火墙默认 DROP 出站时，隧道会在防火墙层被**静默**丢弃（症状和 UDP 被封一模一样）：

```bash
ufw allow out 51820/udp          # ufw
firewall-cmd --permanent --add-udp-port=51820   # firewalld
```

### IP 没换

```bash
journalctl -u surfshark-rotate.service -n 30
```

日志里会打「IP 未变化 → 降到下一档备用节点」。连续降档说明隧道重建有问题，不是脚本问题。

### 延迟比预期高

多半是 `TIERS` 没按你的机房重排。一条命令解决：

```bash
bash /opt/surfshark-rotate/measure-nodes.sh     # 打印可直接粘贴的 TIERS
```

### 大包被卡 / 周期性卡顿

MTU 由 `install.sh` 按本机网卡自动推算，正常不需要管。确认一下实际值：

```bash
ip link show Mihomo | grep mtu                  # 应等于 网卡MTU - 60
sudo grep -c 'mtu:' /opt/surfshark-rotate/config.yaml
```

TUN 和 4 个 proxy 的 `mtu` 必须同值，不一致会在其中一层卡住大包。

---

## 已知限制

### 修不了的

1. **长连接不跟着换 IP** —— 已建立的连接（包括流式响应）会留在旧 IP 上跑到自然结束。

   开发时实测（持一条真实长连接跨一次轮换）：
   ```
   轮换前（同一条连接）   82.26.195.34
     ↓ 轮换：JP -> KR，热重载重建隧道
   轮换后（同一条连接）   82.26.195.34   ← 连接存活，留在旧 IP
   轮换后（新连接）       61.97.243.108  ← 新 IP
   ```
   **轮换不会中断连接**，这是好消息；代价只是老连接不跟着换 IP。

   这是 TCP 的性质，不是配置问题：一个已建立的连接绑定在固定的四元组上，不可能在不中断它的情况下换掉源 IP。唯一"能修"的办法是在切换时主动掐断长连接让它重连——本项目早期版本正是这么做的，结果 253 次轮换里有 113 次造成中断（长连接往往永不自然结束，必然等满超时后被强杀）。**当前取舍：宁可连接留在旧 IP，也不主动掐断。**

### 已验证或已处理的

2. **MTU 自动推算** —— `install.sh` 按本机网卡 MTU 减 60（WireGuard 开销）算出，并同时写入 TUN 与 4 个 proxy。

   写死是错的：各云厂商网卡 MTU 不同（1500 / 1460 / 1400 都有），
   照抄别处的值会导致外层包超网卡 MTU 而分片，或直接黑洞。
   装完想确认：`ip link show Mihomo | grep mtu`。

3. **keepalive 实际是开着的** —— 本条曾写成「`persistent-keepalive` 保持关闭（有意为之）」，理由是「NAT 映射刷新频率高于空闲超时、开了白费流量」。**那个前提是错的**：2026-10-09 实测订阅 mihomo 的 `/logs?level=debug`，8 分钟内 `Sending keepalive packet` 14 次、`Receiving keepalive packet` 6 次，中位周期约 34~37 秒。wireguard-go 只在 `persistent_keepalive_interval > 0` 时才发，而 `config.yaml` 里没有这个键 —— 所以是 mihomo 默认开启的。旧结论整段建立在「它关着」这个假前提上，已作废。

4. **配置文件权限 600** —— `config.yaml` 内含 WireGuard 私钥，install.sh 会设为仅 root 可读。mihomo 和 rotate.py 都以 root 运行，不受影响。

5. **控制接口密钥** —— install.sh 随机生成，只监听 `127.0.0.1`。**不要**把 `external-controller` 改成 `0.0.0.0`。
### 「先测再用」（可选，默认关闭）

实测发现：节点池里约 **4.5%** 的出口 IP 已被上游按来源封禁
（Surfshark 是共享 NAT 出口，别的用户把它用坏了）。
样本 `82.26.195.42` —— 同一时刻 7 个 IP 通过、只有它返回
`429 Rate limit exceeded`，且几分钟后用完全相同的方式独立复现。

**IP 字面上看不出脏不脏**，12h 不重复的承诺也帮不上忙
（它保证的是「我们不重复用同一个 IP」，而脏 IP 是第一次遇到就已经脏了）。

所以 `rotate.py` 提供 `VERIFY_CMD`：换到候选 IP 后先跑一次探测，
非零退出就丢弃这个 IP 并继续抽下一个。预期尝试次数约 1.05 次/轮。

**默认关闭** —— 探测会消耗上游配额，这个取舍该由部署环境决定。
本项目不内置任何具体探测命令（探测哪个上游、算不算通过是环境的事）。

```bash
VERIFY_CMD='magpie provider test opencode-zen-free'   # 退出码 0 = 通过
```

探测走同一个 mixed-port（`listeners` 未启用，没有独立出口），
所以探测期间 AUTOFALL 确实短暂停在候选 IP 上 ——
但这比原行为严格更好：原行为让一个随机 IP 扛 10 分钟，探测只让它扛几秒。
