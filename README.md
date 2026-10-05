# Surfshark 出口 IP 轮换 —— VPS 版

在一台 Linux VPS 上，用 mihomo + Surfshark WireGuard 隧道做**整机分流**，并**每 5 分钟自动换一个出口 IP**。
无 GUI、systemd 托管、开机自启，适合长期挂机跑。

默认分流规则（改 `config.yaml` 即可调整）：

```
整机流量
   ├─ opencode.ai / ip.sb ──→ TUN ──→ PROXY 组 ──→ WireGuard ──→ Surfshark 节点
   │                                                    （每 5 分钟换一次出口 IP）
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
   ├─ opencode.ai / ip.sb ──→ TUN ──→ PROXY 组 ──→ WireGuard ──→ Surfshark JP/KR
   │                                                          （每 5 分钟换一次出口 IP）
   └─ 其他所有（含 SSH）───→ DIRECT ─────────────────→ 物理网卡
```

两个 systemd 单元：

| 单元 | 作用 |
|---|---|
| `mihomo.service` | 内核常驻，`Restart=always` |
| `surfshark-rotate.timer` | **那个 24 小时循环**，每 5 分钟触发一次 `surfshark-rotate.service` |

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

3. **`persistent-keepalive` 保持关闭（有意为之）** —— 本部署每 5 分钟重建一次隧道，NAT 映射的刷新频率远高于任何 UDP 空闲超时（通常 ≥30 分钟），keepalive 在这里没有实际作用，开了只是白费流量。**前提是轮换没被关掉**；如果改成手动轮换或拉长间隔，再考虑开。

4. **配置文件权限 600** —— `config.yaml` 内含 WireGuard 私钥，install.sh 会设为仅 root 可读。mihomo 和 rotate.py 都以 root 运行，不受影响。

5. **控制接口密钥** —— install.sh 随机生成，只监听 `127.0.0.1`。**不要**把 `external-controller` 改成 `0.0.0.0`。