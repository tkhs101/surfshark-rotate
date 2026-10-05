#!/bin/sh
# mihomo 异常崩溃（SIGKILL / OOM）时，auto-route 写下的策略路由规则会残留。
# 后果是整机流量仍然指向一个已经不存在的 TUN 设备 —— 表现为 SSH 突然不通。
#
# systemd 的 ExecStopPost 会在每次停止后调用本脚本兜底。
# mihomo 正常退出时自己会清理，本脚本会发现无事可做并立即退出。
#
# 只删除「lookup 指向 mihomo 默认表 2022」的规则，不按 pref 范围盲删，
# 避免误伤这台机器上其它可能存在的策略路由。

TABLE="${MIHOMO_TABLE:-2022}"

# ip rule del 在规则不存在时返回非零，这里循环直到删干净
while ip rule del lookup "$TABLE" 2>/dev/null; do :; done
while ip -6 rule del lookup "$TABLE" 2>/dev/null; do :; done

# 丢弃该表里可能残留的路由
ip route flush table "$TABLE" 2>/dev/null
ip -6 route flush table "$TABLE" 2>/dev/null

exit 0