import pathlib
p = pathlib.Path("rotate.py")
t = p.read_bytes().decode("utf-8")
old = '''    ap.add_argument("--recheck-tried", action="store_true",'''
new = '''    ap.add_argument("--report-429", nargs="?", const="", metavar="IP",
                    help="上报一次 429：拉黑该 IP（缺省用当前出口）并立即轮换。"
                         "供客户端/包装脚本调用，是「遇到 429 就换」闭环的入口。")
    ap.add_argument("--recheck-tried", action="store_true",'''
assert old in t
t = t.replace(old, new, 1)

old2 = '''      if args.hook_worst_case:'''
new2 = '''      if args.report_429 is not None:
          # 与定时器互斥：两者可能同时触发，撞在一起会写出撕裂的状态。
          with open(ROTATE_LOCK, "w") as lf:
              fcntl.flock(lf, fcntl.LOCK_EX)
              try:
                  st = load_state()
                  ip = args.report_429 or st.get("last_ip") or exit_ip()
                  if not ip:
                      log("上报 429 但取不到当前出口 IP —— 无法拉黑，也不轮换")
                      return 3
                  log(f"收到 429 上报，出口 IP = {ip}")
                  if is_blacklisted(st, ip):
                      log(f"    {ip} 已在黑名单里（未重复记录）")
                  else:
                      blacklist_add(st, ip, "客户端上报 429")
                  # 立刻落盘再轮换：即使轮换失败，拉黑这件事也必须留住，
                  # 否则下一次轮换又会抽回同一个脏 IP。
                  update_state({"blacklist": prune_blacklist(st.get("blacklist"))})
              finally:
                  fcntl.flock(lf, fcntl.LOCK_UN)
          log("立即轮换")
          return 0 if rotate_once(dry_run=args.dry_run) else 1

      if args.hook_worst_case:'''
assert old2 in t
t = t.replace(old2, new2, 1)
p.write_bytes(t.encode("utf-8"))
print("  --report-429 已加")
