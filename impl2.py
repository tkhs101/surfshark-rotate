import pathlib
p = pathlib.Path("rotate.py")
t = p.read_bytes().decode("utf-8")
old = '''    seen = recent_ips(state)
    redraws = 0'''
new = '''    seen = recent_ips(state)
    redraws = 0
    # 【先测再用】VERIFY_CMD 非空时，换到候选 IP 后先探测；
    # 探测不过就拒绝这个 IP 并继续抽下一个 —— 而不是把它当成本轮结果。
    # 实测池里约 4.5% 的 IP 已被上游封禁，而**我们无法从 IP 字面看出脏不脏**。
    rejected = []'''
assert old in t
t = t.replace(old, new, 1)

# 在「重摇后取不到出口 IP」之后、循环条件之前插入探测
old2 = '''          target, new_ip = nxt, exit_ip()
          if not new_ip:
              log("    重摇后取不到出口 IP，保留本轮结果")
              break'''
new2 = '''          target, new_ip = nxt, exit_ip()
          if not new_ip:
              log("    重摇后取不到出口 IP，保留本轮结果")
              break
          if VERIFY_CMD:
              vok, note = probe_ip(new_ip)
              if not vok:
                  rejected.append(new_ip)
                  log(f"    探测未通过：{new_ip} —— 丢弃，换一个（{note}）")
                  if redraws >= VERIFY_MAX_TRY:
                      log(f"    已试 {redraws} 个候选仍全被拒 —— "
                          f"本轮**不认**新 IP，保持当前节点")
                      break
                  continue'''
assert old2 in t
t = t.replace(old2, new2, 1)

# 循环条件里加上「没有候选被拒」
old3 = '''      while new_ip in seen and redraws < MAX_REDRAW:'''
new3 = '''      while (new_ip in seen or (VERIFY_CMD and new_ip in rejected)) \
              and redraws < MAX_REDRAW:'''
assert old3 in t
t = t.replace(old3, new3, 1)
p.write_bytes(t.encode("utf-8"))
print("  重摇循环已接入探测")
