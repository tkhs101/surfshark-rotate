import pathlib
p = pathlib.Path("rotate.py"); t = p.read_bytes().decode("utf-8")
old = 'NODES = ["JP 日本-东京", "KR 韩国-首尔", "TW 台湾-台北", "SG 新加坡"]'
new = ('NODES = [\n'
       '    "JP 日本-东京", "KR 韩国-首尔", "TW 台湾-台北", "SG 新加坡",\n'
       '    # 2026-10-09 加入的近邻节点：实测延迟与原四节点同档（3.0-3.5s），\n'
       '    # 各自的出口 IP 池与原池不重叠 —— 而 12h 不重复的余量本来就靠\n'
       '    # 「池子并集」撑着，加节点是提升余量最直接的手段。\n'
       '    #\n'
       '    # mo-mfm（澳门）**测过但没加**：mihomo 报 alive=True，实际出口取不到，\n'
       '    # 且切过去会让整个 PROXY 组卡在 dial 10.14.0.2 —— 所有节点共用同一个\n'
       '    # 虚拟地址，一个坏节点能拖垮全组。这正是「alive 不等于能用」。\n'
       '    "KH 柬埔寨-金边", "HK 香港", "PH 菲律宾-马尼拉", "VN 越南-胡志明",\n'
       ']')
assert old in t
p.write_bytes(t.replace(old, new, 1).encode("utf-8"))
print("  NODES 已扩到 8 个")
