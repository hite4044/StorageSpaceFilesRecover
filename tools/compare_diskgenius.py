"""M3 验证：扫描结果 vs DiskGenius 报告比对（本地运行）。

用法: python tools/compare_diskgenius.py
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.stdout.reconfigure(encoding="utf-8")

scan = json.load(open(ROOT / "tools" / "out" / "r_scan.json", encoding="utf-8"))
html = (ROOT / "Test Disk(R) - 2026-11-14 10-38-21.html").read_text(encoding="utf-8", errors="replace")

# DiskGenius HTML 内嵌目录树：D.p(["目录*0*...*D", "文件*大小*...", ...])
# 数组首元素 = 目录路径，后续元素 = 该目录下的文件
entries = {}
for m in re.finditer(r'D\.p\(\[(.*?)\]\)', html):
    arr = re.findall(r'"([^"]*)"', m.group(1))
    if not arr:
        continue
    head = arr[0]
    pm = re.match(r"R:/(.*)", head)
    if not pm:
        continue
    dpath = pm.group(1).split("*")[0].replace("/", "\\")
    for f in arr[1:]:
        parts = f.split("*")
        if len(parts) < 2:
            continue
        fname = parts[0]
        try:
            size = int(parts[1])
        except ValueError:
            continue
        entries[dpath + "\\" + fname] = size

print(f"DiskGenius 条目: {len(entries)}")

ours = {}
for e in scan["entries"]:
    if not e["deleted"] or e["dir"]:
        continue
    ours[e["path"]] = {"size": e["size"], "ref": e["ref"]}

print(f"我们的已删文件: {len(ours)}")

matched = 0
size_mismatch = []
only_dg = []
only_ours = []
for path, size in entries.items():
    if path in ours:
        matched += 1
        if ours[path]["size"] != size:
            size_mismatch.append((path, size, ours[path]["size"]))
    else:
        only_dg.append((path, size))
for path in ours:
    if path not in entries:
        only_ours.append(path)

print(f"路径完全匹配: {matched}")
print(f"大小不一致: {len(size_mismatch)}")
for p, a, b in size_mismatch[:8]:
    print(f"  {p}: DG={a} ours={b}")
print(f"仅 DiskGenius 有: {len(only_dg)}")
for p, s in only_dg[:8]:
    print(f"  {p} ({s})")
print(f"仅我们有: {len(only_ours)}")
for p in only_ours[:8]:
    print(f"  {p} ({ours[p]['size']})")

# 重大事件 目录精确比对
dg_zd = {p: s for p, s in entries.items() if p.startswith("重大事件")}
our_zd = {p: v for p, v in ours.items() if p.startswith("重大事件")}
print(f"\n重大事件: DG {len(dg_zd)} 条 / 我们 {len(our_zd)} 条")
dg_ok = sum(1 for p, s in dg_zd.items() if p in our_zd and our_zd[p]["size"] == s)
print(f"重大事件 路径+大小全匹配: {dg_ok}")
