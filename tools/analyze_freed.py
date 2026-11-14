"""空闲 slab 集合分析（本地，基于 meta_head.bin）。

对每块盘：按 rec_no 顺序走存活记录，phys 递增；空槽 = 已释放分配。
输出每盘的空闲 phys 集合与"纪元"（连续段）分布。
"""
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8")

BLOB = (ROOT / "tools" / "out" / "meta_head.bin").read_bytes()
FRAG = BLOB[0x1200:]
N = 23973


def parse_t4(p):
    try:
        if p[0] != 4:
            return None
        off = 1

        def tlv(expect=None):
            nonlocal off
            ln = p[off]
            if expect is not None and ln != expect:
                raise ValueError()
            val = p[off + 1:off + 1 + ln]
            off += 1 + ln
            return int.from_bytes(val, "big") if ln else 0

        tlv(6); tlv(0); tlv(2); tlv(0); tlv(0); tlv(1); tlv(1)
        E = tlv(); seq = tlv(); tlv(); tlv(4); disk = tlv(1); phys = tlv()
        return E, seq, disk, phys
    except Exception:
        return None


def main():
    per_disk = defaultdict(list)   # disk -> [(rec_no, phys)]
    empty = []
    for i in range(8, N):
        s = FRAG[(i - 8) * 0x40:(i - 8) * 0x40 + 0x40]
        if s[0:4] != b"SDBB":
            continue
        en = int.from_bytes(s[8:12], "big")
        if not en:
            empty.append(i)
            continue
        p = s[16:0x40]
        if p[0] != 4:
            continue
        r = parse_t4(p)
        if r and r[2] >= 0 and r[3] >= 0:
            per_disk[r[2]].append((i, r[0], r[3]))

    print(f"空槽（已释放分配）: {len(empty)} 个, rec 范围 {empty[0]}..{empty[-1]}")
    # 每盘数据区容量：分区大小 / 256MB − 2（元数据块）
    CAP = int(499972571136 / (256 * 1024 * 1024)) - 2   # ≈1860
    freed = {}
    for d in sorted(per_disk):
        lst = sorted(per_disk[d])
        phys_set = {p for _, _, p in lst}
        free = sorted(set(range(0, CAP + 1)) - phys_set)
        freed[d] = free
        # 纪元 = 空闲 phys 的连续段
        runs = []
        for x in free:
            if runs and x == runs[-1][1] + 1:
                runs[-1][1] = x
            else:
                runs.append([x, x])
        big = [(a, b, b - a + 1) for a, b in runs if b - a + 1 >= 4]
        print(f"盘 {d}: 存活 {len(lst)}, phys 0..{CAP}, 空闲 {len(free)} 个, "
              f"连续段≥4: {big[:8]}")
    import json
    (ROOT / "tools" / "out" / "freed_slabs.json").write_text(
        json.dumps({str(k): v for k, v in freed.items()}), encoding="utf-8")
    print("[+] freed_slabs.json 已写")


if __name__ == "__main__":
    main()
