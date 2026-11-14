"""诊断（管理员运行）：在空闲 slab 的指定行范围搜索 JPEG 头。

用法: python tools/search_jpeg.py [起始行=1019] [行数=5]
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import RawDevice  # noqa: E402
from ssrecover import BLOCK  # noqa: E402

CH = 0x40000
DISK_DEV = {1: "2", 2: "6", 127: "7", 191: "4", 192: "9", 193: "5", 194: "3", 195: "8"}


class Tee:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, s):
        self.f.write(s)
        self.stdout.write(s)

    def flush(self):
        self.f.flush()
        self.stdout.flush()


def main() -> int:
    sys.stdout = Tee(str(ROOT / "tools" / "out" / "search_jpeg.log"))
    freed = {int(k): v for k, v in json.load(
        open(ROOT / "tools" / "out" / "freed_slabs.json", encoding="utf-8")).items()}
    print("扫描所有空闲 slab 的全部行首 4KB，搜索文件头")
    t0 = time.time()
    PATS = [b"\xff\xd8\xff\xe1\x45\x78\x69\x66",   # Exif 起始
            b"\xff\xd8\xff\xe0\x00\x10\x4a",        # JFIF 起始
            b"\xff\xd8\xff\xdb"]                    # 裸量化表起始

    pstart = 0x8100000
    hits = []
    scanned = 0
    for did, slabs in sorted(freed.items()):
        if did not in DISK_DEV:
            print(f"盘{did}: 无设备映射")
            continue
        try:
            dev = RawDevice(f"\\\\.\\PhysicalDrive{DISK_DEV[did]}")
        except OSError as e:
            print(f"盘{did}: 设备失败 {e}")
            continue
        try:
            found_in_disk = 0
            for phys in slabs:
                base = pstart + (phys + 2) * BLOCK
                try:
                    data = dev.read(base, 1024 * 4096)   # 1024 行 × 行首 4KB（连续段拼接，4KB 对齐）
                except OSError as e:
                    print(f"盘{did}@{phys}: 读取失败 {e}")
                    continue
                scanned += 1
                for k in range(1024):
                    head = data[k * 4096:(k + 1) * 4096]
                    for pi, pat in enumerate(PATS):
                        j = head.find(pat)
                        if j == 0:
                            hits.append((did, phys, k, pi))
                            found_in_disk += 1
                            break
            print(f"盘{did}（{len(slabs)} slab）: {found_in_disk} 处")
        finally:
            dev.close()
    print(f"\n命中 {len(hits)}（用时 {time.time()-t0:.0f}s）:")
    for did, phys, row, j in hits[:30]:
        print(f"  盘{did} 物理块{phys} 行{row} 块内偏移 {j:#x}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BaseException:
        import traceback
        tb = traceback.format_exc()
        (ROOT / "tools" / "out" / "search_jpeg_crash.txt").write_text(tb, encoding="utf-8")
        sys.exit(2)
