"""问题盘诊断（管理员运行）：PD3/5/8 打开/GPT/SPACEDB 逐步检查。只读。"""
import ctypes
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import RawDevice  # noqa: E402
from ssrecover import spaceport  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")


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


sys.stdout = Tee(str(ROOT / "tools" / "out" / "debug_disks.log"))

for idx in [2, 3, 4, 5, 6, 7, 8, 9]:
    path = f"\\\\.\\PhysicalDrive{idx}"
    print(f"== {path} ==")
    try:
        dev = RawDevice(path)
    except OSError as e:
        print(f"  打开失败: {e}")
        continue
    try:
        print(f"  打开 OK, sector={dev.sector_size}, size={dev.size}")
        try:
            hdr = dev.read(512, 512)
            print(f"  LBA1 头 8B: {hdr[:8].hex()}")
        except OSError as e:
            print(f"  LBA1 读取失败: {e}")
            continue
        entries = spaceport.parse_gpt(dev)
        print(f"  GPT 分区 {len(entries)} 个")
        found = False
        for e in entries:
            try:
                head = dev.read(e.offset, 8)
                mark = " ← SPACEDB" if head == b"SPACEDB " else ""
                if head == b"SPACEDB ":
                    found = True
                print(f"    分区{e.index} @{e.offset:#x} size={e.size} type={e.type_guid} 名={e.name!r}{mark}")
            except OSError as ex:
                print(f"    分区{e.index} @{e.offset:#x} 读取失败: {ex}")
        if not found:
            # 兜底：全盘前 2GB 内搜索 SPACEDB 签名（粗扫 8MB 粒度）
            print("  分区内未找到 SPACEDB，粗扫 0..1GB…")
            hit = None
            CH = 8 * 1024 * 1024
            off = 0
            while off < 1024 * 1024 * 1024:
                try:
                    buf = dev.read(off, CH)
                except OSError as ex:
                    print(f"    粗扫读取失败 @+{off:#x}: {ex}")
                    break
                i = buf.find(b"SPACEDB ")
                if i >= 0:
                    hit = off + i
                    break
                off += CH
            print(f"    SPACEDB 粗扫命中: {hex(hit) if hit else '无'}")
    finally:
        dev.close()
