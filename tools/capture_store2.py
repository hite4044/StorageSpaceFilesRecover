"""采集空间级 store（+512MB）与全区特征扫描（管理员运行）。只读。

产出 tools/out/：
  store2_head.bin   (+512MB 起 8MB 原始字节)
  pool_tail.bin     (+16MB 起 8MB —— 池 store 数组之后的未知区)
  scan_1g.json      (0..1GB 内 SDBB/SDBC/SPACEDB/type4 特征偏移报告)
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import RawDevice  # noqa: E402
from ssrecover import spaceport  # noqa: E402


def find_all(blob: bytes, pat: bytes, limit: int = 100000):
    out = []
    start = 0
    while len(out) < limit:
        i = blob.find(pat, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def main() -> int:
    out_dir = ROOT / "tools" / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    disk = None
    pstart = None
    for idx in range(64):
        path = f"\\\\.\\PhysicalDrive{idx}"
        try:
            dev = RawDevice(path)
        except OSError:
            continue
        try:
            for e in spaceport.parse_gpt(dev):
                if dev.read(e.offset, 8) == spaceport.SPACEDB_SIG:
                    disk, pstart = path, e.offset
                    break
        finally:
            dev.close()
        if disk:
            break
    if not disk:
        print("未找到成员盘")
        return 1
    print(f"成员盘 {disk} 分区起点 {pstart:#x}")

    dev = RawDevice(disk)
    report = {"disk": disk, "pstart": pstart}

    # 1) 空间级 store 头部（+512MB 起 8MB）
    store2 = dev.read(pstart + 0x20000000, 8 * 1024 * 1024)
    (out_dir / "store2_head.bin").write_bytes(store2)
    print("store2_head.bin 已写 (8MB)")

    # 2) 池 store 数组之后的未知区（+16MB 起 8MB）
    tail = dev.read(pstart + 0x1000000, 8 * 1024 * 1024)
    (out_dir / "pool_tail.bin").write_bytes(tail)
    print("pool_tail.bin 已写 (8MB)")

    # 3) 全区特征扫描 0..1GB（4MB 一块，内存受限）
    sig_sdbb = []
    sig_sdbc = []
    sig_spacedb = []
    t4_hits = 0
    t4_outside = []
    pat_cd = re.compile(rb'\x04\x06')
    CHUNK = 4 * 1024 * 1024
    total = 1024 * 1024 * 1024
    off = 0
    while off < total:
        n = min(CHUNK, total - off)
        try:
            buf = dev.read(pstart + off, n)
        except OSError as e:
            print(f"读取失败 @+{off:#x}: {e}")
            break
        for m in re.finditer(rb'SDBB', buf):
            sig_sdbb.append(off + m.start())
        for m in re.finditer(rb'SDBC    ', buf):
            sig_sdbc.append(off + m.start())
        for m in re.finditer(rb'SPACEDB ', buf):
            sig_spacedb.append(off + m.start())
        # type4 特征：04 06 + 第8字节00 + 第9字节02
        for m in pat_cd.finditer(buf):
            s = m.start()
            if s + 12 <= len(buf) and buf[s + 8] == 0 and buf[s + 9] == 2:
                t4_hits += 1
                abs_off = off + s
                if not (0x1200 <= abs_off < 0x17A000):
                    if len(t4_outside) < 4096:
                        t4_outside.append(abs_off)
        off += n
        print(f"  扫描 {off//(1024*1024)}MB…", end="\r")
    print()
    report["sdbb_offsets_count"] = len(sig_sdbb)
    report["sdbb_ranges"] = _ranges(sig_sdbb)
    report["sdbc_offsets"] = [hex(pstart + o) for o in sig_sdbc[:64]]
    report["spacedb_offsets"] = [hex(pstart + o) for o in sig_spacedb[:64]]
    report["t4_pattern_hits"] = t4_hits
    report["t4_outside_count"] = len(t4_outside)
    report["t4_outside_first"] = [hex(pstart + o) for o in t4_outside[:64]]
    print(f"SDBB 出现 {len(sig_sdbb)} 次; SDBC {len(sig_sdbc)}; SPACEDB {len(sig_spacedb)}; "
          f"type4特征 {t4_hits} (数组外 {len(t4_outside)})")
    for r in report["sdbb_ranges"]:
        print(f"  SDBB 区: {hex(pstart + r[0])} .. {hex(pstart + r[1])} ({r[1]-r[0]} 字节)")
    (out_dir / "scan_1g.json").write_text(
        __import__("json").dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[+] 报告: {out_dir/'scan_1g.json'}")
    return 0


def _ranges(offs, gap=0x100):
    if not offs:
        return []
    rs = []
    s = p = offs[0]
    for o in offs[1:]:
        if o - p > gap:
            rs.append((s, p + 4))
            s = o
        p = o
    rs.append((s, p + 4))
    return rs


if __name__ == "__main__":
    sys.exit(main())
