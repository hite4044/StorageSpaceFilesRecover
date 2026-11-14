"""成员盘元数据区深度探测（需管理员运行）。只读。

用法：
    python tools/dump_metadata.py [\\.\PhysicalDrive2] [扫描MB数=512]

输出 tools/out/meta_dump_<N>.json + hex 样本。用途：
 1. 定位元数据区内全部 8 字节 ASCII 签名及其分布
 2. 解析每份 SDBC 副本字段
 3. 输出关键区域 hex 样本（SPACEDB/SDBC/SDBB 头、片段区）
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import RawDevice, enumerate_physical_disks  # noqa: E402
from ssrecover import spaceport  # noqa: E402

PRINTABLE = set(range(0x41, 0x5B)) | set(range(0x30, 0x3A)) | {0x20, 0x5F, 0x2D}  # A-Z 0-9 空格 _ -


def ascii_words(buf: bytes, base: int, out: dict):
    n = len(buf)
    i = 0
    # 按 8 对齐扫描
    start = (8 - base % 8) % 8
    for i in range(start, n - 8, 8):
        w = buf[i:i + 8]
        if all(c in PRINTABLE for c in w):
            key = w.decode("ascii")
            lst = out.setdefault(key, [])
            if len(lst) < 4096:
                lst.append(base + i)


def hexdump(buf: bytes, base: int, width: int = 16) -> str:
    lines = []
    for off in range(0, len(buf), width):
        chunk = buf[off:off + width]
        hx = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:010X}  {hx:<{width*3}}  {asc}")
    return "\n".join(lines)


def main() -> int:
    disk = sys.argv[1] if len(sys.argv) > 1 else None
    scan_mb = int(sys.argv[2]) if len(sys.argv) > 2 else 512
    if disk is None:
        disks = enumerate_physical_disks()
        # 自动找第一块成员盘
        for d in disks:
            try:
                m = spaceport.scan_member(d["path"], d["size"])
            except OSError:
                continue
            if m.pool_uuid:
                disk = d["path"]
                break
    if disk is None:
        print("未找到成员盘")
        return 1

    print(f"深度探测 {disk}，扫描 {scan_mb}MB")
    dev = RawDevice(disk)
    entries = spaceport.parse_gpt(dev)
    print("GPT 分区:", [(e.index, e.offset, e.size, e.type_guid) for e in entries])
    part = None
    for e in entries:
        if dev.read(e.offset, 8) == spaceport.SPACEDB_SIG:
            part = e
            break
    assert part is not None, "未找到 SPACEDB 分区"
    pstart = part.offset
    print(f"存储空间分区 @ {pstart:#x} 大小 {part.size}")

    report = {"disk": disk, "partition_start": pstart, "partition_size": part.size,
              "gpt": [{"i": e.index, "off": e.offset, "size": e.size, "type": e.type_guid,
                       "name": e.name} for e in entries]}

    sigs: dict = {}
    total = scan_mb * 1024 * 1024
    chunk = 4 * 1024 * 1024
    off = 0
    while off < min(total, part.size):
        n = min(chunk, part.size - off)
        try:
            buf = dev.read(pstart + off, n)
        except OSError as e:
            print(f"  读取失败 @+{off:#x}: {e}")
            break
        ascii_words(buf, pstart + off, sigs)
        off += n
        print(f"  已扫描 {off // (1024*1024)}MB…", end="\r")
    print()

    interesting = {}
    for sig, offs in sigs.items():
        if len(offs) >= 2 or sig.startswith(("SPACEDB", "SDBC", "SDBB", "SDB", "SLAB", "SPAC")):
            interesting[sig] = offs[:64]
    report["signatures"] = {k: {"count": len(sigs.get(k, [])), "offsets": v}
                            for k, v in sorted(interesting.items())}
    print("\n== 签名直方图（出现≥2次或已知前缀）==")
    for k, v in report["signatures"].items():
        print(f"  {k!r}: count={v['count']} first={v['offsets'][:8]}")

    # 每份 SDBC 副本解析
    sdbc_reps = []
    for off0 in sigs.get("SDBC    ", [])[:20]:
        d = dev.read(off0, 512)
        rep = {"offset": off0,
               "pool_uuid": d[0x10:0x20].hex().upper(),
               "entry_size": int.from_bytes(d[0x24:0x28], "big"),
               "next_entry_number": int.from_bytes(d[0x28:0x2C], "big"),
               "modified": int.from_bytes(d[0x48:0x50], "big")}
        sdbc_reps.append(rep)
        print(f"SDBC @ {off0:#x}: pool={rep['pool_uuid'][:16]}… entry_size={rep['entry_size']} "
              f"next_n={rep['next_entry_number']} modified={rep['modified']}")
    report["sdbc_copies"] = sdbc_reps

    # 关键区域 hex 样本
    samples = {}
    for name, o, ln in [
        ("spacedb_head", pstart, 0x200),
        ("sdbc_area", pstart + 0x1000, 0x200),
        ("frag_start", pstart + 0x1200, 0x800),
        ("frag_64k", pstart + 0x10000, 0x400),
        ("block1_start", pstart + 0x10000000, 0x400),
        ("block2_start", pstart + 0x20000000, 0x400),
    ]:
        try:
            samples[name] = hexdump(dev.read(o, ln), o)
        except OSError as e:
            samples[name] = f"read fail: {e}"
    report["hex_samples"] = samples

    # 每个 SPACEDB 副本的位置
    spacedb_offs = sigs.get("SPACEDB ", [])[:32]
    report["spacedb_copies"] = spacedb_offs
    print("SPACEDB 副本偏移:", [hex(o) for o in spacedb_offs])

    # 片段槽分布统计（从 +0x1200 起每 0x40 一槽，扫 2MB）
    frag_scan = dev.read(pstart + 0x1200, 2 * 1024 * 1024)
    nonempty = 0
    max_nonempty_off = 0
    gaps = []
    run_empty = 0
    for i in range(len(frag_scan) // 0x40):
        slot = frag_scan[i * 0x40:(i + 1) * 0x40]
        if slot[0x0E:0x10] == b"\x00\x00":
            run_empty += 1
        else:
            nonempty += 1
            max_nonempty_off = i * 0x40
            if run_empty >= 8:
                gaps.append((i * 0x40, run_empty))
            run_empty = 0
    report["frag_scan"] = {"slots_scanned": len(frag_scan) // 0x40,
                           "nonempty": nonempty,
                           "max_nonempty_offset": max_nonempty_off,
                           "gaps_8plus": gaps[:64]}
    print(f"片段槽: 扫描 {len(frag_scan)//0x40} 槽, 非空 {nonempty}, 最远非空 @+{max_nonempty_off:#x}, "
          f"≥8空隙 {len(gaps[:64])} 处")

    out_dir = ROOT / "tools" / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    outp = out_dir / ("meta_dump_%s.json" % disk.split("Drive")[-1])
    outp.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n[+] 报告写入 {outp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
