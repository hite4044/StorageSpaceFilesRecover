"""一次性调试（管理员运行）：落盘元数据头部原始字节 + IOCTL 诊断。只读。

产出 tools/out/meta_head.bin（16MB 原始字节）+ tools/out/debug_parse.json
"""
import ctypes
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import RawDevice, enumerate_physical_disks  # noqa: E402
from ssrecover import spaceport  # noqa: E402

IOCTL_GEO = 0x000700A0
IOCTL_LEN = 0x000740C4
IOCTL_LEN_ALT = 0x00074050   # 备选：CTL_CODE(7, 0x14, METHOD_BUFFERED, FILE_ANY_ACCESS)


class GEO(ctypes.Structure):
    _fields_ = [("Cylinders", ctypes.c_int64), ("MediaType", ctypes.c_uint32),
                ("TracksPerCylinder", ctypes.c_uint32), ("SectorsPerTrack", ctypes.c_uint32),
                ("BytesPerSector", ctypes.c_uint32)]


class LENINFO(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_int64)]


def ioctl_test(dev: RawDevice) -> dict:
    k32 = ctypes.windll.kernel32
    res = {}
    for name, code, struct_ in [("geometry", IOCTL_GEO, GEO), ("length", IOCTL_LEN, LENINFO),
                                ("length_alt", IOCTL_LEN_ALT, LENINFO)]:
        s = struct_()
        got = ctypes.c_ulong(0)
        ok = k32.DeviceIoControl(dev.handle, code, None, 0,
                                 ctypes.byref(s), ctypes.sizeof(s),
                                 ctypes.byref(got), None)
        err = ctypes.get_last_error()
        res[name] = {"ok": bool(ok), "err": err, "bytes_returned": got.value,
                     "value": getattr(s, "Length", None) or getattr(s, "BytesPerSector", None),
                     "full": {f: getattr(s, f) for f, _ in struct_._fields_}}
    return res


def main() -> int:
    out_dir = ROOT / "tools" / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    disk = None
    for d in enumerate_physical_disks():
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
    print(f"成员盘: {disk}")

    report = {"disk": disk}
    dev = RawDevice(disk)
    report["ioctl"] = ioctl_test(dev)
    print("IOCTL:", json.dumps(report["ioctl"], ensure_ascii=False, default=str))

    entries = spaceport.parse_gpt(dev)
    pstart = None
    for e in entries:
        if dev.read(e.offset, 8) == spaceport.SPACEDB_SIG:
            pstart = e.offset
    assert pstart
    report["pstart"] = pstart

    blob = dev.read(pstart, 16 * 1024 * 1024)
    (out_dir / "meta_head.bin").write_bytes(blob)
    report["blob_size"] = len(blob)

    # 用解析器跑一遍并输出中间统计
    m = spaceport.MemberScan(disk, 0)
    m.partition_start = pstart
    ok = m._parse_window(blob)
    report["parse"] = {
        "ok": ok, "version": m.meta_version,
        "entry_size": m.sdbc_entry_size,
        "next_entry_number": m.next_sdbb_entry_number,
        "fragments": m.fragment_count,
        "t1": len(m.records["1"]), "t2": len(m.records["2"]),
        "t3": len(m.records["3"]), "t4": len(m.records["4"]),
    }
    print("解析:", json.dumps(report["parse"], ensure_ascii=False))

    # 前 24 个槽的 hexdump
    lines = []
    for i in range(24):
        o = i * 0x40
        slot = blob[0x1200 + o:0x1200 + o + 0x40]
        lines.append(f"slot {i:5d} @+{o:#07x}: {slot.hex()}")
        lines.append(f"             hdr={slot[:0x10].hex()} payload={slot[0x10:0x40].hex()}")
    report["slots_head"] = lines
    (out_dir / "debug_parse.txt").write_text("\n".join(lines), encoding="utf-8")

    dev.close()
    (out_dir / "debug_parse.json").write_text(json.dumps(report, ensure_ascii=False, indent=1, default=str),
                                              encoding="utf-8")
    print(f"[+] 完成: {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
