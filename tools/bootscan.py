"""引导扇区窗口搜索（管理员运行）：确定 slab 数据区基址公式。只读。

对 R:/F: 引导扇区所在的组，在每块列盘的 [phys×256MB, +1.3GB] 窗口内
按 8MB 块流式搜索引导扇区字节（ref[:512]），命中即反推 base。
产出 tools/out/bootscan.json + bootscan.log
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import RawDevice  # noqa: E402
from ssrecover import spaceport  # noqa: E402

BLOCK = 0x10000000
CHUNK = 0x40000


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


def load_all():
    blob = (ROOT / "tools" / "out" / "meta_head.bin").read_bytes()
    frag = blob[0x1200:]

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

    groups = defaultdict(dict)
    id_to_uuid = {}
    for i in range(8, 23973):
        s = frag[(i - 8) * 0x40:(i - 8) * 0x40 + 0x40]
        if s[0:4] != b"SDBB" or not int.from_bytes(s[8:12], "big"):
            continue
        p = s[16:0x40]
        if p[0] == 4:
            r = parse_t4(p)
            if r:
                E, seq, disk, phys = r
                groups[E][seq] = (disk, phys)
        elif p[0] == 2:
            try:
                id_to_uuid[p[9]] = p[13:29]
            except Exception:
                pass
    return groups, id_to_uuid


def scan_window(dev, start, length, pattern, report_every=256 * 1024 * 1024):
    """流式搜索 pattern，返回命中绝对偏移列表。"""
    hits = []
    CH = 8 * 1024 * 1024
    off = start
    end = start + length
    carry = b""
    while off < end:
        n = min(CH, end - off)
        try:
            buf = dev.read(off, n)
        except OSError as e:
            print(f"  读取失败 @+{off:#x}: {e}")
            break
        hay = carry + buf
        base = off - len(carry)
        pos = 0
        while True:
            i = hay.find(pattern, pos)
            if i < 0:
                break
            hits.append(base + i)
            pos = i + 1
        carry = hay[-(len(pattern) - 1):] if len(pattern) > 1 else b""
        off += n
        if off - start >= report_every and (off - start) % report_every < CH:
            print(f"  …{((off - start) // (1024*1024))}MB", flush=True)
    return hits


def main() -> int:
    sys.stdout = Tee(str(ROOT / "tools" / "out" / "bootscan.log"))
    groups, id_to_uuid = load_all()
    print(f"组 {len(groups)}, 磁盘 {len(id_to_uuid)}")

    uuid_to_dev = {}
    for idx in range(64):
        path = f"\\\\.\\PhysicalDrive{idx}"
        try:
            dev = RawDevice(path)
        except OSError:
            continue
        try:
            hit = False
            for e in spaceport.parse_gpt(dev):
                if dev.read(e.offset, 8) == b"SPACEDB ":
                    uuid_to_dev[dev.read(e.offset + 0x30, 16)] = dev
                    hit = True
                    break
            if not hit:
                dev.close()
        except OSError:
            dev.close()

    disk_dev = {did: uuid_to_dev[u] for did, u in id_to_uuid.items() if u in uuid_to_dev}
    print("id→设备:", {k: v.device_path[-1] for k, v in disk_dev.items()})

    vd_dev = None
    for idx in range(64):
        path = f"\\\\.\\PhysicalDrive{idx}"
        if any(d.device_path == path for d in uuid_to_dev.values()):
            continue
        try:
            dev = RawDevice(path)
        except OSError:
            continue
        try:
            entries = spaceport.parse_gpt(dev)
            if any(abs(e.offset - 2987148705792) < 8192 for e in entries):
                vd_dev = dev
                print(f"虚拟盘 = {path}")
                break
            dev.close()
        except OSError:
            dev.close()
    if vd_dev is None:
        print("!! 无虚拟盘")
        return 1

    tests = [
        {"name": "R:引导", "vd_off": 2987148705792},
        {"name": "F:引导", "vd_off": 135266304},
    ]
    results = []
    for t in tests:
        vd_off = t["vd_off"]
        E = vd_off // BLOCK
        while E not in groups:
            E -= 1
        g = groups[E]
        row = (vd_off - E * BLOCK) // (4 * CHUNK)
        inrow = (vd_off - E * BLOCK) % (4 * CHUNK)
        ref = vd_dev.read(vd_off, 4096)
        pat = ref[:512]
        print(f"\n== {t['name']} 组 {E} 行 {row} 行内偏移 {inrow:#x} ==")
        print(f"  模式: {pat[:32].hex()}…")
        hits_all = {}
        for seq, (disk_id, phys) in sorted(g.items()):
            dev = disk_dev.get(disk_id)
            if dev is None:
                print(f"  列{seq} 盘{disk_id}: 设备缺失")
                continue
            start = phys * BLOCK
            length = BLOCK + 1024 * 1024 * 1024  # 256MB + 1GB 窗口
            print(f"  列{seq} 盘{disk_id}(PD{dev.device_path[-1]}) 搜索 [{start:#x}, +{length:#x})")
            hits = scan_window(dev, start, length, pat)
            print(f"    命中 {len(hits)} 个")
            for h in hits[:8]:
                # base = hit - phys*BLOCK - row*CHUNK
                b = h - phys * BLOCK - row * CHUNK
                print(f"    @+{h:#x} → base={b:#x} (={b//(1024*1024)}MB)")
            hits_all[seq] = hits
        results.append({"name": t["name"], "E": E, "row": row, "hits": {str(k): [hex(x) for x in v[:8]] for k, v in hits_all.items()}})

    (ROOT / "tools" / "out" / "bootscan.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    print("[+] 完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
