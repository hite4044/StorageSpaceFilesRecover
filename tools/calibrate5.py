"""标定 v5（管理员运行）：小窗口 + 非零过滤 + XOR 歧义检测。只读。

产出 tools/out/calibration5.json + calibrate5.log
"""
import json
import sys
import traceback
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import RawDevice  # noqa: E402
from ssrecover import spaceport  # noqa: E402

BLOCK = 0x10000000
CHUNK = 0x40000
ROWV = 4 * CHUNK


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
                groups[E][seq] = (disk, phys, i)
        elif p[0] == 2:
            id_to_uuid[p[9]] = p[13:29]
    return groups, id_to_uuid


def xor(a: bytes, b: bytes) -> bytes:
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n]))


def main() -> int:
    sys.stdout = Tee(str(ROOT / "tools" / "out" / "calibrate5.log"))
    groups, id_to_uuid = load_all()

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
    pstart = 0x8100000
    print(f"组 {len(groups)}, 盘 {len(disk_dev)}")

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

    WIN = 32
    report = {"windows": []}
    for E, r0 in [(11128, 0), (11132, 0), (4352, 0), (5000, 0), (8000, 0), (10000, 0),
                  (2000, 0), (6000, 0), (11124, 992)]:
        try:
            if E not in groups or len(groups[E]) != 5:
                print(f"E={E}: 无映射/列数异常")
                continue
            g = groups[E]
            ref0 = E * BLOCK + r0 * ROWV
            ref = vd_dev.read(ref0, WIN * ROWV)
            colbuf = {}
            for seq, (disk_id, phys, _rec) in sorted(g.items()):
                dev = disk_dev[disk_id]
                colbuf[seq] = dev.read(pstart + (phys + 2) * BLOCK + r0 * CHUNK, WIN * CHUNK)
            pcols = {}
            orders = {}
            amb = 0
            zero = 0
            for r in range(WIN):
                rc = {c: colbuf[c][r * CHUNK:(r + 1) * CHUNK] for c in colbuf}
                refrow = ref[r * ROWV:(r + 1) * ROWV]
                segs = [refrow[j * CHUNK:(j + 1) * CHUNK] for j in range(4)]
                if not any(refrow) or not all(any(s) for s in segs):
                    zero += 1
                    continue
                cands = []
                for cand in range(5):
                    others = [rc[c] for c in range(5) if c != cand]
                    acc = others[0]
                    for o in others[1:]:
                        acc = xor(acc, o)
                    if acc == rc[cand]:
                        cands.append(cand)
                if len(cands) != 1:
                    amb += 1
                    continue
                pcol = cands[0]
                dcols = [c for c in range(5) if c != pcol]
                order = []
                okm = True
                for j in range(4):
                    m = [c for c in dcols if rc[c] == segs[j]]
                    if len(m) != 1:
                        okm = False
                        break
                    order.append(m[0])
                if not okm:
                    amb += 1
                    continue
                pcols[r0 + r] = pcol
                orders[r0 + r] = order
            print(f"E={E} r0={r0}: 判定 {len(pcols)}, 歧义 {amb}, 全零/部分零 {zero}")
            if pcols:
                items = sorted(pcols.items())
                print(f"  pcol: {[(k, v) for k, v in items[:16]]}")
                print(f"  order样例: {[orders[k] for k in sorted(orders)[:6]]}")
            report["windows"].append({"E": E, "r0": r0, "pcols": {str(k): v for k, v in pcols.items()},
                                      "orders": {str(k): v for k, v in orders.items()},
                                      "amb": amb, "zero": zero})
        except Exception:
            print(f"E={E}: 异常")
            traceback.print_exc(file=sys.stdout)
            traceback.print_exc(file=sys.stderr)

    (ROOT / "tools" / "out" / "calibration5.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    print("[+] 完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
