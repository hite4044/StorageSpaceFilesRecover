"""标定 v6（管理员运行）：落盘窗口原始字节，分析全部本地化。只读。

对若干组各抓 32 行窗口：ref(4MB) + 5 列各 8MB → tools/out/cal_E{E}_r{r0}.bin
（单文件布局: [ref 4MB][col×5 各 8MB 依 seq 排序]）+ meta JSON。
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
ROWV = 4 * CHUNK
WIN = 32


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


def main() -> int:
    sys.stdout = Tee(str(ROOT / "tools" / "out" / "calibrate6.log"))
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

    out_dir = ROOT / "tools" / "out"
    meta = []
    # 抓取窗口：F: 数据区 + R: $MFT 区（行 0..255 内找非零）
    plans = [(4352, 0), (5000, 0), (11128, 0), (11128, 128), (11132, 0), (11124, 992)]
    for E, r0 in plans:
        if E not in groups or len(groups[E]) != 5:
            print(f"E={E}: 跳过")
            continue
        g = groups[E]
        seqs = sorted(g.keys())
        try:
            ref = vd_dev.read(E * BLOCK + r0 * ROWV, WIN * ROWV)
            buf = bytearray(ref)
            cols = {}
            for seq in seqs:
                disk_id, phys, rec = g[seq]
                dev = disk_dev[disk_id]
                d = dev.read(pstart + (phys + 2) * BLOCK + r0 * CHUNK, WIN * CHUNK)
                cols[seq] = {"disk": disk_id, "phys": phys, "rec": rec}
                buf += d
            fn = out_dir / f"cal_E{E}_r{r0}.bin"
            fn.write_bytes(bytes(buf))
            meta.append({"E": E, "r0": r0, "file": fn.name, "cols": {str(s): cols[s] for s in seqs}})
            print(f"E={E} r0={r0}: 已抓取 → {fn.name}")
        except OSError as e:
            print(f"E={E} r0={r0}: 读失败 {e}")

    (out_dir / "calibration6.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    print("[+] 完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
