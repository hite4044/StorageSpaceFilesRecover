"""标定 v3（管理员运行）：用 R:/F: 引导扇区（必非零）确定 K 公式与校验列旋转。只读。

产出 tools/out/calibration3.json + calibrate3.log
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


def load_groups():
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
    for i in range(8, 23973):
        s = frag[(i - 8) * 0x40:(i - 8) * 0x40 + 0x40]
        if s[0:4] != b"SDBB" or not int.from_bytes(s[8:12], "big"):
            continue
        p = s[16:0x40]
        if p[0] != 4:
            continue
        r = parse_t4(p)
        if r:
            E, seq, disk, phys = r
            groups[E][seq] = (disk, phys)
    return groups


def load_id_to_uuid():
    blob = (ROOT / "tools" / "out" / "meta_head.bin").read_bytes()
    frag = blob[0x1200:]
    m = {}
    for i in range(8, 23973):
        s = frag[(i - 8) * 0x40:(i - 8) * 0x40 + 0x40]
        if s[0:4] != b"SDBB" or not int.from_bytes(s[8:12], "big"):
            continue
        p = s[16:0x40]
        if p[0] != 2:
            continue
        m[p[9]] = p[13:29]  # 修正：uuid 在 p[13:29]
    return m


def main() -> int:
    sys.stdout = Tee(str(ROOT / "tools" / "out" / "calibrate3.log"))
    out_dir = ROOT / "tools" / "out"
    groups = load_groups()
    id_to_uuid = load_id_to_uuid()
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
                    du = dev.read(e.offset + 0x30, 16)
                    uuid_to_dev[du] = dev
                    print(f"成员盘 {path} uuid={du.hex()[:12]}")
                    hit = True
                    break
            if not hit:
                dev.close()
        except OSError:
            dev.close()

    disk_dev = {}
    for did, u in id_to_uuid.items():
        d = uuid_to_dev.get(u)
        if d:
            disk_dev[did] = d
    print("id→设备:", {k: v.device_path[-1] for k, v in disk_dev.items()})

    # 虚拟盘
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
        print("!! 未找到虚拟盘")
        return 1

    tests = [
        {"name": "R:引导扇区", "vd_off": 2987148705792, "group_hint": 11124},
        {"name": "F:引导扇区", "vd_off": 135266304, "group_hint": 0},
        {"name": "R:+16MB", "vd_off": 2987148705792 + 0x1000000, "group_hint": 11128},
    ]
    results = []
    for t in tests:
        vd_off = t["vd_off"]
        E = vd_off // BLOCK
        if E not in groups:
            # 向下取最近的组
            cand = [e for e in groups if e <= E]
            E = max(cand) if cand else None
        if E is None or E not in groups:
            print(f"{t['name']}: 无映射组覆盖 vd_off={vd_off:#x}")
            continue
        g = groups[E]
        if len(g) != 5:
            print(f"{t['name']}: 组 {E} 列数 {len(g)}")
            continue
        row = (vd_off - E * BLOCK) // (4 * CHUNK)
        inrow = (vd_off - E * BLOCK) % (4 * CHUNK)
        try:
            ref = vd_dev.read(vd_off, 4 * CHUNK)
        except OSError as e:
            print(f"{t['name']}: 虚拟盘读失败 {e}")
            continue
        if not any(ref):
            print(f"{t['name']}: 参考数据全 0")
            continue
        print(f"{t['name']}: 组 {E} 行 {row} 行内偏移 {inrow:#x} ref {len(ref)}B")
        found = None
        for K in range(0, 12):
            chunks = {}
            okread = True
            for seq, (disk_id, phys) in g.items():
                dev = disk_dev.get(disk_id)
                if dev is None:
                    okread = False
                    break
                try:
                    chunks[seq] = dev.read((phys + K) * BLOCK + row * CHUNK, CHUNK)
                except OSError:
                    okread = False
                    break
            if not okread or len(chunks) != 5:
                continue
            # ref 的 4 段（可能跨列边界：inrow 偏移在行内）
            segs = []
            pos = inrow
            for j in range(4):
                take = min(CHUNK - (pos % CHUNK) if pos % CHUNK else CHUNK, 4 * CHUNK - len(segs) and 0 or 0)
                # 简化：直接按 256KB 对齐比较——inrow 一般为 0（引导扇区在行首）
                pos += CHUNK
            # 仅当 inrow % CHUNK == 0 时做段匹配
            if inrow % CHUNK != 0:
                print(f"  行内偏移 {inrow:#x} 非 256KB 对齐，跳过段匹配（改用整体搜索）")
                # 在各列 chunk 中搜索 ref 开头 4096 字节
                head = ref[:4096]
                locs = {c: ch.find(head) for c, ch in chunks.items()}
                print(f"  各列搜索 ref[:4096]: { {c: hex(o) if o >= 0 else -1 for c, o in locs.items()} }")
                if any(o >= 0 for o in locs.values()):
                    found = {"K": K, "locs": {str(c): o for c, o in locs.items()}}
                    break
                continue
            segmap = {}
            ok = True
            for j in range(4):
                ref_seg = ref[j * CHUNK:(j + 1) * CHUNK]
                cands = [c for c, ch in chunks.items() if ch == ref_seg]
                if len(cands) != 1:
                    ok = False
                    break
                segmap[j] = cands[0]
            if ok:
                cols = sorted(segmap.values())
                pcols = [c for c in range(5) if c not in cols]
                if len(pcols) == 1:
                    print(f"  ✓ K={K} 该行校验列={pcols[0]} 数据列顺序(虚拟序)={[segmap[j] for j in range(4)]}")
                    found = {"K": K, "pcol": pcols[0], "data_order": [segmap[j] for j in range(4)]}
                    break
        results.append({"name": t["name"], "vd_off": vd_off, "E": E, "row": row, "hit": found})
        if found and results and sum(1 for r in results if r["hit"]) >= 2:
            break

    (out_dir / "calibration3.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    print("[+] 完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
