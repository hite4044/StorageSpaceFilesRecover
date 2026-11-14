"""标定 v2（管理员运行）：数据 slab 公式 + 旋转 + journal 全量落盘。只读。

产出 tools/out/：
  calibrate2.log     全部输出（提权窗口外可见）
  calibration2.json  标定结果
  journal.bin        池 store 加密 journal 全量（+16MB..+512MB, 496MB）
"""
import io
import itertools
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import RawDevice  # noqa: E402
from ssrecover import spaceport  # noqa: E402

BLOCK = 0x10000000
ROWV = 4 * 0x40000


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
            def tlv():
                nonlocal off
                ln = p[off]
                val = p[off + 1:off + 1 + ln]
                off += 1 + ln
                return int.from_bytes(val, "big") if ln else 0
            for _ in range(7):
                tlv()
            E = tlv(); seq = tlv(); tlv(); tlv(); disk = tlv(); phys = tlv()
            return E, seq, disk, phys
        except Exception:
            return None

    groups = defaultdict(dict)
    for i in range(8, 23973):
        s = frag[(i - 8) * 0x40:(i - 8) * 0x40 + 0x40]
        if s[0:4] != b"SDBB":
            continue
        en = int.from_bytes(s[8:12], "big")
        if not en:
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
        if s[0:4] != b"SDBB":
            continue
        en = int.from_bytes(s[8:12], "big")
        if not en:
            continue
        p = s[16:0x40]
        if p[0] != 2:
            continue
        try:
            m[p[9]] = p[14:30]
        except Exception:
            pass
    return m


def main() -> int:
    log_path = ROOT / "tools" / "out" / "calibrate2.log"
    sys.stdout = Tee(log_path)
    out_dir = ROOT / "tools" / "out"
    report = {}

    groups = load_groups()
    print(f"映射组: {len(groups)}")
    id_to_uuid = load_id_to_uuid()
    print(f"type2 磁盘: {len(id_to_uuid)}")

    # 打开成员盘
    uuid_to_dev = {}
    open_devs = []
    for idx in range(64):
        path = f"\\\\.\\PhysicalDrive{idx}"
        try:
            dev = RawDevice(path)
        except OSError as e:
            continue
        try:
            found = False
            for e in spaceport.parse_gpt(dev):
                head = dev.read(e.offset, 8)
                if head == b"SPACEDB ":
                    du = dev.read(e.offset + 0x30, 16)
                    uuid_to_dev[du] = dev
                    open_devs.append(dev)
                    print(f"成员盘 {path} uuid={du.hex()[:12]}…")
                    found = True
                    break
            if not found:
                dev.close()
        except OSError as ex:
            print(f"{path}: {ex}")

    disk_dev = {}
    for did, u in id_to_uuid.items():
        d = uuid_to_dev.get(u)
        if d is not None:
            disk_dev[did] = d
    print("id→设备:", {k: v.device_path[-1] for k, v in disk_dev.items()})
    report["disk_map"] = {str(k): uuid_to_dev[u].device_path for k, u in id_to_uuid.items() if u in uuid_to_dev}

    # 找虚拟盘（含 R: 分区偏移的设备）
    vd_dev = None
    vd_path = None
    for idx in range(64):
        path = f"\\\\.\\PhysicalDrive{idx}"
        if any(d.device_path == path for d in open_devs):
            continue
        try:
            dev = RawDevice(path)
        except OSError:
            continue
        try:
            entries = spaceport.parse_gpt(dev)
            offs = [e.offset for e in entries]
            if any(abs(o - 2987148705792) < 8192 for o in offs):
                vd_dev = dev
                vd_path = path
                print(f"虚拟盘 = {path}")
                break
            dev.close()
        except OSError as ex:
            print(f"{path}: {ex}")
    report["vd"] = vd_path
    if vd_dev is None:
        print("!! 未找到虚拟盘")
        json.dump(report, open(out_dir / "calibration2.json", "w"), ensure_ascii=False, indent=1)
        return 1

    # 标定：多组测试
    tests = []
    tested = 0
    for E in sorted(groups.keys()):
        if tested >= 25:
            break
        g = groups[E]
        if len(g) != 5:
            continue
        try:
            ref = vd_dev.read(E * BLOCK, 4 * ROWV)
        except OSError as e:
            print(f"E={E}: 虚拟盘读失败 {e}")
            continue
        if not any(ref):
            continue
        tested += 1
        hit = None
        for K in range(0, 10):
            chunks = {}
            good = True
            for seq, (disk_id, phys) in g.items():
                dev = disk_dev.get(disk_id)
                if dev is None:
                    good = False
                    break
                try:
                    chunks[seq] = dev.read((phys + K) * BLOCK, 4 * 0x40000)
                except OSError:
                    good = False
                    break
            if not good or len(chunks) != 5:
                continue
            # 每行每段找唯一匹配列
            rowmaps = []
            ok = True
            for r in range(4):
                segmap = {}
                for j in range(4):
                    ref_seg = ref[r * ROWV + j * 0x40000: r * ROWV + (j + 1) * 0x40000]
                    cands = [c for c, ch in chunks.items()
                             if ch[r * 0x40000:(r + 1) * 0x40000] == ref_seg]
                    if len(cands) != 1:
                        ok = False
                        break
                    segmap[j] = cands[0]
                if not ok:
                    break
                cols = sorted(segmap.values())
                pcols = [c for c in range(5) if c not in cols]
                if len(pcols) != 1:
                    ok = False
                    break
                rowmaps.append((pcols[0], [segmap[j] for j in range(4)]))
            if ok:
                hit = {"K": K, "rows": rowmaps}
                print(f"E={E}: ✓ K={K} pcol序列={[m[0] for m in rowmaps]} 行0数据列序={rowmaps[0][1]}")
                break
        tests.append({"E": E, "ref_nonzero": True, "hit": hit})
        if hit:
            break
    report["tests"] = tests

    # journal 全量落盘 (+16MB..+512MB)
    pd2 = None
    for d in open_devs:
        if d.device_path.endswith("PhysicalDrive2"):
            pd2 = d
    if pd2 is None:
        pd2 = open_devs[0]
    jpath = out_dir / "journal.bin"
    CH = 8 * 1024 * 1024
    with open(jpath, "wb") as f:
        off = 0
        total = 496 * 1024 * 1024
        while off < total:
            n = min(CH, total - off)
            try:
                f.write(pd2.read(0x8100000 + 0x1000000 + off, n))
            except OSError as e:
                print(f"journal 读取失败 @+{off:#x}: {e}")
                break
            off += n
            if off % (64 * 1024 * 1024) == 0:
                print(f"journal 已抓 {off//(1024*1024)}MB…")
    print(f"journal.bin 已写 ({off} 字节)")

    (out_dir / "calibration2.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    print("[+] 完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
