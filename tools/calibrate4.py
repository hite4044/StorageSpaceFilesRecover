"""标定 v4（管理员运行）：整组读取 + XOR 判定校验列旋转。只读。

公式（已由 bootscan 确认）: 设备偏移 = pstart + (phys+2)×256MB + row×256KB

对 R: 组 11124 与 F: 组 0 的若干 128 行窗口：
  - 读 5 列的窗口数据（每盘 32MB）+ 虚拟盘参考数据（128MB）
  - 逐行用 XOR 找出校验列，与参考数据比对确定数据列顺序
产出 tools/out/calibration4.json + calibrate4.log
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
CHUNK = 0x40000        # 256KB
ROWV = 4 * CHUNK       # 1MB


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
    sys.stdout = Tee(str(ROOT / "tools" / "out" / "calibrate4.log"))
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

    report = {"windows": []}
    WIN = 128  # 行数
    for E, r0 in [(11124, 896), (11124, 0), (0, 0), (11128, 0), (4352, 0)]:
        if E not in groups or len(groups[E]) != 5:
            print(f"E={E}: 无映射或列数异常，跳过")
            continue
        g = groups[E]
        ref0 = E * BLOCK + r0 * ROWV
        try:
            ref = vd_dev.read(ref0, WIN * ROWV)
        except OSError as e:
            print(f"E={E}: 虚拟盘读失败 {e}")
            continue
        if not any(ref):
            print(f"E={E} 行{r0}+: 参考全 0，跳过")
            continue
        # 每盘读 WIN 行（32MB）
        colbuf = {}
        ok = True
        for seq, (disk_id, phys, _rec) in sorted(g.items()):
            dev = disk_dev.get(disk_id)
            if dev is None:
                ok = False
                break
            try:
                off = pstart + (phys + 2) * BLOCK + r0 * CHUNK
                colbuf[seq] = dev.read(off, WIN * CHUNK)
            except OSError as e:
                print(f"E={E} 列{seq}: 读失败 {e}")
                ok = False
                break
        if not ok or len(colbuf) != 5:
            continue
        # 逐行判定
        pcols = {}
        orders = {}
        mism = 0
        for r in range(WIN):
            rowchunks = {c: colbuf[c][r * CHUNK:(r + 1) * CHUNK] for c in colbuf}
            refrow = ref[r * ROWV:(r + 1) * ROWV]
            if not any(refrow):
                continue
            # 找校验列：某列 == 其余四列 XOR
            pcol = None
            for cand in range(5):
                others = [rowchunks[c] for c in range(5) if c != cand]
                acc = others[0]
                for o in others[1:]:
                    acc = xor(acc, o)
                if acc == rowchunks[cand]:
                    pcol = cand
                    break
            if pcol is None:
                mism += 1
                continue
            pcols[r0 + r] = pcol
            # 数据列顺序：ref 的 4 段匹配 4 个数据列
            dcols = [c for c in range(5) if c != pcol]
            order = []
            okm = True
            for j in range(4):
                seg = refrow[j * CHUNK:(j + 1) * CHUNK]
                m = [c for c in dcols if rowchunks[c] == seg]
                if len(m) != 1:
                    okm = False
                    break
                order.append(m[0])
            orders[r0 + r] = order if okm else None
        print(f"E={E} 行{r0}+{WIN}: 判定 {len(pcols)} 行, XOR 不一致 {mism} 行")
        pc = list(pcols.values())
        if pc:
            print(f"  pcol 序列(前20): {pc[:20]}")
            print(f"  order 序列(前5): {[orders[r0+k] for k in range(min(5, WIN))]}")
        report["windows"].append({"E": E, "r0": r0, "pcols": {str(k): v for k, v in pcols.items()},
                                  "orders": {str(k): v for k, v in orders.items()}, "mism": mism})

    (ROOT / "tools" / "out" / "calibration4.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    print("[+] 完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
