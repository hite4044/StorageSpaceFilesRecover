"""M4b 试点（管理员运行）：已解分配组定位 + 单文件恢复。

流程（单文件、单组）：
 1. 目标文件的簇 → (组E, 组内行)。
 2. 尾锚点：JPEG 的 FFD9 在尾簇内的偏移可由文件大小精确算出，
    在候选 slab 中搜索该偏移处的 FFD9 → 定位一个列。
 3. 其余 4 列：Y/Z 两侧 XOR 相交（chunk0⊕c1⊕c2⊕c3⊕c4=0，跨全部行）。
 4. 多行 XOR-0 验证 → 按数据列序重组导出到 D:\\Recovery_R。

用法: python tools/recover_freed.py [MFT引用号]
"""
import itertools
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.engine import RecoveryEngine  # noqa: E402
from ssrecover.rawdisk import RawDevice, is_admin  # noqa: E402
from ssrecover import layout, BLOCK  # noqa: E402

CH = 0x40000
ROWV = 4 * CH
PSTART = 0x8100000
DISK_DEV = {1: "2", 2: "6", 127: "7", 191: "4", 192: "9", 193: "5", 194: "3", 195: "8"}


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


def xornp(a: bytes, b: bytes) -> bytes:
    return (np.frombuffer(a, dtype=np.uint64) ^ np.frombuffer(b, dtype=np.uint64)).tobytes()


def main() -> int:
    sys.stdout = Tee(str(ROOT / "tools" / "out" / "recover_freed.log"))
    if not is_admin():
        print("!! 需要管理员")
        return 1
    t0 = time.time()

    mft_want = None
    for a in sys.argv[1:]:
        if a.isdigit():
            mft_want = int(a)

    engine = RecoveryEngine(error_sink=lambda rec: None)
    print("== 扫描池 ==")
    pool = engine.scan_local_pool()
    vd = next(v for v in pool.virtual_disks if v.windows_vd_number is not None)
    target = next(p for p in engine.partitions if p.drive_letter == "R")
    vol = engine.open_volume(vd, target)
    entries, stats = engine.scan_filesystem()

    mapped = set()
    for E in (11128, 11132, 11324, 11328, 11520, 11916):
        for k in range(4):
            mapped.add(E + k)

    # 选目标文件：已删、单组、未映射、JPG、2-20MB
    fe = None
    for e in entries:
        if not e.deleted or e.is_dir or e.resident_data is not None:
            continue
        if not e.runs or e.runs[0].lcn < 0:
            continue
        rows = []
        ok_single = True
        for run in e.runs:
            lcn, cl = run.lcn, run.clusters
            if lcn < 0:
                continue
            for k in range(cl):
                L = lcn + k
                row = L - 1
                E = 11128 + 4 * (row // 1024)
                if E in mapped:
                    ok_single = False
                rows.append((E, row % 1024))
        if not ok_single or not rows:
            continue
        if len({E for E, _ in rows}) != 1:
            continue
        if not (2 * 1024 * 1024 <= e.size <= 20 * 1024 * 1024):
            continue
        if not e.name.lower().endswith(".jpg"):
            continue
        if mft_want is not None and e.mft_ref != mft_want:
            continue
        fe = e
        fe_rows = rows
        break
    if fe is None:
        print("!! 无候选")
        return 1
    E = fe_rows[0][0]
    rows = sorted({r for _, r in fe_rows})
    print(f"目标: MFT{fe.mft_ref} {fe.path!r} {fe.size}B 组 {E} 行 {rows}")
    print(f"  簇: {[(r.lcn, r.clusters) for r in fe.runs]}")

    freed = {int(k): v for k, v in json.load(
        open(ROOT / "tools" / "out" / "freed_slabs.json", encoding="utf-8")).items()}
    pstart_map = {d.disk_id: d.partition_start for d in pool.disks}

    # 锚点（两试）：头锚 = 首行 chunk0 的 Exif 头；尾锚 = 末行 FFD9@精确偏移
    anchor_specs = []   # (行, seq, 块内偏移, 模式)
    r_first = rows[0]
    if fe.name.lower().endswith(".jpg"):
        anchor_specs.append((r_first, layout.data_cols_of(vd, r_first)[0], 0,
                             fe.read_bytes if False else b"\xff\xd8\xff\xe1\x45\x78\x69\x66"))
    ffd9_off = fe.size - 2
    last_row = rows[-1]
    n_clusters = len(fe_rows)
    in_c = ffd9_off - (n_clusters - 1) * ROWV
    if 0 <= in_c < ROWV:
        j = in_c // CH
        off_in_ch = in_c % CH
        dcols_last = layout.data_cols_of(vd, last_row)
        if j < len(dcols_last) and off_in_ch + 2 <= CH:
            anchor_specs.append((last_row, dcols_last[j], off_in_ch, b"\xff\xd9"))
    print(f"锚点方案: {[(r, s, hex(o)) for r, s, o, _ in anchor_specs]}")

    # 读取所有候选 slab 的行块
    print("== 读取候选块 ==")
    chunks = {}   # (disk, phys) -> {row: chunk}
    for did, slabs in sorted(freed.items()):
        if did not in DISK_DEV:
            continue
        try:
            dev = RawDevice(f"\\\\.\\PhysicalDrive{DISK_DEV[did]}")
        except OSError:
            continue
        try:
            pstart = pstart_map.get(did, PSTART)
            for phys in slabs:
                base = pstart + (phys + 2) * BLOCK + rows[0] * CH
                try:
                    data = dev.read(base, (rows[-1] - rows[0] + 1) * CH)
                except OSError:
                    continue
                d = {}
                for r in rows:
                    o = (r - rows[0]) * CH
                    d[r] = data[o:o + CH]
                chunks[(did, phys)] = d
        finally:
            dev.close()
    print(f"候选块: {len(chunks)}")

    # 锚点扫描（依次尝试各锚点方案）
    anchor = None   # (row, seq, (disk, phys))
    for row_a, seq_a, off_a, pat in anchor_specs:
        hits = []
        for key, d in chunks.items():
            b = d[row_a][off_a:off_a + len(pat)]
            if b == pat:
                hits.append(key)
        print(f"锚点方案 行{row_a} seq{seq_a} 偏移 {off_a:#x}: 命中 {[(f'盘{k[0]}@{k[1]}') for k in hits]}")
        if len(hits) == 1:
            anchor = (row_a, seq_a, hits[0])
            break
        if hits and anchor is None:
            anchor = (row_a, seq_a, hits[0])
    if anchor is None:
        print("!! 头尾锚点均未命中（对应簇可能已被复用）")
        return 1
    row_a, seq_anchor, (anchor_disk, anchor_phys) = anchor

    # 4 个未知列 = 除锚点列外的全部列
    unknown = [s for s in range(vd.ncols) if s != seq_anchor]
    h1, h2 = unknown[:2], unknown[2:]
    print(f"锚列 seq{seq_anchor}=盘{anchor_disk}@{anchor_phys}；Y 侧 {h1} / Z 侧 {h2}")

    # 锚列的块（全部行）
    anchor_data = chunks[(anchor_disk, anchor_phys)]
    cand_list = [(d, p) for (d, p) in chunks if d != anchor_disk]

    # Y 表：h1 两列的组合（盘互异、≠锚盘）；key = 各行 (锚⊕cA⊕cB) 前16B 拼接
    ytab = {}
    t1 = time.time()
    for (dA, pA), (dB, pB) in itertools.product(cand_list, cand_list):
        if dA == dB:
            continue
        ca = chunks[(dA, pA)]
        cb = chunks[(dB, pB)]
        key_parts = []
        for r in rows:
            v = xornp(anchor_data[r], xornp(ca[r], cb[r]))
            key_parts.append(v[:16])
        ytab.setdefault(b"".join(key_parts), []).append((dA, pA, dB, pB))
    print(f"Y 表: {len(ytab)} 项 ({time.time()-t1:.0f}s)")

    # Z 侧：h2 两列，key = 各行 (锚⊕cC⊕cD) 前16B 拼接，查 Y 表
    found = None
    t2 = time.time()
    tried = 0
    for (dC, pC), (dD, pD) in itertools.product(cand_list, cand_list):
        if dC == dD or dC == anchor_disk or dD == anchor_disk:
            continue
        cc = chunks[(dC, pC)]
        cd = chunks[(dD, pD)]
        key_parts = []
        for r in rows:
            v = xornp(anchor_data[r], xornp(cc[r], cd[r]))
            key_parts.append(v[:16])
        hit = ytab.get(b"".join(key_parts))
        tried += 1
        if hit:
            found = (hit[0], (dC, pC, dD, pD))
            print(f"  ✓ 命中: Y={hit[0]} Z=(盘{dC}@{pC}, 盘{dD}@{pD})")
            break
    print(f"Z 枚举 {tried} 组合 ({time.time()-t2:.0f}s)")
    if not found:
        print("!! 未找到满足 XOR-0 的 5 列组合")
        return 1
    (dA, pA, dB, pB), (dC, pC, dD, pD) = found[0], found[1]
    colmap = {seq_anchor: (anchor_disk, anchor_phys),
              h1[0]: (dA, pA), h1[1]: (dB, pB),
              h2[0]: (dC, pC), h2[1]: (dD, pD)}
    print(f"列映射: {colmap}")
    print(f"盘集合: {sorted(k[0] for k in colmap.values())}")

    # 重组文件数据
    file_data = bytearray()
    n_clusters = len(fe_rows)
    for k in range(n_clusters):
        row = rows[0] + k
        dcs = layout.data_cols_of(vd, row)
        for j, s in enumerate(dcs):
            d, p = colmap[s]
            dev = RawDevice(f"\\\\.\\PhysicalDrive{DISK_DEV[d]}")
            try:
                off = pstart_map[d] + (p + 2) * BLOCK + row * CH
                file_data += dev.read(off, CH)
            finally:
                dev.close()
    file_data = bytes(file_data[:fe.size])

    dest = Path("D:\\Recovery_R") / fe.path.replace("\\", "_")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(file_data)
    print(f"[导出] {dest} ({len(file_data)}B 头={file_data[:4].hex()} 尾={file_data[-2:].hex()})")

    (ROOT / "tools" / "out" / "recover_freed_result.json").write_text(json.dumps({
        "file": fe.path, "size": fe.size, "group": E, "rows": rows,
        "colmap": {str(k): list(v) for k, v in colmap.items()},
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[+] 用时 {time.time()-t0:.0f}s")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BaseException:
        import traceback
        tb = traceback.format_exc()
        (ROOT / "tools" / "out" / "recover_freed_crash.txt").write_text(tb, encoding="utf-8")
        print(tb, file=sys.stderr)
        sys.exit(2)
