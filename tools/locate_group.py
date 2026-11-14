"""M4b（管理员运行）：已解分配 slab 定位器 — 单文件试点（完整实现）。

原理：
 1. MFT 给出目标文件的簇（LCN）→ 组 E、组内行号（1MB 簇 = 1 行）。
 2. 每盘空闲 slab 集合 = 已删数据可能位置（freed_slabs.json）。
 3. 锚点：文件首簇行块 = 文件字节 0..256KB（JPEG FFD8FF / MP4 ftyp 可识别）
    → 在所有 (盘, 空闲slab) 的行块中搜索 → 锚定数据列 0。
 4. 其余 4 列（3 数据 + 1 校验）2+2 XOR 相交：chunk0⊕c_a⊕c_b⊕c_c⊕c_d = 0。
 5. 多行 XOR-0 验证 + 尾簇零填充校验 → 导出该文件全部行。

用法: python tools/locate_group.py [MFT引用号] [--export]
"""
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
    sys.stdout = Tee(str(ROOT / "tools" / "out" / "locate.log"))
    out_dir = ROOT / "tools" / "out"
    if not is_admin():
        print("!! 需要管理员")
        return 1
    t0 = time.time()
    do_export = "--export" in sys.argv
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
    print(f"已删文件 {stats.deleted_files}")

    mapped = set()
    for E in (11128, 11132, 11324, 11328, 11520, 11916):
        for k in range(4):
            mapped.add(E + k)

    def rows_of(e):
        """返回 {组E: [组内行号...]}，仅未映射部分。"""
        out = {}
        for run in e.runs:
            lcn, cl = run.lcn, run.clusters
            if lcn < 0:
                continue
            for k in range(cl):
                L = lcn + k
                row = L - 1  # LCN≥1；LCN0 = boot 区（无文件数据）
                if row < 0:
                    continue
                E = 11128 + 4 * (row // 1024)
                if E in mapped:
                    continue
                out.setdefault(E, []).append(row % 1024)
        return out

    cand = []
    for e in entries:
        if not e.deleted or e.is_dir or e.resident_data is not None:
            continue
        g = rows_of(e)
        if not g:
            continue
        if 2 * 1024 * 1024 <= e.size <= 20 * 1024 * 1024 and e.name.lower().endswith(".jpg"):
            cand.append((e, g))
    cand.sort(key=lambda x: x[0].size)
    if mft_want is not None:
        cand = [x for x in cand if x[0].mft_ref == mft_want] or cand
    if not cand:
        print("!! 无候选文件")
        return 1
    fe, rows_by_group = cand[0]
    print(f"目标: MFT{fe.mft_ref} {fe.path!r} {fe.size}B")
    print(f"  簇: {[(r.lcn, r.clusters) for r in fe.runs]}")
    print(f"  未映射组: {[(E, len(v)) for E, v in sorted(rows_by_group.items())]}")

    freed = {int(k): v for k, v in json.load(
        open(out_dir / "freed_slabs.json", encoding="utf-8")).items()}
    pstart_map = {d.disk_id: d.partition_start for d in pool.disks}
    print(f"空闲 slab: { {d: len(v) for d, v in sorted(freed.items())} }")

    E = sorted(rows_by_group.keys())[0]
    rows = sorted(set(rows_by_group[E]))
    r0 = rows[0]
    ncols = vd.ncols
    pcol0 = layout.parity_col_of(vd, r0)[0]
    dcols0 = layout.data_cols_of(vd, r0)
    print(f"组 {E} 行 {rows}（首行 {r0}）: pcol=seq{pcol0} 数据列序={dcols0}")
    # 未知列 = 除数据列 0（锚点列 dcols0[0]）外的 4 列
    unknown_seqs = [s for s in dcols0[1:]] + [pcol0]
    print(f"未知列（按数据序+校验）: {unknown_seqs}")

    # 读所有 (盘, 空闲slab) 的行 r0 块
    print("== 读取候选行块 ==")
    chunks = {}
    for did, slabs in sorted(freed.items()):
        pstart = pstart_map.get(did)
        if pstart is None:
            continue
        dev = None
        for d in pool.disks:
            if d.disk_id == did and d.device_path:
                dev = RawDevice(d.device_path)
                break
        if dev is None:
            continue
        try:
            for phys in slabs:
                off = pstart + (phys + 2) * BLOCK + r0 * CH
                try:
                    chunks[(did, phys)] = dev.read(off, CH)
                except OSError:
                    pass
        finally:
            dev.close()
    print(f"候选块: {len(chunks)}")

    # 锚点：JPEG 头
    magic = b"\xff\xd8\xff\xe0" if fe.name.lower().endswith(".jpg") else None
    if magic is None:
        magic = b"\xff\xd8\xff"
    anchor = None
    for key, ch in chunks.items():
        if ch[:len(magic)] == magic:
            anchor = key
            break
    if anchor is None:
        print("!! 未找到锚点")
        return 1
    print(f"锚点（数据列0 = seq{unknown_seqs[0]}）: 盘{anchor[0]}@物理块{anchor[1]}")

    # 2+2 XOR 相交（4 未知列分两组各 2 列；盘须互异且 ≠ 锚盘）
    anchor_disk = anchor[0]
    a0 = np.frombuffer(chunks[anchor], dtype=np.uint64)
    h1, h2 = unknown_seqs[1:3], unknown_seqs[3:5]
    print(f"Y 侧列 {h1} / Z 侧列 {h2}")

    def disk_options(exclude):
        return [d for d in freed if d not in exclude]

    ytab = {}
    t1 = time.time()
    for dA in disk_options({anchor_disk}):
        for pA in freed[dA]:
            ka = chunks.get((dA, pA))
            if ka is None:
                continue
            na = np.frombuffer(ka, dtype=np.uint64)
            x1 = a0 ^ na
            for dB in disk_options({anchor_disk, dA}):
                for pB in freed[dB]:
                    kb = chunks.get((dB, pB))
                    if kb is None:
                        continue
                    nb = np.frombuffer(kb, dtype=np.uint64)
                    y = (x1 ^ nb).tobytes()
                    key = y[:24]
                    lst = ytab.get(key)
                    if lst is None:
                        ytab[key] = [(dA, pA, dB, pB)]
                    else:
                        lst.append((dA, pA, dB, pB))
    print(f"Y 表: {len(ytab)} 项 ({time.time()-t1:.0f}s)")

    found = []
    t2 = time.time()
    for dC in disk_options({anchor_disk}):
        for pC in freed[dC]:
            kc = chunks.get((dC, pC))
            if kc is None:
                continue
            nc = np.frombuffer(kc, dtype=np.uint64)
            x1 = a0 ^ nc
            for dD in disk_options({anchor_disk, dC}):
                for pD in freed[dD]:
                    kd = chunks.get((dD, pD))
                    if kd is None:
                        continue
                    nd = np.frombuffer(kd, dtype=np.uint64)
                    z = (x1 ^ nd).tobytes()
                    hit = ytab.get(z[:24])
                    if hit:
                        found.append((hit[0], (dC, pC, dD, pD)))
                        print(f"✓ 命中: Y={hit[0]} Z=(盘{dC}@{pC}, 盘{dD}@{pD})")
        if found:
            break
    print(f"Z 枚举 {time.time()-t2:.0f}s, 命中 {len(found)}")
    if not found:
        print("!! 未找到 5 元组")
        return 1

    # 组装 列→(盘,phys) 映射
    (dA, pA, dB, pB), (dC, pC, dD, pD) = found[0]
    colmap = {unknown_seqs[0]: anchor,
              unknown_seqs[1]: (dA, pA),
              unknown_seqs[2]: (dB, pB),
              unknown_seqs[3]: (dC, pC),
              unknown_seqs[4]: (dD, pD)}
    disks_used = [k[0] for k in colmap.values()]
    print(f"列映射: {colmap}")
    print(f"盘去重: {len(set(disks_used)) == 5} ({disks_used})")

    # 打开各列设备
    devs = {}
    for s, (d, p) in colmap.items():
        for dd in pool.disks:
            if dd.disk_id == d and dd.device_path:
                devs[s] = (RawDevice(dd.device_path), pstart_map[d] + (p + 2) * BLOCK)
                break

    # 多行 XOR-0 验证 + 数据提取
    print("== 多行验证 ==")
    n_clusters = len(rows)
    all_rows_ok = True
    file_data = bytearray()
    for ri, r in enumerate(rows):
        rowchunks = {}
        for s in range(ncols):
            dev, base = devs[s]
            rowchunks[s] = dev.read(base + r * CH, CH)
        acc = np.zeros(CH // 8, dtype=np.uint64)
        for s in range(ncols):
            acc ^= np.frombuffer(rowchunks[s], dtype=np.uint64)
        if acc.any():
            print(f"  行{r}: XOR≠0 ✗")
            all_rows_ok = False
        # 文件数据 = 数据列按序
        dcs = layout.data_cols_of(vd, r)
        for j, c in enumerate(dcs):
            file_data += rowchunks[c]
    print(f"  XOR-0 {'全部通过' if all_rows_ok else '存在失败'}")

    # 尾部零校验（EOF 之后应为 0）
    tail_len = n_clusters * 1048576 - fe.size
    if 0 < tail_len <= 1048576:
        tail = bytes(file_data[fe.size: n_clusters * 1048576])
        print(f"  尾部 {tail_len}B 非零字节: {sum(1 for x in tail if x)}（应为 0）")

    if do_export:
        dest = Path(out_dir / "locate_export") / fe.path.replace("\\", "_")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(bytes(file_data[:fe.size]))
        head = bytes(file_data[:3])
        print(f"[导出] {dest} ({len(file_data[:fe.size])}B, 头={head.hex()})")

    (out_dir / "locate_result.json").write_text(json.dumps({
        "file": fe.path, "size": fe.size, "group": E, "rows": rows,
        "colmap": {str(k): list(v) for k, v in colmap.items()},
        "xor_ok": all_rows_ok,
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    for dev, _ in devs.values():
        dev.close()
    print(f"[+] 用时 {time.time()-t0:.0f}s")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BaseException:
        import traceback
        tb = traceback.format_exc()
        (ROOT / "tools" / "out" / "locate_crash.txt").write_text(tb, encoding="utf-8")
        print(tb, file=sys.stderr)
        sys.exit(2)
