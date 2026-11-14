"""布局推断与虚拟↔物理映射（已在真实 5 列 parity 池上标定验证）。

核心公式（实测确认）：
- 物理定位：pstart + (phys_block + 2) × 256MB + row × interleave
- 组 E 覆盖虚拟字节 [E×256MB, E×256MB + rows×数据列数×256KB)
- 行数 rows = slab_bytes(256MB) / interleave(256KB) = 1024（Win8/2012 为 4096，slab 1GB）
- 校验列（单 parity）：pcol = (ncols - 1 - row) % ncols
- 数据列顺序（虚拟字节序）：从 (pcol+1) 开始循环取 (ncols - parity_cols) 列
  —— 注意是"循环"而非"升序跳过"（行 1 的数据列 = [4,0,1,2]）
- 校验内容：P = XOR(数据列们)（dual parity 的 Q/RS 不在此实现）
"""
from __future__ import annotations

import statistics
from typing import List, Optional, Tuple

from .models import PoolScan, VirtualDiskInfo
from . import BLOCK, SLAB_BYTES_V10, SLAB_BYTES_V8, INTERLEAVE_DEFAULT


def infer_layout(pool: PoolScan, vd: VirtualDiskInfo, all_type4: Optional[list] = None) -> None:
    """根据 type4 记录/组表推断 vd 的布局参数（就地修改 vd）。"""
    from .models import SlabGroup

    if vd.groups:
        raw_groups: dict = {e: dict(g.entries) for e, g in vd.groups.items()}
    elif all_type4:
        raw_groups = {}
        for d in all_type4:
            raw_groups.setdefault(d["E"], {})[d["seq"]] = (d["disk"], d["phys"])
    else:
        vd.mode = "EMPTY"
        return

    starts = sorted(raw_groups.keys())
    if len(starts) > 1:
        diffs = [b - a for a, b in zip(starts, starts[1:])]
        common = statistics.mode(diffs)
        group_vblocks = common if common >= 1 else 1
    else:
        group_vblocks = 1

    ncols = len(raw_groups[starts[0]])

    win8 = pool.meta_version == "win8"
    slab = SLAB_BYTES_V8 if win8 else SLAB_BYTES_V10
    vd.slab_bytes = slab
    vd.interleave = INTERLEAVE_DEFAULT
    vd.rows = slab // vd.interleave
    vd.ncols = ncols
    vd.group_vblocks = group_vblocks

    # 数据列数 = 组覆盖的 vblock 数（Win10+；Win8 时代 1 个组 = 数据列数 × 1GB）
    data_cols = group_vblocks // 4 if win8 else group_vblocks
    data_cols = max(1, min(data_cols, ncols))
    parity_cols = ncols - data_cols
    if parity_cols <= 0:
        vd.mode = "STRIPED" if ncols > 1 else "CONCAT"
        vd.parity_cols = 0
    elif parity_cols == 1:
        vd.mode = "PARITY"
        vd.parity_cols = 1
    elif parity_cols == 2:
        vd.mode = "DPARITY"
        vd.parity_cols = 2
    else:
        vd.mode = "PARITY"
        vd.parity_cols = parity_cols

    vd.group_start_vblocks = starts
    vd.groups = {e: SlabGroup(vblock=e, entries=g) for e, g in raw_groups.items()}
    vd.raw_vd_size = (starts[-1] + group_vblocks) * BLOCK


def parity_col_of(vd: VirtualDiskInfo, row_in_group: int) -> List[int]:
    """返回该行的校验列（列索引列表，升序）。

    单 parity: pcol = (ncols-1-row) % ncols
    双 parity: 校验对每 3 行轮转（SSR 实证；本池未含双 parity，未标定）
    """
    row = row_in_group
    if vd.mode == "DPARITY":
        if vd.rotation == "asc":
            start = (2 * (row % 3)) % vd.ncols
        else:
            start = (vd.ncols - 2 - 2 * (row % 3)) % vd.ncols
        return [start % vd.ncols, (start + 1) % vd.ncols]
    if vd.mode == "PARITY":
        if vd.rotation == "asc":
            return [row % vd.ncols]
        return [(vd.ncols - 1 - row) % vd.ncols]
    return []


def data_cols_of(vd: VirtualDiskInfo, row_in_group: int) -> List[int]:
    """该行的数据列（虚拟字节顺序！）：

    从 (pcol+1) 开始循环取 (ncols - parity_cols) 个列。
    实测（5 列单 parity）：行0 → [0,1,2,3]（pcol=4）；行1 → [4,0,1,2]（pcol=3）。
    """
    pset = parity_col_of(vd, row_in_group)
    if not pset:
        return list(range(vd.ncols))
    pcol = pset[0]
    n = vd.ncols
    return [(pcol + i) % n for i in range(1, n + 1)][: n - len(pset)]


def group_for_voff(vd: VirtualDiskInfo, voff: int) -> Tuple[int, Optional[object]]:
    """虚拟偏移 → (组起始块号, 组)。找不到返回 (-1, None)。"""
    if vd.mode in ("PARITY", "DPARITY", "STRIPED"):
        row_bytes = (vd.ncols - vd.parity_cols) * vd.interleave
        vblock = voff // BLOCK
        g_idx = vblock // vd.group_vblocks
        base = g_idx * vd.group_vblocks
        g = vd.groups.get(base)
        if g is None:
            below = [s for s in vd.group_start_vblocks if s <= base]
            if below:
                base = below[-1]
                g = vd.groups.get(base)
        return base, g
    else:
        vblock = voff // BLOCK
        g = vd.groups.get(vblock)
        if g is None:
            below = [s for s in vd.group_start_vblocks if s <= vblock]
            if below:
                g = vd.groups.get(below[-1])
        return (below[-1] if below else vblock), g


def phys_offset(partition_start_map: dict, disk_id: int, phys_block: int, within: int = 0) -> int:
    """slab 数据定位公式。"""
    return partition_start_map[disk_id] + (phys_block + 2) * BLOCK + within


def xor_bytes(a: bytes, b: bytes) -> bytes:
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n]))


def xor_many(chunks: List[bytes]) -> bytes:
    if not chunks:
        return b""
    acc = chunks[0]
    for c in chunks[1:]:
        acc = xor_bytes(acc, c)
    return acc


def validate_geometry(pool: PoolScan, vd: VirtualDiskInfo) -> List[str]:
    notes = []
    if not vd.groups:
        notes.append("无映射组")
        return notes
    # 每组列数一致性
    bad = [e for e, g in vd.groups.items() if len(g.entries) != vd.ncols]
    if bad:
        notes.append(f"{len(bad)} 个组列数异常，如 {bad[:5]}")
    # 步长一致性
    starts = sorted(vd.groups.keys())
    if len(starts) > 1:
        diffs = [b - a for a, b in zip(starts, starts[1:])]
        common = statistics.mode(diffs)
        odd = sum(1 for d in diffs if d != common)
        notes.append(f"组步长众数 {common}，异常步长 {odd} 处（解分配/未分配区间）")
    return notes
