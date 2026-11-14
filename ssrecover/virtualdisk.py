"""虚拟盘读取器：绕过 Windows 抽象层，按 SpacePort 映射从物理盘组装数据。

公式（已在真实 5 列 parity 池标定）：
  设备偏移 = pstart + (phys_block + 2) × 256MB + row × 256KB
  行内数据列顺序 = 从校验列下一列循环取数据列数个列
  P(校验) = XOR(数据列们)

按组分段的批量读取：每个物理盘一次读出整个行跨度（含校验行），
再在内存中按行挑列组装 —— 每段每盘仅 1 次内核读取。
失败时按遇错规则处理（重试 → P(XOR) 重建 → 填0 / 中止文件 / 中止导出），
并记录含虚拟/物理完整坐标的 ErrorRecord。所有物理读取均为只读。
"""
from __future__ import annotations

import time
from typing import Callable, Dict, Optional

from .models import PoolScan, VirtualDiskInfo, ErrorRecord
from .rawdisk import RawDevice
from . import layout, errors, BLOCK
from .config import ReadParams, ErrorRules, ON_ERROR_ZERO_FILL, ON_ERROR_ABORT_FILE, ON_ERROR_STOP

SPAN_BYTES = 8 * 1024 * 1024   # 单次组装的虚拟跨度上限


class AbortFileError(Exception):
    """按规则中止当前文件。"""


class AbortExportError(Exception):
    """按规则中止整个导出。"""


class VirtualReader:
    """一个虚拟磁盘的按需读取器。"""

    def __init__(self, pool: PoolScan, vd: VirtualDiskInfo,
                 devices: Dict[int, RawDevice],
                 params: ReadParams,
                 rules: ErrorRules,
                 error_sink: Optional[Callable[[ErrorRecord], None]] = None):
        self.pool = pool
        self.vd = vd
        self.devices = devices
        self.params = params
        self.rules = rules
        self.error_sink = error_sink
        self.partition_start_map = {d.disk_id: d.partition_start for d in pool.disks}
        self.disk_name_map = {d.disk_id: d.name for d in pool.disks}
        self.stripe = vd.mode in ("PARITY", "DPARITY", "STRIPED")
        self.row_bytes = ((vd.ncols - vd.parity_cols) * vd.interleave) if self.stripe else BLOCK
        self.zero_check = False          # 导出时由 engine 打开（全 0 区检测）

    # ------------------------------------------------------------ 错误

    def _err(self, code, level, message, **kw) -> ErrorRecord:
        rec = ErrorRecord(code=code, level=level, message=message, **kw)
        if self.error_sink:
            self.error_sink(rec)
        return rec

    # ------------------------------------------------------------ 主入口

    def read(self, voff: int, length: int, file_path: str = "",
             mft_ref: int = -1, run_index: int = -1) -> bytes:
        out = bytearray()
        pos = voff
        end = voff + length
        while pos < end:
            n = min(end - pos, self._seg_limit(pos))
            out += self._read_span(pos, n, file_path, mft_ref, run_index)
            pos += n
        return bytes(out)

    def _seg_limit(self, voff: int) -> int:
        """下一段长度：组/块边界或 SPAN_BYTES 为止。"""
        if self.stripe:
            row = voff // self.row_bytes
            g = row // self.vd.rows
            group_start_v = g * self.vd.group_vblocks * BLOCK
            group_end_v = group_start_v + self.vd.rows * self.row_bytes
            lim = group_end_v - voff
        else:
            lim = (voff // BLOCK + 1) * BLOCK - voff
        return min(lim, SPAN_BYTES)

    def map_voff(self, voff: int) -> Optional[tuple]:
        """虚拟偏移 → (disk_id, phys_block, slab内偏移, 列号)。"""
        vd = self.vd
        if self.stripe:
            row = voff // self.row_bytes
            g = row // vd.rows
            rin = row % vd.rows
            base = g * vd.group_vblocks
            grp = vd.groups.get(base)
            if grp is None:
                return None
            idx_in_row = (voff % self.row_bytes) // vd.interleave
            dcols = layout.data_cols_of(vd, rin)
            if idx_in_row >= len(dcols):
                return None
            col = dcols[idx_in_row]
            ent = grp.entries.get(col)
            if ent is None:
                return None
            return ent[0], ent[1], rin * vd.interleave, col
        else:
            vblock = voff // BLOCK
            grp = vd.groups.get(vblock)
            if grp is None:
                return None
            ent = grp.entries.get(min(grp.entries))
            if ent is None:
                return None
            return ent[0], ent[1], voff % BLOCK, -1

    # ------------------------------------------------------------ 段读取

    def _read_span(self, voff: int, length: int, file_path: str,
                   mft_ref: int, run_index: int) -> bytes:
        if self.stripe:
            return self._read_stripe_group(voff, length, file_path, mft_ref, run_index)
        return self._read_concat_span(voff, length, file_path, mft_ref, run_index)

    def _read_concat_span(self, voff: int, length: int, file_path: str,
                          mft_ref: int, run_index: int) -> bytes:
        vd = self.vd
        vblock = voff // BLOCK
        grp = vd.groups.get(vblock)
        if grp is None or not grp.entries:
            self._err(errors.E_CLUSTERS_MISSING, errors.LEVEL_WARN,
                      f"虚拟块 {vblock} 无映射（未分配/已解分配），填 0",
                      file_path=file_path, mft_ref=mft_ref, run_index=run_index,
                      virtual_offset=voff, length=length, action="zero_fill")
            return b"\x00" * length
        seq = min(grp.entries)
        disk_id, phys_block = grp.entries[seq]
        dev = self.devices.get(disk_id)
        if dev is None:
            self._err(errors.E_DEVICE_READ, errors.LEVEL_ERROR,
                      f"物理盘 #{disk_id} ({self.disk_name_map.get(disk_id, '')}) 未挂载，填 0",
                      file_path=file_path, mft_ref=mft_ref, run_index=run_index,
                      virtual_offset=voff, disk_id=disk_id, length=length, action="zero_fill")
            return b"\x00" * length
        poff = self.partition_start_map.get(disk_id, 0) + (phys_block + 2) * BLOCK + (voff % BLOCK)
        try:
            data = dev.read_aligned(poff, length, retries=self.params.max_retries)
        except OSError as e:
            return self._fail_read(dev, disk_id, poff, length, e, voff,
                                   file_path, mft_ref, run_index)
        self._check_zero(data, voff, disk_id, phys_block, voff % BLOCK,
                         file_path, mft_ref, run_index)
        return data

    def _read_stripe_group(self, voff: int, length: int, file_path: str,
                           mft_ref: int, run_index: int) -> bytes:
        """读取一段（同组内跨多行；不跨组——由 _seg_limit 保证）。"""
        vd = self.vd
        row0 = voff // self.row_bytes
        g = row0 // vd.rows
        base = g * vd.group_vblocks
        grp = vd.groups.get(base)
        group_start_v = base * BLOCK
        group_end_v = group_start_v + vd.rows * self.row_bytes
        seg_end = voff + length

        if grp is None:
            self._err(errors.E_CLUSTERS_MISSING, errors.LEVEL_WARN,
                      f"条带组 {base} 无映射（未分配/已解分配），填 0",
                      file_path=file_path, mft_ref=mft_ref, run_index=run_index,
                      virtual_offset=voff, length=length, action="zero_fill")
            return b"\x00" * length

        rin0 = (voff - group_start_v) // self.row_bytes
        rin1 = min(vd.rows, (seg_end - group_start_v + self.row_bytes - 1) // self.row_bytes)
        nrows = rin1 - rin0

        # 每盘一次批量读取（含校验行）
        bufs: Dict[int, Optional[bytes]] = {}
        for col, ent in grp.entries.items():
            disk_id, phys_block = ent
            dev = self.devices.get(disk_id)
            if dev is None:
                bufs[col] = None
                self._err(errors.E_DEVICE_READ, errors.LEVEL_ERROR,
                          f"物理盘 #{disk_id} ({self.disk_name_map.get(disk_id, '')}) 未挂载",
                          file_path=file_path, mft_ref=mft_ref, run_index=run_index,
                          virtual_offset=group_start_v, disk_id=disk_id,
                          length=nrows * vd.interleave, action="pending")
                continue
            doff = self.partition_start_map.get(disk_id, 0) + (phys_block + 2) * BLOCK + rin0 * vd.interleave
            dlen = nrows * vd.interleave
            try:
                bufs[col] = dev.read_aligned(doff, dlen, retries=self.params.max_retries)
            except OSError as e:
                bufs[col] = None
                self._err(errors.E_DEVICE_READ, errors.LEVEL_ERROR,
                          f"盘 #{disk_id} 批量读失败（已重试 {self.params.max_retries} 次）",
                          file_path=file_path, mft_ref=mft_ref, run_index=run_index,
                          virtual_offset=voff, disk_id=disk_id,
                          disk_name=self.disk_name_map.get(disk_id, ""),
                          disk_path=dev.device_path, physical_offset=doff,
                          length=dlen, retries=self.params.max_retries,
                          action="pending", extra=str(e))

        # 组装行
        ilv = vd.interleave

        def chunk_of(col: int, rin: int) -> Optional[bytes]:
            buf = bufs.get(col)
            if buf is None:
                return None
            o = (rin - rin0) * ilv
            ch = buf[o:o + ilv]
            if len(ch) < ilv:
                ch = ch + b"\x00" * (ilv - len(ch))
            return ch

        out = bytearray()
        skip = voff - (group_start_v + rin0 * self.row_bytes)
        for r in range(rin0, rin1):
            dcols = layout.data_cols_of(vd, r)
            pcols = layout.parity_col_of(vd, r)
            row = bytearray(self.row_bytes)
            missing = []
            for k, col in enumerate(dcols):
                ch = chunk_of(col, r)
                if ch is None:
                    missing.append(k)
                else:
                    row[k * ilv:(k + 1) * ilv] = ch
            if missing:
                row = self._fix_row(row, missing, dcols, pcols, chunk_of, r, grp,
                                    voff, file_path, mft_ref, run_index)
            out += row
        self._check_zero(bytes(out), voff, -1, -1, -1, file_path, mft_ref, run_index)
        return bytes(out[skip:skip + length])

    def _fix_row(self, row: bytearray, missing_idx: list, dcols, pcols, chunk_of,
                 rin: int, grp, voff, file_path, mft_ref, run_index) -> bytearray:
        """行内缺失单元处理：P(XOR) 重建 → 按规则填 0 / 中止文件 / 中止导出。"""
        vd = self.vd
        ilv = vd.interleave
        for k in missing_idx:
            col = dcols[k]
            lo, hi = k * ilv, (k + 1) * ilv
            rebuilt = None
            if self.params.use_parity_rebuild and pcols and vd.mode in ("PARITY", "DPARITY"):
                pch = chunk_of(pcols[0], rin)
                if pch is not None:
                    others = []
                    ok = True
                    for kk, cc in enumerate(dcols):
                        if kk == k:
                            continue
                        ch = chunk_of(cc, rin)
                        if ch is None:
                            ok = False
                            break
                        others.append(ch)
                    if ok:
                        acc = bytearray(pch)
                        for ch in others:
                            n = min(len(acc), len(ch))
                            for i in range(n):
                                acc[i] ^= ch[i]
                        rebuilt = bytes(acc)
            if rebuilt is not None:
                row[lo:hi] = rebuilt
                self._err(errors.E_PARITY_REBUILD, errors.LEVEL_WARN,
                          f"组 {grp.vblock} 行 {rin} 列 {col} 读取失败，已用 P(XOR) 重建",
                          file_path=file_path, mft_ref=mft_ref, run_index=run_index,
                          virtual_offset=voff, length=ilv, action="parity_rebuild")
                continue
            if self.rules.unreadable == ON_ERROR_ABORT_FILE:
                self._err(errors.E_EXPORT_ABORTED, errors.LEVEL_ERROR,
                          f"组 {grp.vblock} 行 {rin} 列 {col} 读取失败且规则=中止文件",
                          file_path=file_path, mft_ref=mft_ref, run_index=run_index,
                          virtual_offset=voff, length=ilv, action="abort_file")
                raise AbortFileError(f"{file_path}: 行 {rin} 列 {col} 读取失败")
            if self.rules.unreadable == ON_ERROR_STOP:
                self._err(errors.E_DEVICE_READ, errors.LEVEL_ERROR,
                          "读取失败，规则=中止导出",
                          file_path=file_path, mft_ref=mft_ref, run_index=run_index,
                          virtual_offset=voff, length=ilv, action="stop")
                raise AbortExportError("按遇错规则中止导出")
            row[lo:hi] = b"\x00" * ilv
            self._err(errors.E_DEVICE_READ, errors.LEVEL_ERROR,
                      f"组 {grp.vblock} 行 {rin} 列 {col} 不可读且无法重建，填 0",
                      file_path=file_path, mft_ref=mft_ref, run_index=run_index,
                      virtual_offset=voff, length=ilv, action="zero_fill")
        return row

    # ------------------------------------------------------------ 辅助

    def _check_zero(self, data: bytes, voff: int, disk_id, phys_block, within,
                    file_path, mft_ref, run_index) -> None:
        if not self.zero_check or not self.params.verify_zero_regions:
            return
        if data and not any(data):
            self._err(errors.E_DATA_ZEROFILLED, errors.LEVEL_INFO,
                      "读出的区域全为 0（可能已被 trim/清零或复用覆盖）",
                      file_path=file_path, mft_ref=mft_ref, run_index=run_index,
                      virtual_offset=voff, disk_id=disk_id,
                      disk_name=self.disk_name_map.get(disk_id, "") if disk_id >= 0 else "",
                      disk_path=self.devices[disk_id].device_path if disk_id in self.devices else "",
                      physical_offset=(self.partition_start_map.get(disk_id, 0)
                                       + (phys_block + 2) * BLOCK + within) if disk_id >= 0 else -1,
                      length=len(data), action="record_only")

    def _fail_read(self, dev, disk_id, poff, size, exc, voff,
                   file_path, mft_ref, run_index) -> bytes:
        common = dict(file_path=file_path, mft_ref=mft_ref, run_index=run_index,
                      virtual_offset=voff, disk_id=disk_id,
                      disk_name=self.disk_name_map.get(disk_id, ""),
                      disk_path=dev.device_path if dev else "",
                      physical_offset=poff, length=size,
                      retries=self.params.max_retries, extra=str(exc))
        if self.rules.unreadable == ON_ERROR_ABORT_FILE:
            self._err(errors.E_EXPORT_ABORTED, errors.LEVEL_ERROR,
                      "物理读失败且规则=中止文件", action="abort_file", **common)
            raise AbortFileError(f"{file_path}: 物理读失败 @{poff:#x}")
        if self.rules.unreadable == ON_ERROR_STOP:
            self._err(errors.E_DEVICE_READ, errors.LEVEL_ERROR,
                      "物理读失败，规则=中止导出", action="stop", **common)
            raise AbortExportError("按遇错规则中止导出")
        self._err(errors.E_DEVICE_READ, errors.LEVEL_ERROR,
                  f"物理盘 #{disk_id} 读失败（已重试 {self.params.max_retries} 次），填 0",
                  action="zero_fill", **common)
        return b"\x00" * size
