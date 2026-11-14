"""NTFS 解析：引导扇区 / $MFT / 属性 / runlist / 目录树 / 删除检测。

读取一律通过传入的 volume_reader（由 engine 提供：卷内偏移 → VirtualReader），
从而绕过 Windows 抽象层拿到删除后仍残留的物理数据。
"""
from __future__ import annotations

import struct
from typing import Callable, Dict, List, Optional, Tuple

from .models import FileEntry, Run, ErrorRecord, ScanStats
from . import errors

ATTR_STD_INFO = 0x10
ATTR_ATTR_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_VOLUME_NAME = 0x60
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOC = 0xA0
ATTR_BITMAP = 0xB0

FILETIME_TICKS = 10_000_000
FILETIME_EPOCH_OFFSET = 11644473600  # 1601→1970 秒


def filetime_to_unix(ft: int) -> int:
    if ft <= 0:
        return 0
    try:
        return ft // FILETIME_TICKS - FILETIME_EPOCH_OFFSET
    except Exception:
        return 0


class NtfsError(Exception):
    pass


class NtfsVolume:
    """一个 NTFS 卷的只读解析器。

    volume_reader: callable(volume_offset_bytes, length, file_path="", mft_ref=-1, run_index=-1) -> bytes
    """

    def __init__(self, volume_reader: Callable[..., bytes],
                 error_sink: Optional[Callable[[ErrorRecord], None]] = None):
        self.vread = volume_reader
        self.error_sink = error_sink
        self.bytes_per_sector = 512
        self.sectors_per_cluster = 8
        self.cluster_size = 4096
        self.total_clusters = 0
        self.mft_lcn = 0
        self.record_size = 1024
        self.mft_runs: List[Run] = []
        self.mft_total_bytes = 0

    def _err(self, code, level, message, **kw):
        rec = ErrorRecord(code=code, level=level, message=message, **kw)
        if self.error_sink:
            self.error_sink(rec)
        return rec

    # ------------------------------------------------------------ 引导扇区

    def read_boot(self) -> None:
        bs = self.vread(0, 512, file_path="NTFS 引导扇区", mft_ref=-1)
        if bs[3:11] != b"NTFS    ":
            raise NtfsError("OEM 签名不是 NTFS（可能是 ReFS 或其他文件系统）")
        self.bytes_per_sector = struct.unpack_from("<H", bs, 0x0B)[0]
        spc = bs[0x0D]
        if spc < 0x80:
            self.sectors_per_cluster = spc
        else:
            # 大簇编码：0xF5 → 2^(0x100-0xF5) = 2^11 扇区（实测 R: 为 1MB 簇）
            self.sectors_per_cluster = 2 ** (0x100 - spc)
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        total_sectors = struct.unpack_from("<Q", bs, 0x28)[0]
        self.total_clusters = total_sectors // self.sectors_per_cluster
        self.mft_lcn = struct.unpack_from("<q", bs, 0x30)[0]
        mftmirr_lcn = struct.unpack_from("<q", bs, 0x38)[0]
        cbs_mft = struct.unpack_from("<b", bs, 0x44)[0]
        if cbs_mft > 0:
            self.record_size = cbs_mft * self.cluster_size
        else:
            self.record_size = 2 ** (-cbs_mft)
        if self.mft_lcn == 0 or self.record_size < 128:
            raise NtfsError("引导扇区参数异常（MFT LCN 或记录大小非法）")

    # ------------------------------------------------------------ MFT 基址

    def _runs_to_volume_offset(self, runs: List[Run], lcn: int) -> Tuple[int, int]:
        """LCN → (卷内字节偏移, 剩余连续簇数)。找不到返回 (0,0)。"""
        cur = 0
        for r in runs:
            if cur <= lcn < cur + r.clusters:
                off = (r.lcn + (lcn - cur)) * self.cluster_size
                return off, cur + r.clusters - lcn
            cur += r.clusters
        return 0, 0

    def load_mft_map(self) -> None:
        """读取 MFT 记录 0 的 $DATA runlist，得到 $MFT 数据流的分片。

        记录尺寸以记录 0 自身的 alloc 字段（0x1C）为准——大簇卷上
        引导扇区的 cbs 字段可能不可靠（实测 R: 为 1MB 簇、1024B 记录）。
        """
        rec = self._read_record_at(self.mft_lcn * self.cluster_size, 0)
        if rec[0:4] != b"FILE":
            raise NtfsError("MFT 记录 0 头不是 FILE")
        alloc = struct.unpack_from("<I", rec, 0x1C)[0]
        if 128 <= alloc <= 65536 and (alloc & (alloc - 1)) == 0 and alloc != self.record_size:
            self.record_size = alloc
        attrs, _ = self._parse_record(rec, 0)
        data = attrs.get("data_unnamed")
        if data is None:
            raise NtfsError("$MFT 记录缺少未命名 $DATA 属性")
        header, runs = data
        self.mft_total_bytes = header.get("real", 0)
        self.mft_runs = runs

    def _mft_record_offset(self, ref: int) -> Tuple[int, int]:
        exact = ref * self.record_size
        cur_bytes = 0
        for r in self.mft_runs:
            run_bytes = r.clusters * self.cluster_size
            if cur_bytes <= exact < cur_bytes + run_bytes:
                return (r.lcn * self.cluster_size) + (exact - cur_bytes), run_bytes - (exact - cur_bytes)
            cur_bytes += run_bytes
        return 0, 0

    # ------------------------------------------------------------ 记录读取/解析

    def _read_record_at(self, vol_off: int, ref: int) -> bytes:
        raw = self.vread(vol_off, self.record_size, file_path="$MFT", mft_ref=ref)
        return self._apply_fixup(raw, ref)

    def read_record(self, ref: int) -> bytes:
        off, _ = self._mft_record_offset(ref)
        if off == 0 and ref != 0:
            self._err(errors.E_RUNS_BAD, errors.LEVEL_WARN,
                      f"MFT 记录 {ref} 超出 $MFT 数据流范围",
                      mft_ref=ref, volume_offset=0, action="skip")
            raise NtfsError(f"record {ref} beyond $MFT")
        return self._read_record_at(off, ref)

    def _apply_fixup(self, raw: bytes, ref: int) -> bytes:
        if raw[0:4] != b"FILE":
            return raw
        fixup_off = struct.unpack_from("<H", raw, 0x04)[0]   # FILE 记录: 修正数组偏移在 0x04
        fixup_count = struct.unpack_from("<H", raw, 0x06)[0]
        buf = bytearray(raw)
        for i in range(1, fixup_count):
            tail_off = fixup_off + i * 2
            if tail_off + 2 > len(raw):
                break
            stored = raw[tail_off:tail_off + 2]
            sec_off = i * 512 - 2  # 第 i 个扇区的末 2 字节被 USN 覆盖，需还原
            if 0 <= sec_off < len(buf) - 1:
                buf[sec_off:sec_off + 2] = stored
        return bytes(buf)

    def _parse_record(self, rec: bytes, ref: int) -> Tuple[dict, List[dict]]:
        """返回 (聚合属性 dict, 原始属性列表)。"""
        if rec[0:4] != b"FILE":
            raise NtfsError("记录头不是 FILE")
        attrs_off = struct.unpack_from("<H", rec, 0x14)[0]
        flags = struct.unpack_from("<H", rec, 0x16)[0]
        used_size = struct.unpack_from("<I", rec, 0x18)[0]
        agg: dict = {"flags": flags, "in_use": bool(flags & 1), "is_dir": bool(flags & 2)}
        raw_attrs = []
        off = attrs_off
        while off + 4 <= min(used_size, len(rec)):
            atype = struct.unpack_from("<I", rec, off)[0]
            if atype == 0xFFFFFFFF or atype == 0:
                break
            alen = struct.unpack_from("<I", rec, off + 4)[0]
            if alen < 8 or off + alen > len(rec):
                self._err(errors.E_ATTR_BAD, errors.LEVEL_WARN,
                          f"MFT#{ref} 属性偏移 {off} 长度非法 ({alen})",
                          mft_ref=ref, volume_offset=off, action="skip_attr")
                break
            nonres = rec[off + 8]
            ainfo = {"type": atype, "off": off, "len": alen, "nonres": nonres}
            raw_attrs.append(ainfo)
            self._parse_attr(rec, off, atype, alen, nonres, ref, agg)
            off += alen
        return agg, raw_attrs

    def _parse_attr(self, rec: bytes, off: int, atype: int, alen: int,
                    nonres: int, ref: int, agg: dict) -> None:
        name_len = rec[off + 9]
        name_off = struct.unpack_from("<H", rec, off + 10)[0]
        aflags = struct.unpack_from("<H", rec, off + 12)[0]
        name = ""
        if name_len:
            no = off + name_off
            name = rec[no:no + name_len * 2].decode("utf-16-le", errors="replace")

        if atype == ATTR_ATTR_LIST:
            # 常驻 $ATTRIBUTE_LIST: value_off @0x14
            value_off = struct.unpack_from("<H", rec, off + 0x14)[0]
            value_len = struct.unpack_from("<I", rec, off + 0x10)[0]
            agg["attr_list_raw"] = rec[off + value_off:off + value_off + value_len]
            agg["has_attribute_list"] = True
            return

        if atype == ATTR_FILE_NAME:
            value_off = struct.unpack_from("<H", rec, off + 0x14)[0]
            value_len = struct.unpack_from("<I", rec, off + 0x10)[0]
            fn = self._parse_file_name(rec[off + value_off:off + value_off + value_len])
            if fn:
                cur = agg.get("file_names", [])
                cur.append(fn)
                agg["file_names"] = cur
            return

        if atype == ATTR_STD_INFO:
            value_off = struct.unpack_from("<H", rec, off + 0x14)[0]
            times = struct.unpack_from("<QQQQ", rec, off + value_off)
            agg["std_times"] = times
            return

        if atype == ATTR_OBJECT_ID:
            value_off = struct.unpack_from("<H", rec, off + 0x14)[0]
            agg["object_id"] = rec[off + value_off:off + value_off + 16].hex().upper()
            return

        if atype == ATTR_DATA and not name:
            # 未命名 $DATA —— 文件内容
            if not nonres:
                value_off = struct.unpack_from("<H", rec, off + 0x14)[0]
                value_len = struct.unpack_from("<I", rec, off + 0x10)[0]
                agg["data_resident"] = rec[off + value_off:off + value_off + value_len]
                agg["data_size"] = value_len
                agg["data_flags"] = aflags
            else:
                start_vcn = struct.unpack_from("<Q", rec, off + 0x10)[0]
                last_vcn = struct.unpack_from("<Q", rec, off + 0x18)[0]
                runs_off = struct.unpack_from("<H", rec, off + 0x20)[0]
                alloc = struct.unpack_from("<Q", rec, off + 0x28)[0]
                real = struct.unpack_from("<Q", rec, off + 0x30)[0]
                init = struct.unpack_from("<Q", rec, off + 0x38)[0]
                try:
                    runs = decode_runs(rec[off + runs_off:off + alen])
                except Exception as e:
                    self._err(errors.E_RUNS_BAD, errors.LEVEL_ERROR,
                              f"MFT#{ref} $DATA runlist 解码失败: {e}",
                              mft_ref=ref, action="mark_bad")
                    runs = []
                entry = {"start_vcn": start_vcn, "last_vcn": last_vcn,
                         "runs": runs, "alloc": alloc, "real": real, "init": init,
                         "flags": aflags}
                prev = agg.get("data_unnamed")
                if prev is None or start_vcn == 0:
                    agg["data_unnamed"] = (entry, runs)
                else:
                    # 多段（$ATTRIBUTE_LIST 拆分）：合并 runs
                    prev_entry, prev_runs = prev
                    prev_entry["runs"] = prev_runs + runs
                    prev_entry["last_vcn"] = last_vcn
                    agg["data_unnamed"] = (prev_entry, prev_entry["runs"])
            return

    def _parse_file_name(self, v: bytes) -> Optional[dict]:
        if len(v) < 0x42:
            return None
        parent = int.from_bytes(v[0:6], "little")
        parent_seq = struct.unpack_from("<H", v, 6)[0]
        times = struct.unpack_from("<QQQQ", v, 0x08)
        alloc = struct.unpack_from("<Q", v, 0x28)[0]
        real = struct.unpack_from("<Q", v, 0x30)[0]
        flags = struct.unpack_from("<I", v, 0x34)[0]
        nlen = v[0x40]
        ns = v[0x41]
        name = v[0x42:0x42 + nlen * 2].decode("utf-16-le", errors="replace") if nlen else ""
        return {"parent": parent, "parent_seq": parent_seq, "times": times,
                "alloc": alloc, "real": real, "flags": flags, "name": name,
                "ns": ns}

    # ------------------------------------------------------------ 全盘扫描

    def scan_all(self, on_progress=None) -> Tuple[List[FileEntry], ScanStats]:
        """遍历 $MFT 所有记录，产出 FileEntry 列表。"""
        stats = ScanStats()
        entries: List[FileEntry] = []
        total_records = self.mft_total_bytes // self.record_size
        for ref in range(total_records):
            if on_progress and ref % 512 == 0:
                on_progress(ref, total_records)
            try:
                rec = self.read_record(ref)
            except NtfsError:
                stats.total_records += 1
                continue
            if rec[0:4] != b"FILE":
                continue
            try:
                agg, _ = self._parse_record(rec, ref)
            except Exception as e:
                self._err(errors.E_MFT_RECORD, errors.LEVEL_WARN,
                          f"MFT#{ref} 记录解析异常: {e}", mft_ref=ref, action="skip")
                continue
            stats.total_records += 1
            fe = self._to_file_entry(ref, agg)
            if fe is None:
                continue
            if fe.is_dir:
                stats.dirs += 1
                stats.deleted_dirs += 1 if fe.deleted else 0
            else:
                stats.files += 1
                stats.total_bytes += fe.size
                if fe.deleted:
                    stats.deleted_files += 1
                    stats.deleted_bytes += fe.size
            entries.append(fe)
        return entries, stats

    def _to_file_entry(self, ref: int, agg: dict) -> Optional[FileEntry]:
        fns = agg.get("file_names")
        if not fns:
            return None
        # 优先 win32/posix 命名空间，其次 dos
        best = None
        for fn in fns:
            ns = fn["ns"]
            if ns in (1, 3):        # 1=posix? 0=posix,1=win32,2=dos,3=win32+dos
                best = fn
                break
            if best is None or ns != 2:
                best = fn
        if best is None:
            best = fns[0]
        fe = FileEntry(
            mft_ref=ref,
            seq=0,
            parent_ref=best["parent"],
            name=best["name"],
            is_dir=bool(agg.get("is_dir")),
            deleted=not agg.get("in_use", False),
            times=(filetime_to_unix(best["times"][0]),
                   filetime_to_unix(best["times"][1]),
                   filetime_to_unix(best["times"][2])),
            dos_attrs=best["flags"],
            has_attribute_list=bool(agg.get("has_attribute_list")),
            object_id=agg.get("object_id", ""),
        )
        data = agg.get("data_unnamed")
        if data is not None:
            entry, runs = data
            fe.runs = runs
            fe.size = entry.get("real", 0)
            fe.alloc_size = entry.get("alloc", 0)
            fe.data_attr_flags = entry.get("flags", 0)
        elif "data_resident" in agg:
            fe.resident_data = agg["data_resident"]
            fe.size = len(agg["data_resident"])
        # 记录解析中的小问题
        fe.load_error = ""
        return fe

    # ------------------------------------------------------------ 属性列表/子记录

    def load_child_attributes(self, fe: FileEntry, child_refs: List[int]) -> None:
        """$ATTRIBUTE_LIST 指向的子记录：把它们的 $DATA runs 合并进来。"""
        for cref in child_refs:
            try:
                rec = self.read_record(cref)
                agg, _ = self._parse_record(rec, cref)
            except Exception:
                continue
            data = agg.get("data_unnamed")
            if data:
                entry, runs = data
                fe.runs.extend(runs)

    # ------------------------------------------------------------ 目录树

    def build_paths(self, entries: List[FileEntry], root_ref: int = 5) -> None:
        by_ref: Dict[int, List[FileEntry]] = {}
        for e in entries:
            by_ref.setdefault(e.mft_ref, []).append(e)
        valid_refs = set(by_ref.keys())

        for e in entries:
            if e.mft_ref == root_ref:
                e.path = ""
                continue
            chain: List[str] = []
            cur = e
            visited = set()
            ok = True
            while True:
                if cur.mft_ref == root_ref:
                    break
                if cur.mft_ref in visited or len(visited) > 64:
                    ok = False
                    break
                visited.add(cur.mft_ref)
                if not cur.name:
                    ok = False
                    break
                chain.append(cur.name)
                parent = by_ref.get(cur.parent_ref)
                if not parent:
                    ok = False
                    break
                cur = parent[0]
                if cur.deleted and cur.mft_ref != root_ref and not e.deleted:
                    # 父目录已删除但文件未删：仍继续尝试
                    pass
            if ok:
                e.path = "\\".join(reversed(chain))
            else:
                e.path = "§孤儿文件\\" + e.name


# ---------------------------------------------------------------- runlist

def decode_runs(data: bytes) -> List[Run]:
    """解码 NTFS runlist（data 为 runs 区域，至 0x00 终止）。"""
    runs: List[Run] = []
    i = 0
    lcn = 0
    n = len(data)
    while i < n:
        header = data[i]
        if header == 0:
            break
        len_size = header & 0x0F
        off_size = header >> 4
        if len_size == 0 or off_size > 8 or i + 1 + len_size > n:
            raise NtfsError(f"runlist 头非法 @{i}: {header:#x}")
        i += 1
        clusters = int.from_bytes(data[i:i + len_size], "little")
        i += len_size
        if off_size:
            if i + off_size > n:
                raise NtfsError("runlist 偏移越界")
            off_bytes = data[i:i + off_size]
            # 有符号（负 = sparse 填充）
            off = int.from_bytes(off_bytes, "little", signed=True)
            i += off_size
            lcn += off
            runs.append(Run(lcn=lcn, clusters=clusters))
        else:
            runs.append(Run(lcn=-1, clusters=clusters))  # sparse hole
    return runs
