"""恢复引擎：扫描 → 文件结构 → 导出。全程对源数据只读。"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import time
from typing import Callable, Dict, List, Optional, Tuple

from .models import (PoolScan, VirtualDiskInfo, PartitionInfo, PhysicalDiskInfo,
                     FileEntry, ErrorRecord, Progress, ScanStats)
from .rawdisk import RawDevice, is_admin, enumerate_physical_disks
from . import spaceport, layout, ntfs, errors
from .config import ExportConfig, ReadParams, ErrorRules, ON_ERROR_ABORT_FILE
from .virtualdisk import VirtualReader, AbortFileError, AbortExportError

ProgressCB = Callable[[Progress], None]
ErrorCB = Callable[[ErrorRecord], None]


def _new_progress(phase: str, message: str = "", **kw) -> Progress:
    p = Progress(phase=phase, message=message)
    for k, v in kw.items():
        setattr(p, k, v)
    return p


class RecoveryEngine:
    def __init__(self, error_sink: Optional[ErrorCB] = None):
        self.error_sink = error_sink or (lambda rec: None)
        self.collected_errors: List[ErrorRecord] = []   # 全量错误记录（始终收集）
        self.pool: Optional[PoolScan] = None
        self.devices: Dict[int, RawDevice] = {}
        self.vd: Optional[VirtualDiskInfo] = None
        self.partitions: List[PartitionInfo] = []
        self.volume: Optional[NtfsVolumeAdapter] = None
        self.entries: List[FileEntry] = []
        self.stats: Optional[ScanStats] = None
        self.windows_ctx: dict = {}
        self._err_seq = 0

    # ------------------------------------------------------------ 错误

    def err(self, code, level, message, **kw) -> ErrorRecord:
        self._err_seq += 1
        rec = ErrorRecord(code=code, level=level, message=message, seq=self._err_seq, **kw)
        self.collected_errors.append(rec)
        self.error_sink(rec)
        return rec

    # ------------------------------------------------------------ Windows 上下文（只读查询）

    def query_windows_context(self) -> dict:
        """PowerShell 只读查询：虚拟磁盘/磁盘/分区信息（无需管理员）。"""
        ps = (
            "$ErrorActionPreference='SilentlyContinue';"
            "Get-VirtualDisk | Select-Object FriendlyName,UniqueId,NumberOfColumns,"
            "NumberOfDataCopies,ParityLayout,Interleave,ProvisioningType,Size | ConvertTo-Json -Compress;"
            "'<<<SPLIT>>>';"
            "Get-Disk | Select-Object Number,FriendlyName,BusType,Size,IsReadOnly | ConvertTo-Json -Compress;"
            "'<<<SPLIT>>>';"
            "Get-Partition | Select-Object DriveLetter,DiskNumber,PartitionNumber,Offset,Size | ConvertTo-Json -Compress"
        )
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True, timeout=60).stdout
            parts = out.split("<<<SPLIT>>>")
            ctx = {"virtual_disks": _load_json(parts[0] if len(parts) > 0 else ""),
                   "disks": _load_json(parts[1] if len(parts) > 1 else ""),
                   "partitions": _load_json(parts[2] if len(parts) > 2 else "")}
            self.windows_ctx = ctx
            return ctx
        except Exception as e:
            self.err(errors.E_NOT_ADMIN, errors.LEVEL_INFO,
                     f"Windows 上下文查询失败（不影响核心功能）: {e}", extra=str(e))
            return {}

    # ------------------------------------------------------------ 池扫描

    def scan_local_pool(self, on_progress: Optional[ProgressCB] = None) -> PoolScan:
        """枚举本机所有 PhysicalDrive，识别存储空间成员并聚合池信息。"""
        if not is_admin():
            raise PermissionError("需要管理员权限运行才能直读物理盘")

        disks = enumerate_physical_disks()
        paths = [d["path"] for d in disks]

        def _p(msg):
            if on_progress:
                on_progress(_new_progress("scan_meta", message=msg))

        members = []
        attempted: Dict[str, int] = {}
        pending_paths = list(paths)
        while pending_paths:
            next_paths = []
            for p in pending_paths:
                attempted[p] = attempted.get(p, 0) + 1
                _p(f"探测 {p} (第 {attempted[p]} 次)")
                try:
                    m = spaceport.scan_member(p)
                except OSError as e:
                    _p(f"  {p}: 读取失败 {e}")
                    if attempted[p] < 3:
                        time.sleep(2.0)
                        next_paths.append(p)
                    continue
                if m.pool_uuid:
                    members.append((p, m))
                elif m.notes:
                    _p(f"  {p}: {m.notes}")
                else:
                    _p(f"  {p}: 非池成员")
            if next_paths and attempted[next_paths[0]] < 3:
                time.sleep(2.0)
            pending_paths = next_paths
        if not members:
            raise RuntimeError("未在任何物理盘上找到存储空间元数据")

        pool_uuid = members[0][1].pool_uuid
        member_paths = [p for p, m in members if m.pool_uuid == pool_uuid]
        _p(f"识别到池 {pool_uuid.hex().upper()}，成员 {len(member_paths)} 块，聚合元数据…")

        pool = spaceport.scan_pool(member_paths, on_progress=lambda s: _p(s))
        self.pool = pool

        # 打开成员盘句柄（只读）
        for d in pool.disks:
            if d.device_path:
                try:
                    self.devices[d.disk_id] = RawDevice(d.device_path, d.sector_size or 512)
                except OSError as e:
                    self.err(errors.E_DEVICE_OPEN, errors.LEVEL_ERROR,
                             f"打开成员盘 {d.device_path} 失败: {e}", disk_id=d.disk_id)

        # Windows 上下文匹配分两步：先识别当前空间（不依赖组映射），再推断布局后匹配分区
        self._match_vd_identity(pool)

        # 布局推断：对匹配到 Windows 的空间推断布局（历史空间无活动映射）
        target = None
        for v in pool.virtual_disks:
            if v.windows_vd_number is not None and len(v.groups) >= len(pool.all_type4 or []) // max(1, len(pool.virtual_disks)):
                target = v
        if target is None:
            for v in pool.virtual_disks:
                if v.windows_vd_number is not None:
                    target = v
                    break
        if target is None:
            target = max(pool.virtual_disks, key=lambda v: len(v.groups)) if pool.virtual_disks else None
        if target is not None:
            layout.infer_layout(pool, target)
            notes = layout.validate_geometry(pool, target)
            for n in notes:
                self.err(errors.E_LAYOUT_UNRESOLVED, errors.LEVEL_WARN, n,
                         virtual_offset=-1, extra=target.name)
            self._match_partitions(pool, target)
        self.pool = pool
        return pool

    def _match_vd_identity(self, pool: PoolScan) -> None:
        ctx = self.windows_ctx or self.query_windows_context()
        vds = ctx.get("virtual_disks") or []
        disks = ctx.get("disks") or []
        if isinstance(vds, dict):
            vds = [vds]
        if isinstance(disks, dict):
            disks = [disks]
        spaces_disks = [d for d in disks if d.get("BusType") == "Spaces"]
        vd_number = None
        if len(spaces_disks) == 1:
            try:
                vd_number = int(spaces_disks[0].get("Number"))
            except Exception:
                vd_number = None
        matched = None
        for vd in pool.virtual_disks:
            uid = spaceport.guid_bytes_le_to_uniqueid(vd.uuid)
            vd.windows_unique_id = uid
            for wv in vds:
                wuid = str(wv.get("UniqueId", "")).upper().replace("{", "").replace("}", "")
                if wuid and wuid == uid:
                    matched = vd
                    vd.name = vd.name or str(wv.get("FriendlyName", ""))
                    try:
                        vd.raw_vd_size = int(wv.get("Size", 0)) or vd.raw_vd_size
                    except Exception:
                        pass
        if matched is None and len(pool.virtual_disks) == 1:
            matched = pool.virtual_disks[0]
        if matched is not None and vd_number is not None:
            matched.windows_vd_number = vd_number

    def _match_partitions(self, pool: PoolScan, vd: VirtualDiskInfo) -> None:
        ctx = self.windows_ctx or self.query_windows_context()
        parts = ctx.get("partitions") or []
        if isinstance(parts, dict):
            parts = [parts]
        if vd.windows_vd_number is None:
            return
        for wp in parts:
            if wp.get("DiskNumber") != vd.windows_vd_number:
                continue
            for part in self.enumerate_partitions(vd):
                if int(wp.get("Offset", -1)) == part.offset_vd and abs(int(wp.get("Size", 0)) - part.size) < 4096:
                    part.drive_letter = str(wp.get("DriveLetter") or "")

    # ------------------------------------------------------------ 虚拟盘分区

    def enumerate_partitions(self, vd: VirtualDiskInfo) -> List[PartitionInfo]:
        """解析虚拟盘 GPT（通过成员盘映射绕过抽象层读，或直读虚拟盘设备）。"""
        parts: List[PartitionInfo] = []
        reader = self._make_vreader(vd)
        if reader is None:
            return parts
        try:
            hdr = reader.read(512, 512)
        except Exception as e:
            self.err(errors.E_META_BAD, errors.LEVEL_ERROR, f"读取虚拟盘 GPT 失败: {e}")
            return parts
        if hdr[0:8] != b"EFI PART":
            self.err(errors.E_META_BAD, errors.LEVEL_WARN, "虚拟盘不是 GPT（可能是 MBR）")
            return parts
        entry_lba = int.from_bytes(hdr[0x48:0x50], "little")
        num = int.from_bytes(hdr[0x50:0x54], "little")
        esz = int.from_bytes(hdr[0x54:0x58], "little") or 128
        table = reader.read(entry_lba * 512, num * esz)
        for i in range(num):
            raw = table[i * esz:(i + 1) * esz]
            type_guid = raw[0:16]
            if type_guid == b"\x00" * 16:
                continue
            first, last = int.from_bytes(raw[0x20:0x28], "little"), int.from_bytes(raw[0x28:0x30], "little")
            name = raw[0x38:0x80].decode("utf-16-le", errors="replace").rstrip("\x00")
            p = PartitionInfo(
                index=i,
                type_guid="{" + __import__("uuid").UUID(bytes_le=type_guid).__str__().upper() + "}",
                part_guid="{" + __import__("uuid").UUID(bytes_le=raw[16:32]).__str__().upper() + "}",
                offset_vd=first * 512,
                size=(last - first + 1) * 512,
                name=name,
            )
            parts.append(p)
        self.partitions = parts
        return parts

    def _make_vreader(self, vd: VirtualDiskInfo, params: Optional[ReadParams] = None,
                      rules: Optional[ErrorRules] = None) -> Optional[VirtualReader]:
        params = params or ReadParams()
        rules = rules or ErrorRules()
        if not vd.groups:
            return None
        # 成员盘句柄优先；缺的盘记录错误
        missing = {d.disk_id for d in self.pool.disks if d.disk_id not in self.devices and d.device_path}
        for did in missing:
            self.err(errors.E_DEVICE_OPEN, errors.LEVEL_WARN,
                     f"成员盘 #{did} 句柄未打开", disk_id=did)
        return VirtualReader(self.pool, vd, self.devices, params, rules,
                             error_sink=self.error_sink)

    # ------------------------------------------------------------ 文件系统

    def open_volume(self, vd: VirtualDiskInfo, part: PartitionInfo,
                    params: Optional[ReadParams] = None,
                    rules: Optional[ErrorRules] = None) -> "NtfsVolumeAdapter":
        reader = self._make_vreader(vd, params, rules)
        if reader is None:
            raise RuntimeError("虚拟盘无映射数据（布局未解析）")
        self.volume = NtfsVolumeAdapter(vd, part, reader, self.error_sink)
        self.volume.open()
        return self.volume

    def scan_filesystem(self, on_progress: Optional[ProgressCB] = None,
                        record_progress: Optional[Callable[[int, int], None]] = None
                        ) -> Tuple[List[FileEntry], ScanStats]:
        if self.volume is None:
            raise RuntimeError("请先 open_volume")
        self.entries, self.stats = self.volume.scan(record_progress)
        if on_progress:
            on_progress(_new_progress("scan_fs", message="完成", phase_percent=100.0))
        return self.entries, self.stats

    # ------------------------------------------------------------ 导出

    def export(self, selection: List[FileEntry], cfg: ExportConfig,
               on_progress: Optional[ProgressCB] = None,
               cancel: Optional[Callable[[], bool]] = None) -> Tuple[int, int, List[str]]:
        """导出选中文件。返回 (成功数, 失败数, 输出路径列表)。"""
        if self.volume is None:
            raise RuntimeError("请先 open_volume")
        reader = self.volume.reader
        reader.zero_check = True

        files = [e for e in selection if not e.is_dir]
        total = sum(e.size for e in files)
        done = 0
        ok_count = 0
        fail_count = 0
        outputs: List[str] = []
        start_time = time.time()

        os.makedirs(cfg.dest_root, exist_ok=True)
        self._check_dest_safety(cfg.dest_root)

        for fe in files:
            if cancel is not None and cancel():
                raise AbortExportError("用户取消")
            if cfg.export_deleted is False and fe.deleted:
                continue
            if cfg.export_live is False and not fe.deleted:
                continue
            rel = self.volume.rel_path_of(fe)
            if not rel:
                fail_count += 1
                continue
            dest = _unique_dest(os.path.join(cfg.dest_root, _sanitize_rel(rel)),
                                cfg.error_rules.on_name_conflict, cfg.conflict_suffix)
            if dest is None:
                self.err(errors.E_NAME_CONFLICT, errors.LEVEL_INFO,
                         f"重名跳过: {rel}", file_path=rel, mft_ref=fe.mft_ref, action="skip")
                continue

            if on_progress:
                on_progress(_new_progress("export", message=rel,
                                          overall_done=done, overall_total=total,
                                          overall_percent=done * 100.0 / total if total else 0,
                                          current_file=rel, current_done=0,
                                          current_total=fe.size,
                                          current_percent=0))

            ok, file_done = self._export_one(fe, dest, cfg, on_progress,
                                             done, total, start_time, cancel)
            if ok:
                ok_count += 1
                outputs.append(dest)
            else:
                fail_count += 1
            done += fe.size

            if on_progress:
                elapsed = time.time() - start_time
                speed = done / elapsed if elapsed > 0 else 0
                eta = (total - done) / speed if speed > 0 else 0
                on_progress(_new_progress("export", message=rel,
                                          overall_done=done, overall_total=total,
                                          overall_percent=done * 100.0 / total if total else 0,
                                          speed=speed, eta=eta,
                                          current_file=rel, current_done=fe.size,
                                          current_total=fe.size, current_percent=100.0))

        return ok_count, fail_count, outputs

    def _export_one(self, fe: FileEntry, dest: str, cfg: ExportConfig,
                    on_progress: Optional[ProgressCB], done: int, total: int,
                    start_time: float, cancel: Optional[Callable[[], bool]] = None
                    ) -> Tuple[bool, int]:
        """导出单个文件，分块读取并回报进度。返回 (成功, 已写字节)。"""
        try:
            if fe.data_attr_flags & 0x4000:
                self.err(errors.E_FS_UNSUPPORTED, errors.LEVEL_WARN,
                         "文件为 EFS 加密，导出的是加密原始数据", file_path=dest,
                         mft_ref=fe.mft_ref, action="export_raw")
            if fe.data_attr_flags & 0x0001:
                self.err(errors.E_FS_UNSUPPORTED, errors.LEVEL_ERROR,
                         "文件为 NTFS 压缩属性，v1 不支持透明解压，已中止该文件",
                         file_path=dest, mft_ref=fe.mft_ref, action="abort_file")
                return False, 0

            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            written = 0
            chunk_mb = max(1, cfg.read_params.chunk_mb) * 1024 * 1024
            cluster = self.volume.cluster_size
            with open(dest, "wb") as f:
                if fe.resident_data is not None:
                    f.write(fe.resident_data)
                    written = len(fe.resident_data)
                else:
                    remaining = fe.size
                    for ri, run in enumerate(fe.runs):
                        if remaining <= 0:
                            break
                        if run.lcn < 0:  # sparse hole
                            take = min(remaining, run.clusters * cluster)
                            f.write(b"\x00" * take)
                            written += take
                            remaining -= take
                            self._emit_prog(on_progress, done + written, total,
                                            fe, start_time, written)
                            continue
                        take = min(remaining, run.clusters * cluster)
                        vol_off = run.lcn * cluster
                        pos = 0
                        while pos < take:
                            if cancel is not None and cancel():
                                raise AbortExportError("用户取消")
                            n = min(chunk_mb, take - pos)
                            chunk = self.volume.read_run(vol_off + pos, n, fe, ri)
                            f.write(chunk)
                            written += len(chunk)
                            pos += len(chunk)
                            remaining -= len(chunk)
                            self._emit_prog(on_progress, done + written, total,
                                            fe, start_time, written)
                    if remaining > 0 and fe.runs:
                        f.write(b"\x00" * remaining)
                        self.err(errors.E_CLUSTERS_MISSING, errors.LEVEL_WARN,
                                 f"数据流末尾缺 {remaining} 字节（run 覆盖不足），补 0",
                                 file_path=dest, mft_ref=fe.mft_ref, action="zero_fill")
            return True, written
        except AbortFileError as e:
            self.err(errors.E_EXPORT_ABORTED, errors.LEVEL_ERROR,
                     str(e), file_path=dest, mft_ref=fe.mft_ref, action="abort_file")
            _safe_remove(dest)
            return False, written
        except AbortExportError:
            _safe_remove(dest)
            raise
        except OSError as e:
            self.err(errors.E_EXPORT_IO, errors.LEVEL_ERROR,
                     f"写出失败: {e}", file_path=dest, mft_ref=fe.mft_ref, action="abort_file")
            _safe_remove(dest)
            return False, written

    def _emit_prog(self, on_progress, overall_done, total, fe, start_time, file_done):
        if on_progress is None:
            return
        elapsed = time.time() - start_time
        speed = overall_done / elapsed if elapsed > 0 else 0
        eta = (total - overall_done) / speed if speed > 0 else 0
        on_progress(_new_progress(
            "export", message=fe.path or fe.name,
            overall_done=overall_done, overall_total=total,
            overall_percent=overall_done * 100.0 / total if total else 0,
            speed=speed, eta=eta,
            current_file=fe.path or fe.name, current_done=file_done,
            current_total=fe.size,
            current_percent=file_done * 100.0 / fe.size if fe.size else 0))

    def _check_dest_safety(self, dest_root: str) -> None:
        """禁止把数据写回恢复源卷。"""
        dest = os.path.abspath(dest_root)
        dest_drive = os.path.splitdrive(dest)[0].upper()
        banned = []
        if self.volume and self.volume.drive_letter:
            banned.append(self.volume.drive_letter.upper() + ":")
        for wp in (self.windows_ctx.get("partitions") or []):
            dl = str(wp.get("DriveLetter") or "")
            if dl and any(p.drive_letter == dl for p in self.partitions):
                banned.append(dl.upper() + ":")
        if dest_drive in banned:
            raise RuntimeError(f"导出目标不能设在恢复源卷 {dest_drive}: 上")

    def close(self) -> None:
        for dev in self.devices.values():
            try:
                dev.close()
            except Exception:
                pass
        self.devices.clear()


# ------------------------------------------------------------ 卷适配器

class NtfsVolumeAdapter:
    """把 VirtualReader + 分区偏移适配成 NTFS 卷读取器。"""

    def __init__(self, vd: VirtualDiskInfo, part: PartitionInfo,
                 reader: VirtualReader, error_sink: ErrorCB):
        self.vd = vd
        self.part = part
        self.reader = reader
        self.error_sink = error_sink
        self.drive_letter = part.drive_letter
        self.ntfs: Optional[ntfs.NtfsVolume] = None
        self.cluster_size = 4096
        self._by_ref: Dict[int, FileEntry] = {}
        self._children: Dict[int, List[FileEntry]] = {}

    def open(self) -> None:
        def vread(vol_off, length, file_path="", mft_ref=-1, run_index=-1):
            return self.reader.read(self.part.offset_vd + vol_off, length,
                                    file_path=file_path, mft_ref=mft_ref, run_index=run_index)
        self.ntfs = ntfs.NtfsVolume(vread, error_sink=self.error_sink)
        self.ntfs.read_boot()
        self.ntfs.load_mft_map()
        self.cluster_size = self.ntfs.cluster_size

    def scan(self, record_progress=None) -> Tuple[List[FileEntry], ScanStats]:
        entries, stats = self.ntfs.scan_all(on_progress=None)
        self.ntfs.build_paths(entries)
        self.entries = entries
        for e in entries:
            self._by_ref[e.mft_ref] = e
            if e.deleted:
                self._children.setdefault(e.parent_ref, []).append(e)
        return entries, stats

    def read_run(self, vol_off: int, length: int, fe: FileEntry, run_index: int) -> bytes:
        return self.reader.read(self.part.offset_vd + vol_off, length,
                                file_path=fe.path or fe.name, mft_ref=fe.mft_ref,
                                run_index=run_index)

    def rel_path_of(self, fe: FileEntry) -> str:
        return fe.path or f"§孤儿文件\\MFT{fe.mft_ref}_{fe.name or 'unnamed'}"


# ------------------------------------------------------------ 工具

def _load_json(s: str):
    s = s.strip()
    if not s:
        return []
    try:
        return json.loads(s)
    except Exception:
        return []


def _sanitize_rel(rel: str) -> str:
    """目标路径净化：去除非法字符，保留目录结构。"""
    parts = rel.replace("/", "\\").split("\\")
    out = []
    illegal = '<>:"|?*'
    for seg in parts:
        if seg in ("", ".", ".."):
            continue
        seg = "".join("_" if c in illegal or ord(c) < 32 else c for c in seg)
        seg = seg.rstrip(". ")
        if not seg:
            seg = "_"
        out.append(seg)
    return "\\".join(out) if out else "_unnamed_"


def _unique_dest(dest: str, rule: str, suffix: str) -> Optional[str]:
    """按冲突规则返回最终路径；skip → None。"""
    if rule == "overwrite" or not os.path.exists(dest):
        return dest
    if rule == "skip":
        return None
    # rename
    base, ext = os.path.splitext(dest)
    for i in range(1, 1000):
        cand = f"{base}({suffix}{i}){ext}" if i > 1 else f"{base}({suffix}){ext}"
        if not os.path.exists(cand):
            return cand
    return f"{base}_{int(time.time())}{ext}"


def _safe_remove(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
