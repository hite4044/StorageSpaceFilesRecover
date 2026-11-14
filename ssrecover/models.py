"""数据模型：扫描结果、文件项、错误记录。"""
from __future__ import annotations

import time as _time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple


# ---------------------------------------------------------------- 元数据层

@dataclass
class PhysicalDiskInfo:
    """池成员物理盘（来自 SDBB type2 + 本机设备匹配）。"""
    disk_id: int                  # 元数据里的物理盘 ID
    uuid: bytes                   # 16B
    name: str                     # 元数据里的名称
    block_count: int              # 256MB 块数（元数据）
    device_path: Optional[str] = None   # \\.\PhysicalDriveN（匹配到本机时）
    window_name: str = ""               # Windows 侧型号（可选）
    partition_start: int = 0            # 存储空间分区起点（字节）
    sector_size: int = 512
    disk_size: int = 0


@dataclass
class Run:
    """NTFS 非常驻数据 run：卷内逻辑簇号 + 簇数。"""
    lcn: int
    clusters: int


@dataclass
class SlabGroup:
    """一个 parity/striped slab 组：组起始虚拟块号 → 各列映射。

    entries[parity_seq] = (disk_id, phys_block)
    """
    vblock: int
    entries: Dict[int, Tuple[int, int]] = field(default_factory=dict)

    def by_disk(self, disk_id: int) -> Optional[Tuple[int, int]]:
        for seq, val in self.entries.items():
            if val[0] == disk_id:
                return val
        return None


@dataclass
class VirtualDiskInfo:
    """池中的一个空间（虚拟磁盘，SDBB type3）。"""
    vd_id: int
    uuid: bytes
    name: str
    description: str
    block_count: int            # 元数据块数（解释随布局不同）
    raw_vd_size: int            # 由布局换算后的虚拟容量（字节）

    # 布局（由 layout.infer_layout 填写）
    mode: str = ""              # CONCAT / STRIPED / MIRROR / PARITY / DPARITY
    ncols: int = 0
    parity_cols: int = 0
    interleave: int = 0x40000
    slab_bytes: int = 0         # 每盘每组顺序消耗字节
    rows: int = 0               # 每组行数
    group_vblocks: int = 0      # 每组覆盖的 256MB 虚拟块数
    group_start_vblocks: List[int] = field(default_factory=list)
    groups: Dict[int, SlabGroup] = field(default_factory=dict)  # vblock -> SlabGroup
    rotation: str = "desc"      # 校验列旋转方向（校准后确定）："desc"/"asc"/"pair_desc"
    parity_xor_index: int = 0   # dual parity 中 P 在校验对内的位置（0/1，校准后确定）
    windows_vd_number: Optional[int] = None   # 匹配到的本机虚拟磁盘 DiskNumber
    windows_unique_id: str = ""


@dataclass
class PartitionInfo:
    """虚拟磁盘上的分区（自行解析虚拟盘 GPT）。"""
    index: int
    type_guid: str
    part_guid: str
    offset_vd: int              # 相对虚拟盘起点（字节）
    size: int
    name: str
    drive_letter: str = ""      # 与 Windows 匹配到的盘符（如 "R"）
    fs_guess: str = ""


@dataclass
class PoolScan:
    pool_uuid: bytes
    disks: List[PhysicalDiskInfo]
    virtual_disks: List[VirtualDiskInfo]
    windows_pool_name: str = ""
    meta_version: str = ""      # win8 / win10+ / unknown
    all_type4: List[dict] = field(default_factory=list)   # 全部 slab 映射记录（未分空间）
    notes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------- NTFS 层

@dataclass
class FileEntry:
    mft_ref: int
    seq: int
    parent_ref: int
    name: str
    path: str = ""              # 扫描后统一计算
    is_dir: bool = False
    deleted: bool = False
    size: int = 0               # $DATA EOF（文件实际大小）
    alloc_size: int = 0
    times: Tuple[int, int, int] = (0, 0, 0)   # (created, modified, accessed) FILETIME
    dos_attrs: int = 0
    runs: List[Run] = field(default_factory=list)
    resident_data: Optional[bytes] = None     # 常驻 $DATA
    resident_offset: int = 0                  # 在其 MFT 记录内的偏移（供读取）
    mft_record_offset: int = 0                # 该记录在 $MFT 数据流中的字节偏移
    data_attr_flags: int = 0                  # 压缩/加密/稀疏标志
    has_attribute_list: bool = False
    object_id: str = ""
    load_error: str = ""                      # 记录解析中的非致命问题


@dataclass
class ScanStats:
    total_records: int = 0
    files: int = 0
    dirs: int = 0
    deleted_files: int = 0
    deleted_dirs: int = 0
    orphans: int = 0
    total_bytes: int = 0
    deleted_bytes: int = 0


# ---------------------------------------------------------------- 错误

@dataclass
class ErrorRecord:
    code: str
    level: str
    message: str
    seq: int = 0
    time: float = field(default_factory=_time.time)
    file_path: str = ""
    mft_ref: int = -1
    run_index: int = -1
    volume_offset: int = -1       # 卷内字节偏移
    virtual_offset: int = -1      # 虚拟盘内字节偏移
    disk_id: int = -1
    disk_name: str = ""
    disk_path: str = ""
    physical_offset: int = -1     # 物理盘内字节偏移（绝对）
    length: int = 0
    action: str = ""              # 采取的动作
    retries: int = 0
    extra: str = ""

    def brief(self) -> str:
        return f"[{self.level}] {self.code}: {self.message}"

    def detail(self) -> str:
        lines = [
            f"时间: {_time.strftime('%Y-%m-%d %H:%M:%S', _time.localtime(self.time))}",
            f"级别/错误码: {self.level} / {self.code}",
            f"描述: {self.message}",
            f"文件: {self.file_path or '-'} (MFT#{self.mft_ref})",
            f"Run# : {self.run_index}",
            f"卷内偏移: {self.volume_offset} (0x{self.volume_offset:X})" if self.volume_offset >= 0 else "卷内偏移: -",
            f"虚拟盘偏移: {self.virtual_offset} (0x{self.virtual_offset:X})" if self.virtual_offset >= 0 else "虚拟盘偏移: -",
            f"物理盘: #{self.disk_id} {self.disk_name} ({self.disk_path})" if self.disk_id >= 0 else "物理盘: -",
            f"物理偏移: {self.physical_offset} (0x{self.physical_offset:X})" if self.physical_offset >= 0 else "物理偏移: -",
            f"长度: {self.length}",
            f"动作: {self.action or '-'} (重试 {self.retries} 次)",
        ]
        if self.extra:
            lines.append(f"附加: {self.extra}")
        return "\n".join(lines)


# ---------------------------------------------------------------- 进度

@dataclass
class Progress:
    """双进度 + 阶段信息（engine 回调负载）。"""
    phase: str = ""               # scan_meta / scan_fs / export ...
    phase_percent: float = -1     # 阶段内百分比（-1 表示不定）
    message: str = ""

    # 总体（导出阶段：全部选中文件的字节进度）
    overall_done: int = 0
    overall_total: int = 0
    overall_percent: float = -1
    speed: float = 0.0            # B/s
    eta: float = 0.0              # 秒

    # 当前文件
    current_file: str = ""
    current_done: int = 0
    current_total: int = 0
    current_percent: float = -1
