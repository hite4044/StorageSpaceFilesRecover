"""读取参数与遇错规则配置。"""
from __future__ import annotations

from dataclasses import dataclass, field


# 遇错动作
ON_ERROR_ZERO_FILL = "zero_fill"      # 记录错误并填 0 继续
ON_ERROR_ABORT_FILE = "abort_file"    # 中止当前文件
ON_ERROR_RECONSTRUCT = "reconstruct"  # 先尝试 XOR 校验重建，失败再按上层规则
ON_ERROR_STOP = "stop"                # 中止整个导出


@dataclass
class ReadParams:
    chunk_mb: int = 4                 # 每次物理读取大小（MB）
    max_retries: int = 3              # 物理读失败重试次数
    verify_zero_regions: bool = True  # 检测读出全 0 区域并记录
    compare_with_windows: bool = False  # 与 \\.\R: 直读比对（校验是否被复用覆盖）
    use_parity_rebuild: bool = True   # 允许 XOR 校验重建


@dataclass
class ErrorRules:
    unreadable: str = ON_ERROR_RECONSTRUCT   # 物理读失败
    zero_region: str = ON_ERROR_ZERO_FILL    # 全 0 可疑区域（导出已删除数据时多为正常，仅记录）
    two_units_bad: str = ON_ERROR_ZERO_FILL  # 校验重建也不可行
    fs_corrupt: str = ON_ERROR_ABORT_FILE    # NTFS 元数据损坏

    # 导出文件名冲突策略
    on_name_conflict: str = "rename"         # rename / overwrite / skip


@dataclass
class ExportConfig:
    dest_root: str = ""
    export_deleted: bool = True       # 导出已删除文件
    export_live: bool = True          # 导出现存文件
    conflict_suffix: str = "恢复"     # 重名时后缀 name(恢复).ext
    read_params: ReadParams = field(default_factory=ReadParams)
    error_rules: ErrorRules = field(default_factory=ErrorRules)
    write_buffer_mb: int = 8
