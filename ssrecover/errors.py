"""错误码定义。

ErrorRecord.code 取以下之一；level 为 INFO/WARN/ERROR/FATAL。
"""

# —— 访问/环境 ——
E_NOT_ADMIN = "E_NOT_ADMIN"                 # 非管理员，无法打开物理盘
E_DEVICE_OPEN = "E_DEVICE_OPEN"             # 设备打开失败
E_DEVICE_READ = "E_DEVICE_READ"             # 设备读取失败（重试后仍失败）
E_META_MISSING = "E_META_MISSING"           # 未找到存储空间元数据
E_META_BAD = "E_META_BAD"                   # 元数据解析异常
E_LAYOUT_UNRESOLVED = "E_LAYOUT_UNRESOLVED" # 布局推断失败/歧义
E_VERSION_UNKNOWN = "E_VERSION_UNKNOWN"     # 未知 Windows 元数据版本
E_FS_UNSUPPORTED = "E_FS_UNSUPPORTED"       # 文件系统不支持
E_BOOT_BAD = "E_BOOT_BAD"                   # NTFS 引导扇区异常

# —— NTFS ——
E_MFT_RECORD = "E_MFT_RECORD"               # MFT 记录损坏（fixup 校验失败等）
E_RUNS_BAD = "E_RUNS_BAD"                   # runlist 解码失败
E_ATTR_BAD = "E_ATTR_BAD"                   # 属性解析异常
E_CLUSTERS_MISSING = "E_CLUSTERS_MISSING"   # 数据簇超出已映射范围（元数据缺失/未分配）
E_DATA_ZEROFILLED = "E_DATA_ZEROFILLED"     # 读出的区域全 0（可能已被清零/覆盖）
E_DATA_OVERWRITTEN = "E_DATA_OVERWRITTEN"   # 物理读与 Windows 读不一致，疑似被复用覆盖

# —— 导出 ——
E_EXPORT_IO = "E_EXPORT_IO"                 # 写出失败
E_EXPORT_ABORTED = "E_EXPORT_ABORTED"       # 按遇错规则中止该文件
E_PARITY_REBUILD = "E_PARITY_REBUILD"       # 校验重建成功/失败记录
E_PARITY_INSUFFICIENT = "E_PARITY_INSUFFICIENT"  # 2 个以上单元损坏，无法用 P 重建
E_NAME_CONFLICT = "E_NAME_CONFLICT"         # 目标重名处理记录

LEVEL_INFO = "INFO"
LEVEL_WARN = "WARN"
LEVEL_ERROR = "ERROR"
LEVEL_FATAL = "FATAL"
