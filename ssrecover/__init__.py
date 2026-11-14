"""ssrecover — Windows 存储空间（Storage Spaces）已删除文件恢复后端。

设计要点：
- 本包不依赖任何 GUI 库；engine 通过回调上报进度/错误。
- 对源数据（物理盘/虚拟盘/卷）的全部操作均为只读。
- 布局依据 SpacePort 元数据（SPACEDB/SDBC/SDBB，参考 KimVegetable/SSR 逆向结论）。
"""

__version__ = "0.1.0"

# 全局常量
INTERLEAVE_DEFAULT = 0x40000          # 256KB 条带单元
BLOCK = 0x10000000                    # 256MB 物理块（slab 定位单位，元数据占前 2 块）
SLAB_BYTES_V10 = 0x10000000           # Win10+ 单盘 slab 256MB
SLAB_BYTES_V8 = 0x40000000            # Win8/2012 单盘 slab 1GB
