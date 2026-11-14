"""Windows 原始设备只读访问层（\\.\PhysicalDriveN / \\.\X:）。

仅使用 GENERIC_READ 打开设备，绝不请求写权限；读写均为扇区对齐。
句柄管理使用显式 restype/argtypes（64 位句柄安全）。
"""
from __future__ import annotations

import ctypes
import time
from typing import Dict, List, Optional

GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
FILE_SHARE_DELETE = 0x4
INVALID_HANDLE = ctypes.c_void_p(-1).value  # 0xFFFFFFFFFFFFFFFF

IOCTL_STORAGE_GET_DRIVE_GEOMETRY = 0x000700A0
IOCTL_DISK_GET_LENGTH_INFO = 0x000740C4

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

kernel32.CreateFileW.restype = ctypes.c_void_p
kernel32.CreateFileW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                 ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                 ctypes.c_void_p]
kernel32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                              ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
kernel32.SetFilePointerEx.argtypes = [ctypes.c_void_p, ctypes.c_int64,
                                      ctypes.POINTER(ctypes.c_int64), ctypes.c_uint32]
kernel32.DeviceIoControl.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                     ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                                     ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]


class DISK_GEOMETRY(ctypes.Structure):
    _fields_ = [
        ("Cylinders", ctypes.c_int64),
        ("MediaType", ctypes.c_uint32),
        ("TracksPerCylinder", ctypes.c_uint32),
        ("SectorsPerTrack", ctypes.c_uint32),
        ("BytesPerSector", ctypes.c_uint32),
    ]


class GET_LENGTH_INFORMATION(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_int64)]


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


class RawDevice:
    """一个物理盘/卷设备的只读句柄。"""

    def __init__(self, device_path: str, sector_size: int = 512):
        self.device_path = device_path
        self.sector_size = sector_size
        self.size = 0
        self.handle = kernel32.CreateFileW(
            device_path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None, OPEN_EXISTING, 0, None)
        if self.handle is None or self.handle == INVALID_HANDLE:
            err = ctypes.get_last_error()
            raise OSError(f"无法打开设备 {device_path}（错误码 {err}；"
                          + ("需要管理员权限运行" if err == 5 else "设备不存在或被独占") + "）")
        self._query_geometry()

    def _query_geometry(self) -> None:
        g = DISK_GEOMETRY()
        got = ctypes.c_ulong(0)
        if kernel32.DeviceIoControl(self.handle, IOCTL_STORAGE_GET_DRIVE_GEOMETRY,
                                    None, 0, ctypes.byref(g), ctypes.sizeof(g),
                                    ctypes.byref(got), None):
            self.sector_size = g.BytesPerSector or 512
            # 容量 = 几何乘积（GET_LENGTH_INFO 在部分设备上不可用）
            geo_size = (g.Cylinders * g.TracksPerCylinder * g.SectorsPerTrack
                        * g.BytesPerSector)
            li = GET_LENGTH_INFORMATION()
            if kernel32.DeviceIoControl(self.handle, IOCTL_DISK_GET_LENGTH_INFO,
                                        None, 0, ctypes.byref(li), ctypes.sizeof(li),
                                        ctypes.byref(got), None):
                self.size = li.Length & 0xFFFFFFFFFFFFFFFF
            elif geo_size > 0:
                self.size = geo_size

    def read(self, offset: int, length: int, spinup_retries: int = 5) -> bytes:
        """任意偏移读取；内部对齐到扇区。HDD 停转（err 21/1117）时等待重试。"""
        if length <= 0:
            return b""
        if offset < 0 or (self.size and offset >= self.size):
            raise OSError(f"读取偏移越界: offset={offset} size={self.size} dev={self.device_path}")
        sector = self.sector_size
        aligned_off = (offset // sector) * sector
        end = min(offset + length, self.size) if self.size else offset + length
        total = ((end - aligned_off + sector - 1) // sector) * sector
        attempt = 0
        while True:
            buf = ctypes.create_string_buffer(total)
            got = ctypes.c_ulong(0)
            li = ctypes.c_int64(aligned_off)
            if not kernel32.SetFilePointerEx(self.handle, li, None, 0):  # FILE_BEGIN
                raise OSError(f"SetFilePointerEx 失败 dev={self.device_path} off={aligned_off} err={ctypes.get_last_error()}")
            if not kernel32.ReadFile(self.handle, buf, total, ctypes.byref(got), None):
                err = ctypes.get_last_error()
                if err in (21, 1117) and attempt < spinup_retries:
                    # ERROR_NOT_READY / ERROR_IO_DEVICE —— 磁盘可能正在启动
                    time.sleep(2.0 * (attempt + 1))
                    attempt += 1
                    continue
                raise OSError(f"ReadFile 失败 dev={self.device_path} off={aligned_off} len={total} err={err}")
            if got.value < end - aligned_off:
                raise OSError(f"读取不完整 dev={self.device_path} off={aligned_off} "
                              f"期望{end - aligned_off} 实得{got.value}")
            break
        start = offset - aligned_off
        return buf.raw[start:start + (end - offset)]

    def read_aligned(self, offset: int, length: int, retries: int = 0) -> bytes:
        """带重试的读取（offset/length 建议扇区对齐）。"""
        err: Optional[OSError] = None
        for attempt in range(retries + 1):
            try:
                return self.read(offset, length)
            except OSError as e:
                err = e
        raise err  # type: ignore[misc]

    def close(self) -> None:
        if getattr(self, "handle", None):
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self) -> "RawDevice":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def enumerate_physical_disks(max_index: int = 64, max_miss: int = 8) -> List[dict]:
    """枚举 \\.\PhysicalDriveN。连续 max_miss 个设备不可用即停止。

    打开成功且能读到引导区的设备才收录；对不存在/无效设备快速失败。
    """
    result: List[dict] = []
    miss = 0
    for i in range(max_index):
        path = f"\\\\.\\PhysicalDrive{i}"
        try:
            dev = RawDevice(path)
        except OSError:
            miss += 1
            if miss >= max_miss and result:
                break
            continue
        try:
            # 验证设备可读（读 LBA0）
            try:
                dev.read(0, 512)
            except OSError:
                miss += 1
                if miss >= max_miss and result:
                    break
                continue
            miss = 0
            result.append({"index": i, "path": path, "size": dev.size,
                           "sector_size": dev.sector_size})
        finally:
            dev.close()
    return result
