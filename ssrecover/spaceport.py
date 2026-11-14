"""SpacePort 元数据解析（真实盘实测格式，2026-11 于 Win11 5 列 parity 池标定）。

成员盘布局（GPT 存储空间分区起点 pstart，分区类型 {E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D}）：
  pstart+0x0000   SPACEDB（读 0x1000）
                    0x00 签名 b'SPACEDB '
                    Win10+: 0x18 格式化时间(u64BE) 0x20 池GUID(16B 原始序)
                            0x30 本盘GUID(16B 原始序)
                    Win8/2012: 0x10 池GUID 0x20 本盘GUID 0x58 时间
  pstart+0x1000   SDBC（512B）
                    0x00 b'SDBC    '  0x10 池GUID  0x24 条目大小(u32BE)
                    0x28 下一条目号(u32BE)  0x48 修改时间(u64BE)
  pstart+0x1200   SDBB 槽数组（每槽 0x40B，槽数 = 下一条目号-8+预留）
                    [0:4]=b'SDBB' [4:8]=rec_no(BE) [8:12]=entry_no(BE,0=空)
                    [12:16]=片段数(BE) [16:0x40]=载荷 0x30B
                    同 entry_no 的片段按 rec_no 顺序拼接成记录：
                      记录[0]=类型(1..7)，其后为 TLV 链（[len][val]，len=0 为空TLV）
  数据 slab：pstart + (phys_block+2)×256MB + row×256KB

记录类型：
  type1 池信息（含池GUID）
  type2 物理盘：[08][8B 尾字节=盘ID][02][常量][16B 盘GUID(原始序)]
                [字符串 UTF-16BE，长度=字符数含NUL][05][盘容量][05][可用容量]
  type3 虚拟盘：[11][17B 头][02][常量][16B 空间GUID(bytes_le!)]
                [名称/描述字符串][块数等]
  type4 (D==143) slab 映射：
                [04][06][6B 代][00][02 分配序][00][00][01 1][01 143]
                [E 组起始vblock len0/1/2][seq 列号 len0/1][skip][04 mirror=FFFFFFFF]
                [01 盘ID][物理块号 len1/2]
  type7 空间的成员盘清单（空间级 store）

所有整数大端。空间 GUID 用 bytes_le（与 Windows UniqueId 对应）。
"""
from __future__ import annotations

import struct
import uuid as _uuid
from typing import Dict, List, Optional, Tuple

from .models import PhysicalDiskInfo, VirtualDiskInfo, PoolScan, SlabGroup
from .rawdisk import RawDevice

SPACEDB_SIG = b"SPACEDB "
SDBC_SIG = b"SDBC    "
META_WINDOW = 0x400000          # 池 store 读取窗口（4MB，覆盖 23973 槽 + 余量）


def be_uint(buf: bytes) -> int:
    return int.from_bytes(buf, "big")


def guid_raw_to_str(b: bytes) -> str:
    """原始序 16B → 十六进制串（用于池/盘 GUID 匹配）。"""
    return b.hex().upper()


def guid_bytes_le_to_uniqueid(b: bytes) -> str:
    """bytes_le GUID → Windows UniqueId 风格（无连字符大写）。"""
    try:
        return str(_uuid.UUID(bytes_le=b)).replace("-", "").upper()
    except Exception:
        return ""


# ---------------------------------------------------------------- GPT

class GptEntry:
    __slots__ = ("index", "type_guid", "part_guid", "first_lba", "last_lba", "name")

    def __init__(self, index, type_guid, part_guid, first_lba, last_lba, name):
        self.index = index
        self.type_guid = type_guid
        self.part_guid = part_guid
        self.first_lba = first_lba
        self.last_lba = last_lba
        self.name = name

    @property
    def offset(self) -> int:
        return self.first_lba * 512

    @property
    def size(self) -> int:
        return (self.last_lba - self.first_lba + 1) * 512


SPACES_PART_TYPE = "{E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D}"


def parse_gpt(dev: RawDevice) -> List[GptEntry]:
    hdr = dev.read(512, 512)
    if hdr[0:8] != b"EFI PART":
        return []
    entry_lba = struct.unpack_from("<Q", hdr, 0x48)[0]
    num_entries = struct.unpack_from("<I", hdr, 0x50)[0]
    entry_size = struct.unpack_from("<I", hdr, 0x54)[0] or 128
    table = dev.read(entry_lba * 512, num_entries * entry_size)
    entries: List[GptEntry] = []
    for i in range(num_entries):
        raw = table[i * entry_size:(i + 1) * entry_size]
        if raw[0:16] == b"\x00" * 16:
            continue
        first_lba, last_lba = struct.unpack_from("<QQ", raw, 0x20)
        name = raw[0x38:0x80].decode("utf-16-le", errors="replace").rstrip("\x00")
        entries.append(GptEntry(i, _guid_str(raw[0:16]), _guid_str(raw[16:32]),
                                first_lba, last_lba, name))
    return entries


def _guid_str(b: bytes) -> str:
    return "{" + str(_uuid.UUID(bytes_le=b)).upper() + "}"


# ---------------------------------------------------------------- 单盘扫描

class MemberScan:
    """一个成员盘的元数据解析结果。"""

    def __init__(self, device_path: str, device_size: int = 0):
        self.device_path = device_path
        self.device_size = device_size
        self.sector_size = 512
        self.partition = None
        self.partition_start = 0
        self.meta_version = "unknown"
        self.pool_uuid = b""
        self.disk_uuid = b""
        self.format_time = 0
        self.sdbc_entry_size = 0
        self.next_sdbb_entry_number = 0
        self.sdbc_modified_time = 0
        self.store_present = False    # 本盘是否携带 SDBC/SDBB store 副本
        self.records: Dict[str, List[Tuple[int, bytes]]] = {"1": [], "2": [], "3": [],
                                                            "4": [], "7": []}
        self.record_count = 0
        self.empty_slots = 0
        self.notes: List[str] = []

    def parse(self) -> bool:
        with RawDevice(self.device_path) as dev:
            self.sector_size = dev.sector_size
            entries = parse_gpt(dev)
            for e in entries:
                try:
                    if dev.read(e.offset, 8) == SPACEDB_SIG:
                        self.partition = e
                        self.partition_start = e.offset
                        break
                except OSError:
                    continue
            if self.partition is None:
                return False
            window = dev.read(self.partition_start, META_WINDOW)
        return self._parse_window(window)

    def _parse_window(self, w: bytes) -> bool:
        if w[0:8] != SPACEDB_SIG:
            self.notes.append("SPACEDB 签名不匹配")
            return False
        # 先取 SPACEDB 头部标识（部分成员盘没有 store 副本，SDBC/SDBB 为空）
        pool_from_sdbc = w[0x1000:0x1008]
        if w[0x1000:0x1008] == SDBC_SIG and w[0x1010:0x1020] == w[0x20:0x30]:
            self.meta_version = "win10+"
            self.format_time = be_uint(w[0x18:0x20])
            self.pool_uuid = w[0x20:0x30]
            self.disk_uuid = w[0x30:0x40]
            self.store_present = True
        elif w[0x1010:0x1020] == w[0x20:0x30] and w[0x20:0x30] != b"\x00" * 16:
            self.meta_version = "win10+"
            self.pool_uuid = w[0x20:0x30]
            self.disk_uuid = w[0x30:0x40]
            self.format_time = be_uint(w[0x18:0x20])
            self.store_present = False
            self.notes.append("本盘无 store 副本（仅 SPACEDB 头）")
        elif w[0x1010:0x1020] == w[0x10:0x20] and w[0x10:0x20] != b"\x00" * 16:
            self.meta_version = "win8"
            self.pool_uuid = w[0x10:0x20]
            self.disk_uuid = w[0x20:0x30]
            self.format_time = be_uint(w[0x58:0x60])
            self.store_present = True
        else:
            self.meta_version = "unknown"
            self.pool_uuid = w[0x20:0x30]
            self.disk_uuid = w[0x30:0x40]
            self.store_present = w[0x1000:0x1008] == SDBC_SIG
            self.notes.append("SPACEDB 版本无法自动识别")
            return False

        if not self.store_present:
            return True
        sdbc = w[0x1000:0x1200]
        self.sdbc_entry_size = be_uint(sdbc[0x24:0x28])
        self.next_sdbb_entry_number = be_uint(sdbc[0x28:0x2C])
        self.sdbc_modified_time = be_uint(sdbc[0x48:0x50])
        self._parse_sdbb(w[0x1200:])
        return True

    def _parse_sdbb(self, frag_area: bytes) -> None:
        n = max(self.next_sdbb_entry_number, 8)
        buckets: Dict[int, List[Tuple[int, bytes]]] = {}
        for i in range(n):
            off = i * 0x40
            if off + 0x40 > len(frag_area):
                break
            slot = frag_area[off:off + 0x40]
            if slot[0:4] != b"SDBB":
                break
            rec_no = be_uint(slot[4:8])
            entry_no = be_uint(slot[8:12])
            if entry_no == 0:
                self.empty_slots += 1
                continue
            buckets.setdefault(entry_no, []).append((rec_no, slot[16:0x40]))
            self.record_count += 1
        for entry_no, frags in buckets.items():
            frags.sort(key=lambda x: x[0])
            payload = b"".join(f for _, f in frags)
            rtype = payload[0] if payload else 0
            if str(rtype) in self.records:
                self.records[str(rtype)].append((entry_no, payload))


# ---------------------------------------------------------------- TLV 记录解析

def _utf16be_strings(rec: bytes, start: int) -> List[str]:
    """启发式提取 UTF-16BE 字符串（拉丁 + CJK 文本对，≥2 字符）。"""
    out = []
    i = start
    n = len(rec)

    def text_pair(hi: int, lo: int) -> bool:
        if hi == 0x00:
            return 0x20 <= lo < 0x100
        if 0x20 <= hi <= 0x9F:   # CJK/常见文字区
            return True
        return False

    while i + 3 < n:
        if text_pair(rec[i], rec[i + 1]):
            j = i
            chars = []
            while j + 1 < n and text_pair(rec[j], rec[j + 1]):
                chars.append(chr((rec[j] << 8) | rec[j + 1]))
                j += 2
            if len(chars) >= 2:
                out.append("".join(chars).rstrip("\x00"))
                i = j
                continue
        i += 1
    return out


def parse_type2(rec: bytes) -> Optional[dict]:
    """[02][08][8B 尾字节=盘ID][02][xx][16B GUID][字符串们][05 容量][05 可用]"""
    try:
        if rec[0] != 2 or rec[1] != 8:
            return None
        disk_id = rec[9]
        uuid = rec[13:29]
        size = usable = None
        off = 29
        while off + 6 <= len(rec):
            ln = rec[off]
            if ln == 5:
                v = be_uint(rec[off + 1:off + 6])
                if v > 10 ** 11:
                    if size is None:
                        size = v
                    else:
                        usable = v
                off += 6
            elif ln == 0:
                off += 1
            else:
                off += 1 + ln  # 字符串/其他字段按字节跳过（不精确但安全）
        strings = _utf16be_strings(rec, 29)
        name = max(strings, key=len) if strings else ""
        serial = ""
        for s in strings:
            if s != name and len(s) >= 5:
                serial = s
                break
        return {"disk_id": disk_id, "uuid": uuid, "name": name,
                "serial": serial, "size": size, "usable": usable}
    except Exception:
        return None


def parse_type3(rec: bytes) -> Optional[dict]:
    """[03][11][8B 尾字节=空间ID][02][xx][16B GUID bytes_le][名称/描述字符串]..."""
    try:
        if rec[0] != 3 or rec[1] != 0x11:
            return None
        vd_id = rec[9]
        uuid = rec[13:29]
        strings = _utf16be_strings(rec, 29)
        name = max(strings, key=len) if strings else ""
        desc = ""
        for s in strings:
            if s != name:
                desc = s
                break
        return {"vd_id": vd_id, "uuid": uuid, "name": name,
                "description": desc, "block_count": 0}
    except Exception:
        return None


def parse_type4(rec: bytes) -> Optional[dict]:
    """严格解析 slab 映射记录（D==vd_id）。返回 None 表示非映射记录。"""
    try:
        if rec[0] != 4 or rec[1] != 6:
            return None
        off = 1
        D = rec[17] if len(rec) > 17 else -1

        def tlv(expect=None):
            nonlocal off
            ln = rec[off]
            if expect is not None and ln != expect:
                raise ValueError()
            val = rec[off + 1:off + 1 + ln]
            off += 1 + ln
            return int.from_bytes(val, "big") if ln else 0

        tlv(6)          # 代
        tlv(0)
        alloc_seq = tlv(2)
        tlv(0)
        tlv(0)
        tlv(1)          # C
        tlv(1)          # D
        E = tlv()       # len 0/1/2
        seq = tlv()     # len 0/1
        tlv()           # skip
        mirror = tlv(4)
        disk = tlv(1)
        phys = tlv()    # len 1/2
        return {"D": D, "alloc_seq": alloc_seq, "E": E, "seq": seq,
                "mirror": mirror, "disk": disk, "phys": phys}
    except Exception:
        return None


def parse_type1(rec: bytes) -> Optional[dict]:
    try:
        if rec[0] != 1:
            return None
        # 池 GUID 在载荷中的位置：[10] 后第 10 字节起 16B（实测）
        # 更稳的方法：在记录中搜索与 SDBC 一致的 GUID 由调用方完成
        return {"raw": rec}
    except Exception:
        return None


def parse_type7(rec: bytes) -> Optional[dict]:
    """[07][01][6B][02][xx][01][05][16B GUID × 5] — 空间成员盘清单。"""
    try:
        if rec[0] != 7:
            return None
        # 找 [01][05] 后的 5 个 16B GUID
        uuids = []
        for off in range(2, min(24, len(rec) - 2)):
            if rec[off] == 1 and off + 1 < len(rec) and rec[off + 1] in (4, 5, 6, 8):
                cnt = rec[off + 1]
                p = off + 2
                good = True
                lst = []
                for k in range(cnt):
                    if p + 16 > len(rec):
                        good = False
                        break
                    lst.append(rec[p:p + 16])
                    p += 16
                if good and lst:
                    uuids = lst
                    break
        return {"disk_uuids": uuids}
    except Exception:
        return None


# ---------------------------------------------------------------- 池聚合

def scan_member(device_path: str, device_size: int = 0) -> MemberScan:
    m = MemberScan(device_path, device_size)
    m.parse()
    return m


def scan_pool(device_paths: List[str], on_progress=None) -> PoolScan:
    members: List[MemberScan] = []
    for i, p in enumerate(device_paths):
        try:
            m = scan_member(p)
        except OSError as e:
            if on_progress:
                on_progress(f"跳过 {p}: {e}")
            continue
        if m.pool_uuid:
            members.append(m)
        if on_progress:
            on_progress(f"已解析 {p} ({m.meta_version}, 记录 {m.record_count})")
    if not members:
        raise RuntimeError("未在任何设备上找到存储空间元数据")

    pools: Dict[bytes, List[MemberScan]] = {}
    for m in members:
        pools.setdefault(m.pool_uuid, []).append(m)
    pool_uuid, group = max(pools.items(), key=lambda kv: len(kv[1]))

    scan = PoolScan(pool_uuid=pool_uuid, disks=[], virtual_disks=[])
    scan.meta_version = group[0].meta_version
    scan.notes.extend(group[0].notes)
    scan.windows_pool_name = ""

    # 池名来自 type1/GPT 分区名（分区名 = 池名，实测 "Resoures"）
    for m in group:
        if m.partition is not None and m.partition.name:
            scan.windows_pool_name = m.partition.name
            break

    master = max(group, key=lambda m: len(m.records["4"]) + len(m.records["2"]))

    uuid_to_dev: Dict[bytes, str] = {}
    for m in group:
        uuid_to_dev[m.disk_uuid] = m.device_path

    # type2 → 物理盘
    for entry_no, rec in master.records["2"]:
        d = parse_type2(rec)
        if not d:
            continue
        info = PhysicalDiskInfo(
            disk_id=d["disk_id"], uuid=d["uuid"], name=d["name"] or d["serial"],
            block_count=d.get("usable") or 0,
            device_path=uuid_to_dev.get(d["uuid"]),
        )
        for m in group:
            if m.disk_uuid == d["uuid"]:
                info.partition_start = m.partition_start
                info.sector_size = m.sector_size
                break
        scan.disks.append(info)
    scan.disks.sort(key=lambda d: d.disk_id)

    # type3 → 虚拟盘（vd_id = 记录 8B 字段尾字节；type4 的 D 字段与之对应）
    for entry_no, rec in master.records["3"]:
        d = parse_type3(rec)
        if not d:
            continue
        scan.virtual_disks.append(VirtualDiskInfo(
            vd_id=d["vd_id"], uuid=d["uuid"], name=d["name"],
            description=d["description"], block_count=0, raw_vd_size=0))
    scan.virtual_disks.sort(key=lambda v: v.vd_id)

    # type4 → 按 D（=vd_id）归组到各空间
    for entry_no, rec in master.records["4"]:
        d = parse_type4(rec)
        if not d:
            continue
        for vd in scan.virtual_disks:
            if vd.vd_id == d["D"]:
                g = vd.groups.setdefault(d["E"], SlabGroup(vblock=d["E"]))
                g.entries[d["seq"]] = (d["disk"], d["phys"])
                break
    return scan


def build_groups(t4: List[dict]) -> Dict[int, SlabGroup]:
    groups: Dict[int, SlabGroup] = {}
    for d in t4:
        g = groups.setdefault(d["E"], SlabGroup(vblock=d["E"]))
        g.entries[d["seq"]] = (d["disk"], d["phys"])
    return groups
