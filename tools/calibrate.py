"""标定工具（管理员运行）：确定数据 slab 物理偏移公式与校验列旋转。只读。

方法：取已映射的组（R:/F: 各若干），用虚拟盘 \\.\PhysicalDrive11 读出真实字节，
再对每个候选公式 (phys_block+K)×256MB 从成员盘读各列，反推 列→字节段 的映射，
从而同时确定 K 与每行校验列位置。
产出 tools/out/calibration.json + 空间级 store #2..#5 头部落盘。
"""
import itertools
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import RawDevice  # noqa: E402

BLOCK = 0x10000000  # 256MB
ROWV = 4 * 0x40000  # 5列单校验：每行虚拟字节 = 4 × 256KB


def load_groups():
    blob = (ROOT / "tools" / "out" / "meta_head.bin").read_bytes()
    frag = blob[0x1200:]

    def parse_t4(p):
        try:
            if p[0] != 4:
                return None
            off = 1
            def tlv():
                nonlocal off
                ln = p[off]
                val = p[off + 1:off + 1 + ln]
                off += 1 + ln
                return int.from_bytes(val, "big") if ln else 0
            tlv(); tlv(); tlv(); tlv(); tlv()
            tlv(); tlv()
            E = tlv()
            seq = tlv()
            tlv()
            tlv()
            disk = tlv()
            phys = tlv()
            return E, seq, disk, phys
        except Exception:
            return None

    groups = defaultdict(dict)
    for i in range(23973):
        s = frag[i * 0x40:(i + 1) * 0x40]
        if s[0:4] != b"SDBB":
            continue
        en = int.from_bytes(s[8:12], "big")
        if not en:
            continue
        r = parse_t4(s[16:0x40])
        if r is None:
            continue
        E, seq, disk, phys = r
        groups[E][seq] = (disk, phys)
    return groups


def main() -> int:
    out_dir = ROOT / "tools" / "out"
    groups = load_groups()
    print(f"映射组: {len(groups)}")

    # 成员盘句柄：从 SPACEDB 扫描得到 uuid→设备，再由 meta 无法直接得 id→uuid，
    # 因此扫描全部盘建立 uuid→device，并从 type2 记录抽取 id↔uuid。
    blob = (ROOT / "tools" / "out" / "meta_head.bin").read_bytes()
    frag = blob[0x1200:]
    id_to_uuid = {}
    for i in range(23973):
        s = frag[i * 0x40:(i + 1) * 0x40]
        if s[0:4] != b"SDBB":
            continue
        en = int.from_bytes(s[8:12], "big")
        if not en:
            continue
        p = s[16:0x40]
        if p[0] != 2:
            continue
        # type2: [02][08][8B][02][07 79][16B uuid]...
        try:
            did = p[9]
            uuid = p[14:30]
            id_to_uuid[did] = uuid
        except Exception:
            pass
    print("type2 磁盘:", {k: v.hex()[:12] for k, v in id_to_uuid.items()})

    uuid_to_dev = {}
    devs = {}
    for idx in range(64):
        path = f"\\\\.\\PhysicalDrive{idx}"
        try:
            dev = RawDevice(path)
        except OSError:
            continue
        try:
            for e in __import__("ssrecover.spaceport", fromlist=["parse_gpt"]).parse_gpt(dev):
                head = dev.read(e.offset, 0x40)
                if head[0:8] == b"SPACEDB ":
                    # Win10+ 布局 disk_uuid @+0x30
                    spacedb = dev.read(e.offset, 0x1000)
                    du = spacedb[0x30:0x40]
                    uuid_to_dev[du] = path
                    devs[du] = dev  # 保持打开
                    print(f"  {path}: uuid={du.hex()[:12]}…")
                    break
        except Exception as ex:
            print(f"  {path}: {ex}")
    # 打开 id→device
    disk_dev = {}
    for did, u in id_to_uuid.items():
        p = uuid_to_dev.get(u)
        if p:
            disk_dev[did] = devs[u]
    print("id→设备:", {k: v.device_path for k, v in disk_dev.items()})

    # 虚拟盘 = BusType Spaces 的盘（DiskNumber 11）——由 Windows 上下文得知，直接试 0..64 中
    # 通过特征：其 GPT 分区偏移与 F:/R: 匹配。简单起见扫描每个盘找 GPT 分区含 2987148705792。
    vd_dev = None
    for idx in range(64):
        path = f"\\\\.\\PhysicalDrive{idx}"
        if path in uuid_to_dev.values():
            continue
        try:
            dev = RawDevice(path)
        except OSError:
            continue
        try:
            entries = __import__("ssrecover.spaceport", fromlist=["parse_gpt"]).parse_gpt(dev)
            offs = [e.offset for e in entries]
            if 2987148705792 in offs or any(abs(o - 2987148705792) < 4096 for o in offs):
                vd_dev = dev
                print(f"虚拟盘 = {path} (分区偏移匹配 R:)")
                break
            dev.close()
        except Exception:
            dev.close()
    if vd_dev is None:
        print("未找到虚拟盘设备!")
        return 1

    report = {"tests": []}
    test_Es = [11128, 11132, 11520, 280, 4352, 10000, 11124]
    for E in test_Es:
        if E not in groups:
            print(f"E={E} 不在映射中，跳过")
            continue
        g = groups[E]
        if len(g) != 5:
            print(f"E={E} 列数 {len(g)}，跳过")
            continue
        try:
            ref = vd_dev.read(E * BLOCK, 4 * ROWV)
        except OSError as e:
            print(f"E={E} 虚拟盘读失败: {e}")
            continue
        if not any(ref):
            print(f"E={E} 虚拟盘读出全 0（可能未分配），跳过")
            continue
        print(f"E={E}: 虚拟盘参考数据 {len(ref)}B 非零")
        # 对每个 K：读各列 (phys+K)×256MB 起 1MB（4 行 × 256KB）
        for K in range(0, 9):
            chunks = {}
            ok_read = True
            for seq, (disk_id, phys) in g.items():
                dev = disk_dev.get(disk_id)
                if dev is None:
                    ok_read = False
                    break
                try:
                    chunks[seq] = dev.read((phys + K) * BLOCK, 4 * 0x40000)
                except OSError:
                    ok_read = False
                    break
            if not ok_read or len(chunks) != 5:
                continue
            # 对每行 r(0..3)、每段 j(0..3)：找 ref[r][j] == chunks[c][r] 的列
            match = True
            pcol_rows = {}
            for r in range(4):
                seg_used = {}
                for j in range(4):
                    ref_seg = ref[r * ROWV + j * 0x40000: r * ROWV + (j + 1) * 0x40000]
                    cands = [c for c, ch in chunks.items() if ch[r * 0x40000:(r + 1) * 0x40000] == ref_seg]
                    if len(cands) != 1:
                        match = False
                        break
                    seg_used[j] = cands[0]
                if not match:
                    break
                cols = sorted(seg_used.values())
                pcol = [c for c in range(5) if c not in cols]
                if len(pcol) != 1:
                    match = False
                    break
                pcol_rows[r] = (pcol[0], [seg_used[j] for j in range(4)])
            if match:
                print(f"  ✓ K={K} 匹配! 每行校验列: {[(r, pcol_rows[r][0]) for r in range(4)]}")
                print(f"    行0 数据列顺序: {pcol_rows[0][1]}")
                report["tests"].append({
                    "E": E, "K": K,
                    "pcol_per_row": {r: pcol_rows[r][0] for r in range(4)},
                    "data_order_row0": pcol_rows[0][1],
                })
                break
        else:
            print(f"  ✗ E={E} 无 K 匹配")

    # 空间级 store #2..#5 头部
    for si, base in enumerate([0x20400000, 0x20800000, 0x20c00000, 0x21000000], start=2):
        try:
            d = vd_dev if False else None
            # 用 PD2（任意成员盘）读即可
            pd2 = None
            for u, p in uuid_to_dev.items():
                if p.endswith("PhysicalDrive2"):
                    pd2 = devs[u]
            if pd2 is None:
                pd2 = list(devs.values())[0]
            data = pd2.read(0x8100000 + base, 4 * 1024 * 1024)
            (out_dir / f"store{si}_head.bin").write_bytes(data)
            print(f"store{si}_head.bin (+{base:#x}) 已写")
        except OSError as e:
            print(f"store{si} 读取失败: {e}")

    (out_dir / "calibration.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[+] {out_dir/'calibration.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
