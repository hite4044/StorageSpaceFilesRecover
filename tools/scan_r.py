"""M3 全管线验证（管理员运行）：扫池 → 绕过层组装 → R: NTFS 扫描。

产出 tools/out/r_scan.json + scan_r.log
"""
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.engine import RecoveryEngine  # noqa: E402
from ssrecover.rawdisk import RawDevice, is_admin  # noqa: E402


class Log:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, s):
        self.f.write(s)
        self.stdout.write(s)

    def flush(self):
        self.f.flush()
        self.stdout.flush()


def main() -> int:
    sys.stdout = Log(str(ROOT / "tools" / "out" / "scan_r.log"))
    out_dir = ROOT / "tools" / "out"
    if not is_admin():
        print("!! 需要管理员权限")
        return 1

    engine = RecoveryEngine(error_sink=lambda rec: print(f"  [ERR] {rec.brief()}"))

    print("== 1. 扫描池 ==")
    pool = engine.scan_local_pool(on_progress=lambda p: print(f"  {p.message}"))
    print(f"池 {pool.pool_uuid.hex().upper()} 名称={pool.windows_pool_name!r} 版本={pool.meta_version}")
    for d in pool.disks:
        print(f"  盘 #{d.disk_id} {d.name!r} → {d.device_path} pstart={d.partition_start:#x}")
    for vd in pool.virtual_disks:
        print(f"  空间 vd{vd.vd_id} {vd.name!r} mode={vd.mode} ncols={vd.ncols} "
              f"parity={vd.parity_cols} 组={len(vd.groups)} rows={vd.rows} "
              f"gvb={vd.group_vblocks} size={vd.raw_vd_size} win_disk={vd.windows_vd_number}")

    print("== 2. 分区 ==")
    for p in engine.partitions:
        print(f"  分区{p.index} @{p.offset_vd:#x} 大小 {p.size} 盘符={p.drive_letter or '-'} "
              f"类型={p.type_guid} 名={p.name!r}")

    # 选 R: 分区（按盘符或已知偏移）
    target = None
    for p in engine.partitions:
        if p.drive_letter == "R" or abs(p.offset_vd - 2987148705792) < 8192:
            target = p
            break
    if target is None:
        print("!! 未找到 R: 分区")
        return 1
    print(f"== 3. 打开卷（分区{target.index} @{target.offset_vd:#x}）==")

    # 校验：绕过层读 boot vs \\.\R: 直读
    vol_dev = RawDevice("\\\\.\\R:")
    boot_win = vol_dev.read(0, 512)
    vd = next((v for v in engine.pool.virtual_disks if v.windows_vd_number is not None),
              engine.pool.virtual_disks[0])
    reader = engine._make_vreader(vd)
    boot_bypass = reader.read(target.offset_vd, 512)
    match = boot_win == boot_bypass
    print(f"  boot 扇区比对: 绕过层 {'==' if match else '!='} Windows直读")
    if not match:
        print(f"    Windows: {boot_win[:64].hex()}")
        print(f"    绕过层 : {boot_bypass[:64].hex()}")

    vol = engine.open_volume(vd, target)
    print("== 4. NTFS 扫描 ==")
    print(f"  簇大小 {vol.cluster_size}, 总簇 {vol.ntfs.total_clusters}, MFT LCN {vol.ntfs.mft_lcn}")
    print(f"  record_size={vol.ntfs.record_size} mft_total={vol.ntfs.mft_total_bytes} "
          f"runs={[(r.lcn, r.clusters) for r in vol.ntfs.mft_runs]}")
    rec0 = vol.ntfs.read_record(0)
    print(f"  记录0 头16: {rec0[:16].hex()} alloc={struct.unpack_from('<I', rec0, 0x1C)[0]}")
    entries, stats = engine.scan_filesystem(
        record_progress=lambda done, total: print(f"\r  MFT {done}/{total}", end="", flush=True)
        if done % 50000 == 0 else None)
    print()
    print(f"  记录 {stats.total_records}, 文件 {stats.files}, 目录 {stats.dirs}, "
          f"已删文件 {stats.deleted_files} ({stats.deleted_bytes} 字节), 孤儿 {stats.orphans}")

    # 活文件抽验：通过绕过层读 1.txt（0 字节，存在）——改读根目录的 $MFT 摘要即可
    out = {
        "stats": {"total_records": stats.total_records, "files": stats.files,
                  "dirs": stats.dirs, "deleted_files": stats.deleted_files,
                  "deleted_bytes": stats.deleted_bytes, "orphans": stats.orphans,
                  "total_bytes": stats.total_bytes},
        "boot_match": match,
        "entries": [{"ref": e.mft_ref, "path": e.path, "name": e.name,
                     "dir": e.is_dir, "deleted": e.deleted, "size": e.size,
                     "runs": len(e.runs), "mtime": e.times[1],
                     "lcn_runs": [[r.lcn, r.clusters] for r in e.runs],
                     "sparse": e.data_attr_flags}
                    for e in entries[:20000]],
    }
    (out_dir / "r_scan.json").write_text(json.dumps(out, ensure_ascii=False, indent=1),
                                         encoding="utf-8")
    print(f"[+] r_scan.json 已写（{len(out['entries'])} 条样例）")
    engine.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BaseException:
        import traceback
        tb = traceback.format_exc()
        try:
            with open(ROOT / "tools" / "out" / "scan_r_crash.txt", "w", encoding="utf-8") as f:
                f.write(tb)
        except OSError:
            pass
        print(tb, file=sys.stderr)
        sys.exit(2)
