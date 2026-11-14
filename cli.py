"""存储空间已删除文件恢复 — 命令行接口（交互式，仅全盘恢复）。

以管理员权限运行:  .venv\\Scripts\\python.exe cli.py [保存根目录]
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.engine import RecoveryEngine  # noqa: E402
from ssrecover.rawdisk import is_admin  # noqa: E402
from ssrecover.config import ExportConfig, ReadParams, ErrorRules  # noqa: E402
from ssrecover.models import Progress  # noqa: E402
from ssrecover.virtualdisk import AbortExportError  # noqa: E402
from ssrecover import errors as errmod  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")

ERROR_LOG = ROOT / "errors.json"


def fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def ask(prompt: str, default: str = "") -> str:
    s = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    return s or default


def ask_int(prompt: str, default: int) -> int:
    s = ask(prompt, str(default))
    try:
        return int(s)
    except ValueError:
        return default


def ask_yn(prompt: str, default: bool = True) -> bool:
    s = ask(f"{prompt} [{'Y/n' if default else 'y/N'}]").lower()
    if not s:
        return default
    return s.startswith("y")


def render_progress(p: Progress):
    if p.phase == "scan_fs":
        return
    if p.phase != "export":
        return
    overall = f"{p.overall_percent:5.1f}% {fmt_size(p.overall_done)}/{fmt_size(p.overall_total)}"
    speed = f"{fmt_size(p.speed)}/s" if p.speed else "--"
    eta = f"ETA {int(p.eta // 60)}:{int(p.eta % 60):02d}" if p.eta else "ETA --"
    cur = f"{p.current_percent:5.1f}%"
    line = (f"\r总进度 {overall} {speed} {eta} | 当前 {p.current_file[:36]:36s} {cur}")
    sys.stdout.write(line[:160])
    sys.stdout.flush()


def main() -> int:
    print("=" * 62)
    print("  存储空间 (Storage Spaces) 已删除文件恢复 — 命令行版")
    print("=" * 62)
    if not is_admin():
        print("!! 请以管理员身份运行（需要直读物理硬盘）")
        return 1

    error_log = []

    def sink(rec):
        error_log.append(rec)
        if rec.level in ("ERROR", "FATAL"):
            print(f"\n  [错误] {rec.brief()}")

    engine = RecoveryEngine(error_sink=sink)

    print("\n[1/5] 扫描存储池（读取各成员盘元数据）…")
    pool = engine.scan_local_pool()
    print(f"  池 {pool.pool_uuid.hex().upper()} 名称 {pool.windows_pool_name!r}")
    for d in pool.disks:
        print(f"    盘#{d.disk_id} {d.name} → {d.device_path or '未挂载'}")
    vd = next((v for v in pool.virtual_disks if v.windows_vd_number is not None), None)
    if vd is None:
        print("!! 未识别到活动空间")
        return 1
    print(f"  空间 {vd.name!r}: {vd.mode} {vd.ncols} 列 parity={vd.parity_cols} "
          f"组 {len(vd.groups)} 容量 {fmt_size(vd.raw_vd_size)}")

    print("\n[2/5] 分区列表:")
    for i, p in enumerate(engine.partitions):
        print(f"  [{i}] @{p.offset_vd:#x} {fmt_size(p.size)} 盘符={p.drive_letter or '-'}")
    idx = ask_int("选择要恢复的分区编号", len(engine.partitions) - 1)
    part = engine.partitions[idx]

    print(f"\n[3/5] 扫描 {part.drive_letter or '分区'} 的 NTFS 结构…")
    vol = engine.open_volume(vd, part)
    entries, st = engine.scan_filesystem()
    print(f"  MFT 记录 {st.total_records}: 文件 {st.files}, 目录 {st.dirs}, "
          f"已删除 {st.deleted_files} 个 / {fmt_size(st.deleted_bytes)}")

    scope = ask("恢复范围 all=全部已删文件 / mapped=仅完整可恢复的", "all")
    dest_root = ask("保存到哪个目录", "D:\\Recovery_R")
    chunk = ask_int("读取块大小(MB)", 4)
    retries = ask_int("物理读重试次数", 3)

    sel = [e for e in entries if e.deleted and not e.is_dir]
    if scope == "mapped":
        mapped = set()
        for E in (11128, 11132, 11324, 11328, 11520, 11916):
            for k in range(4):
                mapped.add(E + k)

        def in_mapped(e):
            for run in e.runs:
                lcn, cl = run.lcn, run.clusters
                if lcn < 0:
                    continue
                for k in range(cl):
                    L = lcn + k
                    vb = 11128 + (L - 1) // 256 if L >= 1 else 11127
                    if vb not in mapped:
                        return False
            return bool(e.runs) or e.resident_data is not None
        sel = [e for e in sel if in_mapped(e)]
    total = sum(e.size for e in sel)
    print(f"  选中 {len(sel)} 个文件 / {fmt_size(total)}")

    cfg = ExportConfig(
        dest_root=dest_root,
        read_params=ReadParams(chunk_mb=chunk, max_retries=retries),
        error_rules=ErrorRules(),
    )

    print(f"\n[4/5] 导出中…（Ctrl+C 中止）")
    t0 = time.time()
    last_print = 0.0

    def on_prog(p: Progress):
        nonlocal last_print
        now = time.time()
        if now - last_print >= 0.2:
            last_print = now
            render_progress(p)

    ok = fail = 0
    outputs = []
    try:
        ok, fail, outputs = engine.export(sel, cfg, on_progress=on_prog)
    except (KeyboardInterrupt, AbortExportError):
        print("\n  已中止")
    print(f"\n\n[5/5] 完成: 成功 {ok}, 失败 {fail}, 用时 {time.time()-t0:.0f}s")

    err_stats = {}
    for rec in error_log:
        err_stats[rec.code] = err_stats.get(rec.code, 0) + 1
    if err_stats:
        print("错误汇总:", json.dumps(err_stats, ensure_ascii=False))
    ERROR_LOG.write_text(json.dumps(
        [{"code": r.code, "level": r.level, "msg": r.message, "file": r.file_path,
          "volume_off": r.volume_offset, "virt_off": r.virtual_offset,
          "disk": r.disk_id, "phys_off": r.physical_offset,
          "action": r.action, "extra": r.extra}
         for r in error_log], ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"错误明细: {ERROR_LOG}")
    print(f"导出目录: {dest_root}")
    engine.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消")
        sys.exit(130)
