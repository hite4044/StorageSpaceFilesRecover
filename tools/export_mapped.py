"""M4a（管理员运行）：导出完全落在已映射组内的已删除文件并验证。只读源数据。

产出: 导出目录 + tools/out/export_mapped.json
"""
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.engine import RecoveryEngine  # noqa: E402
from ssrecover.rawdisk import is_admin  # noqa: E402
from ssrecover.config import ExportConfig  # noqa: E402


class Tee:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, s):
        self.f.write(s)
        self.stdout.write(s)

    def flush(self):
        self.f.flush()
        self.stdout.flush()


def sig_check(path: Path) -> str:
    b = path.read_bytes()[:16]
    if b[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if b[4:8] == b"ftyp":
        return "MP4"
    if len(path.read_bytes()[:16]) >= 16 and b[4:8] == b"E fui":
        return "DNG?"
    if b[:2] == b"\x1a\x45\xdf\xa3":
        return "MKV"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    return "unknown"


def main() -> int:
    sys.stdout = Tee(str(ROOT / "tools" / "out" / "export_mapped.log"))
    out_dir = ROOT / "tools" / "out"
    if not is_admin():
        print("!! 需要管理员")
        return 1

    engine = RecoveryEngine(error_sink=lambda rec: None)
    print("== 扫描池 ==")
    pool = engine.scan_local_pool()
    vd = next(v for v in pool.virtual_disks if v.windows_vd_number is not None)
    target = next(p for p in engine.partitions if p.drive_letter == "R")
    vol = engine.open_volume(vd, target)
    entries, stats = engine.scan_filesystem()
    print(f"记录 {stats.total_records}, 已删文件 {stats.deleted_files}")

    # 已映射的 R: vblock
    mapped = set()
    for E in (11128, 11132, 11324, 11328, 11520, 11916):
        for k in range(4):
            mapped.add(E + k)

    def fully_mapped(e):
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

    sel = [e for e in entries if e.deleted and not e.is_dir and fully_mapped(e)]
    print(f"完全映射的已删文件: {len(sel)}, 总字节 {sum(e.size for e in sel)}")

    dest_root = str(ROOT / "tools" / "out" / "export_mapped")
    cfg = ExportConfig(dest_root=dest_root)
    ok, fail, outputs = engine.export(sel, cfg)
    print(f"导出: 成功 {ok}, 失败 {fail}")

    sigs = {}
    for o in outputs:
        try:
            sigs[o] = sig_check(Path(o))
        except OSError as e:
            sigs[o] = f"read_fail {e}"
    for o, s in list(sigs.items())[:40]:
        print(f"  {Path(o).name} → {s}")

    (out_dir / "export_mapped.json").write_text(json.dumps(
        {"ok": ok, "fail": fail, "outputs": outputs, "sigs": sigs},
        ensure_ascii=False, indent=1), encoding="utf-8")
    print("[+] 完成")
    engine.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BaseException:
        import traceback
        tb = traceback.format_exc()
        (ROOT / "tools" / "out" / "export_mapped_crash.txt").write_text(tb, encoding="utf-8")
        print(tb, file=sys.stderr)
        sys.exit(2)
