"""环境与池探测（需管理员运行）：验证元数据解析器与真实池参数。

用法（管理员 PowerShell 或通过 UAC 启动）：
    python tools/probe_pool.py
输出：tools/out/probe_report.json + 控制台摘要。只读操作。
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import is_admin, enumerate_physical_disks  # noqa: E402
from ssrecover import spaceport, layout, errors  # noqa: E402
from ssrecover.engine import RecoveryEngine  # noqa: E402


def main() -> int:
    print("== probe_pool ==")
    report = {"admin": is_admin()}
    if not report["admin"]:
        print("[!] 当前不是管理员：元数据解析将被跳过，仅输出 Windows 查询")
        report["meta"] = None
    else:
        print("[+] 管理员权限 OK")
        engine = RecoveryEngine()
        ctx = engine.query_windows_context()
        report["windows"] = {
            "virtual_disks": ctx.get("virtual_disks"),
            "disks": [d for d in ctx.get("disks", []) if d.get("BusType") == "Spaces"],
            "partitions_on_spaces": [p for p in ctx.get("partitions", [])
                                     if any(d.get("Number") == p.get("DiskNumber")
                                            for d in ctx.get("disks", []) if d.get("BusType") == "Spaces")],
        }
        print("[*] Windows 上下文:", json.dumps(report["windows"], ensure_ascii=False, indent=2))

        disks = enumerate_physical_disks()
        report["physical_disks"] = disks
        print(f"[*] 枚举到 {len(disks)} 个物理盘")

        members = []
        for d in disks:
            try:
                m = spaceport.scan_member(d["path"], d["size"])
            except OSError as e:
                print(f"    {d['path']}: 打开失败 {e}")
                continue
            except Exception as e:
                print(f"    {d['path']}: 解析异常 {e}")
                continue
            status = "成员" if m.pool_uuid else "非成员"
            print(f"    {d['path']}: {status} ver={m.meta_version} pool={m.pool_uuid.hex().upper()[:16]}… "
                  f"frag={m.fragment_count} t2={len(m.records['2'])} t3={len(m.records['3'])} t4={len(m.records['4'])}")
            if m.pool_uuid:
                members.append((d["path"], m))
        report["members"] = [{"path": p, "version": m.meta_version,
                              "pool": m.pool_uuid.hex().upper(),
                              "disk_uuid": m.disk_uuid.hex().upper(),
                              "partition_start": m.partition_start,
                              "fragments": m.fragment_count,
                              "t2": len(m.records["2"]), "t3": len(m.records["3"]),
                              "t4": len(m.records["4"])} for p, m in members]

        if members:
            pool_uuid = members[0][1].pool_uuid
            paths = [p for p, m in members if m.pool_uuid == pool_uuid]
            pool = spaceport.scan_pool(paths, on_progress=lambda s: print("   ", s))
            for vd in pool.virtual_disks:
                layout.infer_layout(pool, vd)
                notes = layout.validate_geometry(pool, vd)
                print(f"\n[虚拟盘 {vd.vd_id}] name={vd.name!r} desc={vd.description!r}")
                print(f"  mode={vd.mode} ncols={vd.ncols} parity_cols={vd.parity_cols} "
                      f"rows={vd.rows} group_vblocks={vd.group_vblocks} "
                      f"slab={vd.slab_bytes>>20}MB raw_size={vd.raw_vd_size}")
                print(f"  groups={len(vd.groups)} block_count(type3)={vd.block_count}")
                if notes:
                    print("  [校验提示]", notes)
                g0 = sorted(vd.groups.keys())[:2]
                for vb in g0:
                    print(f"  组 {vb}: {vd.groups[vb].entries}")
            report["pool"] = {
                "pool_uuid": pool.pool_uuid.hex().upper(),
                "meta_version": pool.meta_version,
                "disks": [{"disk_id": d.disk_id, "name": d.name, "uuid": d.uuid.hex().upper(),
                           "block_count": d.block_count, "device": d.device_path,
                           "partition_start": d.partition_start} for d in pool.disks],
                "virtual_disks": [{"vd_id": v.vd_id, "name": v.name, "uuid": v.uuid.hex().upper(),
                                   "mode": v.mode, "ncols": v.ncols, "parity_cols": v.parity_cols,
                                   "rows": v.rows, "group_vblocks": v.group_vblocks,
                                   "groups": len(v.groups), "block_count": v.block_count,
                                   "raw_vd_size": v.raw_vd_size} for v in pool.virtual_disks],
            }

            # 交叉验证 Windows 参数
            wv = report["windows"]["virtual_disks"]
            if isinstance(wv, dict):
                wv = [wv]
            report["cross_check"] = []
            for vd in pool.virtual_disks:
                for w in wv or []:
                    cands = spaceport.uuid_candidates(vd.uuid)
                    uid = str(w.get("UniqueId", "")).upper().replace("{", "").replace("}", "")
                    if uid in cands:
                        report["cross_check"].append({
                            "vd": vd.name, "ncols_meta": vd.ncols,
                            "ncols_windows": w.get("NumberOfColumns"),
                            "interleave_windows": w.get("Interleave"),
                            "parity_windows": w.get("ParityLayout"),
                            "thin": w.get("ProvisioningType"),
                        })
                        print(f"[交叉验证] {vd.name}: meta_ncols={vd.ncols} win_ncols={w.get('NumberOfColumns')} "
                              f"win_interleave={w.get('Interleave')} win_parity={w.get('ParityLayout')}")
            engine.close()

    out_dir = ROOT / "tools" / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "probe_report.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] 报告已写入 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
