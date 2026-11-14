"""对比抓取 PD2 与 PD3/5/8 的元数据头（管理员运行）。只读。

产出 tools/out/pd358_meta.json
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import RawDevice  # noqa: E402
from ssrecover import spaceport  # noqa: E402


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


def main() -> int:
    sys.stdout = Tee(str(ROOT / "tools" / "out" / "pd358.log"))
    out_dir = ROOT / "tools" / "out"
    report = {}

    for idx in [2, 3, 5, 8]:
        path = f"\\\\.\\PhysicalDrive{idx}"
        try:
            dev = RawDevice(path)
        except OSError as e:
            print(f"{path}: 打开失败 {e}")
            continue
        try:
            entries = spaceport.parse_gpt(dev)
            pstart = None
            for e in entries:
                if dev.read(e.offset, 8) == b"SPACEDB ":
                    pstart = e.offset
                    break
            if pstart is None:
                print(f"{path}: 无 SPACEDB")
                continue
            # 头部 2MB 逐段检查
            info = {"pstart": pstart}
            # SPACEDB 头 0x60 字节
            info["spacedb_head"] = dev.read(pstart, 0x60).hex()
            # 检查 +0x1000 处
            s1 = dev.read(pstart + 0x1000, 8)
            info["sig_at_0x1000"] = s1.decode("ascii", errors="replace")
            # 在前 2MB 内搜索 SDBC/SDBB 签名
            blob = dev.read(pstart, 2 * 1024 * 1024)
            sdbc_offs = []
            off = 0
            while True:
                i = blob.find(b"SDBC    ", off)
                if i < 0:
                    break
                sdbc_offs.append(i)
                off = i + 1
            sdbb_offs = []
            off = 0
            while True:
                i = blob.find(b"SDBB", off)
                if i < 0:
                    break
                sdbb_offs.append(i)
                off = i + 1
            info["sdbc_offsets"] = [hex(o) for o in sdbc_offs[:8]]
            info["sdbb_first"] = [hex(o) for o in sdbb_offs[:8]]
            info["sdbb_count_2mb"] = len(sdbb_offs)
            # SPACEDB 头部字段（Win10+ 与 Win8 两种候选）
            info["cand_win10"] = {"time": info["spacedb_head"][0x30:0x40],
                                  "pool": info["spacedb_head"][0x40:0x60]}
            # hex 样本：0x1000 附近
            info["hex_0x1000"] = dev.read(pstart + 0x1000, 128).hex()
            report[path] = info
            print(f"{path}: pstart={pstart:#x} sig@0x1000={info['sig_at_0x1000']!r} "
                  f"SDBC@{info['sdbc_offsets']} SDBB数={len(sdbb_offs)}")
        finally:
            dev.close()

    (out_dir / "pd358_meta.json").write_text(json.dumps(report, ensure_ascii=False, indent=1),
                                             encoding="utf-8")
    print("[+] 完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
