"""M4-1（管理员运行）：8 盘并行收割空闲 slab 中的完整内嵌 JPEG。

策略：每盘一线程顺序流式读取空闲 slab（256MB/slab，按 phys 排序 = 磁头顺序移动），
边读边 carving：FFD8FF 起始 → FFD9 结束，≥100KB 且哈希去重 → 落盘 D:\\Recovery_R\\previews。

产出: D:\\Recovery_R\\previews\\*.jpg + tools/out/harvest.json
"""
import hashlib
import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import RawDevice, is_admin  # noqa: E402
from ssrecover import BLOCK  # noqa: E402

PSTART = 0x8100000
CH = 0x40000
READ_BLK = 8 * 1024 * 1024
DISK_DEV = {1: "2", 2: "6", 127: "7", 191: "4", 192: "9", 193: "5", 194: "3", 195: "8"}
MIN_JPEG = 100 * 1024
MAX_JPEG = 30 * 1024 * 1024


class Tee:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8")
        self.stdout = sys.stdout
        self.lock = threading.Lock()

    def write(self, s):
        with self.lock:
            self.f.write(s)
            self.stdout.write(s)

    def flush(self):
        self.f.flush()
        self.stdout.flush()


def carve_stream(disk_id: int, dev: RawDevice, slabs: list, dest: Path,
                 seen: set, seen_lock: threading.Lock, results: list):
    """单盘流式 carving：FFD8FF 起始 → FFD9 结束，跨块续接，哈希去重。"""
    pstart = PSTART
    pending = None   # 未结束的 JPEG 累积（以 FFD8FF 开头）
    pending_meta = None
    saved = 0
    for phys in slabs:
        base = pstart + (phys + 2) * BLOCK
        try:
            block = dev.read(base, BLOCK)
        except OSError as e:
            print(f"[盘{disk_id}@{phys}] 读取失败: {e}")
            pending = None
            continue
        data = (pending + block) if pending else block
        pending = None
        n = len(data)
        i = 0
        while i + 3 < n:
            start = data.find(b"\xff\xd8\xff", i)
            if start < 0:
                break
            end = data.find(b"\xff\xd9", start + 3)
            if end < 0:
                # JPEG 延伸到块外 → 结转
                pending = data[start:]
                pending_meta = (disk_id, phys, start)
                break
            size = end + 2 - start
            if MIN_JPEG <= size <= MAX_JPEG:
                blob = data[start:end + 2]
                h = hashlib.sha256(blob).hexdigest()[:16]
                with seen_lock:
                    if h not in seen:
                        seen.add(h)
                        name = dest / f"d{disk_id}_p{phys}_o{start:#x}_{size}.jpg"
                        name.write_bytes(blob)
                        results.append({"disk": disk_id, "phys": phys,
                                        "off": start, "size": size,
                                        "hash": h, "file": str(name)})
                        saved += 1
            i = end + 2
        if len(results) % 50 == 0 and saved:
            print(f"[盘{disk_id}@{phys}] 累计 {len(results)} 张", flush=True)
    if pending is not None and MIN_JPEG <= len(pending) <= MAX_JPEG:
        # 到磁盘末尾仍未闭合：整段保存（可能是大盘残片）
        blob = pending
        h = hashlib.sha256(blob).hexdigest()[:16]
        with seen_lock:
            if h not in seen:
                seen.add(h)
                name = dest / f"d{disk_id}_tail_{len(blob)}.jpg"
                name.write_bytes(blob)
                results.append({"disk": disk_id, "size": len(blob),
                                "hash": h, "file": str(name), "tail": True})


def main() -> int:
    sys.stdout = Tee(str(ROOT / "tools" / "out" / "harvest.log"))
    if not is_admin():
        print("!! 需要管理员")
        return 1
    t0 = time.time()
    freed = {int(k): v for k, v in json.load(
        open(ROOT / "tools" / "out" / "freed_slabs.json", encoding="utf-8")).items()}
    dest = Path("D:\\Recovery_R\\previews")
    dest.mkdir(parents=True, exist_ok=True)

    seen = set()
    seen_lock = threading.Lock()
    results = []
    threads = []
    total_slabs = sum(len(v) for v in freed.values())
    print(f"并行收割 {len(freed)} 盘 / {total_slabs} 个空闲 slab → {dest}", flush=True)

    def worker(did):
        slabs = sorted(freed[did])
        try:
            dev = RawDevice(f"\\\\.\\PhysicalDrive{DISK_DEV[did]}")
        except OSError as e:
            print(f"[盘{did}] 设备失败: {e}")
            return
        try:
            carve_stream(did, dev, slabs, dest, seen, seen_lock, results)
            print(f"[盘{did}] 完成，当前累计 {len(results)} 张", flush=True)
        finally:
            dev.close()

    for did in sorted(freed):
        if did in DISK_DEV:
            th = threading.Thread(target=worker, args=(did,), daemon=True)
            th.start()
            threads.append(th)
            time.sleep(0.5)
    for th in threads:
        th.join()

    (ROOT / "tools" / "out" / "harvest.json").write_text(json.dumps(
        {"count": len(results), "results": results}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    print(f"\n[+] 收割 {len(results)} 张，用时 {time.time()-t0:.0f}s")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BaseException:
        import traceback
        tb = traceback.format_exc()
        (ROOT / "tools" / "out" / "harvest_crash.txt").write_text(tb, encoding="utf-8")
        print(tb, file=sys.stderr)
        sys.exit(2)
