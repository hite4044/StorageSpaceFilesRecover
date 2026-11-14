"""池元数据分析（本地，针对 tools/out/meta_head.bin）。只读，不需要管理员。

用法: python tools/analyze_meta.py [命令]
  groups            组提取统计
  find <E>          搜索指定 E 的全部记录
  rec <起> <止>     打印 rec 范围内记录
  gaps              空槽分布统计
"""
import sys
from collections import defaultdict, Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOB = (ROOT / "tools" / "out" / "meta_head.bin").read_bytes()
FRAG = BLOB[0x1200:]
N = 23973

sys.stdout.reconfigure(encoding="utf-8")


def parse_t4_strict(p):
    """严格按已知结构解析 type4。返回 dict 或 None。"""
    try:
        if p[0] != 4:
            return None
        off = 1

        def tlv(expect=None):
            nonlocal off
            ln = p[off]
            if expect is not None and ln != expect:
                raise ValueError(f"len {ln} != {expect}")
            val = p[off + 1:off + 1 + ln]
            off += 1 + ln
            return int.from_bytes(val, "big") if ln else 0

        tlv(6)   # A
        tlv(0)
        tlv(2)   # B
        tlv(0)
        tlv(0)
        tlv(1)   # C
        D = tlv(1)
        E = tlv()
        seq = tlv()
        tlv()    # skip
        tlv(4)   # mirror
        disk = tlv(1)
        phys = tlv()
        return {"A": 0, "B": 0, "D": D, "E": E, "seq": seq, "disk": disk, "phys": phys}
    except Exception:
        return None


def iter_records():
    for i in range(8, N):
        s = FRAG[(i - 8) * 0x40:(i - 8) * 0x40 + 0x40]
        if s[0:4] != b"SDBB":
            continue
        en = int.from_bytes(s[8:12], "big")
        if not en:
            continue
        p = s[16:0x40]
        yield i, en, p


def cmd_groups():
    groups = defaultdict(dict)
    d_other = []
    bad = 0
    for i, en, p in iter_records():
        if p[0] != 4:
            continue
        D = p[17] if len(p) > 17 else -1
        r = parse_t4_strict(p)
        if r is None:
            bad += 1
            continue
        if r["D"] == 143:
            groups[r["E"]][r["seq"]] = (r["disk"], r["phys"], i)
        else:
            d_other.append((i, r))
    print(f"严格解析: 组 {len(groups)}, 解析失败 {bad}, D!=143 记录 {len(d_other)}")
    cnt = Counter(len(g) for g in groups.values())
    print("每组列数分布:", dict(sorted(cnt.items())))
    Es = sorted(groups)
    f = [e for e in Es if e < 11128]
    r_ = [e for e in Es if 11128 <= e < 11920]
    print(f"F: 组 {len(f)} (E {f[0]}..{f[-1]}), R: 组 {len(r_)}: {r_}")
    print("D!=143 记录样例:", d_other[:6])
    # seq 缺失统计
    missing = defaultdict(list)
    for e in Es:
        for s in range(5):
            if s not in groups[e]:
                missing[e].append(s)
    print("缺列的组数:", len(missing))
    for e in list(missing)[:10]:
        print(f"  组{e} 缺 seq {missing[e]}: 现有 {dict(sorted((s, (d, p, rr)) for s, (d, p, rr) in groups[e].items()))}")


def cmd_find(target):
    target = int(target)
    hits = []
    for i, en, p in iter_records():
        if p[0] != 4:
            continue
        r = parse_t4_strict(p)
        if r and r["E"] == target:
            hits.append((i, r))
    print(f"E={target} 记录 {len(hits)} 条:")
    for i, r in hits:
        print(f"  rec{i} seq={r['seq']} disk={r['disk']} phys={r['phys']}")


def cmd_rec(a, b):
    a, b = int(a), int(b)
    for i, en, p in iter_records():
        if a <= i <= b:
            r = parse_t4_strict(p)
            if p[0] != 4:
                print(f"rec{i} entry={en} type={p[0]}")
            else:
                print(f"rec{i} entry={en} strict={'OK ' + str(r) if r else 'FAIL ' + p.hex()}")


def cmd_gaps():
    empty = []
    for i in range(8, N):
        s = FRAG[(i - 8) * 0x40:(i - 8) * 0x40 + 0x40]
        if s[0:4] != b"SDBB":
            continue
        en = int.from_bytes(s[8:12], "big")
        if not en:
            empty.append(i)
    print(f"空槽 {len(empty)} 个, 范围 {empty[0]}..{empty[-1]}")
    # 每 1000 rec 的空槽密度
    dens = Counter(e // 1000 for e in empty)
    print("按 1000 段密度:", dict(sorted(dens.items())))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "groups"
    if cmd == "groups":
        cmd_groups()
    elif cmd == "find":
        cmd_find(sys.argv[2])
    elif cmd == "rec":
        cmd_rec(sys.argv[2], sys.argv[3])
    elif cmd == "gaps":
        cmd_gaps()
