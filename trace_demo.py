"""
In từng bước chạy của KMP và k-KMP để đọc hiểu luồng hoạt động.
Chạy: python trace_demo.py
"""

import kmp


def show_table(p: bytes) -> None:
    pi = kmp.compute_prefix_table(p)
    print(f"\nPrefix Table của {p.decode()!r}")
    print("  j   :", "  ".join(f"{j:>2}" for j in range(len(p))))
    print("  P[j]:", "  ".join(f"{chr(c):>2}" for c in p))
    print("  pi  :", "  ".join(f"{v:>2}" for v in pi))


def trace_kmp(text: bytes, p: bytes) -> None:
    s = kmp.build(p)
    pi, m = s["pi"], s["m"]
    print(f"\nKMP: T={text.decode()!r}, P={p.decode()!r}")
    print(f"  {'i':>2} {'T[i]':>4}  hành động -> j mới")
    j = 0
    for i, b in enumerate(text):
        acts = []
        while j > 0 and p[j] != b:
            acts.append(f"lệch P[{j}]={chr(p[j])!r}, lùi j={j}->pi[{j-1}]={pi[j-1]}")
            j = pi[j - 1]
        if p[j] == b:
            acts.append(f"khớp P[{j}]={chr(p[j])!r}, j={j}->{j+1}")
            j += 1
        else:
            acts.append(f"lệch P[{j}]={chr(p[j])!r}, giữ j=0")
        line = "; ".join(acts)
        if j == m:
            line += f"  ==> TÌM THẤY tại pos={i-m+1}, lùi j={m}->pi[{m-1}]={pi[m-1]} (giữ overlap)"
            j = pi[m - 1]
        print(f"  {i:>2} {chr(b)!r:>4}  {line}  [j={j}]")
    matches, c, fs = kmp.scan_stats(text, s)
    print(f"  kết quả={[pos for pos, _ in matches]}, so sánh={c} (<= 2N={2*len(text)}), bước lùi={fs}")


def trace_kkmp(text: bytes, pats) -> None:
    import kmp_k
    s = kmp_k.build(pats)
    names = [p.decode() for p in pats]
    print(f"\nk-KMP: T={text.decode()!r}, mẫu={names}")
    print("  1 vòng ngoài trên văn bản, mỗi byte đi qua k máy; trạng thái j của từng máy:")
    states = [0] * s["k"]
    for i, b in enumerate(text):
        hits = []
        for pid, (p, pi, m) in enumerate(s["machines"]):
            j = states[pid]
            while j > 0 and p[j] != b:
                j = pi[j - 1]
            if p[j] == b:
                j += 1
            if j == m:
                hits.append(f"{names[pid]}@{i-m+1}")
                j = pi[j - 1]
            states[pid] = j
        extra = f"  ==> {', '.join(hits)}" if hits else ""
        print(f"  i={i} {chr(b)!r}: " + " ".join(f"{n}:{st}" for n, st in zip(names, states)) + extra)
    print("  kết quả:", sorted(kmp_k.scan(text, s)), "(pos, pid)")


if __name__ == "__main__":
    show_table(b"abab")
    show_table(b"aaaaab")
    show_table(b"abacaba")
    trace_kmp(b"abababab", b"abab")
    trace_kmp(b"aaaaaaab", b"aaaaab")
    trace_kkmp(b"ushers", [b"he", b"she", b"his", b"hers"])
