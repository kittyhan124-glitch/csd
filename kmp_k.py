"""
k-KMP: tìm k mẫu bằng k máy KMP, đúng đề: MỘT lượt duyệt văn bản.

  vòng ngoài : từng byte text[i], i = 0..N-1 (chỉ một lần, không quay lui)
  vòng trong : cập nhật trạng thái j của từng máy pid = 0..k-1

Chi phí build O(L), L = tổng độ dài các mẫu. Chi phí scan O(k*N): đọc văn bản một
lần KHÔNG xóa được thừa số k vì mỗi byte vẫn phải đi qua k máy.

Hợp đồng: build(patterns_bytes) -> structure; scan(text, structure) -> [(pos, pid)].
pid là chỉ số của mẫu trong danh sách đầu vào (bắt đầu từ 0).
"""

from typing import Any, Dict, List, Tuple, Union

from kmp import compute_prefix_table, compute_checksum  # noqa: F401  (tái xuất)

Matches = List[Tuple[int, int]]


def build(patterns: List[bytes]) -> Dict[str, Any]:
    if not isinstance(patterns, (list, tuple)):
        raise TypeError("patterns must be a list or tuple of bytes")
    if len(patterns) == 0:
        raise ValueError("Pattern list must not be empty.")

    clean: List[bytes] = []
    pi_list: List[List[int]] = []
    m_list: List[int] = []
    for pid, p in enumerate(patterns):
        if not isinstance(p, (bytes, bytearray)):
            raise TypeError(f"Pattern at index {pid} must be bytes, got {type(p)}")
        pb = bytes(p)
        if len(pb) == 0:
            raise ValueError(f"Pattern at index {pid} is empty (mẫu rỗng phải báo lỗi).")
        clean.append(pb)
        pi_list.append(compute_prefix_table(pb))
        m_list.append(len(pb))

    total = sum(m_list)
    return {
        "patterns": clean,
        "pi_list": pi_list,
        "m_list": m_list,
        "k": len(clean),
        "total_length": total,                 # L
        "states": total + len(clean),          # tổng trạng thái của k máy
        # gom sẵn để vòng trong không phải tra 3 danh sách mỗi byte
        "machines": list(zip(clean, pi_list, m_list)),
    }


def scan(text: bytes, structure: Dict[str, Any],
         count_comparisons: bool = False) -> Union[Matches, Tuple[Matches, int]]:
    if not isinstance(text, (bytes, bytearray)):
        raise TypeError(f"Text must be bytes or bytearray, got {type(text)}")
    if count_comparisons:
        matches, comparisons, _ = scan_stats(text, structure)
        return matches, comparisons

    machines = structure["machines"]
    k: int = structure["k"]
    n = len(text)
    matches: Matches = []
    if n == 0:
        return matches

    states = [0] * k
    for i in range(n):                       # đúng một lượt trên văn bản
        b = text[i]
        for pid in range(k):                 # k máy KMP
            p, pi, m = machines[pid]
            j = states[pid]
            while j > 0 and p[j] != b:
                j = pi[j - 1]
            if p[j] == b:
                j += 1
            if j == m:
                matches.append((i - m + 1, pid))
                j = pi[j - 1]                # giữ overlap
            states[pid] = j
    return matches


def scan_stats(text: bytes, structure: Dict[str, Any]) -> Tuple[Matches, int, int]:
    """(matches, comparisons, failure_steps) cộng trên cả k máy; mỗi phép so sánh đếm 1 lần."""
    if not isinstance(text, (bytes, bytearray)):
        raise TypeError(f"Text must be bytes or bytearray, got {type(text)}")
    machines = structure["machines"]
    k: int = structure["k"]
    n = len(text)
    matches: Matches = []
    if n == 0:
        return matches, 0, 0

    states = [0] * k
    comparisons = 0
    failure_steps = 0
    for i in range(n):
        b = text[i]
        for pid in range(k):
            p, pi, m = machines[pid]
            j = states[pid]
            while True:
                comparisons += 1
                if p[j] == b:
                    j += 1
                    break
                if j == 0:
                    break
                failure_steps += 1
                j = pi[j - 1]
            if j == m:
                matches.append((i - m + 1, pid))
                j = pi[j - 1]
            states[pid] = j
    return matches, comparisons, failure_steps
