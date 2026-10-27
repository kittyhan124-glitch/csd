"""
KMP (Knuth-Morris-Pratt) đơn mẫu, làm việc trên bytes.

Hợp đồng chung của nhóm:
  build(pattern_bytes)            -> structure
  scan(text_bytes, structure)     -> [(pos, pid), ...]   (pid = 0 với đơn mẫu)
- pos là offset bắt đầu theo BYTE, tính từ 0, trên văn bản đã NFC -> UTF-8.
- Báo đủ khớp chồng lấn (overlap). Mẫu rỗng -> ValueError.
- Không dùng bytes.find() trong lõi thuật toán.

Ba chế độ chạy tách biệt (không trộn vào nhau khi đo):
  scan(...)                          chế độ timing: không có bộ đếm nào
  scan(..., count_comparisons=True)  chế độ --count: trả (matches, comparisons)
  scan_stats(...)                    chế độ phân tích: trả thêm failure_steps

Định nghĩa "một phép so sánh" = một lần đối chiếu pattern[j] với một byte văn bản.
"""

from typing import Any, Dict, List, Tuple, Union

Matches = List[Tuple[int, int]]


def compute_prefix_table(pattern: bytes) -> List[int]:
    """
    pi[i] = độ dài tiền tố thực sự dài nhất của pattern[0..i]
            đồng thời là hậu tố thực sự của pattern[0..i].
    Thời gian O(m), bộ nhớ O(m).
    """
    m = len(pattern)
    if m == 0:
        raise ValueError("Pattern must not be empty (mẫu không được rỗng).")

    pi = [0] * m
    k = 0  # độ dài biên hiện tại của pattern[0..i-1]
    for i in range(1, m):
        while k > 0 and pattern[k] != pattern[i]:
            k = pi[k - 1]  # thử biên ngắn hơn kế tiếp
        if pattern[k] == pattern[i]:
            k += 1
        pi[i] = k
    return pi


def build(pattern: bytes) -> Dict[str, Any]:
    if not isinstance(pattern, (bytes, bytearray)):
        raise TypeError(f"Pattern must be bytes or bytearray, got {type(pattern)}")
    if len(pattern) == 0:
        raise ValueError("Pattern must not be empty (mẫu không được rỗng).")

    p = bytes(pattern)
    pi = compute_prefix_table(p)
    return {
        "pattern": p,
        "pi": pi,
        "m": len(p),
        "states": len(p) + 1,          # trạng thái j = 0..m
        "longest_border": pi[-1],      # biên dài nhất của cả mẫu (dùng cho phân tích)
    }


def _check_text(text: bytes) -> None:
    if not isinstance(text, (bytes, bytearray)):
        raise TypeError(f"Text must be bytes or bytearray, got {type(text)}")


def scan(text: bytes, structure: Dict[str, Any],
         count_comparisons: bool = False) -> Union[Matches, Tuple[Matches, int]]:
    """Quét một lượt từ trái sang phải; con trỏ văn bản không bao giờ lùi."""
    _check_text(text)
    if count_comparisons:
        matches, comparisons, _ = scan_stats(text, structure)
        return matches, comparisons

    p: bytes = structure["pattern"]
    pi: List[int] = structure["pi"]
    m: int = structure["m"]
    n = len(text)
    matches: Matches = []
    if n == 0 or m > n:
        return matches

    j = 0  # số byte đầu của mẫu đang khớp với hậu tố của văn bản đã đọc
    for i in range(n):
        b = text[i]
        while j > 0 and p[j] != b:
            j = pi[j - 1]
        if p[j] == b:
            j += 1
        if j == m:
            matches.append((i - m + 1, 0))
            j = pi[j - 1]  # lùi theo biên để giữ khớp chồng lấn
    return matches


def scan_stats(text: bytes, structure: Dict[str, Any]) -> Tuple[Matches, int, int]:
    """
    Trả (matches, comparisons, failure_steps).
    comparisons: mỗi lần đối chiếu pattern[j] với text[i] được đếm đúng 1 lần.
    failure_steps: số lần thực hiện j <- pi[j-1].
    Với KMP luôn có comparisons <= 2N (xem phép thế năng trong THEORY).
    """
    _check_text(text)
    p: bytes = structure["pattern"]
    pi: List[int] = structure["pi"]
    m: int = structure["m"]
    n = len(text)
    matches: Matches = []
    if n == 0 or m > n:
        return matches, 0, 0

    comparisons = 0
    failure_steps = 0
    j = 0
    for i in range(n):
        b = text[i]
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
            matches.append((i - m + 1, 0))
            j = pi[j - 1]
    return matches, comparisons, failure_steps


def compute_checksum(matches: Matches) -> int:
    """check = (check + (pos + 1) * 1_000_003 + pid) mod 2^64 (mục 11 của đề)."""
    check = 0
    mod = 1 << 64
    for pos, pid in matches:
        check = (check + (pos + 1) * 1000003 + pid) % mod
    return check
