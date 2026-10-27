"""Module Brute Force (BF) theo hợp đồng kỹ thuật môn CSD203

Quy định:
- Đầu vào: bytes (không dùng chuỗi string thông thường)
- Trả về đủ các vị trí trùng khớp kể cả khi chồng lấn (overlap)
- Dừng so sánh ngay khi gặp byte đầu tiên sai khớp
- Mẫu rỗng phải báo lỗi ValueError
"""


def build(pattern_bytes: bytes):
    """Tiền xử lý mẫu."""
    if not isinstance(pattern_bytes, (bytes, bytearray)):
        raise TypeError("Pattern phải là kiểu bytes hoặc bytearray")
    if len(pattern_bytes) == 0:
        raise ValueError("Pattern không được rỗng")
    return pattern_bytes


def scan(text_bytes: bytes, pattern_bytes: bytes):
    """Tìm tất cả các lần xuất hiện của pattern_bytes trong text_bytes.

    Trả về danh sách các cặp (pos, pid) với pid mặc định là 0.
    """
    if not isinstance(text_bytes, (bytes, bytearray)):
        raise TypeError("Text phải là kiểu bytes hoặc bytearray")

    n = len(text_bytes)
    m = len(pattern_bytes)

    if m == 0:
        raise ValueError("Pattern không được rỗng")

    results = []

    for i in range(n - m + 1):
        match = True
        for j in range(m):
            if text_bytes[i + j] != pattern_bytes[j]:
                match = False
                break  
        if match:
            results.append((i, 0))

    return results


def scan_with_comparisons(text_bytes: bytes, pattern_bytes: bytes):
    """Phiên bản phụ dành riêng cho lượt đo --count của RQ1 (đếm số phép so sánh byte)."""
    n = len(text_bytes)
    m = len(pattern_bytes)
    comparisons = 0
    results = []

    for i in range(n - m + 1):
        match = True
        for j in range(m):
            comparisons += 1
            if text_bytes[i + j] != pattern_bytes[j]:
                match = False
                break
        if match:
            results.append((i, 0))

    return results, comparisons