"""Kiểm thử KMP và k-KMP. Chạy: python -m unittest test_kmp -v"""

import random
import unicodedata
import unittest

import bf
import kmp
import kmp_k
from oracle import oracle_find


class CountingBytes(bytes):
    """bytes ghi lại chỉ số được truy cập, để chứng minh chỉ quét một lượt."""
    def __new__(cls, data):
        obj = super().__new__(cls, data)
        obj.accessed = []
        return obj

    def __getitem__(self, idx):
        if isinstance(idx, int):
            self.accessed.append(idx)
        return super().__getitem__(idx)


def positions(res):
    return [p for p, _ in res]


class PrefixTable(unittest.TestCase):
    def test_examples(self):
        self.assertEqual(kmp.compute_prefix_table(b"abab"), [0, 0, 1, 2])
        self.assertEqual(kmp.compute_prefix_table(b"aaaaab"), [0, 1, 2, 3, 4, 0])
        self.assertEqual(kmp.compute_prefix_table(b"abacaba"), [0, 0, 1, 0, 1, 2, 3])
        self.assertEqual(kmp.compute_prefix_table(b"a"), [0])

    def test_matches_definition(self):
        """So với định nghĩa trực tiếp (chậm) trên mẫu ngẫu nhiên."""
        rng = random.Random(1)
        for _ in range(300):
            p = bytes(rng.choice(b"ab") for _ in range(rng.randint(1, 14)))
            expect = []
            for i in range(len(p)):
                s = p[: i + 1]
                expect.append(max((k for k in range(len(s)) if s[:k] == s[len(s) - k:]), default=0))
            self.assertEqual(kmp.compute_prefix_table(p), expect, p)


class EdgeCases(unittest.TestCase):
    def test_overlap(self):
        self.assertEqual(positions(kmp.scan(b"aaaaa", kmp.build(b"aaa"))), [0, 1, 2])
        self.assertEqual(positions(kmp.scan(b"abababab", kmp.build(b"abab"))), [0, 2, 4])

    def test_ushers(self):
        pats = [b"he", b"she", b"his", b"hers"]
        res = sorted(kmp_k.scan(b"ushers", kmp_k.build(pats)))
        self.assertEqual(res, [(1, 1), (2, 0), (2, 3)])  # she@1, he@2, hers@2; his không khớp

    def test_empty_and_short(self):
        for mod, arg in ((kmp, b""), (bf, b"")):
            with self.assertRaises(ValueError):
                mod.build(arg)
        with self.assertRaises(ValueError):
            kmp_k.build([b"abc", b""])
        with self.assertRaises(ValueError):
            kmp_k.build([])
        self.assertEqual(kmp.scan(b"", kmp.build(b"abc")), [])
        self.assertEqual(kmp.scan(b"ab", kmp.build(b"abc")), [])
        self.assertEqual(kmp_k.scan(b"", kmp_k.build([b"a"])), [])

    def test_single_byte_and_binary(self):
        self.assertEqual(positions(kmp.scan(b"abacadae", kmp.build(b"a"))), [0, 2, 4, 6])
        t = bytes([0, 255, 0, 255, 0, 85, 255])
        self.assertEqual(positions(kmp.scan(t, kmp.build(bytes([0, 255, 0])))), [0, 2])

    def test_suffix_and_duplicate_patterns(self):
        pats = [b"abc", b"bc", b"c", b"abc"]          # hậu tố của nhau + trùng lặp
        t = b"xabcabc"
        self.assertEqual(sorted(kmp_k.scan(t, kmp_k.build(pats))), sorted(oracle_find(t, pats)))

    def test_vietnamese_nfc_bytes(self):
        s = unicodedata.normalize("NFC", "Trường Đại học FPT - nghiên cứu Tiếng Việt")
        p = unicodedata.normalize("NFC", "nghiên cứu").encode()
        self.assertEqual(len("nghiên cứu"), 10)
        self.assertEqual(len(p), 13)                  # 13 byte, không phải 12
        t = s.encode()
        res = kmp.scan(t, kmp.build(p))
        self.assertEqual(res, oracle_find(t, [p]))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0][0], len(s[: s.index("nghiên")].encode()))  # offset theo byte


class Complexity(unittest.TestCase):
    def test_comparisons_bound_2N(self):
        """Phép thế năng: số so sánh <= 2N; mỗi phép so sánh chỉ đếm một lần."""
        rng = random.Random(7)
        for alpha in (b"ab", b"ACGT", bytes(range(256))):
            for _ in range(60):
                t = bytes(rng.choice(alpha) for _ in range(rng.randint(50, 800)))
                p = bytes(rng.choice(alpha) for _ in range(rng.randint(1, 12)))
                _, c, fs = kmp.scan_stats(t, kmp.build(p))
                self.assertLessEqual(c, 2 * len(t))
                self.assertLessEqual(fs, len(t))

    def test_t4_exact(self):
        """T4 = a^N, mẫu a^(m-1)b: mỗi byte đúng 2 phép so sánh (1 lệch + 1 khớp), 1 bước lùi."""
        n, m = 5000, 16
        t, p = b"a" * n, b"a" * (m - 1) + b"b"
        matches, c, fs = kmp.scan_stats(t, kmp.build(p))
        self.assertEqual(matches, [])
        self.assertLessEqual(c, 2 * n)
        self.assertGreater(c, 2 * n - 2 * m)          # xấp xỉ 2N, trừ giai đoạn khởi động
        self.assertLessEqual(fs, n)
        _, cb = bf.scan_with_comparisons(t, bf.build(p))   # giao diện BF của TV1
        self.assertEqual(cb, (n - m + 1) * m)         # BF: đúng m phép/ vị trí

    def test_count_mode_same_result(self):
        t, p = b"abababab" * 20, b"abab"
        s = kmp.build(p)
        plain = kmp.scan(t, s)
        counted, c = kmp.scan(t, s, count_comparisons=True)
        self.assertEqual(plain, counted)
        self.assertGreater(c, 0)

    def test_kkmp_single_pass(self):
        """Mỗi chỉ số văn bản được đọc đúng một lần, theo thứ tự tăng dần."""
        t = CountingBytes(b"ushers and hers and his" * 5)
        kmp_k.scan(t, kmp_k.build([b"he", b"she", b"his", b"hers"]))
        self.assertEqual(t.accessed, list(range(len(t))))

    def test_kkmp_comparisons_sum_of_machines(self):
        """Cộng comparisons của k-KMP = tổng comparisons của k lần KMP đơn mẫu."""
        rng = random.Random(3)
        t = bytes(rng.choice(b"ab") for _ in range(2000))
        pats = [bytes(rng.choice(b"ab") for _ in range(rng.randint(1, 8))) for _ in range(6)]
        _, c_k, _ = kmp_k.scan_stats(t, kmp_k.build(pats))
        c_sum = sum(kmp.scan_stats(t, kmp.build(p))[1] for p in pats)
        self.assertEqual(c_k, c_sum)


class Fuzz(unittest.TestCase):
    ALPHABETS = (b"ab", b"ACGT", b"abcdefghijklmnopqrstuvwxyz", bytes(range(256)))

    def test_single_pattern_vs_oracle_and_bf(self):
        rng = random.Random(42)
        for case in range(2000):
            a = rng.choice(self.ALPHABETS)
            n = rng.randint(0, 400)
            t = bytes(rng.choice(a) for _ in range(n))
            m = rng.randint(1, 16)
            if n >= m and rng.random() < 0.7:
                s = rng.randint(0, n - m)
                p = t[s:s + m]
            else:
                p = bytes(rng.choice(a) for _ in range(m))
            exp = oracle_find(t, [p])
            self.assertEqual(kmp.scan(t, kmp.build(p)), exp, f"kmp case {case}")
            self.assertEqual(bf.scan(t, bf.build(p)), exp, f"bf case {case}")
            self.assertEqual(kmp.compute_checksum(kmp.scan(t, kmp.build(p))), kmp.compute_checksum(exp))

    def test_multi_pattern_vs_oracle(self):
        rng = random.Random(99)
        for case in range(1000):
            a = rng.choice(self.ALPHABETS)
            n = rng.randint(0, 600)
            t = bytes(rng.choice(a) for _ in range(n))
            pats = []
            for _ in range(rng.randint(1, 12)):
                m = rng.randint(1, 10)
                if n >= m and rng.random() < 0.6:
                    s = rng.randint(0, n - m)
                    pats.append(t[s:s + m])
                else:
                    pats.append(bytes(rng.choice(a) for _ in range(m)))
            got = kmp_k.scan(t, kmp_k.build(pats))
            self.assertEqual(sorted(got), oracle_find(t, pats), f"kkmp case {case}")


if __name__ == "__main__":
    unittest.main()