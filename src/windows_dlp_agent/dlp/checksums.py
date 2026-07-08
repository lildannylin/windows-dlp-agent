"""Checksum validators for structured sensitive data (spec §4.1/§4.2).

These make structured detections near-zero false-positive, which is what lets
the engine treat them as hard-block (§4.3).
"""

from __future__ import annotations

import math
import re
from collections import Counter

__all__ = [
    "luhn_valid",
    "taiwan_id_valid",
    "taiwan_ubn_valid",
    "shannon_entropy",
]


def luhn_valid(number: str) -> bool:
    """Luhn (mod-10) check used by credit-card numbers. Ignores separators."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12:  # shortest real PAN-ish length we accept
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# Letter -> two-digit code for the Taiwan national ID checksum.
_TW_LETTER = {
    "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16, "H": 17,
    "I": 34, "J": 18, "K": 19, "L": 20, "M": 21, "N": 22, "O": 35, "P": 23,
    "Q": 24, "R": 25, "S": 26, "T": 27, "U": 28, "V": 29, "W": 32, "X": 30,
    "Y": 31, "Z": 33,
}

_TW_ID_RE = re.compile(r"[A-Z][12][0-9]{8}")


def taiwan_id_valid(s: str) -> bool:
    """Taiwan national ID: 1 letter + gender digit(1/2) + 8 digits, weighted mod-10."""
    s = s.strip().upper()
    if not _TW_ID_RE.fullmatch(s):
        return False
    code = _TW_LETTER[s[0]]
    n1, n2 = divmod(code, 10)
    digits = [n1, n2] + [int(c) for c in s[1:]]
    weights = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1]
    total = sum(d * w for d, w in zip(digits, weights))
    return total % 10 == 0


_UBN_RE = re.compile(r"[0-9]{8}")
_UBN_WEIGHTS = [1, 2, 1, 2, 1, 2, 4, 1]


def taiwan_ubn_valid(s: str) -> bool:
    """Taiwan unified business number (統一編號): 8 digits, weighted digit-sum mod-10."""
    s = s.strip()
    if not _UBN_RE.fullmatch(s):
        return False

    def digit_sum(n: int) -> int:
        return n // 10 + n % 10

    total = sum(digit_sum(int(s[i]) * _UBN_WEIGHTS[i]) for i in range(8))
    if total % 10 == 0:
        return True
    # Special rule: when the 7th digit is 7 either total or total+1 may divide by 10.
    return s[6] == "7" and (total + 1) % 10 == 0


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char; high values flag unstructured secrets (§4.2)."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
