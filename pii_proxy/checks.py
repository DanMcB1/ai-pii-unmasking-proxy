"""Checksums used by the detector: Luhn (cards), ABA routing, VIN check digit."""

from __future__ import annotations


def luhn_ok(digits: str) -> bool:
    """Return True if `digits` (0-9 only) passes the Luhn check."""
    if not digits or not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    alt = False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def aba_routing_ok(digits: str) -> bool:
    """US ABA routing number checksum (weights 3, 7, 1)."""
    if not digits or not digits.isdigit() or len(digits) != 9:
        return False
    weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    total = sum(int(d) * w for d, w in zip(digits, weights))
    return total % 10 == 0


# VIN transliteration for the check-digit algorithm (ISO 3779).
_VIN_MAP = {
    **{str(i): i for i in range(10)},
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def vin_ok(vin: str) -> bool:
    """17-character VIN with at least one letter, no I/O/Q, and a valid check digit."""
    vin = vin.upper()
    if len(vin) != 17:
        return False
    if any(ch in "IOQ" for ch in vin):
        return False
    if any(ch not in _VIN_MAP for ch in vin):
        return False
    # Real VINs always contain letters. A 17-digit numeric run is not a VIN
    # even if the ISO 3779 check digit happens to pass (for example, all nines).
    if not any(ch.isalpha() for ch in vin):
        return False
    total = 0
    for i, ch in enumerate(vin):
        total += _VIN_MAP[ch] * _VIN_WEIGHTS[i]
    check = total % 11
    expected = "X" if check == 10 else str(check)
    return vin[8] == expected
