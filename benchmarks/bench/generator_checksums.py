"""Checksum primitives shared by synthetic benchmark generators.

GitHub classic/OAuth tokens and npm tokens embed a six-character base62
encoding of the standard CRC32 of their entropy body. Keeping this arithmetic
here prevents one corpus from generating values that another corpus, or the
production scanner, correctly rejects as forged.
"""

from __future__ import annotations

BASE62_DIGITS = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def crc32_iso_hdlc(data: bytes) -> int:
    """Return standard reflected CRC-32/ISO-HDLC."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def base62_encode_u32(value: int, width: int) -> str:
    """Encode a non-negative u32 with KeyHog's fixed base62 alphabet."""
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError("value must fit in an unsigned 32-bit integer")
    if width < 1:
        raise ValueError("width must be positive")
    if value == 0:
        return "0" * width
    digits: list[str] = []
    while value > 0:
        digits.append(chr(BASE62_DIGITS[value % 62]))
        value //= 62
    if len(digits) > width:
        raise ValueError("encoded value does not fit requested width")
    digits.extend("0" for _ in range(width - len(digits)))
    return "".join(reversed(digits))


def crc32_base62(entropy: str, width: int = 6) -> str:
    """Encode the UTF-8 entropy body's CRC32 as fixed-width base62."""
    return base62_encode_u32(crc32_iso_hdlc(entropy.encode()), width)
