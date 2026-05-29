"""Byte-exact Python port of `crates/scanner/src/decode_structure.rs`.

Used two ways by the ML pipeline:
  1. As ML feature #42 (`is_binary_payload`): the decode-through verdict fed
     into the model so it learns to discount base64/hex-wrapped binary while
     keeping real base64-wrapped secrets.
  2. As a corpus oracle: lets `corpus.py` label generated base64-of-binary
     negatives without round-tripping through the Rust binary.

Parity contract: for any credential string, `is_binary_payload(s)` here MUST
agree with `decode_structure::is_encoded_binary(s)` in Rust. The parity harness
(`ml/parity_check.py`) drives a battery of inputs through both and asserts they
match; keep this file and the Rust module in lockstep.

Known, bounded divergence: Rust's base64 STANDARD/URL_SAFE decoders forbid
non-canonical trailing bits, while Python's `base64` silently masks them. This
can only flip the verdict on the final decoded byte of a non-canonical blob,
which never carries a magic header or completes a protobuf parse, so the
`is_binary_payload` verdict is unaffected. The parity harness still checks it.
"""

from __future__ import annotations

import base64
import binascii

MIN_DECODE_LEN = 16

# Leading magic bytes that are definitional: a stream starting with one of
# these IS that format, and no credential carries them. Order matters only for
# reporting the name; membership is what drives the verdict.
_SIGS: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"%PDF-", "pdf"),
    (b"\x7fELF", "elf"),
    (b"\xfe\xed\xfa\xce", "mach-o"),
    (b"\xfe\xed\xfa\xcf", "mach-o"),
    (b"\xcf\xfa\xed\xfe", "mach-o"),
    (b"\xca\xfe\xba\xbe", "java-class"),
    (b"MZ", "pe"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"OggS", "ogg"),
    (b"RIFF", "riff"),
    (b"\x00\x61\x73\x6d", "wasm"),
    (b"\x78\x01", "zlib"),
    (b"\x78\x9c", "zlib"),
    (b"\x78\xda", "zlib"),
    (b"\x78\x5e", "zlib"),
]


class DecodeStructure:
    """Mirror of the Rust `DecodeStructure` struct."""

    __slots__ = ("decodable", "decoded_len", "printable_ratio", "magic", "protobuf_wire")

    def __init__(
        self,
        decodable: bool = False,
        decoded_len: int = 0,
        printable_ratio: float = 0.0,
        magic: str | None = None,
        protobuf_wire: bool = False,
    ) -> None:
        self.decodable = decodable
        self.decoded_len = decoded_len
        self.printable_ratio = printable_ratio
        self.magic = magic
        self.protobuf_wire = protobuf_wire

    def is_binary_payload(self) -> bool:
        return self.magic is not None or (self.protobuf_wire and self.decoded_len >= 8)


def _decode_candidate(s: str) -> bytes | None:
    """Decode as base64 (standard then url-safe, padded or not) or even-length
    hex. Only whole-string clean decodes count, mirroring the Rust logic."""
    looks_b64 = all(
        c.isalnum() or c in "+/-_=" for c in s
    ) and s.isascii()
    if looks_b64:
        rem = len(s) % 4
        padded = s + ("=" * (4 - rem) if rem != 0 else "")
        pb = padded.encode("ascii")
        try:
            return base64.b64decode(pb, validate=True)
        except (binascii.Error, ValueError):
            pass
        try:
            return base64.urlsafe_b64decode(pb)
        except (binascii.Error, ValueError):
            pass
    if (
        len(s) >= MIN_DECODE_LEN
        and len(s) % 2 == 0
        and s.isascii()
        and all(c in "0123456789abcdefABCDEF" for c in s)
    ):
        try:
            return bytes.fromhex(s)
        except ValueError:
            return None
    return None


def _magic_format(b: bytes) -> str | None:
    for sig, name in _SIGS:
        if b.startswith(sig):
            return name
    return None


def _read_varint(data: bytes, start: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    i = start
    n = len(data)
    while True:
        if i >= n:
            return None
        byte = data[i]
        i += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, i
        shift += 7
        if shift > 63:
            return None


def _parse_protobuf_wire(data: bytes) -> bool:
    n = len(data)
    if n < 8:
        return False
    i = 0
    fields = 0
    while i < n:
        tagres = _read_varint(data, i)
        if tagres is None:
            return False
        tag, i = tagres
        wire = tag & 0x07
        field_no = tag >> 3
        if field_no == 0:
            return False
        if wire == 0:
            vres = _read_varint(data, i)
            if vres is None:
                return False
            _, i = vres
        elif wire == 1:
            if i + 8 <= n:
                i += 8
            else:
                return False
        elif wire == 2:
            lres = _read_varint(data, i)
            if lres is None:
                return False
            length, nxt = lres
            x = nxt + length
            if x <= n:
                i = x
            else:
                return False
        elif wire == 5:
            if i + 4 <= n:
                i += 4
            else:
                return False
        else:
            return False
        fields += 1
    return i == n and fields >= 3


def analyze(candidate: str) -> DecodeStructure:
    trimmed = candidate.strip()
    if len(trimmed) < MIN_DECODE_LEN:
        return DecodeStructure()
    decoded = _decode_candidate(trimmed)
    if decoded is None or len(decoded) == 0:
        return DecodeStructure()
    printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
    return DecodeStructure(
        decodable=True,
        decoded_len=len(decoded),
        printable_ratio=printable / len(decoded),
        magic=_magic_format(decoded),
        protobuf_wire=_parse_protobuf_wire(decoded),
    )


def is_encoded_binary(candidate: str) -> bool:
    return analyze(candidate).is_binary_payload()
