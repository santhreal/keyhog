"""Tests for the CredData miss-analysis dev tool (bench.creddata_miss_analysis).

The tool informs detection decisions (which keyword/shape combinations are worth
surfacing) but never fabricates truth — every value it buckets must be sliceable
from its on-disk byte span, exactly like the production CredData adapter. These
tests pin the value-slicing + per-keyword precision split on a tiny synthetic
corpus so the numbers the tool reports are provably the corpus's, not an artifact
of the regex or the canonicaliser.
"""

from __future__ import annotations

import csv
import pathlib

from bench import creddata_miss_analysis as cma


def _write_corpus(root: pathlib.Path, rows: list[dict]) -> None:
    """Materialise a CredData-shaped corpus: one source file + one meta CSV.

    Each row is (rel_path, line_text, value, ground_truth). The meta CSV records
    1-based LineStart and 0-based ValueStart/ValueEnd byte columns the tool reads.
    """
    (root / "meta").mkdir(parents=True)
    by_file: dict[str, list[str]] = {}
    meta_rows = []
    for rel, line_text, value, gt in rows:
        lines = by_file.setdefault(rel, [])
        lines.append(line_text)
        line_no = len(lines)  # 1-based
        vs = line_text.index(value)
        meta_rows.append(
            {
                "FilePath": rel,
                "LineStart": line_no,
                "LineEnd": line_no,
                "ValueStart": vs,
                "ValueEnd": vs + len(value),
                "GroundTruth": gt,
                "Category": "Key",
            }
        )
    for rel, lines in by_file.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with open(root / "meta" / "corpus.csv", "w", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "FilePath",
                "LineStart",
                "LineEnd",
                "ValueStart",
                "ValueEnd",
                "GroundTruth",
                "Category",
            ],
        )
        w.writeheader()
        w.writerows(meta_rows)


def _hexn(n: int, seed: int) -> str:
    """A distinct, non-repetitive n-char hex string (deterministic per seed)."""
    digits = "0123456789abcdef"
    # A simple LCG over the seed gives varied, non-uniform nibbles so the value
    # is not a repetitive-run decoy and is a unique span in its line.
    s, x = [], (seed * 2654435761 + 12345) & 0xFFFFFFFF
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        s.append(digits[(x >> 16) & 0xF])
    return "".join(s)


def test_keywords_buckets_hex32_48_by_canonical_keyword(tmp_path, capsys):
    # `key`-canonical bucket: 4 POS hex32 + 1 POS hex48 + 1 NEG hex32 = 6 rows,
    # P = 5/6 = 0.833, split h32 4/1 and h48 1/0.
    rows = []
    for i in range(4):
        v = _hexn(32, i)
        rows.append(("data/k.txt", f"Key = {v}", v, "T"))
    v48 = _hexn(48, 100)
    rows.append(("data/k.txt", f"Key = {v48}", v48, "T"))
    vneg = _hexn(32, 200)
    rows.append(("data/k.txt", f"Key = {vneg}", vneg, "F"))
    # `apikey`-canonical bucket: 5 POS hex32 -> P=1.000, a separate bucket.
    for i in range(5):
        v = _hexn(32, 300 + i)
        rows.append(("data/a.txt", f"api_key = {v}", v, "T"))
    # hex64 must be ignored entirely (not a mirror-safe length), 5 of them so a
    # length bug would surface as its own bucket row.
    for i in range(5):
        v = _hexn(64, 400 + i)
        rows.append(("data/h.txt", f"Key = {v}", v, "T"))
    _write_corpus(tmp_path, rows)

    rc = cma.cmd_keywords(tmp_path)
    assert rc == 0
    out = capsys.readouterr().out

    key_line = next(ln for ln in out.splitlines() if ln.startswith("key "))
    parts = key_line.split()
    assert parts[0] == "key"
    assert parts[1] == "5", f"key POS should be 5: {key_line}"
    assert parts[2] == "1", f"key NEG should be 1: {key_line}"
    assert parts[3] == "0.833", f"key precision should be 0.833: {key_line}"
    assert "4/1" in key_line, f"key hex32 split should be 4/1: {key_line}"
    assert "1/0" in key_line, f"key hex48 split should be 1/0: {key_line}"

    # apikey bucket present and perfectly precise across its 5 samples.
    api_line = next(ln for ln in out.splitlines() if ln.startswith("apikey "))
    assert api_line.split()[1] == "5"
    assert api_line.split()[3] == "1.000"

    # hex64 was excluded: total = 5 (key POS) + 1 (key NEG) + 5 (apikey) = 11.
    assert "POS=10 NEG=1" in out, out


def test_keywords_ignores_unsliceable_and_non_hex(tmp_path, capsys):
    # A non-hex value and a hex of non-canonical length (40) must not bucket.
    rows = [
        ("data/x.txt", 'key = "not_hex_value_here_abcdef"', "not_hex_value_here_abcdef", "T"),
        ("data/x.txt", "key = " + "a" * 40, "a" * 40, "T"),
    ]
    _write_corpus(tmp_path, rows)
    rc = cma.cmd_keywords(tmp_path)
    assert rc == 0
    out = capsys.readouterr().out
    # No qualifying rows -> the per-keyword table has no data line and the
    # total line reports the empty-corpus sentinel.
    assert "none" in out, out
