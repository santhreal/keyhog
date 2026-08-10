"""Tests for the CredData miss-analysis dev tool (bench.creddata_miss_analysis).

The tool informs detection decisions (which keyword/shape combinations are worth
surfacing) but never fabricates truth, every value it buckets must be sliceable
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


def test_decompose_redact_mirrors_keyhog_core_redact():
    # `decompose` joins a --dogfood event's redacted credential back to the
    # ground-truth value, so its redaction MUST be byte-identical to
    # keyhog_core::redact: <=8 ASCII chars -> "****", else first4 + "..." + last4.
    assert cma._redact("") == "****"
    assert cma._redact("short8ch") == "****"  # exactly 8 -> masked
    assert cma._redact("abcdefghi") == "abcd...fghi"  # 9 -> first4...last4
    assert cma._redact("GRAPHITE_PASS_value_1234") == "GRAP...1234"
    # The reconstructed redaction is what the bucketer matches on, so a regression
    # here would silently mis-bucket suppressed positives as never-candidate.
    assert cma._redact("gjbubxsu") == "****"  # an 8-char password -> masked


def test_decompose_is_a_registered_command():
    # Coherence: the mode must be wired into argparse (a missing --scanner-bin
    # default would also surface here). `decompose` with a missing corpus exits 2
    # (the same guard the other modes use), proving the command is recognised.
    rc = cma.main(["decompose", "--root", "/nonexistent-corpus-xyz",
                   "--scanner-bin", "keyhog"])
    assert rc == 2

def test_cluster_fn_misses_ranks_by_recoverable_f1_gain():
    fn_items = [
        {"detector": "github-classic-pat", "failed_gate": "un-generated_candidate"},
        {"detector": "github-classic-pat", "failed_gate": "un-generated_candidate"},
        {"detector": "aws-secret-access-key", "failed_gate": "suppressed_by_entropy_floor"},
    ]
    ranked = cma.cluster_fn_misses(fn_items, tp_count=10, total_positives=20, fp_count=2)
    assert len(ranked) == 2
    assert ranked[0]["detector"] == "github-classic-pat"
    assert ranked[0]["fn_count"] == 2
    assert ranked[0]["recoverable_f1_gain"] > ranked[1]["recoverable_f1_gain"]

def test_cluster_fn_misses_handles_ambiguous_detectors_and_multiple_reasons():
    fn_items = [
        {"detector": "ambiguous:aws-key,generic-secret", "failed_gate": "entropy_floor,shape_gate"},
        {"detector": "github-pat", "failed_gate": "un-generated_candidate"},
    ]
    ranked = cma.cluster_fn_misses(fn_items, tp_count=5, total_positives=10, fp_count=1)
    assert len(ranked) == 2
    dets = {r["detector"] for r in ranked}
    assert "ambiguous:aws-key,generic-secret" in dets

def test_cluster_fn_misses_recomputes_precision_with_fp_count():
    fn_items = [
        {"detector": "det_a", "failed_gate": "gate_1"},
        {"detector": "det_a", "failed_gate": "gate_1"},
    ]
    # tp=10, fp=10, total_pos=20 => base_p = 10/20 = 0.5, base_r = 10/20 = 0.5, base_f1 = 0.5
    # new_tp=12, fp=10 => new_p = 12/22 = 0.5455, new_r = 12/20 = 0.6, new_f1 = 0.5714
    ranked = cma.cluster_fn_misses(fn_items, tp_count=10, total_positives=20, fp_count=10)
    assert len(ranked) == 1
    assert ranked[0]["recoverable_f1_gain"] == 0.0714

def test_cluster_is_a_registered_command():
    rc = cma.main(["cluster", "--root", "/nonexistent-corpus-xyz", "--scanner-bin", "keyhog"])
    assert rc == 2
def test_cmd_cluster_uses_one_matching_relation_for_near_hits():
    """Containment matches are TPs in both miss attribution and FP accounting."""
    positive = "secret_value_12345"
    rel = "src/config.py"
    supp: dict[str, set[tuple[str, str, str]]] = {}

    for finding in [positive, "secret_value", f'"{positive}"']:
        is_tp, fn_item = cma.attribute_miss(
            positive,
            rel,
            {rel: [(finding, "my-custom-detector")]},
            supp,
        )
        assert is_tp
        assert fn_item is None
    finds = {
        rel: [
            ("secret_value", "narrow-span"),
            (f'"{positive}"', "wide-span"),
            ("unrelated_finding", "false-positive"),
        ]
    }
    assert cma.count_false_positives(finds, [(rel, positive)]) == 1
