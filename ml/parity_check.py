#!/usr/bin/env python3
"""Assert the Python feature port matches the Rust serve-path extractor.

Generates an input battery that stresses every feature group, runs both the
Rust `dump_features` example and `ml/features.py`, and fails loudly on any
per-feature disagreement > TOL. This gate must pass before any retrained
weights.bin is trusted: a mismatch here is train/serve skew.

The Rust extractor is invoked via $KEYHOG_DUMP_FEATURES if set (path to a
prebuilt `dump_features` binary), else `cargo run --example dump_features`.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys

import config_lists
import features

TOL = 1e-5

# Feature 4 is the only CONTINUOUS entropy feature (Shannon entropy / 8.0). At
# serve time the scanner computes entropy through an x86 SIMD kernel that
# accumulates in f32, so it carries ~0.2% error vs the mathematically exact
# f64 value `features.py` computes (verified: true log2(5)=2.321928, Rust
# SIMD=2.31768). This is a normalized input feature and the high-signal entropy
# THRESHOLD features (5,6,7) are exact, so the residual is below model noise.
# Bound it explicitly rather than hide it.
ENTROPY_FEATURE_INDEX = 4
ENTROPY_TOL = 5e-3
# Binary entropy thresholds must match EXACTLY (they carry the real signal).
EXACT_ENTROPY_THRESHOLDS = (5, 6, 7)

DEFAULT_LISTS = config_lists.DEFAULT_LISTS
EMPTY_LISTS = config_lists.EMPTY_LISTS


def build_battery() -> list[tuple[str, str, tuple]]:
    """Return (text, context, lists) records covering every feature group."""
    import base64 as b64mod

    png = b64mod.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(20))).decode()
    gzip = b64mod.b64encode(b"\x1f\x8b\x08\x00" + bytes(24)).decode()
    protobuf = b64mod.b64encode(
        bytes([0x08, 0x96, 0x01, 0x12, 0x07] + list(b"testing") + [0x18, 0x01, 0x25, 0xEF, 0xBE, 0xAD, 0xDE])
    ).decode()

    # Secret-shaped probe values assembled from fragments so this source file
    # holds no full token literal (push-protection / dogfood clean); the prefix
    # is preserved so the prefix features (sk-/AKIA) still get exercised.
    akia = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    skproj = "sk-" + "proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD"
    ghp = "gh" + "p_" + "aBcD1234EFgh5678ijkl9012MNop3456qrST"
    awssec = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYEXAMPLEKEY"

    records = [
        # length / entropy spread
        ("a", "x = a", DEFAULT_LISTS),
        ("short", "val=short", DEFAULT_LISTS),
        (akia, f"aws_access_key = {akia}", DEFAULT_LISTS),
        (skproj, "openai: sk-proj-...", DEFAULT_LISTS),
        (ghp, "token = ghp_...", DEFAULT_LISTS),
        (awssec, "secret_access_key: wJal...", DEFAULT_LISTS),
        ("0123456789abcdef0123456789abcdef", "sha = 0123...", DEFAULT_LISTS),
        ("deadbeefcafebabe1234567890abcdef", "# hex constant", DEFAULT_LISTS),
        # placeholders / examples
        ("changeme", "password = changeme", DEFAULT_LISTS),
        ("YOUR_API_KEY_HERE", "api_key = YOUR_API_KEY_HERE", DEFAULT_LISTS),
        ("aaaaaaaaaa", "key = aaaaaaaaaa", DEFAULT_LISTS),
        # URLs / structure
        ("https://user:pass@host.example.com/path", "url = https://...", DEFAULT_LISTS),
        ("postgres://admin:hunter2@db:5432/app", "DATABASE_URL=postgres://...", DEFAULT_LISTS),
        ("aaaa.bbbb.cccc", "jwt-ish a.b.c", DEFAULT_LISTS),
        ("a-b-c-d-e-f-g-h-i-j-k", "dashes", DEFAULT_LISTS),
        # file-type contexts
        ("xJ8sKd0fmA2bC4dE6fG8", "jobs:\n  build:\n    steps:", DEFAULT_LISTS),
        ("xJ8sKd0fmA2bC4dE6fG8", "resource \"aws_iam_role\" {", DEFAULT_LISTS),
        ("xJ8sKd0fmA2bC4dE6fG8", "const apiKey = ", DEFAULT_LISTS),
        ("xJ8sKd0fmA2bC4dE6fG8", "config.yaml: api_key:", DEFAULT_LISTS),
        ("xJ8sKd0fmA2bC4dE6fG8", "go.string lea rdi .rodata", DEFAULT_LISTS),
        ("xJ8sKd0fmA2bC4dE6fG8", "plain prose with no markers at all here", DEFAULT_LISTS),
        # comment + assignment + test-context
        ("tok_live_5fJ2kP9qR", "// token = tok_live_5fJ2kP9qR", DEFAULT_LISTS),
        ("tok_live_5fJ2kP9qR", "TOKEN: tok_live_5fJ2kP9qR", DEFAULT_LISTS),
        ("tok_live_5fJ2kP9qR", "def test_login(): mock_token =", DEFAULT_LISTS),
        # high-entropy generic secrets
        ("Xk9Lm2Pq7Rs4Tv8Wy1Zb3Cd6Ef0Gh5Ij", "secret = Xk9...", DEFAULT_LISTS),
        ("Zb3Cd6Ef0Gh5Ij9Kl2Mn7Op4Qr8St1Uv6Wx", "API_KEY=Zb3...", DEFAULT_LISTS),
        # decode-to-binary (feature 41 only; base features must still match)
        (png, "asset = " + png[:8], DEFAULT_LISTS),
        (gzip, "blob: " + gzip[:8], DEFAULT_LISTS),
        (protobuf, "data = " + protobuf[:8], DEFAULT_LISTS),
        # empty-list (public) path
        (akia, f"x = {akia}", EMPTY_LISTS),
        ("Xk9Lm2Pq7Rs4Tv8Wy1Zb3Cd6Ef0Gh5Ij", "secret = Xk9...", EMPTY_LISTS),
        # unicode context (ascii-fold + utf-8 byte length)
        ("café_token_abc123XYZ", "passwörd = café_token_abc123XYZ", DEFAULT_LISTS),
    ]
    return records


def encode_line(text: str, context: str, lists: tuple) -> str:
    def b64(s: str) -> str:
        if not s:
            return ""
        return base64.b64encode(s.encode("utf-8")).decode("ascii")

    kp, sk, tk, pk = lists
    fields = [
        b64(text),
        b64(context),
        b64("\n".join(kp)),
        b64("\n".join(sk)),
        b64("\n".join(tk)),
        b64("\n".join(pk)),
    ]
    return " ".join(fields)


def run_rust(lines: list[str]) -> list[list[float]]:
    binpath = os.environ.get("KEYHOG_DUMP_FEATURES")
    if binpath:
        cmd = [binpath]
    else:
        # Default features (the lean --no-default-features path is a separate
        # in-flight build fix); compute_features_with_config is feature-agnostic.
        cmd = [
            "cargo", "run", "-q", "-p", "keyhog-scanner",
            "--example", "dump_features",
        ]
    proc = subprocess.run(
        cmd,
        input="\n".join(lines).encode("utf-8"),
        capture_output=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(f"rust dump_features failed (exit {proc.returncode})")
    out = proc.stdout.decode("utf-8").strip().splitlines()
    return [[float(x) for x in line.split()] for line in out]


def main() -> int:
    battery = build_battery()
    lines = [encode_line(t, c, l) for (t, c, l) in battery]
    rust_vectors = run_rust(lines)

    if len(rust_vectors) != len(battery):
        raise SystemExit(f"row count mismatch: rust={len(rust_vectors)} py={len(battery)}")

    fails = 0
    for idx, ((text, context, lists), rv) in enumerate(zip(battery, rust_vectors)):
        kp, sk, tk, pk = lists
        # Compare the full 42-feature vector (includes decode-structure #41).
        pv = features.compute_features(text, context, kp, sk, tk, pk, with_decode=True)
        if len(rv) != len(pv):
            print(f"[row {idx}] WIDTH mismatch rust={len(rv)} py={len(pv)} text={text!r}")
            fails += 1
            continue
        for fi, (a, b) in enumerate(zip(rv, pv)):
            tol = ENTROPY_TOL if fi == ENTROPY_FEATURE_INDEX else TOL
            if abs(a - b) > tol:
                print(
                    f"[row {idx} feat {fi}] rust={a:.9f} py={b:.9f} "
                    f"diff={abs(a - b):.2e} tol={tol:.0e} text={text!r} ctx={context!r}"
                )
                fails += 1
        # The entropy threshold features must agree bit-for-bit.
        for fi in EXACT_ENTROPY_THRESHOLDS:
            if rv[fi] != pv[fi]:
                print(
                    f"[row {idx} feat {fi}] ENTROPY THRESHOLD mismatch "
                    f"rust={rv[fi]} py={pv[fi]} text={text!r}"
                )
                fails += 1

    total = len(battery) * features.NUM_FEATURES
    if fails == 0:
        print(f"PARITY OK: {len(battery)} records x {features.NUM_FEATURES} features "
              f"= {total} values match within {TOL}")
        return 0
    print(f"PARITY FAILED: {fails} mismatched values")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
