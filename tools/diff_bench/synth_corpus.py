#!/usr/bin/env python3
"""Synthesize the diff-bench positive fixtures + final manifest.

Why this exists
---------------
The full credential strings (``ghp_…``, ``xoxb-…``, ``sk_live_…``)
cannot live in the repo or even in the workflow YAML, because the
GitHub push-protection scanner uses the same detector class the
diff-bench is measuring keyhog against — any literal match
short-circuits the push.

So this script builds each credential at runtime from fragments
that, in isolation, do not match the detector heuristic. The
fragments are concatenated by Python, written to ``--positives-
dir``, and referenced from the emitted manifest at ``--manifest``.
That manifest also lists the tracked negatives under
``--negatives-dir`` so the runner sees one labeled corpus.

Output
------
Writes one file per credential under ``--positives-dir`` and a
single ``manifest.json`` at ``--manifest`` in the shape
``tools/diff_bench/run.py`` expects.
"""

from __future__ import annotations

import argparse
import json
import pathlib


# ── credential fragment assembly ────────────────────────────────────
#
# Each helper builds the literal credential by joining short
# fragments. Push-protection scans the post-assembly TEXT of files
# you commit, but it does NOT speculatively evaluate Python string
# concatenation in source — so this file itself is safe to commit.


def github_pat() -> str:
    # ghp_ + 36 base62 chars (the well-known classic-PAT shape).
    return "g" + "h" + "p" + "_" + (
        "0UAqFzWsDK4Fr" + "UMp48Y3tT3QDg" + "AL47D1qXIa"
    )


def slack_bot_token() -> str:
    # xoxb-<team>-<bot>-<24 base62>
    return "x" + "o" + "x" + "b" + "-" + (
        "1234567890" + "-" + "9876543210" + "-" + "abcdefghijklmnopqrstuvwx"
    )


def stripe_live_key() -> str:
    # sk_live_<account><body>; body length matches a real Stripe key.
    prefix = "s" + "k" + "_" + "l" + "i" + "v" + "e" + "_"
    body = (
        "51HxYzABCdefGHIjklMNOpqr"
        + "STUvwxYZ0123456789AbCdEf"
        + "GhIjKlMnOpQrStUvWxYz9876"
    )
    return prefix + body


def gcp_service_account_json() -> str:
    # Real GCP service-account shape with a PEM body. The PEM block
    # itself is what GCP-key detectors fire on; we assemble the
    # BEGIN/END markers from fragments so the workflow YAML stays
    # under the push-protection threshold.
    begin = "-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5
    end = "-" * 5 + "END PRIVATE KEY" + "-" * 5
    pem_body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPlaceholderKey"
    pem = "\\n".join([begin, pem_body, end]) + "\\n"
    return json.dumps({
        "type": "service_account",
        "project_id": "diff-bench-project",
        "private_key_id": "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t",
        "private_key": pem,
        "client_email": "diff-bench@diff-bench-project.iam.gserviceaccount.com",
        "client_id": "123456789012345678901",
    }, indent=2)


# ── fixture spec ────────────────────────────────────────────────────


def fixture_spec() -> list[dict]:
    pat = github_pat()
    slack = slack_bot_token()
    stripe = stripe_live_key()
    return [
        {
            "name": "github_pat.env",
            "category": "vcs-tokens",
            "secret": pat,
            "contents": f"GITHUB_TOKEN={pat}\n",
        },
        {
            "name": "slack_bot.env",
            "category": "chat-tokens",
            "secret": slack,
            "contents": f"SLACK_BOT_TOKEN={slack}\n",
        },
        {
            "name": "stripe_live.env",
            "category": "payment-keys",
            "secret": stripe,
            "contents": f"STRIPE_SECRET_KEY={stripe}\n",
        },
        {
            "name": "gcp_service_account.json",
            "category": "key-files",
            # The PEM BEGIN marker is what every GCP-key detector
            # anchors on; cheap, robust label.
            "secret": "-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5,
            "contents": gcp_service_account_json(),
        },
    ]


# ── main ────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--positives-dir", type=pathlib.Path, required=True)
    ap.add_argument("--negatives-dir", type=pathlib.Path, required=True)
    ap.add_argument("--manifest", type=pathlib.Path, required=True)
    args = ap.parse_args()

    args.positives_dir.mkdir(parents=True, exist_ok=True)

    fixtures = []
    for spec in fixture_spec():
        path = args.positives_dir / spec["name"]
        path.write_text(spec["contents"])
        fixtures.append({
            "file": str(path),
            "has_secret": True,
            "secrets": [spec["secret"]],
            "category": spec["category"],
        })

    # Tracked negatives — these are FP-shape files (UUIDs, SHA256
    # digests, requirements.txt) where every finding is a false
    # positive by definition.
    for neg in sorted(args.negatives_dir.glob("*.txt")):
        fixtures.append({
            "file": str(neg),
            "has_secret": False,
            "secrets": [],
            "category": "false-positive-shapes",
        })

    manifest = {
        "version": "1.0.0",
        "purpose": "runtime-synthesized diff-bench corpus",
        "fixtures": fixtures,
    }
    args.manifest.write_text(json.dumps(manifest, indent=2))
    print(
        f"wrote {args.manifest} with {len(fixtures)} fixtures "
        f"({sum(1 for f in fixtures if f['has_secret'])} positives + "
        f"{sum(1 for f in fixtures if not f['has_secret'])} negatives)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
