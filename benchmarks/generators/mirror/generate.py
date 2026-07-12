#!/usr/bin/env python3
"""Generate the SecretBench mirror corpus.

Emits a directory of source files + a `manifest.jsonl` in the
SecretBench-shape record schema. The manifest is what the bench scorer
(`bench.corpora.mirror` + `bench.score`) reads to evaluate scanners.

Defaults aim for the same scale as the real SecretBench dataset
(~15 k labeled positives + ~80 k labeled negatives). The generator
is deterministic for a given `--seed`, so two runs produce the same
corpus.

Usage (normally driven by the bench wrapper, which lifts the manifest into
the split layout the loader expects):
    python -m bench.corpora.mirror --ensure --positives 3000 --negatives 12000

Direct invocation:
    python benchmarks/generators/mirror/generate.py \
        --out <corpus_dir> --positives 15000 --negatives 80000 --seed 0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import random
import sys
from collections.abc import Iterator

# Import sibling modules without forcing the user to install the
# package — script lives next to providers/wrappers/negatives.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
# benchmarks/ on the path so `bench.textstats` (the ONE Shannon-entropy home) is
# importable without installing the package.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
import negatives  # noqa: E402
import providers  # noqa: E402
import wrappers  # noqa: E402

from bench.textstats import shannon_entropy  # noqa: E402


# ── helpers ────────────────────────────────────────────────────────


# base64url alphabet: the same symbol set `has_symbol` excludes from being a
# symbol (`+ / = - _`), so a value with `-`/`_` is base64(url), not alphanumeric.
_BASE64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
)


def classify_charset(s: str) -> str:
    has_letter = any(c.isalpha() for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_symbol = any(not c.isalnum() and c not in {"+", "/", "=", "-", "_"} for c in s)
    if has_symbol:
        return "symbolic"
    if all(c in "0123456789abcdefABCDEF" for c in s):
        return "hex"
    if s and all(c in _BASE64_CHARS for c in s):
        return "base64"
    if has_letter and has_digit:
        return "alphanumeric"
    return "mixed"


def has_word(s: str) -> bool:
    # Cheap dictionary-shape probe: a single 5+ letter alpha run.
    run = 0
    for ch in s:
        if ch.isalpha():
            run += 1
            if run >= 5:
                return True
        else:
            run = 0
    return False


# ── repo-name + commit-id fabricators ─────────────────────────────


_SYNTH_REPO_ORG = [
    "acme", "globex", "initech", "umbrella", "wonka", "cyberdyne",
    "soylent", "stark", "wayne", "tyrell", "weyland", "yutani",
]
_SYNTH_REPO_NAME = [
    "api", "core", "infra", "deploy", "monorepo", "platform",
    "service", "edge", "ingest", "backend", "frontend", "ops",
]


def synth_repo_name(rnd: random.Random) -> str:
    return f"{rnd.choice(_SYNTH_REPO_ORG)}/{rnd.choice(_SYNTH_REPO_NAME)}"


def synth_commit_id(rnd: random.Random) -> str:
    return "".join(rnd.choice("0123456789abcdef") for _ in range(40))


def synth_path(rnd: random.Random, ext: str) -> str:
    dirs = rnd.choice([
        "src", "config", "deploy", "ops", "internal", "pkg",
        "cmd", "scripts", "infra", "examples", "lib",
    ])
    sub = rnd.choice(["api", "core", "auth", "db", "billing", "user", "search"])
    name = rnd.choice([
        "settings", "config", "secrets", "deploy", "env", "main",
        "client", "service", "broker", "consumer", "producer",
    ])
    if ext == "Dockerfile":
        return f"{dirs}/{sub}/Dockerfile"
    return f"{dirs}/{sub}/{name}.{ext}"


# ── record builders ───────────────────────────────────────────────


def make_positive_record(
    rnd: random.Random,
    idx: int,
) -> tuple[dict, str]:
    """Build one labeled-positive (record, file_contents)."""
    category, file_type_default, secret, anchors = next(providers.weighted_iter(rnd, 1))
    wrapper_name, extension, wrapper_fn = wrappers.pick_wrapper(file_type_default, rnd)
    # 70% chance use service-anchor, 30% fall back to generic key pool.
    key_override = wrappers.pick_anchor_key(rnd, anchors)
    contents = wrapper_fn(secret, rnd, key_override)

    # Locate the secret within the wrapper's emitted text. For
    # multi-line PEMs / k8s base64 the secret may have been
    # transformed; we record the first occurrence we can find. If
    # the wrapper applied a transformation (k8s base64) we still
    # report the position of the wrapper's emitted body so the
    # scanner is scored on what it surfaces from THIS file.
    needle = secret
    pos = contents.find(needle)
    if pos < 0:
        # k8s wrapper base64-encoded the secret; pick the encoded
        # body line so location at least anchors to it.
        for cand in contents.split("\n"):
            if cand.strip().startswith("api-key:") or cand.strip().startswith("token:") or cand.strip().startswith("secret-key:"):
                pos = contents.find(cand)
                needle = cand.split(":", 1)[1].strip()
                break
    if pos < 0:
        pos = 0

    pre = contents[:pos]
    start_line = pre.count("\n") + 1
    start_column = pos - (pre.rfind("\n") + 1)
    end_offset = pos + len(needle)
    end_pre = contents[:end_offset]
    end_line = end_pre.count("\n") + 1
    end_column = end_offset - (end_pre.rfind("\n") + 1)
    is_multiline = "\n" in needle

    rec = {
        "id": f"mirror-pos-{idx:07d}",
        "secret": needle,
        "repo_name": synth_repo_name(rnd),
        "commit_id": synth_commit_id(rnd),
        "file_path": synth_path(rnd, extension),
        "start_line": start_line,
        "end_line": end_line,
        "start_column": start_column,
        "end_column": end_column,
        "label": True,
        "category": category,
        "comment": f"wrapper={wrapper_name}",
        "entropy": round(shannon_entropy(needle), 3),
        "character_set": classify_charset(needle),
        "has_words": has_word(needle),
        "length": len(needle),
        "is_template": False,
        "is_multiline": is_multiline,
        "in_url": needle.startswith(("http://", "https://"))
        or "://" in needle and "@" in needle,
        "committer_email": f"engineer-{rnd.randint(1, 999)}@example.org",
        "commit_date": f"2026-{rnd.randint(1, 5):02d}-{rnd.randint(1, 28):02d}T10:00:00Z",
        "domain": "",
        "file_type": extension,
    }
    return rec, contents


def make_negative_record(
    rnd: random.Random,
    idx: int,
) -> tuple[dict, str]:
    kind, body = next(negatives.weighted_iter(rnd, 1))
    # Wrap the FP body in a realistic shape too — same wrapper pool
    # as positives, so a scanner is judged on the same file
    # population either way. Negatives ALWAYS get a generic key
    # (no `key_override`) — a base64 protobuf wrapped as
    # `AWS_SECRET_ACCESS_KEY=` would be a real-world misuse worth
    # flagging, so we keep the bench's negative shapes neutral.
    wrapper_name, extension, wrapper_fn = wrappers.pick_wrapper("env", rnd)
    contents = wrapper_fn(body, rnd, None)

    pos = contents.find(body)
    if pos < 0:
        pos = 0
    pre = contents[:pos]
    start_line = pre.count("\n") + 1
    start_column = pos - (pre.rfind("\n") + 1)
    end_offset = pos + len(body)
    end_pre = contents[:end_offset]
    end_line = end_pre.count("\n") + 1
    end_column = end_offset - (end_pre.rfind("\n") + 1)

    rec = {
        "id": f"mirror-neg-{idx:07d}",
        "secret": body,
        "repo_name": synth_repo_name(rnd),
        "commit_id": synth_commit_id(rnd),
        "file_path": synth_path(rnd, extension),
        "start_line": start_line,
        "end_line": end_line,
        "start_column": start_column,
        "end_column": end_column,
        "label": False,
        "category": kind,
        "comment": f"negative-shape; wrapper={wrapper_name}",
        "entropy": round(shannon_entropy(body), 3),
        "character_set": classify_charset(body),
        "has_words": has_word(body),
        "length": len(body),
        "is_template": kind in {"template-placeholder", "docs-example-marker"},
        "is_multiline": "\n" in body,
        "in_url": False,
        "committer_email": f"engineer-{rnd.randint(1, 999)}@example.org",
        "commit_date": f"2026-{rnd.randint(1, 5):02d}-{rnd.randint(1, 28):02d}T10:00:00Z",
        "domain": "",
        "file_type": extension,
    }
    return rec, contents


# ── main ──────────────────────────────────────────────────────────


def shard_path(out: pathlib.Path, idx: int) -> pathlib.Path:
    """Spread files across 256 directories (00-ff) so no single
    directory has more than ~400 entries. Filesystem-friendly on
    every common FS we care about (ext4/btrfs/xfs/apfs/ntfs)."""
    bucket = f"{(idx & 0xFF):02x}"
    return out / bucket


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=pathlib.Path, required=True,
                    help="Output corpus directory")
    ap.add_argument("--positives", type=int, default=15000,
                    help="Number of labeled positive records")
    ap.add_argument("--negatives", type=int, default=80000,
                    help="Number of labeled negative records")
    ap.add_argument("--seed", type=int, default=0,
                    help="RNG seed (deterministic output)")
    args = ap.parse_args()

    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    rnd = random.Random(args.seed)
    manifest_path = out / "manifest.jsonl"

    written = 0
    total = args.positives + args.negatives

    with open(manifest_path, "w") as mf:
        for i in range(args.positives):
            rec, contents = make_positive_record(rnd, i)
            shard = shard_path(out, i)
            shard.mkdir(parents=True, exist_ok=True)
            file_path = shard / f"{rec['id']}.{rec['file_type']}"
            file_path.write_text(contents)
            rec["on_disk_path"] = str(file_path.relative_to(out))
            mf.write(json.dumps(rec) + "\n")
            written += 1
            if written % 1000 == 0:
                pct = 100.0 * written / total
                print(f"  generated {written:>6}/{total} ({pct:5.1f}%)",
                      file=sys.stderr, flush=True)

        for i in range(args.negatives):
            rec, contents = make_negative_record(rnd, i)
            shard = shard_path(out, i + args.positives)
            shard.mkdir(parents=True, exist_ok=True)
            file_path = shard / f"{rec['id']}.{rec['file_type']}"
            file_path.write_text(contents)
            rec["on_disk_path"] = str(file_path.relative_to(out))
            mf.write(json.dumps(rec) + "\n")
            written += 1
            if written % 1000 == 0:
                pct = 100.0 * written / total
                print(f"  generated {written:>6}/{total} ({pct:5.1f}%)",
                      file=sys.stderr, flush=True)

    # Corpus stats hash so subsequent runs can verify reproducibility.
    h = hashlib.sha256()
    with open(manifest_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    (out / "manifest.sha256").write_text(h.hexdigest() + "\n")

    print(
        f"\nDone. Wrote {written} records ({args.positives} positives + "
        f"{args.negatives} negatives) to {out}\nmanifest: {manifest_path}\n"
        f"manifest sha256: {h.hexdigest()}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
