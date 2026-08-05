#!/usr/bin/env python3
"""Audit a KeyHog ignore policy for provenance and staleness.

Every suppression in a repository dogfood policy has to answer three
questions: who approved it, why it exists, and whether it still suppresses
anything. A flat list of hashes answers none of them, and a `path:` entry
that names a file which was renamed or split keeps passing while it silently
stops covering the fixture it was written for.

This auditor enforces:

* every active entry carries inline `reason=` and `approved_by=` metadata
  (the governance trailer `keyhog_core::Allowlist` already parses);
* every `path:` entry that names a concrete path (no glob metacharacter)
  resolves on disk;
* every `hash:` entry actually matched something in a companion
  no-suppression scan report, when one is supplied.

It also writes a coverage manifest so two lanes running different policies
can be diffed instead of trusted.

Usage:
    suppression_audit.py --policy .keyhogignore --root . \
        [--unsuppressed report.json ...] [--manifest out.json] [--allow-unused-hashes]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

GLOB_METACHARACTERS = set("*?[]{}!")

# Parsed shape of one policy line.
KIND_HASH = "hash"
KIND_PATH = "path"
KIND_DETECTOR = "detector"

BARE_SHA256 = re.compile(r"\A[0-9a-fA-F]{64}\Z")


class Entry:
    __slots__ = ("line_number", "kind", "value", "metadata", "raw")

    def __init__(self, line_number: int, kind: str, value: str, metadata: dict, raw: str):
        self.line_number = line_number
        self.kind = kind
        self.value = value
        self.metadata = metadata
        self.raw = raw

    def label(self) -> str:
        return f"{self.kind}:{self.value}"


def metadata_tokens(trailer: str) -> list[str]:
    """Split on `;` outside quotes, mirroring `keyhog_core::allowlist::metadata`.

    A `reason=` free-text value routinely contains a semicolon, so a naive
    split truncates it and the auditor reads a different reason than the
    scanner does.
    """
    tokens: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(trailer):
        if escaped:
            escaped = False
            continue
        if quote is not None and char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == ";":
            tokens.append(trailer[start:index])
            start = index + 1
    tokens.append(trailer[start:])
    return tokens


def split_metadata(trailer: str) -> dict:
    """Parse the `; key=value; key=value` trailer.

    Mirrors `keyhog_core::allowlist::metadata`: `;`-separated tokens, one
    layer of matching quotes stripped.
    """
    out: dict[str, str] = {}
    for token in metadata_tokens(trailer):
        token = token.strip()
        if not token or "=" not in token:
            continue
        key, _, value = token.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def parse_policy(path: Path) -> tuple[list[Entry], list[str]]:
    entries: list[Entry] = []
    errors: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        head, _, trailer = line.partition(";")
        head = head.strip()
        metadata = split_metadata(trailer)
        if head.startswith("hash:"):
            entry = Entry(number, KIND_HASH, head[len("hash:") :].strip().lower(), metadata, line)
        elif head.startswith("path:"):
            entry = Entry(number, KIND_PATH, head[len("path:") :].strip(), metadata, line)
        elif head.startswith("detector:"):
            entry = Entry(number, KIND_DETECTOR, head[len("detector:") :].strip(), metadata, line)
        elif BARE_SHA256.match(head):
            entry = Entry(number, KIND_HASH, head.lower(), metadata, line)
        else:
            errors.append(f"{path}:{number}: unrecognized entry `{head}`")
            continue
        entries.append(entry)
    return entries, errors


def load_report_hashes(report: Path) -> set[str]:
    """Collect credential hashes from a KeyHog `json` or `jsonl` report."""
    text = report.read_text(encoding="utf-8").strip()
    if not text:
        return set()
    hashes: set[str] = set()
    if text.startswith("["):
        findings = json.loads(text)
    else:
        findings = [json.loads(line) for line in text.splitlines() if line.strip()]
    for finding in findings:
        digest = finding.get("credential_hash")
        if isinstance(digest, str):
            hashes.add(digest.lower())
    return hashes


def audit(args: argparse.Namespace) -> int:
    policy = Path(args.policy)
    root = Path(args.root)
    entries, failures = parse_policy(policy)

    for entry in entries:
        missing = [
            field for field in ("reason", "approved_by") if not entry.metadata.get(field, "").strip()
        ]
        if missing:
            failures.append(
                f"{policy}:{entry.line_number}: `{entry.label()}` is missing "
                f"{' and '.join(missing)}= metadata; every suppression needs an owner and a reason"
            )

    # A `path:` entry naming a concrete file is the fragile kind: a rename or a
    # module split leaves it parsing fine while covering nothing. Glob entries
    # are matched against scanned paths at runtime and can legitimately match
    # zero files in a partial checkout. A `reason=transient:` entry names a
    # generated, gitignored, or external tree that is absent on a clean
    # checkout. Everything else must resolve.
    for entry in (e for e in entries if e.kind == KIND_PATH):
        if entry.metadata.get("reason", "").startswith("transient:"):
            continue
        literal = not (set(entry.value) & GLOB_METACHARACTERS)
        if not literal:
            continue
        target = root / entry.value.rstrip("/")
        if not target.exists():
            failures.append(
                f"{policy}:{entry.line_number}: `path:{entry.value}` does not exist under {root}. "
                "A renamed or split file leaves this entry suppressing nothing."
            )

    unused_hashes: list[Entry] = []
    observed: set[str] = set()
    if args.unsuppressed:
        for report in args.unsuppressed:
            observed |= load_report_hashes(Path(report))
        for entry in (e for e in entries if e.kind == KIND_HASH):
            if entry.value not in observed:
                unused_hashes.append(entry)
        if unused_hashes and not args.allow_unused_hashes:
            for entry in unused_hashes:
                failures.append(
                    f"{policy}:{entry.line_number}: `hash:{entry.value}` matched nothing in the "
                    "no-suppression scan; it is stale and should be removed"
                )

    if args.manifest:
        manifest = {
            "policy": str(policy),
            "root": str(root),
            "entries": {
                "total": len(entries),
                "hash": sum(1 for e in entries if e.kind == KIND_HASH),
                "path": sum(1 for e in entries if e.kind == KIND_PATH),
                "detector": sum(1 for e in entries if e.kind == KIND_DETECTOR),
            },
            "excluded_paths": sorted(e.value for e in entries if e.kind == KIND_PATH),
            "suppressions": [
                {
                    "line": e.line_number,
                    "kind": e.kind,
                    "value": e.value,
                    "reason": e.metadata.get("reason", ""),
                    "approved_by": e.metadata.get("approved_by", ""),
                    "expires": e.metadata.get("expires", ""),
                }
                for e in entries
            ],
            "observed_hashes": len(observed),
            "unused_hashes": sorted(e.value for e in unused_hashes),
        }
        Path(args.manifest).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    if failures:
        print(f"suppression audit FAILED for {policy}", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(
        f"suppression audit OK: {policy} has {len(entries)} entries "
        f"(all carry reason + approved_by, all literal paths resolve"
        + (f", {len(observed)} hashes observed" if args.unsuppressed else "")
        + ")"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, help="ignore policy file to audit")
    parser.add_argument("--root", default=".", help="repository root the policy applies to")
    parser.add_argument(
        "--unsuppressed",
        action="append",
        default=[],
        help="KeyHog json/jsonl report produced WITHOUT this policy; enables stale-hash detection",
    )
    parser.add_argument("--manifest", help="write a coverage manifest here")
    parser.add_argument(
        "--allow-unused-hashes",
        action="store_true",
        help="report unused hashes in the manifest without failing (partial-corpus runs)",
    )
    return audit(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
