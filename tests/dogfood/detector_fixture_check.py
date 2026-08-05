#!/usr/bin/env python3
"""Sample-aware gate for credentials inside `detectors/`.

The operator lane hides the whole detector corpus behind `path:detectors/`.
That is unreviewable: it cannot tell an intentional sample from a credential
somebody pasted into a detector definition. The strict lane scans the corpus
and gates it here instead.

Two mechanisms, because neither is sufficient alone:

* An **inventory** of every reviewed credential in the corpus, keyed by value
  hash and committed next to this script. A hash that is not in the inventory
  fails. A hash in the inventory that no longer appears fails too, so the file
  cannot rot the way a hand-maintained suppression list does. Regenerate with
  `--update` and the diff is the review.

* A **field classification** for each finding. A detector TOML declares its own
  sample material in `regex`, `test_positive`, `test_negative`, `example`, and
  friends. The inventory records whether each credential sits on one of those
  lines, so a reviewer reading the diff can see at a glance that a new entry
  landed somewhere a sample has no business being.

Usage:
    detector_fixture_check.py --report strict-report.json --root . [--update]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_INVENTORY = Path(__file__).with_name("detector_fixture_inventory.json")

# TOML keys whose values are, by construction, detector sample material.
FIXTURE_KEYS = {
    "companion_regex",
    "description",
    "example",
    "examples",
    "regex",
    "required_literals",
    "test_negative",
    "test_positive",
    "validator_example",
}

KEY_LINE = re.compile(r"""^\s*(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rest>.*)$""")


def fixture_lines(toml_path: Path) -> set[int]:
    """Line numbers (1-based) owned by a declared fixture field or a comment.

    Handles `key = "value"`, `key = '''multi-line'''`, and `key = [ ... ]`.
    """
    lines = toml_path.read_text(encoding="utf-8", errors="replace").splitlines()
    owned: set[int] = set()
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.strip().startswith("#"):
            owned.add(index + 1)
            index += 1
            continue
        match = KEY_LINE.match(line)
        if not match or match.group("key") not in FIXTURE_KEYS:
            index += 1
            continue
        owned.add(index + 1)
        rest = match.group("rest")
        terminator = None
        for opener, closer in (("'''", "'''"), ('"""', '"""'), ("[", "]")):
            if rest.startswith(opener) and not rest[len(opener) :].rstrip().endswith(closer):
                terminator = closer
                break
        index += 1
        if terminator is None:
            continue
        while index < len(lines):
            owned.add(index + 1)
            if lines[index].rstrip().endswith(terminator):
                index += 1
                break
            index += 1
    return owned


def collect(report: Path, root: Path, detectors_dir: str) -> dict[str, dict]:
    prefix = detectors_dir.rstrip("/") + "/"
    findings = json.loads(report.read_text(encoding="utf-8"))
    cache: dict[str, set[int]] = {}
    inventory: dict[str, dict] = {}

    for finding in findings:
        location = finding.get("location") or {}
        raw = location.get("file_path") or ""
        if not raw:
            continue
        candidate = Path(raw)
        if candidate.is_absolute():
            try:
                path = candidate.resolve().relative_to(root).as_posix()
            except ValueError:
                continue
        else:
            path = candidate.as_posix()
        if not path.startswith(prefix):
            continue

        line = location.get("line")
        target = root / path
        if path not in cache:
            cache[path] = fixture_lines(target) if target.is_file() else set()
        on_fixture_line = isinstance(line, int) and line in cache[path]

        digest = finding.get("credential_hash")
        entry = inventory.setdefault(
            digest,
            {
                "detector_ids": set(),
                "sites": set(),
                "on_declared_fixture_line": True,
            },
        )
        entry["detector_ids"].add(finding.get("detector_id"))
        entry["sites"].add(f"{path}:{line}")
        entry["on_declared_fixture_line"] &= on_fixture_line

    return {
        digest: {
            "detector_ids": sorted(value["detector_ids"]),
            "sites": sorted(value["sites"]),
            "on_declared_fixture_line": value["on_declared_fixture_line"],
        }
        for digest, value in inventory.items()
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    parser.add_argument("--root", default=".")
    parser.add_argument("--detectors-dir", default="detectors")
    parser.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    parser.add_argument("--update", action="store_true", help="regenerate the inventory")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    inventory_path = Path(args.inventory)
    current = collect(Path(args.report), root, args.detectors_dir)

    if args.update:
        payload = {
            "detectors_dir": args.detectors_dir,
            "reviewed": dict(sorted(current.items())),
        }
        inventory_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        off_line = [d for d, v in current.items() if not v["on_declared_fixture_line"]]
        print(
            f"wrote {inventory_path} with {len(current)} reviewed credential(s); "
            f"{len(off_line)} sit outside a declared fixture field"
        )
        return 0

    if not inventory_path.is_file():
        print(
            f"detector fixture inventory missing at {inventory_path}. "
            "Generate it with --update and review the result.",
            file=sys.stderr,
        )
        return 1

    reviewed = json.loads(inventory_path.read_text(encoding="utf-8"))["reviewed"]
    added = sorted(set(current) - set(reviewed))
    removed = sorted(set(reviewed) - set(current))
    moved = sorted(
        digest
        for digest in set(current) & set(reviewed)
        if current[digest]["sites"] != reviewed[digest]["sites"]
    )

    if added:
        print(
            f"detector fixture check FAILED: {len(added)} unreviewed credential(s) in "
            "detector definitions",
            file=sys.stderr,
        )
        for digest in added:
            entry = current[digest]
            flag = "" if entry["on_declared_fixture_line"] else "  [NOT on a declared fixture field]"
            print(
                f"  {digest}  {','.join(entry['detector_ids'])}  "
                f"{' '.join(entry['sites'])}{flag}",
                file=sys.stderr,
            )
    if removed:
        print(
            f"detector fixture check FAILED: {len(removed)} inventory entr(ies) no longer "
            "appear; the inventory is stale",
            file=sys.stderr,
        )
        for digest in removed:
            print(f"  {digest}  {' '.join(reviewed[digest]['sites'])}", file=sys.stderr)
    # A move is line drift, not a review event: the value hash is unchanged, so
    # it is the same reviewed fixture at a new offset. Editing an unrelated line
    # in a detector TOML must not fail the security gate. Reported so the
    # inventory can be refreshed, never fatal.
    if moved:
        print(
            f"detector fixture check: {len(moved)} reviewed credential(s) moved "
            "(line drift, not a new credential; re-run with --update to refresh)"
        )
        for digest in moved:
            print(
                f"  {digest}  {' '.join(reviewed[digest]['sites'])} -> "
                f"{' '.join(current[digest]['sites'])}"
            )

    if added or removed:
        print(
            "Review each change. Re-run with --update once every entry is a known "
            "detector sample.",
            file=sys.stderr,
        )
        return 1

    off_line = sum(1 for v in current.values() if not v["on_declared_fixture_line"])
    # `moved` is intentionally excluded from the failure condition above.
    print(
        f"detector fixture check OK: {len(current)} reviewed credential(s) in the detector "
        f"corpus, {len(current) - off_line} on a declared fixture field"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
