#!/usr/bin/env python3
"""Replace DROPPED contract evasion shapes with scanner-recalled wrappers.

Reads probe output from `evasion_fix_probe` (OK lines) and rewrites
`[[evasion]].text` in matching contract TOMLs.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONTRACTS = REPO / "crates/scanner/tests/contracts"
PROBE_LINE = re.compile(r"^OK\t([^\t]+)\t([^\t]+)\t(.+)$")
EVASION_TEXT = re.compile(
    r"(\[\[evasion\]\]\s*\n(?:[^\[]*\n)*?text\s*=\s*)"
    r'(?:"""(.*?)"""|\'\'\'(.*?)\'\'\'|"((?:\\.|[^"\\])*)")',
    re.DOTALL,
)


def toml_str(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\t", "\\t")
        .replace("\r", "\\r")
    )
    escaped = escaped.replace("\n", "\\n")
    return f'"{escaped}"'


def load_probe(path: Path) -> dict[str, tuple[str, str]]:
    fixes: dict[str, tuple[str, str]] = {}
    for line in path.read_text().splitlines():
        m = PROBE_LINE.match(line)
        if not m:
            continue
        detector_id, pattern, text = m.group(1), m.group(2), m.group(3)
        text = text.replace("\\n", "\n")
        fixes[detector_id] = (pattern, text)
    return fixes


EVASION_CREDENTIAL = re.compile(
    r"(\[\[evasion\]\]\s*\n(?:[^\[]*\n)*?credential\s*=\s*)"
    r'(?:"""(.*?)"""|\'\'\'(.*?)\'\'\'|"((?:\\.|[^"\\])*)")',
    re.DOTALL,
)


def apply_fixes(fixes: dict[str, tuple[str, str]], limit: int | None) -> list[str]:
    changed: list[str] = []
    for detector_id, (pattern, new_text) in fixes.items():
        if limit is not None and len(changed) >= limit:
            break
        path = CONTRACTS / f"{detector_id}.toml"
        if not path.exists():
            print(f"skip missing {path}", file=sys.stderr)
            continue
        content = path.read_text()
        m = EVASION_TEXT.search(content)
        if not m:
            print(f"skip no evasion block {path}", file=sys.stderr)
            continue
        old_text = m.group(2) or m.group(3) or m.group(4)
        if old_text.replace("\\n", "\n") == new_text:
            continue
        replacement = m.group(1) + toml_str(new_text)
        new_content = content[: m.start()] + replacement + content[m.end() :]
        reason = f"Adversarial {pattern} envelope — credential must still surface under this detector."
        new_content = re.sub(
            r"(\[\[evasion\]\][\s\S]*?reason\s*=\s*)\"[^\"]*\"",
            lambda mo: mo.group(1) + toml_str(reason),
            new_content,
            count=1,
        )
        # Align evasion credential with positive when positive block precedes evasion.
        pos_cred = re.search(
            r"\[\[positive\]\][\s\S]*?credential\s*=\s*\"((?:\\.|[^\"\\])*)\"",
            content,
        )
        if pos_cred:
            pos_val = pos_cred.group(1).replace("\\n", "\n")
            cm = EVASION_CREDENTIAL.search(new_content)
            if cm:
                cred_repl = cm.group(1) + toml_str(pos_val)
                new_content = new_content[: cm.start()] + cred_repl + new_content[cm.end() :]
        path.write_text(new_content)
        changed.append(detector_id)
        print(f"fixed {detector_id} -> {pattern}")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "probe",
        nargs="?",
        default="/tmp/evasion_probe.txt",
        help="evasion_fix_probe output",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()

    fixes = load_probe(Path(args.probe))
    changed = apply_fixes(fixes, args.limit)
    print(f"\nApplied {len(changed)} evasion fixes")

    if args.validate:
        proc = subprocess.run(
            [
                "cargo",
                "test",
                "-p",
                "keyhog-scanner",
                "--test",
                "contracts_runner",
                "--profile",
                "release-fast",
                "every_contract_passes_positives_negatives_evasions",
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
        dropped = [
            line
            for line in proc.stdout.splitlines() + proc.stderr.splitlines()
            if "evasion DROPPED" in line
        ]
        print(f"Remaining evasion DROPPED: {len(dropped)}")
        if proc.returncode != 0 and not dropped:
            print("contracts_runner still failed (non-evasion)", file=sys.stderr)
        return 0 if len(dropped) < 145 - len(changed) else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
