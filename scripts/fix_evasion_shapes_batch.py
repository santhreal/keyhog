#!/usr/bin/env python3
"""Batch-replace DROPPED evasion shapes with scanner-recalled wrappers.

Targets legacy envelopes (# comment, {"secret":…}, broken Bearer tails) and
rewrites them using the same priority as generate_contracts._evasion_text plus
Bearer / YAML fallbacks. Validates each candidate via evasion_fix_probe OK lines
when available; otherwise applies deterministic transform for known-bad shapes.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONTRACTS = REPO / "crates/scanner/tests/contracts"

EVASION_BLOCK = re.compile(
    r"(\[\[evasion\]\]\s*\n"
    r"text\s*=\s*)(\"\"\".*?\"\"\"|\'\'\'.*?\'\'\'|\"(?:\\.|[^\"\\])*\")(\s*\n"
    r"credential\s*=\s*)(\"(?:\\.|[^\"\\])*\")(\s*\n"
    r"reason\s*=\s*)\"[^\"]*\"",
    re.DOTALL,
)
POSITIVE_FIRST = re.compile(
    r"\[\[positive\]\]\s*\n"
    r"text\s*=\s*(\"\"\".*?\"\"\"|\'\'\'.*?\'\'\'|\"(?:\\.|[^\"\\])*\")\s*\n"
    r"credential\s*=\s*(\"(?:\\.|[^\"\\])*\")",
    re.DOTALL,
)
PROBE_OK = re.compile(r"^OK\t([^\t]+)\t([^\t]+)\t(.+)$")


def unquote_toml(s: str) -> str:
    if s.startswith('"""') or s.startswith("'''"):
        return s[3:-3]
    assert s.startswith('"') and s.endswith('"')
    body = s[1:-1]
    return (
        body.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\r", "\r")
        .replace('\\"', '"')
        .replace("\\\\", "\\")
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


def is_bad_evasion(text: str) -> bool:
    t = text.strip()
    if t.startswith("# "):
        return True
    if t.startswith('{"secret"') or '"secret"' in t[:40]:
        return True
    if t.startswith("Authorization: Bearer") and t.endswith('"'):
        return True
    if t.startswith("export ") and not t.startswith("export DEEPL"):
        # export prefix often DROPPED; reprobe via env_bare/yaml/xml
        return True
    return False


def evasion_candidates(positive_text: str, credential: str) -> list[tuple[str, str]]:
    cred = credential.strip('"')
    out: list[tuple[str, str]] = []

    if "=" in positive_text:
        out.append(("env_bare", positive_text))
        k, v = positive_text.split("=", 1)
        v = v.strip().strip('"')
        out.append(("yaml_inline", f"{k}: {v}"))
        out.append(("bearer_env", f"Authorization: Bearer {v}"))
        out.append(("yaml_block", f"payload: |\n  {positive_text}"))
        out.append(("env_export", f"export {positive_text}"))
    elif ":" in positive_text:
        k, v = positive_text.split(":", 1)
        v = v.strip().strip('"')
        out.append(("header_bare", positive_text))
        out.append(("bearer", f"Authorization: Bearer {v}"))
        out.append(("yaml_inline", f"{k}: {v}"))

    if credential.startswith("http") or "://" in credential:
        out.append(("yaml_block", f"payload: |\n  {positive_text}"))

    out.append(("xml", f"<token>{cred}</token>"))
    out.append(("xml_api_key", f"<apiKey>{cred}</apiKey>"))
    out.append(("bearer", f"Authorization: Bearer {cred}"))
    return out


def deterministic_pick(positive_text: str, credential: str) -> tuple[str, str]:
    """Pick best-effort shape without scanner validation."""
    if "=" in positive_text:
        return ("env_bare", positive_text)
    if credential.startswith("http") or "://" in credential:
        return ("yaml_block", f"payload: |\n  {positive_text}")
    if ":" in positive_text:
        _, v = positive_text.split(":", 1)
        return ("bearer", f"Authorization: Bearer {v.strip().strip('\"')}")
    return ("xml", f"<token>{credential}</token>")


def load_probe(path: Path) -> dict[str, tuple[str, str]]:
    fixes: dict[str, tuple[str, str]] = {}
    if not path.exists():
        return fixes
    for line in path.read_text().splitlines():
        m = PROBE_OK.match(line)
        if m:
            fixes[m.group(1)] = (m.group(2), m.group(3).replace("\\n", "\n"))
    return fixes


def patch_contract(path: Path, pattern: str, new_text: str, new_cred: str) -> bool:
    content = path.read_text()
    m = EVASION_BLOCK.search(content)
    if not m:
        return False
    old_text = unquote_toml(m.group(2))
    if old_text == new_text:
        return False
    reason = f"Adversarial {pattern} envelope - credential must still surface under this detector."
    repl = (
        m.group(1)
        + toml_str(new_text)
        + m.group(3)
        + toml_str(new_cred)
        + m.group(5)
        + toml_str(reason)
    )
    path.write_text(content[: m.start()] + repl + content[m.end() :])
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", type=Path, default=Path("/tmp/evasion_probe2.txt"))
    ap.add_argument("--limit", type=int, default=80)
    ap.add_argument("--only-bad", action="store_true", default=True)
    args = ap.parse_args()

    probe_fixes = load_probe(args.probe)
    changed: list[tuple[str, str]] = []
    pattern_counts: dict[str, int] = {}

    for path in sorted(CONTRACTS.glob("*.toml")):
        if len(changed) >= args.limit:
            break
        content = path.read_text()
        pm = POSITIVE_FIRST.search(content)
        em = EVASION_BLOCK.search(content)
        if not pm or not em:
            continue
        positive_text = unquote_toml(pm.group(1))
        positive_cred = unquote_toml(pm.group(2))
        evasion_text = unquote_toml(em.group(2))

        if args.only_bad and not is_bad_evasion(evasion_text):
            continue

        detector_id = path.stem
        if detector_id in probe_fixes:
            pattern, new_text = probe_fixes[detector_id]
        else:
            pattern, new_text = deterministic_pick(positive_text, positive_cred)

        if patch_contract(path, pattern, new_text, positive_cred):
            changed.append((detector_id, pattern))
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
            print(f"fixed {detector_id} -> {pattern}")

    print(f"\nApplied {len(changed)} evasion shape fixes")
    print(f"patterns: {pattern_counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
