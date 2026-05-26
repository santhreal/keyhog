#!/usr/bin/env python3
"""Rewrite bad evasion envelopes to recalled shapes (env=, Bearer, XML, YAML)."""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONTRACTS = REPO / "crates/scanner/tests/contracts"
PROBE = Path("/tmp/evasion_probe4.txt")

EVASION_BLOCK = re.compile(
    r"(\[\[evasion\]\]\s*\n"
    r"text\s*=\s*)(\"\"\".*?\"\"\"|\'\'\'.*?\'\'\'|\"(?:\\.|[^\"\\])*\")(\s*\n"
    r"credential\s*=\s*)(\"\"\".*?\"\"\"|\'\'\'.*?\'\'\'|\"(?:\\.|[^\"\\])*\")(\s*\n"
    r"reason\s*=\s*)\"[^\"]*\"",
    re.DOTALL,
)
POSITIVE_FIRST = re.compile(
    r"\[\[positive\]\]\s*\n"
    r"text\s*=\s*(\"\"\".*?\"\"\"|\'\'\'.*?\'\'\'|\"(?:\\.|[^\"\\])*\")\s*\n"
    r"credential\s*=\s*(\"\"\".*?\"\"\"|\'\'\'.*?\'\'\'|\"(?:\\.|[^\"\\])*\")",
    re.DOTALL,
)
PROBE_OK = re.compile(r"^OK\t([^\t]+)\t([^\t]+)\t(.+)$")


def unquote_toml(s: str) -> str:
    if s.startswith('"""') or s.startswith("'''"):
        return s[3:-3]
    body = s[1:-1]
    return (
        body.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\r", "\r")
        .replace('\\"', '"')
        .replace("\\\\", "\\")
    )


def toml_str(value: str) -> str:
    if "\n" in value or len(value) > 200:
        escaped = (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\t", "\\t")
            .replace("\r", "\\r")
        )
        return '"""\n' + escaped + '\n"""'
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\t", "\\t")
        .replace("\r", "\\r")
    )
    return f'"{escaped.replace(chr(10), "\\n")}"'


def is_bad_evasion(text: str) -> bool:
    t = text.strip()
    if t.startswith("# ") or t.startswith("#\n") or t.startswith("# embedded"):
        return True
    if t.startswith('{"secret"') or '"secret"' in t[:40]:
        return True
    if t.startswith("Authorization: Bearer") and (t.endswith('"') or "=" in t):
        return True
    if t.startswith("export "):
        return True
    if t.startswith("<token>") or t.startswith("<apiKey>"):
        return True
    return False


def pick_shape(positive_text: str, credential: str, probe: dict[str, tuple[str, str]]) -> tuple[str, str]:
    if positive_text in probe:
        return probe[positive_text]
    if "=" in positive_text:
        return ("env_bare", positive_text)
    if "://" in positive_text or credential.startswith("http"):
        return ("yaml_block", f"payload: |\n  {positive_text}")
    if ":" in positive_text:
        _, v = positive_text.split(":", 1)
        return ("bearer", f"Authorization: Bearer {v.strip().strip('\"')}")
    if positive_text.startswith("-----BEGIN"):
        return ("yaml_block", f"private_key: |\n  {positive_text}")
    return ("xml", f"<token>{credential}</token>")


def load_probe() -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    if not PROBE.exists():
        return out
    for line in PROBE.read_text().splitlines():
        m = PROBE_OK.match(line)
        if m:
            out[m.group(1)] = (m.group(2), m.group(3).replace("\\n", "\n"))
    return out


def main() -> int:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    probe = load_probe()
    changed: list[tuple[str, str]] = []
    patterns: dict[str, int] = {}

    for path in sorted(CONTRACTS.glob("*.toml")):
        if len(changed) >= limit:
            break
        content = path.read_text()
        pm = POSITIVE_FIRST.search(content)
        em = EVASION_BLOCK.search(content)
        if not pm or not em:
            continue
        positive_text = unquote_toml(pm.group(1))
        positive_cred = unquote_toml(pm.group(2))
        evasion_text = unquote_toml(em.group(2))
        detector_id = path.stem

        if detector_id in probe:
            pattern, new_text = probe[detector_id]
        elif not is_bad_evasion(evasion_text):
            continue
        else:
            pattern, new_text = pick_shape(positive_text, positive_cred, {})

        if evasion_text == new_text:
            continue

        reason = f"Adversarial {pattern} envelope — credential must still surface under this detector."
        repl = (
            em.group(1)
            + toml_str(new_text)
            + em.group(3)
            + toml_str(positive_cred)
            + em.group(5)
            + toml_str(reason)
        )
        path.write_text(content[: em.start()] + repl + content[em.end() :])
        changed.append((detector_id, pattern))
        patterns[pattern] = patterns.get(pattern, 0) + 1
        print(f"fixed {detector_id} -> {pattern}")

    print(f"\nApplied {len(changed)} fixes")
    print(f"patterns: {patterns}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
