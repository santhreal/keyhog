#!/usr/bin/env python3
"""Harvest betterleaks' OWN labeled ground truth into a SecretBench-shape
corpus so the bench scorer can run keyhog and the competitors over
betterleaks' home turf (``python -m bench leaderboard --corpus
homefield-betterleaks``).

betterleaks (a gitleaks fork) generates its shipped config from
`cmd/generate/config/rules/*.go`. Every rule embeds two labeled lists:

    tps := []string{ ... }   // true positives  — the rule MUST match these
    fps := []string{ ... }   // false positives — the rule must NOT match

These are betterleaks' own precision+recall oracle: the regexes were tuned
to score 100% on exactly these strings. Harvesting them lets us ask the
only fair "home turf" question — how close does keyhog get to betterleaks
on betterleaks' own truth, and which services does betterleaks cover that
keyhog misses (a capability gap, not a tuning gap).

Only STATIC string literals are taken. Lines that are Go function calls
(`utils.GenerateSampleSecret(...)`, `secrets.NewSecret(...)`) or
concatenations resolve to random values at generate-time and cannot be
extracted statically, so they are skipped — never guessed. This keeps the
corpus free of fabricated fixtures (no fake truth).

Output (split layout the bench loader reads):
    benchmarks/corpora/homefield/betterleaks/manifest.jsonl
    benchmarks/corpora/homefield/betterleaks/corpus/<shard>/<id>.txt
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

BL = pathlib.Path(
    "/home/mukund-thiru/go/pkg/mod/github.com/betterleaks/betterleaks@v1.1.1"
)
RULES_DIR = BL / "cmd" / "generate" / "config" / "rules"
# Split layout under the canonical corpus home: answer key at
# <home>/manifest.jsonl, neutrally-named scan tree at <home>/corpus/ — see
# bench.corpora.homefield / bench.corpora.mirror for why the manifest must
# sit beside, not inside, the scan tree.
_HOME = (
    pathlib.Path(__file__).resolve().parents[2] / "corpora" / "homefield" / "betterleaks"
)
OUT = _HOME / "corpus"

# A Go double-quoted string that is the WHOLE element (optionally trailed by
# a comma): the line, stripped, is exactly "..." or "...",. Anchored so a
# concatenation (`"a"+f()`) or call (`f("a")`) is rejected — those embed a
# quote but are not standalone literals.
_DQUOTE_ELEM = re.compile(r'^"((?:[^"\\]|\\.)*)"\s*,?$')
# Raw (backtick) string element on a single line.
_RAW_ELEM = re.compile(r"^`([^`]*)`\s*,?$")
_RULEID = re.compile(r'RuleID:\s*"([^"]+)"')


def _unescape_go(s: str) -> str:
    """Decode the Go escapes that appear in these literals. Go and JSON
    agree on \\n \\t \\r \\" \\\\, so json round-trips them safely; fall back
    to the raw text if a non-JSON escape (e.g. \\x, \\u in Go form) trips it."""
    try:
        return json.loads('"' + s + '"')
    except Exception:
        return (
            s.replace('\\"', '"')
            .replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace("\\r", "\r")
            .replace("\\\\", "\\")
        )


def _extract_block(lines: list[str], start: int) -> tuple[list[str], int]:
    """From the line index of a `tps :=`/`fps :=` opening, collect static
    string-literal elements until the closing `}`. Returns (values, end_idx)."""
    vals: list[str] = []
    depth = 0
    i = start
    opened = False
    while i < len(lines):
        raw = lines[i]
        depth += raw.count("{") - raw.count("}")
        if "{" in raw:
            opened = True
        body = raw.strip()
        if body.startswith("//"):
            i += 1
            continue
        # strip a trailing line comment that follows a literal
        m = _DQUOTE_ELEM.match(body)
        if m:
            vals.append(_unescape_go(m.group(1)))
        else:
            mr = _RAW_ELEM.match(body)
            if mr:
                vals.append(mr.group(1))
            # else: function call / concatenation / brace line — skip
        if opened and depth <= 0:
            return vals, i
        i += 1
    return vals, i


def harvest() -> list[dict]:
    records: list[dict] = []
    counter = 0
    go_files = sorted(RULES_DIR.glob("*.go"))
    for gf in go_files:
        text = gf.read_text(errors="replace")
        lines = text.splitlines()
        current_rule = gf.stem  # fallback to filename if no RuleID found
        i = 0
        while i < len(lines):
            line = lines[i]
            rm = _RULEID.search(line)
            if rm:
                current_rule = rm.group(1)
                i += 1
                continue
            stripped = line.strip()
            label = None
            if stripped.startswith("tps :=") or stripped.startswith("tps:="):
                label = True
            elif stripped.startswith("fps :=") or stripped.startswith("fps:="):
                label = False
            if label is not None:
                vals, end = _extract_block(lines, i)
                for v in vals:
                    if not v.strip():
                        continue
                    counter += 1
                    rid = f"bl-{counter:05d}"
                    records.append(
                        {
                            "id": rid,
                            "secret": v if label else "",
                            "label": label,
                            "category": current_rule,
                            "source_tool": "betterleaks",
                            "value": v,
                            "file_type": "txt",
                        }
                    )
                i = end + 1
                continue
            i += 1
    return records


def write_corpus(records: list[dict]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = _HOME / "manifest.jsonl"
    with open(manifest, "w") as mf:
        for rec in records:
            shard = rec["id"][-2:]
            (OUT / shard).mkdir(exist_ok=True)
            rel = f"{shard}/{rec['id']}.txt"
            (OUT / rel).write_text(rec["value"])
            out = {k: v for k, v in rec.items() if k != "value"}
            out["on_disk_path"] = rel
            mf.write(json.dumps(out) + "\n")


def main() -> int:
    if not RULES_DIR.is_dir():
        print(f"betterleaks rules dir not found: {RULES_DIR}", file=sys.stderr)
        return 1
    records = harvest()
    pos = sum(1 for r in records if r["label"])
    neg = len(records) - pos
    cats = len({r["category"] for r in records})
    write_corpus(records)
    print(
        f"harvested {len(records)} fixtures from betterleaks "
        f"({pos} tps / {neg} fps) across {cats} rules → {OUT}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
