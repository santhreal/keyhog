#!/usr/bin/env python3
"""Harvest betterleaks' OWN labeled ground truth into a SecretBench-shape
corpus so the bench scorer can run keyhog and the competitors over
betterleaks' home turf (``python -m bench leaderboard --corpus
homefield-betterleaks``).

betterleaks (a gitleaks fork) generates its shipped config from
`cmd/generate/config/rules/*.go`. Every rule embeds two labeled lists:

    tps := []string{ ... }   // true positives, the rule MUST match these
    fps := []string{ ... }   // false positives, the rule must NOT match

These are betterleaks' own precision+recall oracle: the regexes were tuned
to score 100% on exactly these strings. Harvesting them lets us ask the
only fair "home turf" question, how close does keyhog get to betterleaks
on betterleaks' own truth, and which services does betterleaks cover that
keyhog misses (a capability gap, not a tuning gap).

Only STATIC string literals are taken. Lines that are Go function calls
(`utils.GenerateSampleSecret(...)`, `secrets.NewSecret(...)`) or
concatenations resolve to random values at generate-time and cannot be
extracted statically, so they are skipped, never guessed. This keeps the
corpus free of fabricated fixtures (no fake truth).

Output (split layout the bench loader reads):
    benchmarks/corpora/homefield/betterleaks/manifest.jsonl
    benchmarks/corpora/homefield/betterleaks/corpus/<shard>/<id>.txt
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import sys

BETTERLEAKS_MODULE = "github.com/betterleaks/betterleaks@v1.1.1"
# Split layout under the canonical corpus home: answer key at
# <home>/manifest.jsonl, neutrally-named scan tree at <home>/corpus/, see
# bench.corpora.homefield / bench.corpora.mirror for why the manifest must
# sit beside, not inside, the scan tree.
_HOME = (
    pathlib.Path(__file__).resolve().parents[2] / "corpora" / "homefield" / "betterleaks"
)

# A Go double-quoted string that is the WHOLE element (optionally trailed by
# a comma): the line, stripped, is exactly "..." or "...",. Anchored so a
# concatenation (`"a"+f()`) or call (`f("a")`) is rejected, those embed a
# quote but are not standalone literals.
_DQUOTE_ELEM = re.compile(r'^"((?:[^"\\]|\\.)*)"\s*,?$')
# Raw (backtick) string element on a single line.
_RAW_ELEM = re.compile(r"^`([^`]*)`\s*,?$")
_RULEID = re.compile(r'RuleID:\s*"([^"]+)"')


def _candidate_roots(explicit: str | None = None) -> list[pathlib.Path]:
    roots: list[pathlib.Path] = []
    if explicit:
        roots.append(pathlib.Path(explicit).expanduser())
    if os.environ.get("BETTERLEAKS_ROOT"):
        roots.append(pathlib.Path(os.environ["BETTERLEAKS_ROOT"]).expanduser())
    if os.environ.get("GOMODCACHE"):
        roots.append(pathlib.Path(os.environ["GOMODCACHE"]).expanduser() / BETTERLEAKS_MODULE)
    gopaths = os.environ.get("GOPATH")
    if gopaths:
        for entry in gopaths.split(os.pathsep):
            if entry:
                roots.append(
                    pathlib.Path(entry).expanduser() / "pkg" / "mod" / BETTERLEAKS_MODULE
                )
    else:
        roots.append(pathlib.Path.home() / "go" / "pkg" / "mod" / BETTERLEAKS_MODULE)
    return roots


def resolve_betterleaks_root(explicit: str | None = None) -> pathlib.Path:
    tried: list[pathlib.Path] = []
    for root in _candidate_roots(explicit):
        tried.append(root)
        if (root / "cmd" / "generate" / "config" / "rules").is_dir():
            return root
    attempts = "\n  - ".join(str(p) for p in tried)
    raise FileNotFoundError(
        "betterleaks rules dir not found. Pass --betterleaks-root or set "
        f"BETTERLEAKS_ROOT. Tried:\n  - {attempts}"
    )


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


def _strip_go_strings(line: str) -> str:
    """Blank the contents of Go double-quoted and raw (backtick) string literals
    so brace counting isn't skewed by braces INSIDE a literal (a secret or a
    Go template like `{...}`). Quotes/backticks themselves are dropped too."""
    out: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == '"':
            i += 1
            while i < n and line[i] != '"':
                i += 2 if line[i] == "\\" else 1
            i += 1
        elif ch == "`":
            i += 1
            while i < n and line[i] != "`":
                i += 1
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _extract_block(lines: list[str], start: int) -> tuple[list[str], int]:
    """From the line index of a `tps :=`/`fps :=` opening, collect static
    string-literal elements until the closing `}`. Returns (values, end_idx)."""
    vals: list[str] = []
    depth = 0
    i = start
    opened = False
    while i < len(lines):
        raw = lines[i]
        code = _strip_go_strings(raw)
        depth += code.count("{") - code.count("}")
        if "{" in code:
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
            # else: function call / concatenation / brace line, skip
        if opened and depth <= 0:
            return vals, i
        i += 1
    return vals, i


def harvest(rules_dir: pathlib.Path) -> list[dict]:
    records: list[dict] = []
    counter = 0
    go_files = sorted(rules_dir.glob("*.go"))
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


def write_corpus(records: list[dict], home: pathlib.Path = _HOME) -> pathlib.Path:
    out_dir = home / "corpus"
    # Prune any prior fixture set so a re-harvest with FEWER records leaves no
    # orphan file (a scan hit on an unrecorded file scores as a false positive).
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = home / "manifest.jsonl"
    with open(manifest, "w") as mf:
        for rec in records:
            shard = rec["id"][-2:]
            (out_dir / shard).mkdir(exist_ok=True)
            rel = f"{shard}/{rec['id']}.txt"
            (out_dir / rel).write_text(rec["value"])
            out = {k: v for k, v in rec.items() if k != "value"}
            out["on_disk_path"] = rel
            mf.write(json.dumps(out) + "\n")
    return out_dir


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--betterleaks-root",
        default=None,
        help="checkout or Go module-cache root for github.com/betterleaks/betterleaks@v1.1.1 "
             "(also accepted via BETTERLEAKS_ROOT)",
    )
    ap.add_argument(
        "--out-home",
        type=pathlib.Path,
        default=_HOME,
        help="homefield output directory that will receive manifest.jsonl and corpus/",
    )
    args = ap.parse_args()
    try:
        root = resolve_betterleaks_root(args.betterleaks_root)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    rules_dir = root / "cmd" / "generate" / "config" / "rules"
    records = harvest(rules_dir)
    pos = sum(1 for r in records if r["label"])
    neg = len(records) - pos
    cats = len({r["category"] for r in records})
    out_dir = write_corpus(records, args.out_home)
    print(
        f"harvested {len(records)} fixtures from betterleaks "
        f"({pos} tps / {neg} fps) across {cats} rules → {out_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
