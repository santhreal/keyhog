#!/usr/bin/env python3
"""Harvest kingfisher's OWN rule fixtures into a SecretBench-shape corpus.

kingfisher ships one YAML per service under
`crates/kingfisher-rules/data/rules/*.yml`. Every rule embeds:

    examples:           # positive samples the rule MUST match
      - 'splunk.token = "C73A9E41-..."'
    negative_examples:  # near-miss strings the rule must NOT match
      - "..."

Like the betterleaks generator, these are kingfisher's own
precision+recall oracle — the rule regexes were authored to score 100%
on exactly these strings. Harvesting them lets the bench scorer run
keyhog and the competitors over kingfisher's home turf (``python -m bench
leaderboard --corpus homefield-kingfisher``) and answer the only fair
question: how close does keyhog get to kingfisher on kingfisher's own
truth, and which services does kingfisher cover that keyhog misses (a
capability gap).

Output (split layout the bench loader reads):
    benchmarks/corpora/homefield/kingfisher/manifest.jsonl
    benchmarks/corpora/homefield/kingfisher/corpus/<shard>/<id>.txt
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import sys

import yaml

# Rules dir under a kingfisher checkout, relative to its root.
_RULES_REL = pathlib.Path("crates") / "kingfisher-rules" / "data" / "rules"
# Split layout under the canonical corpus home (manifest beside, not inside,
# the neutrally-named scan tree) — see bench.corpora.homefield.
_HOME = (
    pathlib.Path(__file__).resolve().parents[2] / "corpora" / "homefield" / "kingfisher"
)


def _candidate_roots(explicit: str | None = None) -> list[pathlib.Path]:
    # No hardcoded machine path: a kingfisher checkout has no standard cache
    # location, so the root is supplied via --kingfisher-root / KINGFISHER_ROOT
    # (mirrors harvest_betterleaks' resolution contract; fails closed otherwise).
    roots: list[pathlib.Path] = []
    if explicit:
        roots.append(pathlib.Path(explicit).expanduser())
    if os.environ.get("KINGFISHER_ROOT"):
        roots.append(pathlib.Path(os.environ["KINGFISHER_ROOT"]).expanduser())
    return roots


def resolve_kingfisher_root(explicit: str | None = None) -> pathlib.Path:
    tried: list[pathlib.Path] = []
    for root in _candidate_roots(explicit):
        tried.append(root)
        if (root / _RULES_REL).is_dir():
            return root
    attempts = "\n  - ".join(str(p) for p in tried)
    raise FileNotFoundError(
        "kingfisher rules dir not found. Pass --kingfisher-root or set "
        f"KINGFISHER_ROOT. Tried:\n  - {attempts}"
    )


def _as_str_list(v) -> list[str]:
    """Coerce an examples/negative_examples value into a list of strings.
    kingfisher uses both block-sequence lists and the occasional scalar."""
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str)]
    return []


def harvest(rules_dir: pathlib.Path) -> list[dict]:
    records: list[dict] = []
    counter = 0
    for yf in sorted(rules_dir.glob("*.yml")) + sorted(rules_dir.glob("*.yaml")):
        try:
            doc = yaml.safe_load(yf.read_text(errors="replace"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        rules = doc.get("rules")
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rid = rule.get("id") or rule.get("name") or yf.stem
            for label, key in ((True, "examples"), (False, "negative_examples")):
                for sample in _as_str_list(rule.get(key)):
                    if not sample.strip():
                        continue
                    counter += 1
                    fid = f"kf-{counter:05d}"
                    records.append(
                        {
                            "id": fid,
                            "secret": sample if label else "",
                            "label": label,
                            "category": str(rid),
                            "source_tool": "kingfisher",
                            "value": sample,
                            "file_type": "txt",
                        }
                    )
    return records


def write_corpus(records: list[dict], home: pathlib.Path = _HOME) -> pathlib.Path:
    out_dir = home / "corpus"
    # Prune any prior fixture set so a re-harvest with FEWER records leaves no
    # orphan file (a scan hit on an unrecorded file scores as a false positive).
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Answer key beside, not inside, the neutrally-named scan tree — the loader
    # (bench.corpora.homefield) reads <home>/manifest.jsonl.
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
        "--kingfisher-root",
        default=None,
        help="checkout root for kingfisher (also accepted via KINGFISHER_ROOT)",
    )
    ap.add_argument(
        "--out-home",
        type=pathlib.Path,
        default=_HOME,
        help="homefield output directory that will receive manifest.jsonl and corpus/",
    )
    args = ap.parse_args()
    try:
        root = resolve_kingfisher_root(args.kingfisher_root)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    records = harvest(root / _RULES_REL)
    pos = sum(1 for r in records if r["label"])
    neg = len(records) - pos
    cats = len({r["category"] for r in records})
    out_dir = write_corpus(records, args.out_home)
    print(
        f"harvested {len(records)} fixtures from kingfisher "
        f"({pos} examples / {neg} negative_examples) across {cats} rules → {out_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
