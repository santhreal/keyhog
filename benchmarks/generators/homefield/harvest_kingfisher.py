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

import json
import pathlib
import sys

import yaml

KF = pathlib.Path(
    "/mnt/FlareTraining/santh-corpus/competitor-src/kingfisher"
    "/crates/kingfisher-rules/data/rules"
)
# Split layout under the canonical corpus home (manifest beside, not inside,
# the neutrally-named scan tree) — see bench.corpora.homefield.
_HOME = (
    pathlib.Path(__file__).resolve().parents[2] / "corpora" / "homefield" / "kingfisher"
)
OUT = _HOME / "corpus"


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


def harvest() -> list[dict]:
    records: list[dict] = []
    counter = 0
    for yf in sorted(KF.glob("*.yml")) + sorted(KF.glob("*.yaml")):
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


def write_corpus(records: list[dict]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "manifest.jsonl", "w") as mf:
        for rec in records:
            shard = rec["id"][-2:]
            (OUT / shard).mkdir(exist_ok=True)
            rel = f"{shard}/{rec['id']}.txt"
            (OUT / rel).write_text(rec["value"])
            out = {k: v for k, v in rec.items() if k != "value"}
            out["on_disk_path"] = rel
            mf.write(json.dumps(out) + "\n")


def main() -> int:
    if not KF.is_dir():
        print(f"kingfisher rules dir not found: {KF}", file=sys.stderr)
        return 1
    records = harvest()
    pos = sum(1 for r in records if r["label"])
    neg = len(records) - pos
    cats = len({r["category"] for r in records})
    write_corpus(records)
    print(
        f"harvested {len(records)} fixtures from kingfisher "
        f"({pos} examples / {neg} negative_examples) across {cats} rules → {OUT}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
