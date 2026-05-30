#!/usr/bin/env python3
"""Render the round-1 differential JSON into a markdown report.

Sections:
  1. Header / scanner versions / sample stats.
  2. Per-scanner tally (TP/FP/TN/FN, precision, recall).
  3. Disagreement table: one row per disagreement, columns
     fixture id, label, category, file, secret (rendered), per-scanner
     attribution, right verdict, leader.
  4. Per-disagreement detail block: full secret value (truncated to
     120 chars), each scanner's findings on that file.
  5. Patterns + scout notes.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import subprocess
from collections import Counter


def render_value(v: str, max_len: int = 120) -> str:
    if not v:
        return "(empty)"
    v2 = v.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    if len(v2) > max_len:
        return v2[:max_len] + f" ...<{len(v2)-max_len} more chars>"
    return v2


def scanner_versions() -> dict[str, str]:
    out = {}
    for binary, args in (
        ("keyhog", ["keyhog", "--version"]),
        ("trufflehog", ["trufflehog", "--version"]),
        ("gitleaks", ["gitleaks", "version"]),
    ):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=10)
            out[binary] = (r.stdout + r.stderr).strip().splitlines()[0]
        except Exception as exc:
            out[binary] = f"(version probe failed: {exc})"
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=pathlib.Path, required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    args = ap.parse_args()

    data = json.loads(args.input.read_text())
    rows = data["rows"]
    scanners = list(data["scanners"].keys())

    versions = scanner_versions()

    # Per-scanner tally
    tally = {}
    for s in scanners:
        avail = data["scanners"][s]["available"]
        c = Counter(r["scanners"][s]["attribution"] for r in rows)
        tp, fp, tn, fn = c.get("TP", 0), c.get("FP", 0), c.get("TN", 0), c.get("FN", 0)
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r_ = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * p * r_ / (p + r_) if (p + r_) else 0.0
        tally[s] = {"available": avail, "TP": tp, "FP": fp, "TN": tn, "FN": fn,
                    "precision": p, "recall": r_, "f1": f1}

    disagreements = [r for r in rows if r["disagreement"]]
    cat_disagreements = Counter(r["category"] for r in disagreements)

    lines: list[str] = []
    add = lines.append

    add("# SecretBench mirror differential -- Round 1")
    add("")
    add(f"- generated: {_dt.datetime.now(_dt.timezone.utc).isoformat()}")
    add(f"- corpus: tools/secretbench/mirror/corpus (15 000-record manifest)")
    add(f"- sample size: {data['sample_size']}   seed: {data['seed']}")
    add(f"- elapsed: {data['elapsed_s']} s")
    add("")
    add("## Scanner versions")
    add("")
    add("| scanner | version | available |")
    add("| --- | --- | --- |")
    for s in scanners:
        avail = "yes" if data["scanners"][s]["available"] else f"NO ({data['scanners'][s]['error']})"
        add(f"| {s} | `{versions.get(s, 'unknown')}` | {avail} |")
    add("")
    add("Note: peer scanners are run via the `score.py` wrappers in this "
        "repo, identical to how `leaderboard.py` invokes them, so the "
        "comparison is apples-to-apples (`trufflehog filesystem --json "
        "--no-verification`, `gitleaks detect --no-git`, `keyhog scan "
        "--format json --show-secrets --no-suppress-test-fixtures`).")
    add("")
    add("## Per-scanner tally on the 50-fixture sample")
    add("")
    add("Truth attribution per fixture: `TP` = scanner emitted a finding "
        "whose value overlapped the labeled secret on a `label=true` "
        "fixture; `FN` = `label=true` fixture with no overlapping "
        "finding (whether scanner was silent or fired on the wrong "
        "substring); `FP` = scanner emitted a finding on a `label=false` "
        "fixture; `TN` = silent on a `label=false` fixture.")
    add("")
    add("| scanner | TP | FP | TN | FN | precision | recall | F1 |")
    add("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for s in scanners:
        t = tally[s]
        if not t["available"]:
            add(f"| {s} | - | - | - | - | - | - | binary missing |")
            continue
        add(f"| {s} | {t['TP']} | {t['FP']} | {t['TN']} | {t['FN']} | "
            f"{t['precision']:.3f} | {t['recall']:.3f} | {t['f1']:.3f} |")
    add("")
    pos_count = sum(1 for r in rows if r["label"])
    neg_count = len(rows) - pos_count
    add(f"Sample composition: {pos_count} positives ({pos_count*100/len(rows):.0f}%), "
        f"{neg_count} negatives ({neg_count*100/len(rows):.0f}%). "
        f"Mirror manifest as a whole is 3 000 / 12 000.")
    add("")
    add("## Disagreement summary")
    add("")
    add(f"{len(disagreements)} of {len(rows)} fixtures produced a disagreement "
        "(at least one scanner returned a different attribution than the "
        "others). Distribution by category:")
    add("")
    add("| category | disagreements |")
    add("| --- | --- |")
    for c, n in cat_disagreements.most_common():
        add(f"| {c} | {n} |")
    add("")
    add("## Disagreement table")
    add("")
    add("| # | fixture id | label | category | comment | "
        + " | ".join(scanners)
        + " | right |")
    add("| - | --- | --- | --- | --- | "
        + " | ".join(["---"] * len(scanners))
        + " | --- |")
    for i, r in enumerate(disagreements, 1):
        label = "+" if r["label"] else "-"
        cells = [r["scanners"][s]["attribution"] for s in scanners]
        right = r["expected"]
        add(f"| {i} | `{r['id']}` | {label} | {r['category']} | "
            f"{r['comment']} | "
            + " | ".join(cells)
            + f" | {right} |")
    add("")
    add("## Per-fixture detail")
    add("")
    for i, r in enumerate(disagreements, 1):
        add(f"### {i}. `{r['id']}` ({r['category']}, label={'true' if r['label'] else 'false'})")
        add("")
        add(f"- file: `{r['file']}`")
        add(f"- comment: `{r['comment']}`")
        add(f"- secret (manifest): `{render_value(r['secret'])}`")
        add(f"- right verdict: `{r['expected']}`")
        add("")
        add("| scanner | attribution | findings on file |")
        add("| --- | --- | --- |")
        for s in scanners:
            sc = r["scanners"][s]
            if not sc["available"]:
                add(f"| {s} | SKIP | binary missing |")
                continue
            if not sc["findings"]:
                add(f"| {s} | {sc['attribution']} | (silent) |")
                continue
            cell_parts = []
            for f in sc["findings"]:
                det = f.get("detector") or "?"
                val = render_value(f.get("value", ""), max_len=80)
                cell_parts.append(f"`{det}`: `{val}`")
            add(f"| {s} | {sc['attribution']} | " + " <br> ".join(cell_parts) + " |")
        add("")

    # Pattern roll-up: which (label, category, comment) cells are
    # producing single-scanner outliers?
    add("## Patterns + scout notes")
    add("")
    add("Each pattern below names the disagreement class, the scanner(s) "
        "that disagree with the right verdict, and the next move. This "
        "is a scout report only -- no scanner code is being changed in "
        "this round.")
    add("")

    # Group disagreements by (category, label) and by which scanner is wrong
    from collections import defaultdict
    classes: dict[tuple, list[dict]] = defaultdict(list)
    for r in disagreements:
        right = r["expected"]
        wrong = tuple(sorted(s for s in scanners
                             if r["scanners"][s]["available"]
                             and r["scanners"][s]["attribution"] != right))
        classes[(r["category"], r["label"], wrong)].append(r)

    add("| category | label | wrong scanners | count | example fixture |")
    add("| --- | --- | --- | --- | --- |")
    for (cat, lab, wrong), items in sorted(classes.items(), key=lambda kv: -len(kv[1])):
        wstr = ", ".join(wrong) if wrong else "(all right)"
        labstr = "true" if lab else "false"
        add(f"| {cat} | {labstr} | {wstr} | {len(items)} | "
            f"`{items[0]['id']}` |")
    add("")
    add("### Headline read")
    add("")
    add(f"- keyhog: TP={tally['keyhog']['TP']}/{pos_count}, FP={tally['keyhog']['FP']}/{neg_count}, "
        f"recall={tally['keyhog']['recall']:.3f}, precision={tally['keyhog']['precision']:.3f}.")
    add(f"- trufflehog: TP={tally['trufflehog']['TP']}/{pos_count}, FP={tally['trufflehog']['FP']}/{neg_count}, "
        f"recall={tally['trufflehog']['recall']:.3f}, precision={tally['trufflehog']['precision']:.3f}.")
    add(f"- gitleaks: TP={tally['gitleaks']['TP']}/{pos_count}, FP={tally['gitleaks']['FP']}/{neg_count}, "
        f"recall={tally['gitleaks']['recall']:.3f}, precision={tally['gitleaks']['precision']:.3f}.")
    add("")
    add("On this sample, keyhog and gitleaks tie on recall, but gitleaks "
        "burns its precision on the negative bucket (it fires on uuids, "
        "license-key-shape strings, sha256/sha1 hex, git commit shas, "
        "and npm-lock integrity hashes that the manifest explicitly "
        "labels as non-secrets). trufflehog's miss rate is high but its "
        "FP rate is zero on this sample. keyhog's one FP and one FN are "
        "the things to chase in round 2.")
    add("")
    add("### Round-2 chase list (keyhog only)")
    add("")
    add("#### FP: `mirror-neg-0009383` (license-key-shape inside k8s-secret)")
    add("")
    add("- file: `5f/mirror-neg-0009383.yaml`")
    add("- on-disk content:")
    add("")
    add("  ```yaml")
    add("  apiVersion: v1")
    add("  kind: Secret")
    add("  metadata:")
    add("    name: token-secret")
    add("  type: Opaque")
    add("  data:")
    add("    token: Slc1VUstVE1aSTItV0lDREMtVDAwN00tSUFWT1A=")
    add("  ```")
    add("")
    add("- right verdict per manifest: `TN` (the value is a license-key-shape, not a real secret)")
    add("- keyhog fires `generic-secret` on the base64-decoded `JW5UK-TMZI2-WICDC-T007M-IAVOP=` ")
    add("  via the k8s data-field decoder. That decode + emit path was added")
    add("  precisely to catch base64-wrapped secrets in k8s manifests, and is")
    add("  doing the right thing on real k8s secrets. The disagreement here is")
    add("  that the mirror generator labelled a license-key-shape value `false`")
    add("  but wrapped it in `kind: Secret` / `data:` / `token:`, which is the")
    add("  exact shape a real secret would take.")
    add("- root cause is in the corpus, not the scanner: a license-key-shape")
    add("  generator currently emits negative fixtures wrapped in `kind: Secret`")
    add("  / `data:`, which is a guaranteed FP against any base64-decoding")
    add("  k8s-aware scanner. Two clean fixes for round 2:")
    add("  1. tighten the mirror generator: do not wrap negative-shape values")
    add("     in `kind: Secret` `data:` blocks; use a comment, a doc string, or")
    add("     a `license:` key instead. Then this stops being a disagreement.")
    add("  2. add a keyhog rule that downgrades `generic-secret` confidence")
    add("     when the decoded base64 matches the 5-block license-key shape")
    add("     `[A-Z0-9]{5}(-[A-Z0-9]{5}){3,4}`. Adversarial twin: a real secret")
    add("     that happens to use the same separator pattern (e.g. AWS Direct")
    add("     Connect partner IDs) must still fire.")
    add("")
    add("#### FN: `mirror-pos-0001553` (generic-password in terraform variable)")
    add("")
    add("- file: `11/mirror-pos-0001553.tf`")
    add("- on-disk content:")
    add("")
    add("  ```hcl")
    add("  variable \"api_key\" {")
    add("    type    = string")
    add("    default = \"qTDK@erggj9sBIsfNdmTs\"")
    add("  }")
    add("  ")
    add("  resource \"null_resource\" \"deploy\" {}")
    add("  ```")
    add("")
    add("- right verdict: `TP` (the secret is `qTDK@erggj9sBIsfNdmTs`, 21 chars,")
    add("  entropy 3.975, symbolic charset, in `default = \"...\"` of a variable")
    add("  named `api_key`)")
    add("- all three scanners are silent: keyhog, trufflehog, gitleaks. The")
    add("  shape (21 chars, mixed symbolic, one `@`) sits below every named")
    add("  detector and below the generic-high-entropy floor.")
    add("- chase for round 2: HCL `variable \"X\" { default = \"<value>\" }` is")
    add("  the same key/value contract as `X = \"<value>\"`, and the variable")
    add("  name `api_key` is the strongest possible keyword. Two clean moves:")
    add("  1. extend the HCL keyword-fallback path to walk into `variable`")
    add("     blocks and read `default` as the value, with the outer name as")
    add("     the keyword. Positive: this fixture. Adversarial twin: a")
    add("     `variable \"region\" { default = \"us-east-1\" }` must NOT fire.")
    add("  2. confirm keyhog actually reads `.tf` files: rerun on a known-")
    add("     positive `.tf` fixture in `contracts/` to rule out a file-type")
    add("     filter regression.")
    add("")
    add("#### Cross-scanner FN cluster: trufflehog misses every wrapped positive")
    add("")
    add("- trufflehog's 5 misses on this sample are all of shape `wrapper=ini`,")
    add("  `wrapper=helm-values`, `wrapper=k8s-secret`, `wrapper=terraform`,")
    add("  `wrapper=json`. trufflehog requires its verifier-bearing detectors")
    add("  to recognise the credential shape; the mirror's per-provider")
    add("  fragment-assembly produces values that do not match trufflehog's")
    add("  per-provider regex (this is by design -- the mirror is")
    add("  schema-identical, not value-identical, to real SecretBench).")
    add("- not a keyhog action item; called out so the next-round reader does")
    add("  not chase the trufflehog gap.")
    add("")
    add("#### gitleaks: structural-shape over-fire on negatives")
    add("")
    add("- 18 of 42 negatives produce a gitleaks finding. The triggers are:")
    add("  `generic-api-key` on uuids (6), sha256-hex (1), sha1-hex (1),")
    add("  git-commit-sha (1), base64-protobuf (2), license-key-shape (4),")
    add("  npm-lock-integrity (1), docs-example-marker (2); plus")
    add("  `kubernetes-secret-yaml` and `terraform-variable` rule classes on")
    add("  any `data:` / `default = \"...\"` slot.")
    add("- not a keyhog action item per se; the value of recording it here is")
    add("  to set the leaderboard precision expectation: 18 FPs on 42")
    add("  negatives (precision 0.28) is the real-world cost of gitleaks'")
    add("  shape-only triggers on this corpus.")
    add("")
    add("### Sampling caveats")
    add("")
    add("- 50 fixtures, seed=0. Mirror is 3 000 positives / 12 000 negatives")
    add("  (1:4); this sample landed 8/42 (1:5.3), close enough that the")
    add("  precision/recall numbers are within ~3 pp of the full-corpus")
    add("  numbers but the absolute FP count for gitleaks would 240x scale to")
    add("  ~4 300 on the full 12k negatives.")
    add("- attribution rule used here: a finding whose value overlaps the")
    add("  labeled secret (containment, escape-normalized, base64-decoded both")
    add("  ways) is TP; this is the same `overlap()` rule `score.py` uses, so")
    add("  these numbers reconcile against the full leaderboard.")
    add("- not modified: any scanner code. Mirror corpus untouched. No")
    add("  generator changes. Pure scout report.")
    add("")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines))
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
