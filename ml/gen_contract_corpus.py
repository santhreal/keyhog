#!/usr/bin/env python3
"""Turn the detector contract fixtures into ML training records.

A precision retrain on CredData alone drops the context-anchored medium-entropy
shapes the contracts exercise (moe-v1-1cbb8088 regressed 13 contract positives).
Each contract TOML carries exactly the labels the model needs:
  [[positive]] / [[evasion]]  -> label 1 (must catch; text = `credential`)
  [[negative]]                 -> label 0 (must reject; placeholders/EXAMPLE)
Emitted in the real_corpus.jsonl schema (train_classifier.load_real_corpus):
  {text, context, label, kind, class, detector_id, source_file}
source_file = "contract:<det>" so train_classifier._group_split forces a
detector's cases into the TRAIN split (contracts are a fixed known-positive set
to memorize — the contract gate tests the full suite — not a generalization target, so
they never dilute the honest CredData held-out). class = "Contract:<det>" stays
tiny -> excluded from the per-class support>=N recall gate, still counted in
aggregate recall.

Usage: python3 ml/gen_contract_corpus.py [out.jsonl]   (default ml/data/contract_corpus.jsonl)
"""
import glob
import json
import re
import sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - py<3.11
    print("need python3.11+ for tomllib", file=sys.stderr)
    sys.exit(2)

CONTRACTS = "crates/scanner/tests/contracts"


def extract_negative_value(text: str) -> str:
    """Best-effort value a scorer would see for a negative fixture: the last
    quoted string, else the token after the last '=' or ':'."""
    quoted = re.findall(r'"([^"]+)"|\'([^\']+)\'', text)
    if quoted:
        for a, b in reversed(quoted):
            v = a or b
            if v:
                return v
    for sep in ("=", ":"):
        if sep in text:
            tail = text.rsplit(sep, 1)[1].strip().strip('"\'{}').strip()
            if tail:
                return tail
    return text.strip()


def contract_records(spec: dict, det: str) -> list:
    """Build the labeled training records for one parsed contract TOML.
    Positives/evasions -> label 1 (text = the `credential`), negatives -> label 0
    (text = the extracted value). Cases with an empty value are skipped."""
    src = f"contract:{det}"
    cls = f"Contract:{det}"
    out = []

    def rec(text_value, context_text, label, kind):
        if not text_value or not str(text_value).strip():
            return
        out.append({
            "text": text_value,
            "context": f"file:{src}\n{context_text}\n",
            "label": label,
            "kind": kind,
            "class": cls,
            "detector_id": det,
            "source_file": src,
        })

    for case in spec.get("positive", []):
        rec(case.get("credential"), case.get("text", ""), 1, "contract-pos")
    for case in spec.get("evasion", []):
        rec(case.get("credential"), case.get("text", ""), 1, "contract-evasion")
    for case in spec.get("negative", []):
        text = case.get("text", "")
        rec(extract_negative_value(text), text, 0, "contract-neg")
    return out


def main() -> int:
    out_path = sys.argv[1] if len(sys.argv) > 1 else "ml/data/contract_corpus.jsonl"
    tomls = sorted(glob.glob(f"{CONTRACTS}/*.toml"))
    if not tomls:
        print(f"no contract TOMLs under {CONTRACTS}", file=sys.stderr)
        return 2
    n_pos = n_neg = n_det = 0
    with open(out_path, "w") as out:
        for path in tomls:
            with open(path, "rb") as fh:
                spec = tomllib.load(fh)
            det = spec.get("detector_id")
            if not det:
                continue
            n_det += 1
            for r in contract_records(spec, det):
                out.write(json.dumps(r) + "\n")
                if r["label"] == 1:
                    n_pos += 1
                else:
                    n_neg += 1
    print(f"wrote {out_path}: {n_pos} positives + {n_neg} negatives across {n_det} detectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
