# secretbench — keyhog vs the SecretBench corpus

Drop-in benchmarking harness against the **SecretBench** dataset
(Basak et al., MSR 2023 — *SecretBench: A Dataset of Software
Secrets*, [arXiv:2303.06729](https://arxiv.org/abs/2303.06729),
[GitHub](https://github.com/setu1421/SecretBench)). Same harness
scores keyhog against trufflehog and gitleaks on the identical
fixture set so the leaderboard is apples-to-apples.

The original dataset (15 084 true-positive secrets + ~82 k labeled
negatives across 818 GitHub repos, 49 languages, 311 file types) is
gated — see [`access/`](access/) for the request flow.

## Layout

| Path | What |
| --- | --- |
| `schema/secretbench_schema.json` | The 22-field record format we score against. |
| `mirror/` | Mirror-corpus generator. Synthesises SecretBench-schema records using fragment-assembled credentials so the repo never embeds a live secret. ~15 k positives + ~80 k negatives. |
| `scoring/score.py` | Runs keyhog over a SecretBench-schema corpus, computes TP/FP/FN/precision/recall/F1 per category and overall. |
| `scoring/leaderboard.py` | Runs every installed scanner (keyhog + trufflehog + gitleaks; opt-in for noseyparker/detect-secrets/ggshield) and emits one JSON. |
| `access/` | Email template + tracking notes for SecretBench access. |
| `results/` | Scoreboards produced by `leaderboard.py`. One JSON per run, dated. |

## Quickstart (mirror corpus)

```bash
# 1. Generate the mirror corpus (~15 k TP + 80 k FP, ~500 MB on disk).
python tools/secretbench/mirror/generate.py \
    --out tools/secretbench/mirror/corpus \
    --positives 15000 --negatives 80000 --seed 0

# 2. Score keyhog alone.
python tools/secretbench/scoring/score.py \
    --corpus tools/secretbench/mirror/corpus \
    --scanner keyhog \
    --output tools/secretbench/results/keyhog-mirror.json

# 3. Full leaderboard (every scanner on $PATH).
python tools/secretbench/scoring/leaderboard.py \
    --corpus tools/secretbench/mirror/corpus \
    --output tools/secretbench/results/leaderboard.json
```

## Quickstart (real SecretBench)

Once you have access (see [`access/REQUEST_TEMPLATE.md`](access/REQUEST_TEMPLATE.md))
and have exported the BigQuery table to a directory of `.parquet`
files:

```bash
python tools/secretbench/scoring/leaderboard.py \
    --corpus ~/datasets/secretbench/parquet/ \
    --schema secretbench-v1 \
    --output tools/secretbench/results/leaderboard-real.json
```

The schema parser auto-detects parquet/csv/jsonl input.

## Why a mirror corpus exists

SecretBench is gated and ~10 GB. We can't redistribute it and we
can't expect a contributor to wait on an academic data-protection
agreement to run the benchmark. The mirror is:

* **Schema-identical** to the real dataset (same 22 columns, same
  category taxonomy, same label semantics).
* **Synthesised**, not real — every "true-positive" credential is
  built at generator runtime from fragments that never themselves
  match a detector heuristic. This means we can commit fixtures
  freely without push-protection blocks.
* **Distribution-matched** to the published per-category counts in
  the paper so the per-category precision/recall numbers from the
  mirror trend the same way as the real dataset numbers.

The mirror is NOT a substitute for the real dataset for academic
comparison — it lets us hill-climb on the harness, and once the
real data lands, the same `score.py` / `leaderboard.py` run
against it without code change.

## Truth & attribution rules

Identical to `tools/diff_bench/run.py` (kept identical so historical
diff-bench results stay comparable to secretbench results):

* **True positive** — finding's surfaced credential value contains,
  or is contained in, any of the fixture's labeled secrets.
* **False positive** — finding fires on a `label=false` fixture, or
  on a `label=true` fixture but doesn't overlap any labeled secret.
* **False negative** — a labeled secret on a `label=true` fixture
  has no matching finding.
* **Precision** = TP / (TP + FP); **Recall** = TP / (TP + FN);
  **F1** = 2·P·R / (P + R).

Per-category scoring uses the SecretBench category taxonomy
(AWS keys, GCP service-account keys, Slack tokens, JWT, PEM
private keys, generic high-entropy, &c.).
