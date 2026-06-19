# Home-turf benchmark

Diversified accuracy benchmark built from the **competitors' own shipped
labeled fixtures** — beating a tool on a neutral corpus is one thing;
matching or beating it on *its own* regression truth is the stronger claim.

This adds only new **corpora**, not new scoring logic. The single canonical
scorer in `bench/` consumes them through the `homefield-<turf>` corpus adapter
(it attributes findings by file + value-overlap and knows keyhog + every
competitor). One scorer, many corpora — no second source of accuracy truth.

## Corpora

| dir | harvested from | shape |
|---|---|---|
| `betterleaks/` | `cmd/generate/config/rules/*.go` `tps`/`fps` | pos + neg |
| `kingfisher/` | `data/rules/*.yml` `examples`/`negative_examples` | pos + neg |

Each fixture is one file containing the exact string the competitor ships as
its own ground truth. Only STATIC literals are harvested — generator calls
(`utils.GenerateSampleSecret`, `secrets.NewSecret`) resolve to random values
at the tool's build time and are skipped, never guessed, so the corpus
contains no fabricated truth.

Harvest (sources must be present locally) — writes the split-layout corpus to
`benchmarks/corpora/<turf>/` (`manifest.jsonl` + neutral `corpus/` scan tree):

```sh
python3 harvest_betterleaks.py   # reads the betterleaks go-module cache
python3 harvest_kingfisher.py    # reads a kingfisher checkout
```

## Run

Scored by the unified bench, from `benchmarks/`:

```sh
python3 -m bench leaderboard --corpus homefield-betterleaks --scanners keyhog,trufflehog,betterleaks,kingfisher
python3 -m bench leaderboard --corpus homefield-kingfisher  --scanners keyhog,trufflehog,betterleaks,kingfisher
```

keyhog is pinned to the deterministic SIMD backend (`--no-gpu`) so the
score is reproducible and independent of GPU backend selection.

## Reading the numbers

A tool scores ~100 % on its **own** turf by construction — its regexes were
authored to pass exactly these strings. The decisive figures are
**cross-tool**: how close keyhog gets to the home tool on its own truth, and
whether keyhog beats the *other* competitors there. A keyhog false-negative
on a competitor's positive fixture is a concrete **capability gap** (a
service that tool detects and keyhog does not) — file it, add the detector,
re-run.
