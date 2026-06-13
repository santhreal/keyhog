# keyhog architecture — the whole pipeline, one page

This is the **map**: where everything lives and how a byte becomes a finding.
It links to the authoritative in-code docs rather than restating them, so there
is one source of truth per fact. Read this first; then jump to the cited module.

- New contributor? Read [Repository layout](#repository-layout) →
  [The pipeline](#the-pipeline-bytes--finding) → the "[where do I find X?](#where-do-i-find-x)" table.
- Touching detection? The detector format is data, not code — see
  [`detectors/`](#detectors--data-not-code).
- Touching the scan engine? Its own header doc is the deepest map:
  [`crates/scanner/src/engine/mod.rs`](../crates/scanner/src/engine/mod.rs)
  ("# The one flow" + "# Where each method lives").

---

## Repository layout

Every top-level directory, one line each. **Code** is Rust under `crates/`;
everything else is data, tooling, docs, or eval harness.

| Dir | What it is |
|-----|-----------|
| `crates/` | The Rust workspace — the only place runtime code lives. Five crates (below). |
| `detectors/` | **902 detector TOMLs — DATA, not code.** One file = one secret type. Drop a file to add a detector; no recompile of detection logic. See [below](#detectors--data-not-code). |
| `rules/` | Other Tier-B data files (e.g. `aws-canary-accounts.toml`). Same idea as `detectors/`: ship data, users extend by dropping files. |
| `ml/` | The Python ML pipeline that produces the scanner's embedded `weights.bin`: synthetic + real corpus → blend → train → gate. Entry point `retrain_loop.sh`. Trains the model; `crates/scanner` *serves* it. |
| `benchmarks/` | Reproducible eval harness (`bench/` python pkg): corpus generators, scanner adapters, scorer, the regression/differential `gate`, and the README leaderboard generator. The numbers in the README come from here. |
| `tests/` | **Repo-level** integration tests (Docker images, install flows, cross-OS). Per-crate unit/contract tests live under each crate's own `tests/`. |
| `fuzz/` | `cargo-fuzz` targets (structure-aware, one sink per target). |
| `tools/` | Build-time generators (`gen_contracts.py`, `gen_companion_contracts.py`) that emit test fixtures. (Also holds a large *gitignored* SecretBench corpus.) |
| `scripts/` | Dev/ops scripts: dogfood-all-os, prerelease, audit, triage. |
| `docs/` | Markdown docs. This file; the [`legendary/`](legendary/) execution plan + ledger; `GPU_DETECTION_REWRITE.md`; `OOB.md`; etc. |
| `site/` | The published documentation website (HTML). `architecture.html` is the long-form, diagram-rich version of this page. |
| `demo/` | A self-contained demo deployment (app + infra + scripts). |
| `vendor/` | **Read-only** vendored snapshots (`vyre`, `bogon`). NEVER edit — the build pins the published crate; fix the source repo and re-vendor. |
| `backlog/`, `audits/`, `metrics/` | Working notes: thematic backlogs, audit plans, star metrics. Planning, not shipped artifacts. |
| `coordination/` | *Gitignored* multi-agent scratch (review rounds, spec waivers). Not part of the build. |

Two planning trees coexist on purpose: **`docs/legendary/`** is the structured,
append-only execution plan + ledger (the live tracker); **`backlog/`** holds the
older thematic deep-dives (detection / performance / testing / coherence) kept
for their evidence. When they disagree, `docs/legendary/99_LEDGER.md` wins.

---

## The crates and their layering

Dependencies point one way — `core` is the foundation and depends on no other
keyhog crate; `cli` sits on top and wires the rest together. This DAG is enforced
by Cargo and must stay acyclic (domain logic never imports CLI/transport/UI).

```
            ┌─────────────────────────── cli ───────────────────────────┐
            │  binary, subcommands, daemon, watch, baselines, installer  │
            └───────┬───────────────┬───────────────┬───────────────────┘
                    │               │               │
              ┌─────▼─────┐   ┌─────▼─────┐          │
              │  scanner  │   │  sources  │          │
              │ detection │   │  inputs   │          │
              └──┬─────┬──┘   └──┬─────┬──┘          │
                 │     │         │     │             │
                 │     └────┬────┘     │             │
                 │      ┌───▼────┐     │             │
                 │      │verifier│     │             │
                 │      │  live  │     │             │
                 │      └───┬────┘     │             │
                 └──────────┼──────────┴─────────────┘
                        ┌───▼───┐
                        │ core  │   types · detector registry · report · dedup
                        └───────┘   · allowlists · incremental (merkle) cache
```

| Crate | Owns | Start reading at |
|-------|------|------------------|
| **`core`** | Detector loading/registry, the `Finding`/`Credential`/`Spec` types, reporters (text/JSON/SARIF), dedup, allowlists, the merkle incremental-scan cache, calibration. | `crates/core/src/lib.rs`, `registry.rs`, `finding.rs`, `report/` |
| **`scanner`** | The detection engine: hardware routing, prefilter, compile, scan, decode-through, entropy, ML confidence, multiline, suppression. | `crates/scanner/src/engine/mod.rs` (the flow), `pipeline/`, `lib.rs` |
| **`sources`** | Where bytes come from: filesystem, git (staged/diff/history), stdin, Docker, S3, GitHub-org, web, HAR, strings. | `crates/sources/src/lib.rs` |
| **`verifier`** | Turning a *candidate* into a *verified-live* credential: per-detector verify endpoints, SSRF/bogon guards, OOB, rate limiting. | `crates/verifier/src/lib.rs`, `verify/`, `ssrf.rs` |
| **`cli`** | The user-facing binary: argument parsing, the scan orchestrator, daemon/watch, baselines, calibrate, hook installer, output formatting. | `crates/cli/src/main.rs`, `args/`, `orchestrator/` |

---

## The pipeline: bytes → finding

The end-to-end flow, stage by stage, each pointing at the crate/module that owns
it. The scan engine's own header doc
([`engine/mod.rs`](../crates/scanner/src/engine/mod.rs)) is the authoritative,
method-level version of steps 2–4.

1. **Acquire bytes** — a source yields file-path + content chunks.
   `sources/` (`filesystem/`, `git/`, `stdin`, `docker`, `s3`, `github_org/`, `web/`).
2. **Phase 1 — trigger production** (which detectors *could* fire, and where).
   Swappable backend: CPU Hyperscan prefilter (`engine/scan.rs`) or the GPU
   batched-DFA megakernel (`engine/megakernel_dispatch.rs`). Produces one
   "which detectors may match here" bitmap per chunk. The fast prefilters
   (`simdsieve`, `bigram_bloom`, `alphabet_filter`, `prefix_trie`) live at
   `scanner/src/` top level; the detector→matcher build is `engine/compile.rs`
   + `compiler*.rs`.
3. **Phase 2 — extraction** (the shared tail, identical for CPU and GPU):
   per-chunk `confirmed → fallback → generic → entropy → ML`
   (`engine/extract.rs`, `engine/fallback*.rs`, `engine/scan.rs`). Decode-through
   (base64/hex/url/unicode/json) runs here and recurses: `decode/`.
4. **Post-process** — suppression, dedup, confidence, decode recursion, cross-chunk
   seam reassembly (`engine/scan_postprocess.rs`, `engine/process.rs`,
   `engine/boundary.rs`). Confidence + ML scoring: `confidence/`, `ml_scorer.rs`
   (+ `ml_features.rs`, `ml_weights.rs`); context inference: `context/`.
5. **Verify (optional)** — for the ~341 detectors with a `[detector.verify]`
   endpoint, turn a candidate into verified-live, behind SSRF/bogon/rate guards.
   `verifier/`.
6. **Report** — dedup, allowlist, emit text/JSON/SARIF; diff against a baseline
   for CI gates. `core/report/`, `core/dedup.rs`, `cli/reporting.rs`,
   `cli/format.rs`.

**Two-phase coalesced** is the key perf idea: 95 %+ of files have no Phase-1 hit
and pay near-zero cost; full extraction runs only on hits. Determinism is a
contract: same input → byte-exact same output.

### The ML model (`weights.bin`)

The scanner *serves* a Mixture-of-Experts confidence model embedded at build time
(`crates/scanner/src/weights.bin`, `include_bytes!`). It is *trained* out-of-band
by the Python pipeline in `ml/`:

```
ml/harvest_corpus.py   real labelled candidates (CredData), harvested at a LOW
                       report floor so sub-floor hard negatives are captured
        │
ml/train_classifier.py blend synthetic + real, file-grouped split (no leakage),
                       train the 42-feature MoE, gate on held-out F1 + recall
        │
ml/retrain_loop.sh     one command: harvest → train → (--write) ship weights.bin
                       → (--verify) rebuild + per-detector-FP bench gate,
                       fail-closed revert on any regression
```

Because the model is compile-time-embedded, a new model is only observable after
a rebuild — which is why `--verify` rebuilds before benching.

---

## Where do I find X?

| I want to… | Go to |
|------------|-------|
| Add/edit a detector | `detectors/<name>.toml` (data; see `CONTRIBUTING.md` for the schema) |
| Understand the scan flow at method level | `crates/scanner/src/engine/mod.rs` header |
| Change how confidence is scored | `crates/scanner/src/confidence/`, `ml_scorer.rs` |
| Retrain / improve the ML model | `ml/retrain_loop.sh` (+ `ml/README.md`) |
| Add an input source | `crates/sources/src/` |
| Add live verification for a detector | `[detector.verify]` in the TOML + `crates/verifier/src/verify/` |
| Change output format / exit codes | `crates/cli/src/format.rs`, `reporting.rs` |
| Add a benchmark / change the gate | `benchmarks/bench/` |
| See what's planned / landed | `docs/legendary/99_LEDGER.md` (newest last) |
| Verify a perf or detection claim | `benchmarks/` (the README numbers regenerate from here) |

---

*The long-form, diagram-rich version of this page (hardware routing matrix,
profiling tips) is [`site/architecture.html`](../site/architecture.html). When
they disagree, this file — checked next to the code — wins.*
