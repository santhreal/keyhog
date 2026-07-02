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
| `detectors/` | **916 detector TOMLs — DATA, not code.** One file = one secret type. Drop a file to add a detector; no recompile of detection logic. See [below](#detectors--data-not-code). |
| `rules/` | Other Tier-B data files (e.g. `aws-canary-accounts.toml`). Same idea as `detectors/`: ship data, users extend by dropping files. |
| `ml/` | The Python ML pipeline that produces the scanner's embedded `weights.bin`: synthetic + real corpus → blend → train → gate. Entry point `retrain_loop.sh`. Trains the model; `crates/scanner` *serves* it. |
| `benchmarks/` | Reproducible eval harness (`bench/` python pkg): corpus generators, scanner adapters, scorer, the regression/differential `gate`, and the README leaderboard generator. The numbers in the README come from here. |
| `tests/` | **Repo-level** integration tests (Docker images, install flows, cross-OS). Per-crate unit/contract tests live under each crate's own `tests/`. |
| `fuzz/` | `cargo-fuzz` targets (structure-aware, one sink per target). |
| `tools/` | Build-time generators (`gen_contracts.py`, `gen_companion_contracts.py`) that emit test fixtures. (Also holds a large *gitignored* SecretBench corpus.) |
| `scripts/` | Dev/ops scripts: dogfood-all-os, prerelease, audit, triage. |
| `docs/` | Markdown docs. This file, mdBook source, execution plan, and deep technical references. |
| `site/` | The published documentation website (HTML). `architecture.html` is the long-form, diagram-rich version of this page. |
| `demo/` | A self-contained demo deployment (app + infra + scripts). |
| `metrics/` | Star and project-health metrics. |

Internal execution planning lives in the private Santh monorepo, not in this
public repository.

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
| **`sources`** | Where bytes come from: filesystem, git (staged/diff/history), stdin, Docker, S3, GCS, Azure Blob, GitHub-org, web, HAR, strings, binary. | `crates/sources/src/lib.rs` |
| **`verifier`** | Turning a *candidate* into a *verified-live* credential: per-detector verify endpoints, SSRF/bogon guards, OOB, rate limiting. | `crates/verifier/src/lib.rs`, `verify/`, `ssrf.rs` |
| **`cli`** | The user-facing binary: argument parsing, the scan orchestrator, daemon/watch, baselines, calibrate, hook installer, output formatting. | `crates/cli/src/main.rs`, `args/`, `orchestrator/` |

---

## The pipeline: bytes → finding

The end-to-end flow, stage by stage, each pointing at the crate/module that owns
it. The scan engine's own header doc
([`engine/mod.rs`](../crates/scanner/src/engine/mod.rs)) is the authoritative,
method-level version of steps 2–4.

1. **Acquire bytes** — a source yields file-path + content chunks.
   `sources/` (`filesystem/`, `git/`, `stdin`, `docker`, `s3/`, `gcs.rs`,
   `cloud/azure_blob.rs`, `github_org.rs`, `gitlab_group.rs`,
   `bitbucket_workspace.rs`, `hosted_git.rs`, `web/`, `har.rs`, `strings.rs`,
   `binary/`).
2. **Phase 1 — trigger production** (which detectors *could* fire, and where).
   Swappable backend: CPU Hyperscan prefilter (`engine/scan.rs`) or the GPU
   batched literal region-presence route (`engine/gpu_region_dispatch.rs`). Produces one
   "which detectors may match here" bitmap per chunk. The fast prefilters
   (`simdsieve`, `bigram_bloom`, `alphabet_filter`, `prefix_trie`) live at
   `scanner/src/` top level; the detector→matcher build is `engine/compile.rs`
   + `compiler.rs` + `compiler/`.
3. **Phase 2 — extraction** (the shared tail, identical for CPU and GPU):
   per-chunk `confirmed → phase2 capture → generic → entropy → ML`
   (`engine/extract.rs`, `engine/phase2*.rs`, `engine/scan.rs`). Decode-through
   (base64/hex/url/unicode/json) runs here and recurses: `decode/`.
4. **Post-process** — suppression, dedup, confidence, decode recursion, cross-chunk
   seam reassembly (`engine/scan_postprocess.rs`, `engine/process.rs`,
   `engine/boundary.rs`). Confidence + ML scoring: `confidence/`, `ml_scorer.rs`
   + `ml_scorer/` (`ml_features`, `ml_weights`); context inference: `context/`. The
   per-match policy here (suppression gates · example/placeholder · checksum ·
   confidence penalties) is governed by one invariant — see **Match adjudication:
   one policy, one chokepoint** below.
5. **Verify (optional)** — for the 344 detectors with a `[detector.verify]`
   endpoint, turn a candidate into verified-live, behind SSRF/bogon/rate guards.
   `verifier/`.
6. **Report** — dedup, allowlist, emit text/JSON/SARIF; diff against a baseline
   for CI gates. `core/report/`, `core/dedup.rs`, `cli/reporting.rs`,
   `cli/format.rs`.

**Two-phase coalesced** is the key perf idea: 95 %+ of files have no Phase-1 hit
and pay near-zero cost; full extraction runs only on hits. Determinism is a
contract: same input → byte-exact same output.

### Finding identity and dedup

There is one identity contract with stage-specific keys, not interchangeable
"same finding" guesses:

| Stage | Owner | Key | Why |
|-------|-------|-----|-----|
| Window overlap and raw collector | `scanner/src/engine/windowed_support.rs::record_window_match`; `scanner/src/scanner_config.rs::ScanState::into_matches` | `(detector_id, credential, source_offset)` | Adjacent 1 MiB windows overlap by 128 KiB, and more than one backend signal can surface the same span. The source-offset key removes duplicate raw hits without merging separate occurrences on different lines. |
| Raw-match correlation helper | `core/src/finding.rs::RawMatch::deduplication_key` | `(detector_id, credential)` | Tests and internal correlation can ask whether two raw matches carry the same detector/value before a report scope is applied. It is not a report key because it intentionally excludes location. |
| User-selected report scope | `core/src/dedup.rs::dedup_matches` | `DedupScope::Credential`: `(detector_id, credential)`; `DedupScope::File`: `(detector_id, credential, source + file_path + commit)`; `DedupScope::None`: no grouping | This is the operator-visible grouping. The primary location is the lowest source offset; additional locations use `(source, file_path, line, commit)` so structured/decode aliases on the same source line collapse. |
| Cross-detector report collapse | `core/src/dedup.rs::dedup_cross_detector` | `(credential_hash, primary_file_path)` after `dedup_matches` | One secret value can match several detectors. This keeps one reported finding, chooses the best detector deterministically, and records alternate detector evidence as companions while preserving file-scoped reports. |
| Reporter-local location cleanup | `core/src/report/sarif.rs` | `(file_path, line, offset)` within one reported finding | Output adapters may remove repeated locations for format stability. They do not decide scan/report identity. |

The required seam test is `scan_windowed_overlap_dedups_end_to_end`: a token
placed wholly inside the 128 KiB overlap must scan as one raw match and one
final reported finding.

### Match adjudication: one policy, one chokepoint

**Governing invariant.** Whether a candidate match becomes a reported finding —
and at what confidence — is a pure function of the **value and its context**,
*never* of which emission path produced it. A value that is a `${}` shell
template, a `name-name:v1` public identifier, or `Config-Word-and-Word-only`
policy prose is not a secret no matter whether the entropy detector, the generic
keyword bridge, the weak-anchor post-pass, or the hot-pattern fast path surfaced
it. Phase-2 has several emission paths; they exist for *speed and recall*, not to
each carry their own copy of policy.

**The rule.** Every emission path produces `CandidateMatch`es and funnels them
through one adjudicator. Paths *find*; they do not *decide*. The adjudicator runs
a single ordered policy, each stage a pure `fn(value, ctx) -> StageOutcome`:

```
emission paths (entropy · generic/keyword bridge · weak-anchor · hot fast path · GPU)
        │  each yields CandidateMatch { detector, span, value }
        ▼
adjudicate_match(CandidateMatch, MatchCtx)            ← the ONLY funnel
   1. public_noncredential_shape(value, ctx)   one gate list, every `looks_like_*`
   2. example / placeholder suppression(value, ctx)   one entry point
   3. checksum_adjusted_confidence(value)
   4. apply_path_confidence_penalties(ctx)     comment / path / context
        ▼
   Verdict::Suppressed(stage_name)  |  Verdict::Reported(confidence)
```

`MatchCtx` carries every input a stage needs (`value, detector, span, path,
entropy, anchor_kind, in_comment, …`) so no stage is silently starved of data —
the reason a path could otherwise reach for a weaker overload. The `Verdict`
names the deciding stage, which is exactly what `--dogfood` prints, so every
suppression is explainable in one place. Adding a gate is a one-line edit to
`public_noncredential_shape` and applies to *all* paths by construction.

**Why this shape.** Per-match policy split across paths drifts: a richer path
gains a gate the others lack, and a value's fate starts depending on its path —
a silent override (Law 10). One funnel makes the whole policy readable top to
bottom and makes divergence impossible to introduce. Enforcement is mechanical:
no `looks_like_*` / `checksum_adjusted_confidence` / `should_suppress_known_example_*`
call may exist outside the adjudicator (grep-contract tests), and a cross-path
test feeds the same tricky value through every path and asserts one identical
verdict.

> Status: `adjudicate_match` exists and many drop decisions now emit typed
> `StageId`s through the adjudicator, including hot-pattern min-length and
> policy/validator/checksum suppression plus exact named-detector shape/path
> suppression reasons.
> Named-detector adjudication also preserves exact shared-cascade and
> decode-through suppression reasons instead of using a generic bucket.
> Some policy stages still execute from their emission-path owners instead of
> one full verdict that owns suppression and report confidence end to end. Any
> emission path must route policy decisions through the adjudicator stage model,
> not a silent local subset.

### The ML model (`weights.bin`)

The scanner *serves* a Mixture-of-Experts confidence model embedded at build time
(`crates/scanner/src/weights.bin`, `include_bytes!`). It is *trained* out-of-band
by the Python pipeline in `ml/`:

```
ml/harvest_corpus.py   real labelled candidates (CredData), harvested at a LOW
                       report floor so sub-floor hard negatives are captured
        │
ml/train_classifier.py blend synthetic + real, file-grouped split (no leakage),
                       train the 42-feature MoE, gate on held-out F1 plus
                       aggregate, per-class, and per-detector real recall
        │
ml/retrain_loop.sh     one command: harvest → train → (--write) ship weights.bin
                       → (--verify) rebuild + per-detector-FP bench gate,
                       fail-closed revert on any regression
```

Because the model is compile-time-embedded, a new model is only observable after
a rebuild — which is why `--verify` rebuilds before benching. The adjacent
`crates/scanner/src/model_card.json` carries the model hash, training inputs,
and gate metrics; `build.rs` refuses a card/weights mismatch and embeds the
summary shown by `keyhog --version`.

---

## Where do I find X?

| I want to… | Go to |
|------------|-------|
| Add/edit a detector | `detectors/<name>.toml` (data; see `CONTRIBUTING.md` for the schema) |
| Understand the scan flow at method level | `crates/scanner/src/engine/mod.rs` header |
| Change how confidence is scored | `crates/scanner/src/confidence/`, `ml_scorer.rs` |
| Add a suppression gate / change what counts as a non-secret | the one gate list `public_noncredential_shape` — see "Match adjudication" above (never inline a `looks_like_*` call in an emission path) |
| Retrain / improve the ML model | `ml/retrain_loop.sh` (+ `ml/README.md`) |
| Add an input source | `crates/sources/src/` |
| Add live verification for a detector | `[detector.verify]` in the TOML + `crates/verifier/src/verify/` |
| Change output format / exit codes | `crates/cli/src/format.rs`, `reporting.rs` |
| Add a benchmark / change the gate | `benchmarks/bench/` |
| Verify a perf or detection claim | `benchmarks/` (the README numbers regenerate from here) |

---

*The long-form, diagram-rich version of this page (hardware routing matrix,
profiling tips) is [`site/architecture.html`](../site/architecture.html). When
they disagree, this file — checked next to the code — wins.*
