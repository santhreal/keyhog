# Architecture

This is the **map**: where everything lives and how a byte becomes a finding.
It links to the authoritative in-code docs rather than restating them, so there
is one source of truth per fact. Read this first; then jump to the cited module.

- New contributor? Read [Repository layout](#repository-layout) →
  [The pipeline](#the-pipeline-bytes--finding) → the "[where do I find X?](#where-do-i-find-x)" table.
- Touching detection? The detector format is data, not code; see the
  [detector reference](./detectors.md).
- Touching the scan engine? Its own header doc is the deepest map:
  [`crates/scanner/src/engine/mod.rs`](https://github.com/santhreal/keyhog/blob/main/crates/scanner/src/engine/mod.rs)
  ("# The one flow" + "# Where each method lives").
- Choosing between a one-shot scan, a large repository scan, the daemon, and
  `watch`? Start with [Execution surfaces](#execution-surfaces), then read the
  [daemon workflow](./workflows/daemon.md) and
  [autoroute reference](./reference/autoroute-calibration.md).

---

## Repository layout

Every top-level directory, one line each. **Code** is Rust under `crates/`;
everything else is data, tooling, docs, or eval harness.

| Dir | Role |
|-----|------|
| `crates/` | Rust workspace: runtime code only (five crates; see [below](#the-crates-and-their-layering)). |
| `detectors/` | Embedded detector TOMLs (data, not code). One file = one secret type; drop a file to add a detector without rewriting detection logic. The generated catalog owns the current count. See the [detector reference](./detectors.md). |
| `rules/` | Tier-B data (e.g. `aws-canary-accounts.toml`); same drop-in model as `detectors/`. |
| `ml/` | Python pipeline for embedded `weights.bin`: harvest → blend → train → gate (`retrain_loop.sh`). Trains; `crates/scanner` serves. |
| `benchmarks/` | Eval harness (`bench/`): corpora, scanner adapters, scorer, regression/differential `gate`, README leaderboard. |
| `tests/` | Repo-level integration tests (Docker, install, cross-OS). Per-crate tests live under each crate's `tests/`. |
| `fuzz/` | `cargo-fuzz` targets (structure-aware, one sink per target). |
| `tools/` | Build-time generators (`gen_contracts.py`, `gen_companion_contracts.py`). Large *gitignored* SecretBench corpus. |
| `scripts/` | Maintained dev/release entrypoints and organization/product-truth gates. One-off corpus rewrite scripts do not ship. |
| `docs/src/` | The single canonical documentation set, built and deployed as mdBook. |
| `demo/` | Self-contained demo deployment (app + infra + scripts). |
| `metrics/` | Star and project-health metrics. |

Internal execution planning lives in the private Santh monorepo, not in this
public repository.

---

## The crates and their layering

Dependencies point one way: `core` is the foundation and depends on no other
KeyHog crate; `cli` sits on top and wires the rest together. This DAG is enforced
by Cargo and must stay acyclic (domain logic never imports CLI/transport/UI).

```text
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
| **`core`** | Embedded detector loading, detector specs, the `Finding`/`Credential` types, reporters, dedup, allowlists, the Merkle incremental-scan cache, and confidence-calibration data. | `crates/core/src/lib.rs`, `spec.rs`, `finding.rs`, `report/` |
| **`scanner`** | The detection engine: hardware probing and backend dispatch, prefilters, compile, scan, decode-through, entropy, ML confidence, multiline handling, and suppression. Persisted CLI route selection is intentionally not owned here. | `crates/scanner/src/compiled_scanner/` (construction and lifecycle), `engine/mod.rs` (execution flow), `adjudicate/`, `pipeline/`, `lib.rs` |
| **`sources`** | Where bytes come from: filesystem, git (staged/diff/history), stdin, Docker, S3, GCS, Azure Blob, GitHub-org, web, HAR, strings, binary. | `crates/sources/src/lib.rs` |
| **`verifier`** | Turning a *candidate* into a *verified-live* credential: per-detector verify endpoints, SSRF/bogon guards, OOB, rate limiting. | `crates/verifier/src/lib.rs`, `verify/`, `ssrf.rs` |
| **`cli`** | The user-facing binary: argument parsing, the scan orchestrator, daemon/watch, baselines, calibrate, hook installer, output formatting. | `crates/cli/src/lib.rs`, `args/`, `orchestrator/`; `main.rs` owns process/signal startup only |

---

## The pipeline: bytes → finding

The end-to-end flow, stage by stage, each pointing at the crate/module that owns
it. The scan engine's own header doc
([`engine/mod.rs`](https://github.com/santhreal/keyhog/blob/main/crates/scanner/src/engine/mod.rs)) is the authoritative,
method-level version of steps 2-4.

1. **Acquire bytes:** a source yields file-path + content chunks.
   `crates/sources/src/` (`filesystem/`, `git/`, `stdin.rs`, `docker/`, `s3/`,
   `gcs.rs`, `cloud/azure_blob.rs`, `github_org.rs`,
   `github_collaboration.rs`, `gitlab_group.rs`,
   `bitbucket_workspace.rs`, `hosted_git/`, `web/`, `har.rs`, `strings.rs`,
   `binary/`).
2. **Phase 1: trigger production** (which detectors *could* fire, and where).
   Swappable backend: scalar CPU literal/regex, SIMD Hyperscan
   (`engine/backend_triggered.rs`, `engine/scan_coalesced.rs`), or the GPU
   batched literal region-presence route (`engine/gpu_region_dispatch.rs`).
   It produces one "which detectors may match here" bitmap per chunk. The fast
   prefilters (`simdsieve`, `bigram_bloom`, `alphabet_filter`, `prefix_trie`)
   live at `crates/scanner/src/`; detector-to-matcher construction lives in
   `compiled_scanner/compile.rs`, `compiler.rs`, and `compiler/`.
3. **Phase 2: extraction** (the shared tail, identical for CPU and GPU):
   per-chunk `confirmed → phase2 capture → generic → entropy → ML`
   (`engine/extract.rs`, `engine/phase2*.rs`, `engine/backend_triggered.rs`,
   `engine/scan.rs`). Decode-through (base64/hex/url/unicode/json) runs here and
   recurses: `decode/`.
4. **Finish raw matches:** scanner-owned suppression, confidence, and
   cross-chunk seam reassembly run in `engine/scan_postprocess/`,
   `engine/process.rs`, and `engine/boundary.rs`. Confidence + ML scoring live in
   `confidence/`, `ml_scorer.rs`, and `ml_scorer/`; context inference lives in
   `context/`. The per-match policy here (suppression gates ·
   example/placeholder · checksum · confidence penalties) is governed by one
   invariant; see **Match adjudication: one policy, one chokepoint** below.
5. **Verify (optional):** for detectors with a `[detector.verify]`
   endpoint, turn a candidate into verified-live, behind SSRF/bogon/rate guards.
   `verifier/`.
6. **Resolve and report:** the CLI orchestrator applies scan-level policy and
   allowlists; core deduplication and reporters emit text/JSON/SARIF and support
   baseline comparison. `crates/cli/src/orchestrator/postprocess.rs`,
   `crates/cli/src/orchestrator/reporting.rs`, `crates/core/src/dedup.rs`, and
   `crates/core/src/report/` own these steps.

`keyhog_core::VerifiedFinding::from_deduped` is the conversion boundary from a
deduplicated match to a report-safe finding. It initializes the complete
finding shape, including measured entropy and redacted companions, so verifier,
skipped, and diff paths cannot silently drift when the report contract grows.

The accelerated batch path is **two-phase and coalesced**. A file with no
phase-one hit stops only when the shared no-hit admission proof also rules out
phase-two patterns, generic assignments, and enabled entropy analysis. This
proof is identical for portable CPU, Hyperscan, CUDA, and WGPU routes. Large
filesystem scans may instead use the fused reader/scanner pipeline so I/O and
scanning overlap; `crates/cli/src/orchestrator/dispatch.rs` and
`dispatch/fused.rs` own that execution choice. Both paths feed the same scanner
and report contracts. Backend choice must change performance only, never finding
semantics.

Within the shared SIMD/GPU coalesced tail, detector, generic, and entropy
candidates retain their per-chunk state while their precomputed ML feature rows
are submitted as one CPU or GPU MoE batch. Final scores return to the
originating chunk before its cap, decode postprocess, seam handling, and report
adjudication run. Portable CPU-fallback, single-file, and oversized windowed
scans keep the same scoring contract with smaller local batches.

### Execution surfaces

The CLI owns process-level routing. The scanner crate exposes explicit backend
execution; it does not read the autoroute cache or silently choose from local
hardware. This keeps library calls deterministic and makes CLI routing
inspectable.

| Workload | Execution surface | Routing and ownership |
|---|---|---|
| One in-process scan | `keyhog scan ... --daemon=off` | Full orchestrator; persisted one-shot autoroute evidence or an explicit diagnostic `--backend`. |
| Large tree, multiple inputs, Git, cloud, container, binary, or live verification | In-process orchestrator | Fused or coalesced batches; the daemon is not eligible even when it is running. |
| Repeated eligible stdin or single-file scans on Unix | `keyhog daemon start`, then `keyhog scan ...` | Client checks request eligibility and peer identity; the ready daemon uses warm-runtime autoroute evidence. |
| Continuous local directory monitoring | `keyhog watch` | Foreground watcher with its own compiled scanner; not the daemon and not reported by `daemon status`. |

Persisted backend selection lives under
`crates/cli/src/orchestrator/dispatch/backend.rs` and
`orchestrator/dispatch/backend/`. Daemon transport and lifecycle live under
`crates/cli/src/daemon/`. See the operator references for cache-miss,
cold-versus-warm, and active-versus-inactive daemon behavior.

The routing package keeps measurement, proof, and persistence separate:

| Boundary | Owner |
|---|---|
| Candidate measurement and cross-backend parity probes | `backend/calibration.rs` |
| One-shot and warm-daemon route decision policy | `backend/evidence.rs` |
| Statistical trial evidence and confidence intervals | `backend/evidence/timing.rs` |
| Secret-safe, complete finding identity used for parity | `backend/evidence/match_identity.rs` |
| Workload identity and bucketing | `backend/workload.rs` |
| Host and accelerator identity | `backend/host.rs` |
| Cache schema, exact artifact/build identity, bounded codec, validation, inspection, and locked persistence | the matching modules under `backend/store/` |

This separation is deliberate: persisted bytes cannot define routing policy,
inspection cannot bypass cache validation, and performance evidence cannot
silently weaken detection parity.

### Failure and recovery contract

KeyHog separates trust failures from recoverable execution failures:

- **Complete:** the selected backend covered the input normally.
- **Complete after recovery:** an automatically selected accelerator failed,
  KeyHog warned visibly, replayed the same stable batch through the scalar
  reference path, and counted the recovered chunks and bytes. The result is
  complete, but the backend fault remains visible and invalidates confidence in
  that accelerator's runtime health.
- **Incomplete:** some requested bytes or transformation could not be recovered.
  The scan may report findings from covered input, but it cannot report clean.
- **Fatal trust or explicit-contract failure:** invalid policy, corrupt or
  unauthenticated artifacts, or an explicitly required backend cannot be
  substituted.

Recovery is an owned execution path, not a silent fallback. It must operate on
the same stable source snapshot, preserve finding parity, identify exactly how
much work was replayed, and remain absent during autoroute calibration so a
backend that needs recovery cannot be certified fastest-correct.

### Finding identity and dedup

There is one identity contract with stage-specific keys, not interchangeable
"same finding" guesses:

| Stage | Owner | Key | Why |
|-------|-------|-----|-----|
| Window overlap and raw collector | `crates/scanner/src/engine/windowed_support.rs::record_window_match`; `crates/scanner/src/scanner_config.rs::ScanState::into_matches` | `(detector_id, credential, source_offset)` | Adjacent 1 MiB windows overlap by 128 KiB, and more than one backend signal can surface the same span. The source-offset key removes duplicate raw hits without merging separate occurrences on different lines. |
| Raw-match correlation helper | `crates/core/src/finding.rs::RawMatch::deduplication_key` | `(detector_id, credential)` | Tests and internal correlation can ask whether two raw matches carry the same detector/value before a report scope is applied. It is not a report key because it intentionally excludes location. |
| User-selected report scope | `crates/core/src/dedup.rs::dedup_matches` | `DedupScope::Credential`: `(detector_id, credential)`; `DedupScope::File`: `(detector_id, credential, source + file_path + commit)`; `DedupScope::None`: no grouping | This is the operator-visible grouping. The primary location is the lowest source offset; additional locations use `(source, file_path, line, commit)` so structured/decode aliases on the same source line collapse. |
| Cross-detector report collapse | `crates/core/src/dedup.rs::dedup_cross_detector` | `(credential_hash, primary_file_path)` after `dedup_matches` | One secret value can match several detectors. This keeps one reported finding, chooses the best detector deterministically, and records alternate detector evidence as companions while preserving file-scoped reports. |
| Reporter-local location cleanup | `crates/core/src/report/sarif.rs` | `(file_path, line, offset)` within one reported finding | Output adapters may remove repeated locations for format stability. They do not decide scan/report identity. |

The required seam test is `scan_windowed_overlap_dedups_end_to_end`: a token
placed wholly inside the 128 KiB overlap must scan as one raw match and one
final reported finding.

### Match adjudication: one policy, one chokepoint

**Governing invariant.** Whether a candidate match becomes a reported finding,
and at what confidence, is a pure function of the **value and its context**,
*never* of which emission path produced it. A value that is a `${}` shell
template, a `name-name:v1` public identifier, or `Config-Word-and-Word-only`
policy prose is not a secret no matter whether the entropy detector, the generic
keyword bridge, the weak-anchor post-pass, or the hot-pattern fast path surfaced
it. Phase-2 has several emission paths; they exist for *speed and recall*, not to
each carry their own copy of policy.

Detector-local canonical and transport-decoded hexadecimal key-material rules
follow the same boundary. Scanner construction compacts declared lengths,
keywords, suffixes, and exclusions into detector-indexed programs. Named,
generic, and entropy candidate paths execute those programs; only stable public
compatibility helpers without a compiled scanner inspect `DetectorSpec`
directly. Generic assignment processing resolves its entropy-policy owner and
canonical-policy owner from one normalized key lookup.

The same construction step compiles hot scalar execution facts such as generic
classification, minimum length and confidence, severity, structural password
slots, exact detector keywords, and public-identifier assignment markers.
Emission paths address that cache-local record by detector index. Once all
matchers and policies are built, `CompiledScanner` drops `DetectorSpec` itself;
the flexible structure remains a configuration and introspection schema, not a
second runtime policy owner.

Each detector index addresses one compiled plan containing its interned primary
and entropy-fallback metadata, execution facts, canonical/decoded key-material
program, entropy floor and policy, ML policy, credential-shape gate,
suppression policy, weak-anchor state, and compiled companions. Those policies
remain separate modules by responsibility, but their runtime ownership and
index alignment live in one structure rather than parallel vectors.

**The rule.** Emission paths produce `CandidateMatch` values and typed signals;
`adjudicate_match` owns the ordered suppression verdict. Path owners may compute
context-specific facts (entropy shape, generic bridge boundaries, named
detector policy), but they do not invent an untyped final drop reason:

```text
emission paths (entropy · generic/keyword bridge · weak-anchor · hot fast path · GPU)
        │  each yields CandidateMatch { detector, span, value }
        ▼
adjudicate_match(CandidateMatch, MatchCtx)
   1. explicit/process signals
   2. generic/entropy/hot-pattern signals
   3. named-detector suppression
   4. final report-floor policy
        ▼
   Verdict::Suppressed(stage_name)  |  Verdict::Reported(confidence)
```

`MatchCtx` carries one explicit signal family at a time. The `Verdict` names the
deciding `StageId`, which is what dogfood telemetry records. Shared shape policy
lives under `suppression::shape`; path-specific callers convert its result into
the matching typed signal before adjudication.

**Why this shape.** Candidate discovery necessarily differs by detector family,
but the final vocabulary and ordering of suppression decisions must not. Typed
signals preserve the context each path needs while keeping one auditable verdict
pipeline and one telemetry reason per decision.

### The ML model (`weights.bin`)

The scanner *serves* a Mixture-of-Experts confidence model embedded at build time
(`crates/scanner/src/weights.bin`, `include_bytes!`). It is *trained* out-of-band
by the Python pipeline in `ml/`:

```text
ml/harvest_corpus.py   real labelled candidates (CredData), harvested at a LOW
                       report floor so sub-floor hard negatives are captured
        │
ml/train_classifier.py blend synthetic + real, file-grouped split (no leakage),
                       train the 55-feature detector-conditioned MoE, gate on
                       held-out F1 plus
                       aggregate plus recall-sensitive class/detector recall
        │
ml/retrain_loop.sh     one command: harvest → train → (--write) ship weights.bin
                       → (--verify) rebuild + per-detector-FP bench gate,
                       fail-closed revert on any regression
```

Because the model is compile-time-embedded, a new model is only observable after
a rebuild, which is why `--verify` rebuilds before benching. The adjacent
`crates/scanner/src/model_card.json` carries the model hash, training inputs,
and gate metrics; `build.rs` refuses a card/weights mismatch and embeds the
summary shown by `keyhog --version`.

Scanner construction also compiles the detector-conditioned feature facts used
by that model, including service identity, verifier and companion presence,
generic/structural classification, phase-2 ownership, and entropy family.
Inference indexes that compact immutable policy and does not reinterpret the
loaded detector schema for each candidate. The public training oracle compiles
the same facts from the supplied detector before extracting its feature row.

## Detector-owned compiled validation

Offline validation is declared in each detector TOML's `validators` array. A
declaration selects a typed shared primitive and supplies that secret type's
prefixes, layout widths, bounds, and confidence floor. Scanner construction
compiles those declarations into the same immutable detector plan as matching,
entropy, suppression, companions, and ML policy.

Named matches dispatch directly to their detector plan. Generic and entropy
candidates use a first-byte index compiled from the active corpus instead of
walking a global validator registry. CRC32/base62 comparison is allocation-free;
base64 validation reuses zeroed per-thread scratch storage. Boundary extension
returns its validation decision with the final credential slice, and ML pending
rows carry that decision to final reporting. No candidate is revalidated after
model inference, and custom detector corpora never inherit an embedded service
table.

---

## Where do I find X?

| I want to… | Go to |
|------------|-------|
| Add/edit a detector | `detectors/<name>.toml` (data; see `CONTRIBUTING.md` for the schema) |
| Understand the scan flow at method level | `crates/scanner/src/engine/mod.rs` header |
| Change how confidence is scored | `crates/scanner/src/confidence/`, `ml_scorer.rs` |
| Add a suppression gate / change what counts as a non-secret | the one gate list `public_noncredential_shape`; see "Match adjudication" above (never inline a `looks_like_*` call in an emission path) |
| Retrain / improve the ML model | `ml/retrain_loop.sh` (+ `ml/README.md`) |
| Change an entropy entry path or weak-anchor floor | the owning detector TOML (`entropy_roles`, `entropy_floor`, `entropy_high`) |
| Add or tune offline validation | the owning detector TOML `validators` declaration |
| Add an input source | `crates/sources/src/` |
| Add live verification for a detector | `[detector.verify]` in the TOML + `crates/verifier/src/verify/` |
| Change output format / exit codes | `crates/cli/src/format.rs`, `reporting.rs` |
| Add a benchmark / change the gate | `benchmarks/bench/` |
| Verify a perf or detection claim | `benchmarks/` (the README numbers regenerate from here) |
