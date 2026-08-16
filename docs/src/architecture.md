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
- Choosing between a one-shot scan, Git modes, `scan-system`, the daemon, and
  `watch`? Start with [Execution surfaces](#execution-surfaces).
- Changing process termination or shell behavior? Read
  [Process and exit ownership](#process-and-exit-ownership), then the
  [exit-code reference](./reference/exit-codes.md).
- Changing the Marketplace Action or release publication path? Read the
  [load-bearing boundary owner map](#load-bearing-boundary-owner-map) before
  changing a wrapper or duplicating policy.

---

## Repository layout

Every top-level directory, one line each. **Code** is Rust under `crates/`;
everything else is data, tooling, docs, or eval harness.

| Dir | Role |
|-----|------|
| `crates/` | Rust workspace: runtime code only (six crates; see [below](#the-crates-and-their-layering)). |
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

Dependencies point one way: `core` and `profile` are foundations and depend on
no other KeyHog crate; `cli` sits on top and wires the rest together. This DAG
is enforced by Cargo and must stay acyclic (domain logic never imports
CLI/transport/UI).

```text
                          cli
            orchestration · transport · process exits
             ┌─────────────┼──────────────┬──────────┐
             ▼             ▼              ▼          ▼
          scanner        sources       verifier   profile
          detection       inputs       live checks  timing · run state
             │  ╲          │  ╲           │          ▲
             │   ╲         │   ╲ optional │          │
             │    └────────┼────┼─────────┼──────────┘
             └─────────────┼────▼─────────┘
                           ▼
                          core
        types · detector registry · reports · dedup · caches
```

`scanner` and `verifier` depend on `core`. `scanner` also records fixed stages
through `profile`. `sources` depends on `core` and, for network-enabled source
features, reuses `verifier` for shared SSRF and request-signing policy. `cli`
selects features, composes all five libraries, and owns the operator-run profile
session.

| Crate | Owns | Start reading at |
|-------|------|------------------|
| **`core`** | Embedded detector loading, detector specs, the `Finding`/`Credential` types, reporters, dedup, allowlists, the Merkle incremental-scan cache, and confidence-calibration data. | `crates/core/src/lib.rs`, `spec.rs`, `finding.rs`, `report/` |
| **`profile`** | Allocation-free fixed-stage timing, causal run identity, state transitions, process resource sampling, and portable JSON and text profile records. | `crates/profile/src/lib.rs` |
| **`scanner`** | The detection engine: hardware probing and backend dispatch, prefilters, compile, scan, decode-through, entropy, ML confidence, multiline handling, and suppression. Persisted CLI route selection is intentionally not owned here. | `crates/scanner/src/compiled_scanner/` (construction and lifecycle), `engine/mod.rs` (execution flow), `adjudicate/`, `pipeline/`, `lib.rs` |
| **`sources`** | Where bytes come from: filesystem, Git (staged/diff/history), stdin, Docker, S3, GCS, Azure Blob, GitHub, GitLab, Bitbucket, web, HAR, strings, and optional binary/decompiler inputs. | `crates/sources/src/lib.rs` |
| **`verifier`** | Turning a *candidate* into a *verified-live* credential: per-detector verify endpoints, SSRF/bogon guards, OOB, rate limiting. | `crates/verifier/src/lib.rs`, `verify/`, `ssrf.rs` |
| **`cli`** | The user-facing binary: argument parsing, the scan orchestrator, daemon/watch, baselines, calibrate, hook installer, output formatting. | `crates/cli/src/lib.rs`, `args/`, `orchestrator/`; `main.rs` owns process/signal startup only |

The crate graph does not imply that every build exposes every source or
backend. The official and default CLI builds enable the full documented
network-source set. The `portable`, `ci-lean`, and `ci` profiles deliberately
remove different accelerator or source features. Library callers select their
own feature set.

## Load-bearing boundary owner map

The crate DAG is not the whole shipping boundary. The Action entrypoint,
automatic crates.io publication, and each load-bearing library or CLI handoff
have one definitional owner. Wrappers may compose these owners; they must not
restate their policy.

| Boundary | Definitional owner |
|---|---|
| Marketplace metadata, documented inputs/outputs, and top-level composite steps | `action.yml` |
| Repository-local Action metadata consumed by GitHub workflows | `.github/actions/keyhog/action.yml` |
| Action input validation, authenticated binary acquisition, scan invocation, exit mapping, and output publication | `.github/actions/keyhog/run-scan.sh` |
| Automatic version, changelog, and crates.io publication | `.github/workflows/release.yml` |
| CLI argument dispatch and setup-error exit routing | `crates/cli/src/lib.rs::cli_main` |
| Completed-scan exit precedence | `crates/cli/src/orchestrator/run.rs::resolve_scan_exit` |
| Curated source-crate export surface | `crates/sources/src/api.rs` |
| Live-verification construction and execution | `crates/verifier/src/lib.rs::VerificationEngine` |
| Deduplicated match to report-safe finding conversion | `crates/core/src/finding.rs::VerifiedFinding::from_deduped` |
| Scanner execution flow | `crates/scanner/src/engine/mod.rs` |

This table is enforced by `scripts/org_audit.py`: every required boundary must
remain paired with its exact owner row, every file must exist, and every named
symbol must resolve. Merely retaining the same unordered set of paths is not
enough. A move therefore updates implementation and architecture in the same
change instead of leaving a plausible but stale owner behind.

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
   fused resident literal-evidence route (`engine/gpu_region_dispatch.rs`).
   It produces one "which detectors may match here" bitmap plus optional
   confirmed-anchor and generic-keyword positions per chunk. The fast
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
   `engine/process.rs`, and `engine/boundary/mod.rs`. Confidence + ML scoring live in
   `confidence/`, `ml_scorer.rs`, and `ml_scorer/`; context inference lives in
   `context/`. The per-match policy here (suppression gates ·
   example/placeholder · checksum · confidence penalties) is governed by one
   invariant; see **Match adjudication: one policy, one chokepoint** below.
5. **Verify (optional and networked):** for detectors with a
   `[detector.verify]` plan, the verifier sends a credential-derived request to
   the declared service behind SSRF, bogon, and rate-limit guards.
6. **Resolve and report:** the CLI orchestrator applies scan-level policy and
   allowlists; core deduplication and reporters emit text/JSON/SARIF and support
   baseline comparison. `crates/cli/src/orchestrator/postprocess.rs`,
   `crates/cli/src/orchestrator/reporting.rs`, `crates/core/src/dedup.rs`, and
   `crates/core/src/report/` own these steps.

`keyhog_core::VerifiedFinding::from_deduped` is the conversion boundary from a
deduplicated match to a report-safe finding. It initializes the complete
finding shape, including measured entropy and redacted companions, so verifier,
skipped, and diff paths cannot silently drift when the report contract grows.

The CLI keeps one owner for each finding graph as it advances through this
pipeline. Scan-level suppression compacts the raw-match vector in place.
Deduplication moves each accepted match into its group, verification partitions
the deduplicated vector in place, and baseline suppression compacts the final
finding vector in place. A stage may allocate indexes or output slots, but it
does not clone the complete old graph while building a replacement graph.

An `allocation-profile` build assigns every retained heap allocation to the
innermost active profile stage. Its allocation header preserves that owner when
another stage or thread frees the value. Allocations outside a stage belong to
the explicit root owner. Stage and root live-byte totals must equal the process
allocator total, so retained memory cannot disappear into an unattributed
remainder.

The accelerated batch path is **two-phase and coalesced**. A file with no
phase-one hit stops only when the shared no-hit admission proof also rules out
phase-two patterns, generic assignments, and enabled entropy analysis. This
proof uses the active corpus's compiled generic-keyword stems and the owning
detector's `keyword_free_min_len` plus effective Shannon floor; it does not
substitute the embedded corpus or a scanner-wide run length for a focused
custom corpus. Chunk size never disables an active detector path; overlapping
source and scanner windows bound work instead. Portable CPU, Hyperscan, CUDA,
and WGPU share this proof. Large
filesystem scans may instead use the fused reader/scanner pipeline so I/O and
scanning overlap; `crates/cli/src/orchestrator/dispatch.rs` and
`dispatch/fused.rs` own that execution choice. Both paths feed the same scanner
and report contracts. Backend choice must change performance only, never finding
semantics.

Within the shared SIMD/GPU coalesced tail, detector, generic, and entropy
candidates retain their per-chunk state while precomputed ML feature rows are
scored in one deterministic CPU batch. Final scores return to the originating
chunk before its cap, decode postprocess, seam handling, and report adjudication
run. Every backend uses this confidence path; VYRE owns GPU detection only.

### Execution surfaces

The CLI owns process-level routing. The scanner crate exposes explicit backend
execution; it does not read the autoroute cache or silently choose from local
hardware. This keeps library calls deterministic and makes CLI routing
inspectable.

| Workload | Execution surface | Routing and ownership |
|---|---|---|
| One in-process scan | `keyhog scan ... --daemon=off` | Full orchestrator; persisted one-shot autoroute evidence or an explicit diagnostic `--backend`. |
| Mass directories or source batches | `keyhog scan --daemon=mass ...` | Streams bounded batches to a mass-enabled daemon (`daemon start --mass`). |
| Perpetual repository guard and staged commits | `keyhog guard` and `keyhog scan --git-staged` | Daemon-resident guard runtime with in-memory Git OID clean attestation cache and watcher reconciliation. |
| Repeated eligible stdin or single-file scans on Unix | `keyhog daemon start`, then `keyhog scan ...` | Client checks request eligibility and peer identity; a calibrated daemon uses warm-runtime autoroute evidence. Invalid startup state prevents readiness. Persisted quarantine is labeled `autoroute-degraded`, and affected requests fail closed without scanning. |
| Continuous local directory monitoring | `keyhog watch` | Foreground watcher with its own compiled scanner and warm-runtime autoroute policy; not the daemon and not reported by `daemon status`. |
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

### Execution-pack dependency direction

The execution-pack cutover has one dependency direction. Treat code that points
against this direction as migration code, not as a second supported design.

```text
install or update
  detector TOML -> validation -> canonical detector IR
  canonical detector IR -> route classifier + policy/backend programs
  programs -> route-scoped matcher sections -> exact finding parity
  parity-proven packs -> installation-key signatures -> atomic pack generation
  binary + authenticated packs + pack-bound calibration -> one published generation

normal scan startup
  route decision -> authenticate one selected mapped pack
  selected sections -> owned route classifier + selected detector runtime
  discard authenticated mapping pages -> release mapping after hydration
normal scan
  source adapter -> chunks -> owned route classifier -> selected runtime -> RawMatch
  RawMatch -> CLI post-filter -> verifier -> reporter
```

The arrows are ownership boundaries:

| Owner | May depend on | Must not depend on |
|---|---|---|
| Install compiler | Detector schema, validators, pack codec, every eligible backend compiler | Source adapters, reporters, ordinary scan state |
| Route classifier | Authenticated literal index, decoder identity, chunk metadata | Backend materialization, detector TOML parsing, reporting |
| Selected detector runtime | Authenticated canonical detector IR, selected policy/backend sections, VYRE orchestration for GPU | Source adapters, autoroute persistence, CLI, reporters, an unselected backend |
| Source adapters | Core chunk and source contracts | Scanner internals, execution packs, reporters |
| CLI orchestrator | Sources, route decisions, selected runtime, verifier, reporters | Detector-local execution ownership |
| Reporters | Redacted findings and coverage state | Detector compilation, source acquisition, backend selection |

The installer writes a protected 32-byte signing key, builds every policy pack in a sibling staging directory, fsyncs every pack, signature, manifest, and directory, then publishes the generation by one rename. The next compiler run removes dead-process staging directories, removes replaced backups when a current generation exists, and recovers the sole backup when publication was interrupted before a current generation appeared. A failed or interrupted health check, pack build, or calibration restores the prior binary, pack directory, and autoroute cache as one installation transaction. `keyhog update` applies the same rule: it verifies the candidate, compiles the candidate embedded detector corpus into host packs, calibrates those authenticated packs, and publishes all three artifacts under rollback guards.

`keyhog doctor` reports the installed pack path, authenticates the manifest and every detached signature, and fails health when route evidence is missing its pack binding or names a different generation.

Calibration authenticates the installed manifest and every detached pack signature before measuring routes. The versioned autoroute cache stores the manifest digest and every policy/backend pack identity. A missing policy pack, a replaced manifest, changed pack bytes, a different installation key, or binary, target, feature, and detector drift invalidates the calibration transaction.

A normal installed scan maps one policy pack, authenticates it, and decodes canonical detector execution IR instead of parsing the embedded TOML corpus. Authentication pages are discarded before section hydration. Each section faults back only when decoded into owned runtime state, and the mapping is released before the scan begins. Detector specs move once from decoded IR into shared ownership used by the orchestrator and scanner compiler; startup no longer clones the complete corpus for scanner construction. Normal one-shot scans also skip eager regex cache warming; explicit resident and calibration paths retain their deliberate warm transition. A normal scan never parses detector TOML, compiles regex or backend programs, benchmarks a route, or maps a losing backend. A missing, stale, incompatible, or incomplete generation is an invalid autoroute state. It is not permission to construct the old universal scanner or replay through another backend.

CPU sections contain canonical scalar programs. SIMD sections contain signed
native Hyperscan shards for phase one and every phase-two scope. GPU sections
contain VYRE orchestration receipts with the complete fused matcher bytes and
the exact target, runtime, driver, device, and limits identity. A selected scan
deserializes these artifacts directly from the authenticated pack. It does not
compile patterns, rebuild GPU literal rows, or construct an unselected backend.
VYRE remains the sole owner of device programs, dispatch, and GPU-resident
memory.
An exact CPU or SIMD scanner also omits GPU literal rows, regex-bound rows,
matcher programs, peer state, and upload/readback scratch. Those allocations
exist only after an exact GPU route or calibration census selects a usable VYRE
peer.

An exact SIMD scanner does not retain the scalar phase-one automaton. Before
first use, its lazy plan shares the canonical literal allocation with scanner
construction. After materialization, it retains native Hyperscan shards and
only the literals rejected by Hyperscan for exact host recovery. Phase-two
keyword catalogs and alphabet screens borrow detector-owned strings while they
build. Only synthesized keyword stems and VYRE matcher rows allocate new bytes.

Detector-indexed matcher relationships use flat `u32` data plus row offsets.
SIMD pattern mappings, confirmed-suffix rows, and structural detector
partitions therefore retain two contiguous vectors per table rather than one
heap allocation and pointer-sized header per detector or pattern.
Their builders ingest flat row/value pairs, so scanner construction also avoids
temporary per-row vectors.

Frozen runtime indexes retain only populated rows and final-sized storage.
Detector-relation maps omit detectors with no relations, metadata and generic
ownership maps release duplicate-heavy builder capacity, and matcher vectors
discard geometric growth slack before entering the compiled scanner.

Cache retention follows the live workload. The process-wide detector-regex
index stores bounded weak references, so compiled regex programs disappear
when the last scanner using them drops. Fragment-reassembly shards start with
one scope row, grow geometrically only as distinct `(prefix, path)` scopes
arrive, keep the existing hard ceiling, and shrink to the minimum when the
workload cache is cleared.

Scanner construction releases compiler-only keyword catalogs, diagnostics,
route-neutral literal strings, and decoded detector schemas as soon as their
final runtime owner has been built. These inputs are gone before the compiled
scanner crosses into health and scan-state measurement.

The CLI then returns freed compiler arenas to the allocator before the runtime
is exposed. Mimalloc builds collect every Rayon worker heap plus the caller
heap; Linux glibc builds trim the process heap. Collection runs once at scanner
construction, never in the per-chunk scan path.

The KeyHog-owned Rayon pool reserves the standard 2 MiB Rust worker stack.
Scanner parsing and traversal are iterative, so the previous 8 MiB reservation
only multiplied per-worker virtual memory without protecting a required call
depth.

With live verification disabled, the orchestrator retains only the resolved
policy needed for configuration and receipt identity. Detector verification
graphs are dropped after scanner construction; verifier candidate queues,
caches, HTTP clients, and OOB state are constructed only inside the enabled
postprocess path.

Every mapped byte has one owner: pack metadata, detector IR, route classifier,
regex programs, suppression policy, or the selected backend. Header, table, and
alignment padding belong to pack metadata. The ownership ledger must sum to the
complete mapping length.

Pack files use read-only shared mappings. Concurrent scanners fault the same immutable physical pages while they authenticate and hydrate a generation, rather than allocating one input copy per process. Each process retains only its owned decoded runtime after releasing the transient mapping.

Worker-local scratch is lazy and route-scoped. Uppercase, checksum-decode, and
generic-keyword pools retain at most one scan chunk per worker; decode-fact maps
start empty. Host anchor candidates retain at most one scan chunk. Single-chunk
VYRE upload/readback buffers retain at most one scan chunk, while coalesced VYRE
buffers retain at most the portable dispatch grid so repeated GPU batches do
not reallocate. Outliers are zeroed where they can contain source bytes and
released before that worker serves another route.

### Failure and recovery contract

KeyHog separates trust failures from recoverable execution failures:

- **Complete:** the selected backend covered the input normally.
- **Complete after recovery:** an authenticated, automatically selected backend
  faulted. KeyHog warned visibly and counted every recovered range, chunk, and
  byte. Runtime faults retain completed dispatches and replay only unprocessed
  ranges through a proven recovery peer.
- **Incomplete:** some requested bytes or transformation was not scanned.
  Missing, invalid, or quarantined autoroute state selects no backend and leaves
  the affected batch unscanned. The scan may report findings from independently
  covered input, but it cannot report clean.
- **Fatal trust or explicit-contract failure:** invalid policy, corrupt or
  unauthenticated artifacts, or an explicitly required backend cannot be
  substituted.

Recovery is an owned execution path, not a silent fallback. It must operate on
the same stable source snapshot, preserve finding parity, merge results
deterministically, identify every replayed interval, and remain absent during
autoroute calibration so a backend that needs recovery cannot be certified
fastest-correct.

### Process and exit ownership

The library crates do not terminate the process. `core`, `scanner`, `sources`,
and `verifier` return values or errors to their caller. The CLI owns the
operator-visible exit:

1. `crates/cli/src/main.rs` installs the Unix SIGINT handler before starting the
   runtime. SIGINT writes the interruption diagnostic and exits `130`.
2. `crates/cli/src/lib.rs::cli_main` dispatches subcommands. Successful
   subcommands return `std::process::ExitCode`; setup and execution errors pass
   through `cli_error_exit_code`.
3. `crates/cli/src/orchestrator/run.rs::resolve_scan_exit` owns completed scan
   precedence: scanner panic, live credentials, findings, incremental-cache
   failure, incomplete source coverage, then clean success. Autoroute
   calibration has its explicit success path.
4. A scanner-thread panic sets the shared panic marker. The CLI flushes the
   diagnostic streams and exits `11` immediately instead of allowing a later
   accelerator teardown to replace the documented code.

Normal automatic autoroute recovery is part of a completed scan, so it keeps
the ordinary finding or clean code. An explicit backend contract that cannot be
honored is an error before completed-scan precedence applies. See
[Exit codes](./reference/exit-codes.md) for every number and shell examples.

### Finding identity and dedup

There is one identity contract with stage-specific keys, not interchangeable
"same finding" guesses:

| Stage | Owner | Key | Why |
|-------|-------|-----|-----|
| Window overlap and raw collector | `crates/scanner/src/engine/windowed_support.rs::record_window_match`; `crates/scanner/src/scan_state.rs::ScanState::into_matches` | `(detector_id, credential, source_offset)` | Adjacent 1 MiB windows overlap by 128 KiB, and more than one backend signal can surface the same span. The source-offset key removes duplicate raw hits without merging separate occurrences on different lines. |
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
matchers and policies are built, `CompiledScanner` drops `DetectorSpec` itself.
The CLI also releases the decoded detector corpus before a non-verifying scan;
only `--verify` retains it for verifier-plan construction. The flexible
structure remains a configuration, verification, and introspection schema, not
a second owner during ordinary scanning.
The interner owns each unique string once as a lookup-map key, with no parallel
arena. Resolution and cross-detector relation indexes clone those same
allocations instead of storing another copy of each detector ID.

Every public scanner constructor reaches one full-corpus quality gate before it
builds matchers or probes backends. This also applies when you construct
`DetectorSpec` values in memory instead of loading TOML. The gate rejects
invalid detector fields and duplicate IDs with detector-indexed configuration
errors.

Each detector index addresses one compiled plan containing its interned primary
and entropy-fallback metadata, execution facts, canonical/decoded key-material
program, entropy floor and policy, ML policy, credential-shape gate,
suppression policy, weak-anchor state, and compiled companions. Those policies
remain separate modules by responsibility, but their runtime ownership and
index alignment live in one structure rather than parallel vectors.

The same plan owner compiles detector `decode_transforms` declarations into one
active-corpus reverse and Caesar admission program. The decoders do not read the
scanner-global confidence prefix list. A custom corpus therefore changes both
matching and evasion recovery through the same detector digest.

Scanner construction also snapshots the ordered decoder registry. Decode
execution, decode admission, and autoroute workload sketches all read that same
immutable snapshot. Each decoder supplies a stable name and version. Those
descriptors contribute to the detector digest, so cached routing evidence does
not survive a decoder-plan change. If you register a decoder after scanner
construction, the existing scanner does not change. Compile another scanner to
use the new decoder.

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

Model-driven confidence reductions require an entry in
`crates/scanner/src/pattern_calibration.json` for the exact detector corpus
digest, detector ID, pattern index, candidate channel, source role, and
pre-verification context. Each entry carries positive and negative held-out
support, recall at the blocking floor, Brier score, and expected calibration
error. Missing, stale, unsupported, or under-supported entries abstain. Generic
assignment and entropy channels cannot use pattern calibration.

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
| Add or tune reverse or Caesar recovery | the owning detector TOML `decode_transforms` declaration |
| Add an input source | `crates/sources/src/` |
| Add live verification for a detector | `[detector.verify]` in the TOML + `crates/verifier/src/verify/` |
| Change output formatting | `crates/cli/src/format.rs`, `crates/cli/src/orchestrator/reporting.rs` |
| Change process exit codes or precedence | `crates/cli/src/exit_codes.rs`, `crates/cli/src/lib.rs::cli_error_exit_code`, `crates/cli/src/orchestrator/run.rs::resolve_scan_exit`, and `crates/cli/src/main.rs` for Unix SIGINT |
| Add a benchmark / change the gate | `benchmarks/bench/` |
| Verify a performance or detection claim | `benchmarks/` (the README numbers regenerate from here) |
| Change backend selection or autoroute | [Backends and routing](./backends.md), [Autoroute calibration](./reference/autoroute-calibration.md) |
| Operate the daemon or plan a mass scan | [Daemon and warm scans](./workflows/daemon.md), [Mass repository and cloud scanning](./guides/mass-scanning.md) |
| Understand detection, suppression, or verification | [Detection](./detection.md), [Suppressions](./suppressions.md), [Verification](./verification.md) |
| Configure scanning or findings output | [Configuration](./reference/configuration.md), [Output formats](./output-formats.md) |
