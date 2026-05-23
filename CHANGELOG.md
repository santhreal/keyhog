# Changelog

All notable changes to KeyHog. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased — kimi-dogfood sweep + daemon mode

### Added

- **Daemon mode.** `keyhog daemon start | stop | status` runs a long-
  lived scanner over a Unix socket (default
  `$XDG_RUNTIME_DIR/keyhog.sock`, falls back to
  `~/.cache/keyhog/server.sock`; socket is `chmod 0600`).
  `keyhog scan --daemon` (or auto-detected when the socket exists)
  routes a stdin scan / single-file scan through the daemon instead
  of paying the ~3 s `CompiledScanner::compile` cold start.
  Measured **105× speedup** (7 ms via daemon vs 740 ms in-process)
  on a real GitHub PAT, same detector + hash + offset in both
  paths. `--no-daemon` forces the in-process path. `--verify`,
  `--baseline`, directory walks, git-staged scans, and archive
  decoding stay in-process by design (the daemon doesn't replicate
  that pipeline).
- **`.keyhogignore` gitignore-style shorthand.** Bare path globs
  (`*.log`, `node_modules/`, `vendor/**/*.json`) and bare 64-char
  hex hashes are now accepted alongside the explicit
  `path:` / `hash:` / `detector:` prefixes. Lets users drop a copied
  `.gitignore` in place and have it work.
- **`--max-file-size` skip summary.** Files dropped by the size cap
  now emit a per-file WARN AND an end-of-scan summary line
  ("N file(s) skipped: exceeded --max-file-size"). Walker's silent
  filter was the only behavior before — a user looking at a
  smaller-than-expected scan had no signal about which files were
  dropped.
- **Live progress ticker.** Long scans paint a self-overwriting
  `scanning N/M chunks · K findings · t.t s` line on stderr every
  250 ms; suppressed under `--stream` or when stderr isn't a TTY.
- **25 companion-required detector contracts** at
  `crates/scanner/tests/contracts/companion/`. Per-detector TOMLs
  encode the three-shape contract (positive_with_companion,
  positive_primary_only with `must_not_verify`,
  negative_companion_lookalike) for AWS, Twilio (api-key /
  auth-token / IoT), Algolia, Razorpay, Amplitude, AppDynamics,
  Avalara, Backblaze, Belvo, Bitbucket, Booking, Akoya, 4everland,
  Lark, Linear, Linode, Plaid, Reddit, RingCentral, SumoLogic,
  Trulioo, Vanta. Runner test at
  `companion_contracts_runner.rs` enforces all three shapes per
  contract.

### Fixed

- **Mega-scan allocated ~20 GB RSS on tiny inputs.** Every shard's
  static input/state buffers were sized for
  `MEGASCAN_INPUT_LEN=256 MiB`. Forcing `--backend mega-scan` on a
  19-byte file uploaded ~570 × 256 MiB ≈ 20 GB of GPU memory and
  burned ~20 s before returning. Small-buffer guard at the entry
  of `scan_coalesced_megascan` now routes batches under 64 KiB
  through the literal-set GPU path. Same recall (same AC literal
  prefix anchors), orders of magnitude lower setup cost. Confirmed
  20.77 s / 19.7 GB → 0.34 s / 399 MB on the kimi reproducer.
- **GPU fallback regex-NFA dispatch silently dropped to CPU.** The
  fallback `RulePipeline::scan` was passed
  `max_matches_per_dispatch=1_000_000` which trips vyre's
  hard-coded `max_hits=10_000` static buffer declaration. Capping
  the dispatch at `NFA_HITS_PER_DISPATCH=10_000` keeps the GPU
  path live; the always-active fallback regex set is small enough
  that 10 K matches per dispatch is well above what we'd ever see.
- **`env::args()` panicked on non-UTF-8 args.** Linux allows
  raw-byte paths; `std::env::args()` calls `.unwrap()` on each Result
  which aborts with SIGABRT. Switched the version-flag detection in
  `main.rs` to `args_os()` + lossy compare.
- **Non-UTF-8 paths reported "No such file or directory"** even
  when the file existed. New pre-flight at the CLI boundary refuses
  non-UTF-8 paths with a clear message ("Rename the file or scan
  its parent directory") instead of confusing the user with a
  missing-file rabbit hole.
- **Nonexistent / unreadable input paths exited 0** with a WARN
  and "No secrets found, your code is clean." Per the documented
  exit-code contract these are runtime errors. CLI now stat's the
  input pre-walk; missing path → exit 2 with "path does not exist",
  unreadable file → exit 2 with "cannot read … (fix `chmod +r …`)".
- **`--backend invalid` silently ignored** and the scan ran with
  the default. clap now validates against the PossibleValues set
  `{gpu, mega-scan, megascan, simd, cpu, auto}` and exits 2 with a
  clear error.
- **`.keyhogignore` `detector:` entries were dead.** The parser
  populated `ignored_detectors` but the orchestrator's per-finding
  filter never read it. Now applied alongside `is_path_ignored` /
  `is_raw_hash_ignored`.
- **RefCell double-borrow panic in `fallback.rs`.** Per-pool
  thread-local borrows now `try_borrow_mut` + fresh-alloc fallback
  at three sites (`ACTIVE_PATTERNS_POOL`, `ACTIVE_INDICES_POOL`,
  `TRIGGER_POOL`). Was a hard P0: the rayon worker re-entry caught
  itself on the second borrow and aborted mid-scan.
- **FP storms killed**: lastpass-dev-creds firing on random
  `id=<digits>` in /var/log archives (87% FP rate per kimi); GitHub
  PAT placeholder `ghp_xxxxxxxx…` flagged at 0.80; xoxb tokens
  with ascending-digit runs flagged. Tightened
  lastpass-dev-creds to require `lastpass` context within 40
  chars; extended `looks_like_prefixed_masked_sequence` to suppress
  x/X-dominance, all-same-char, and ascending-digit-run ≥ 13.

### Improved

- **LayeredPipelineCache short-circuits compile on warm hits.** The
  prior `rule_pipeline_cached` always called
  `build_rule_pipeline` upfront to keep typed-error semantics for
  vyre's infallible-closure `cached_load_or_compile`, which made
  the on-disk cache pointless. Now uses vyre's
  `engine_cache_path` + manual load/save so a warm hit returns the
  deserialised `RulePipeline` without paying the compile.
- **`PreparedChunk::line_offsets()` memoised** via `OnceLock`.
  `compute_line_offsets` used to walk the preprocessed text twice
  per chunk (once for the triggered path, once for the
  pattern-hits path); the second caller now hits the memoised Vec.
- **Mega-scan compile-failure WARN demoted to debug.** Falling back
  to the literal-set GPU dispatch when vyre's byte-NFA frontend
  can't represent every pattern (e.g. pattern 990 in the bundled
  detector corpus uses lookaround) is the designed degradation —
  the user can't fix it, and one WARN per `--backend mega-scan`
  invocation creates noise without signal.

### Differential parity

`.internal/bench/differential/compare.py` against gitleaks 8.30.0
and trufflehog 3.95.3 on the 64 MiB `big_with_secrets` corpus:
**gate green**. Every secret two independent competitors HASH-confirm
keyhog also surfaces, except `sk_live_4eC39…` which is
documented as a public Stripe docs example (suppressed by
`test_fixture_suppressions::bundled()` and listed in
`baseline.toml`).

## v0.5.7 — 2026-05-17

### Fixed

- **The 'No secrets found. Your code is clean.' message lied when
  every match was suppressed as an EXAMPLE/test key.** The 0.5.6
  bump wired example-suppression telemetry into the orchestrator,
  but the user-facing summary is owned by `TextReporter::finish()`
  in `keyhog-core`, not the orchestrator — so the misleading
  banner still printed. `TextReporter` now takes the suppression
  count via `set_example_suppressions(n)` and prints "No real
  secrets — but N example/test key(s) suppressed. Pass --dogfood
  to see them." instead. Verified end-to-end against
  `demo-secret.env`. Regression tests pin all three states.

## v0.5.6 — 2026-05-17

### Added — dogfooding-driven UX

- **`--dogfood`** — opt-in JSON trace on stderr after the scan. Each
  example/test/placeholder credential that was matched and then
  suppressed gets a redacted-prefix event with the algorithmic reason
  (`contains_EXAMPLE_token`, `algorithmic_placeholder`). Closes the
  "did the scanner miss this, or silence it?" question without a debug
  rebuild. Full credentials are never emitted — `--dogfood` is a
  decision tracer, not a credential exfil channel.
- **Honest scan summary when only example keys were found.** Previously,
  scanning `demo-secret.env` (which holds `AKIAIOSFODNN7EXAMPLE`)
  printed *"No secrets found. Your code is clean."* — identical to a
  genuinely clean repo. Now the summary distinguishes:
  - 0 findings, 0 suppressed → "0 secrets in 0.12s. You are secure!"
  - 0 findings, N suppressed → "0 real secrets, N example/test key(s) suppressed (pass --dogfood to see them)."

### Internal

- New `keyhog_scanner::telemetry` module: per-scan atomic counters +
  optional event log. Engines call `record_example_suppression(...)`
  from the existing `should_suppress_known_example_credential_*` paths;
  the orchestrator drains events at the end of `run()`. Zero new
  state threaded through engine boundaries — single `OnceLock`
  process-local container with a `reset()` for tests.
- Two regression tests pinning the demo-secret.env case + the dogfood
  redaction contract. Telemetry-touching tests serialise behind a
  module-local `Mutex` so `cargo test`'s parallel runner doesn't let
  them step on each other.

## v0.5.5 — 2026-05-09

GPU foundations + vyre composition pass. The session wires keyhog
deeper into vyre as a primitive consumer and contributes new
general-purpose capability back to vyre.

**Tier-aware GPU routing + 2 MiB threshold on RTX 40/50-class GPUs.**
`select_backend` now classifies the detected adapter into High /
Mid / Low tiers and consults per-tier crossover thresholds:

| Tier   | Adapter examples                          | min_bytes | solo cap |
|--------|-------------------------------------------|-----------|----------|
| High   | RTX 40/50, A100/H100, M-Max/Ultra, RX 7900 | 2 MiB    | 16 MiB   |
| Mid    | RTX 20/30, GTX 16, Arc, M-Pro/base, RX 6/7 | 16 MiB   | 64 MiB   |
| Low    | iGPU, older discretes, unknown            | 64 MiB   | 256 MiB  |

Pattern-count breakeven is also tier-aware (100 / 500 / 2000).
`keyhog backend` reports the active tier and effective thresholds
for the live adapter. Backwards compatible: unknown adapters
classify as Low and keep the legacy thresholds.

**GPU dispatch sharding + correctness fix.** `scan_coalesced_gpu`
now slices the coalesced buffer at `65535 * 32 = 2,097,120` bytes
per dispatch (the wgpu workgroup-per-dimension cap × vyre's
`workgroup_size_x = 32`) and re-bases shard-local match offsets
into the global buffer's coordinate space. Eliminated the silent
`dispatch group size > 65535` error that the prior single-dispatch
path hit on every 100 MiB+ batch. Recall on the realistic
benchmark fixture now matches CPU/SIMD within rounding (303,554
vs 302,168 vs 304,128) — earlier `121× speedup` numbers were
lying because the dispatch errored mid-batch and only ~1% of
true hits came back.

**Vyre `intern::perfect_hash` wired for static-string interning.**
`CompiledScanner` builds a CHD perfect hash from every detector's
`(id, name, service)` plus the seed source-type literals at
construction time. `ScanState::intern_metadata` consults this
frozen interner first; only dynamic strings (file paths, commit
SHAs, author names, dates) hit the per-scan `HashSet<Arc<str>>`
fallback. Per-scan allocation count drops by ~100k on a typical
1000-chunk run. 6 unit tests + 282 scanner tests still green.

**Vyre megakernel scaffolding (gated behind KEYHOG_USE_MEGAKERNEL).**
`engine/megakernel_dispatch.rs` ships a working DFA-per-literal
compile + `BatchDispatcher` init + dispatch loop that hands back
the same per-chunk per-pattern trigger bitmask the literal-set
GPU path produces. Routed in `scan_coalesced_megakernel` behind
the env opt-in. Defaults OFF: vyre's `BatchDispatcher` is
optimised for "many files × few rules" but keyhog's corpus is
"few files × 6000+ rules" — modelling each literal as its own
`BatchRuleProgram` allocates `chunks × rules ≈ 600,000` work
items per dispatch, which keeps the persistent kernel sleeping
in S-state on RTX 5090. Real megakernel win needs vyre-side
multi-pattern hit reporting (one DFA covering many literals,
`HitRecord` gains a per-pattern field) — wiring then collapses
to a one-line swap.

Cross-platform compile fix in vendored vyre-runtime: `GpuStream<'a>`
now carries `PhantomData<&'a ()>` on non-Linux so the lifetime
parameter isn't flagged unused when `uring` is cfg'd out.
Windows / macOS builds now pull vyre-runtime cleanly.

**Vyre rule engine wired for declarative `.keyhogignore.toml`.**

Upstream vyre additions (general-purpose, lives in vyre-libs):
- `vyre_libs::rule::cpu_eval` — pure-CPU evaluator for
  `RuleCondition` / `RuleFormula` trees. Mirror of the GPU
  lowering. Useful for any consumer that wants per-record rule
  evaluation without dispatching a backend program. 11 unit tests.
- `vyre_libs::rule::ast::RuleCondition::FieldInSet` — new variant
  for "context field's value is in this set". Distinct from
  `SetMembership` (which compares a static value, not a field
  lookup). Required for expressing "detector_id is one of …"
  without resorting to regex alternation. Builder lowering errors
  with an actionable Fix: message — only the CPU evaluator can
  resolve field lookups today.
- vyre `smallvec` workspace pin bumped 1.14.0 → 1.15.1 so consumers
  carrying gix (which requires ^1.15.1) can share the type — keyhog
  needed this to put `SmallVec<[Arc<str>; 4]>` on the wire between
  core and vyre.

Keyhog consumes via new `crates/core/src/rule_filter.rs`. Schema
documented in `docs/keyhogignore-toml.md`. `[[suppress]]` tables
compose AND of named predicates (detector / service / severity /
severity_lte / path_eq / path_contains / path_starts_with /
path_ends_with / path_regex / credential_hash). Multiple
`[[suppress]]` tables compose with OR. Empty entry rejected at
parse to prevent accidental suppress-everything. Unknown fields
rejected via serde `deny_unknown_fields`. Wired into
`orchestrator.rs::run` after `finalize()` returns
`VerifiedFinding`s — predicates need the resolved fields that
`dedup_cross_detector` populates. Malformed
`.keyhogignore.toml` is non-fatal: warn + load zero rules; legacy
`.keyhogignore` still applies. 11 keyhog rule_filter tests pass.

**Realistic benchmark fixture.** The previous `--benchmark` corpus
used 36-char alphanumeric filler on every line, triggering the
entropy detector constantly so the benchmark was measuring
per-chunk extraction cost rather than the literal-prefilter
crossover it claims to measure. New fixture mirrors typical
TypeScript/Go/Rust source: short identifiers, natural-language
comments, short string literals. RTX 5090 against this fixture:
130 MiB/s (cpu-fallback) / 136 MiB/s (simd-regex) / 34 MiB/s
(gpu-zero-copy). The architectural fix for GPU loss on dense
corpora is megakernel fusion of the extraction pipeline (vyre
upstream feature, queued).

**Vyre full 30-crate audit doc** (`docs/vyre-usage.md`). Catalogues
every vyre crate (foundation, driver, driver-wgpu, driver-megakernel,
driver-spirv, libs, primitives, runtime, spec, intrinsics, reference,
cc, harness, macros) with the public surface of each. Lists every
vyre-libs and vyre-primitives module by name with what keyhog
could conceivably wire from each.

## v0.5.4 — 2026-05-08

Roadmap-clearing pass plus the first crates.io publish for every
workspace crate. The README's "Roadmap" section drops four items and
a long-standing ignored regression test goes green.

**Cross-chunk window-boundary reassembly (roadmap #3).** New
`crates/scanner/src/engine/boundary.rs` splices the tail of each
large-file scan window to the head of the next and rescans the seam,
catching secrets that physically straddle the 64 MiB scan-window
boundary. Wired into `scan_coalesced` after Phase 2 in both the SIMD
and no-SIMD paths. Bounded to 1 KiB per side (2 KiB per pair), so
cost is independent of chunk size: a 64 GiB file sliced into 1000
chunks pays ~2 MiB of total boundary work — negligible next to the
per-chunk regex pass. Six unit tests + the previously-`#[ignore]`-
marked `test_window_boundary_detection` integration test now pass;
the test itself was rewritten to use an AKIA-shaped secret (the
original `XX_FAKE_*` shape was unconditionally suppressed by the
placeholder filter, so the test would have stayed red even with
reassembly).

**`keyhog detectors --audit` and `keyhog detectors --fix`
(roadmap #4).** `detectors --audit` runs every detector through
`keyhog_core::validate_detector`, prints issues grouped by detector
ID, and exits with code 3 when any `Error`-severity issue surfaces —
drop it into CI to gate detector PRs. `detectors --fix` scans the
on-disk TOML corpus for the one validator finding that's safe to
repair mechanically — single-brace template references (`{shop}`)
inside `[detector.verify*]` blocks — and rewrites them to the
double-brace form (`{{shop}}`) the interpolator actually honours.
Rewrites are scoped to verify blocks only (regex quantifiers like
`[A-Z]{4,6}` in pattern blocks stay untouched), atomic-written via
NamedTempFile, and re-validated post-rewrite so a corrupted result
backs off rather than overwriting the original. `--dry-run` previews
without writing. The 888-detector embedded corpus shows zero errors
today (the v0.4.x detector cleanup wave already cleared them) — the
subcommand is the regression net for the next batch of contributions.
Seven unit tests cover the rewriter's edge cases.

**Streaming finding previews (roadmap #5).** New `--stream` flag emits
a one-line redacted preview to stderr per finding as the scanner
produces it, instead of waiting for dedup + verification before
printing anything. Format is grep-friendly:
`[stream] CRITICAL aws/aws-access-key  src/foo.rs:42  AKIA...XYZ_a`.
The full report (text/json/sarif/jsonl) still lands on stdout/`--output`
at the end — the stream is purely a UX hint that the scanner is
making progress on long-running runs (large monorepos, scan-system,
GitHub-org walks). Implemented inside the existing scanner thread via
`io::LineWriter` so per-line writes land atomically across rayon
workers.

**`--verify-rate` + `--verify-batch` (roadmap #7).** The per-service
token-bucket rate limiter (`crates/verifier/src/rate_limit.rs`) is now
hot-swappable via a new `set_default_rps()` (atomic-backed nanosecond
interval) so the CLI's `--verify-rate <RPS>` flag can take effect
after the global limiter has lazily initialised. Default stays at
5 rps; existing per-service overrides via `update_limit` are
preserved. `--verify-batch` adds per-service serialisation
(`max_concurrent_per_service = 1`) on top of the rate cap — use it
for repos with hundreds of fixture findings where bursting an
upstream auth endpoint would get the scan IP throttled. Three new
unit tests cover the rps→nanos clamp behaviour and the atomic update
path.

**Robustness sweep.**
- `entropy_1000_chars_under_1ms` was unconditionally failing under
  `cargo test` on debug builds (2.5 ms vs the 1 ms threshold). Marked
  `#[ignore]` matching the two sibling perf-threshold tests; rerun
  locally with `cargo test -- --ignored` against a release build.
- `crates/cli/src/scan_runtime.rs` was a 0-byte dead module with no
  references anywhere in the workspace. Deleted.
- Workspace `license` field downgraded from `MIT OR Apache-2.0` to
  `MIT` — the only license file shipped in the repo is the MIT one.
  Honesty over ecosystem convention.
- `cargo clippy --workspace --all-targets` now clean (was 4 warnings:
  unused-mut in `dedup.rs`, items-after-test-module in
  `orchestrator_config.rs`, an unnecessary `as_ref()` in the new
  streaming preview, and an explicit-counter loop in
  `extract_plain_matches` that's intentional for deadline-cadence
  gating and now carries an explanatory `#[allow]`).
- `detectors/.keyhog-cache.json` (runtime parse cache) is now
  gitignored AND `keyhog-core/Cargo.toml` carries an explicit
  `exclude` so a stale cache file can't sneak into the published
  tarball.
- `scripts/audit.sh` wraps `cargo audit` with the four
  accept-with-rationale `--ignore` flags so local audits exit clean
  the way CI does (cargo-audit 0.22 doesn't auto-load `audit.toml`).

**Crates.io publish setup.** Workspace package metadata
(description/license/repo/homepage/docs/keywords/categories/readme)
audited end-to-end across all five crates; package contents verified
via `cargo package --list` for each crate before publish (no stray
fixtures, no .work-linux.bundle, no target tree). Path-dep version
pins on the four library crates bumped in lockstep with the
workspace version (`=0.5.4` everywhere) — the `=` pin guarantees a
downstream `cargo install keyhog 0.5.4` resolves to a self-consistent
set.

## v0.5.3 — 2026-05-07

I/O perfection pass — five staged perf + correctness landings on the
filesystem source path, plus one latent-bug fix surfaced by the new
test coverage.

**Stage A — content cache (perf + correctness).** Merkle index schema
v2: each entry now carries `(mtime_ns, size, BLAKE3)` and the file
gets a top-level `spec_hash` derived from the canonical detector set.
`metadata_unchanged(path, mtime, size)` short-circuits the file read
entirely when stat metadata matches a stored entry — the dominant
cost on cold-cache disk for `--incremental` re-runs.
`load_with_spec(path, expected_spec_hash)` invalidates the cache the
moment any detector regex, group, or companion changes, fixing a
latent correctness bug where an added detector would silently miss
unchanged files forever.

**Stage B — mmap big-file scan.** Replaced the read+seek loop in
FilesystemSource's >64 MiB path with a single mmap + zero-copy slice
into `window_size`-byte windows with `window_overlap` shared bytes
between neighbours. Drops the 64 MiB heap working buffer and the
per-window `seek+re-read` overlap round-trip; `madvise(SEQUENTIAL)`
drives kernel readahead. Falls back cleanly to the buffered loop
when mmap is refused (locked writer, exotic filesystem).

**Stage C — I/O ↔ scan pipeline.** `scan_sources` spawns the scanner
in a dedicated thread holding `Arc<CompiledScanner>`. The producer
(main thread) iterates sources and builds batches; the scanner pulls
completed batches off a `sync_channel(1)` and runs `scan_coalesced`.
While the scanner is busy on regex, the producer is busy on disk
I/O, so total wall time approaches `max(read, scan)` instead of
`read + scan`. Channel capacity 1 keeps memory bounded to one
in-flight batch.

**Stage D — mmap compressed reads.** ziftsieve only takes a
contiguous `&[u8]` so streaming decompression isn't on the menu, but
mmap'ing the compressed file lets us hand it the whole input without
a corresponding heap allocation. A 1 GiB `.zst` previously manifested
as a 1 GiB `Vec<u8>` before decompression began. New `FileBytes` enum
(`Mmap` | `Owned`) with size-cap gating; falls back to `fs::read`
only on mmap refusal.

**Stage E — per-platform mmap threshold.** Lowered to 64 KiB on Unix
where `mmap` setup is sub-microsecond and avoids the page cache →
userland buffer copy. Held at 1 MiB on Windows where `MapViewOfFile`
carries section-object + security-token costs that buffered
`ReadFile` doesn't pay.

**Latent bug fixed alongside Stage D.** `gz` and `zst` were in
`SKIP_EXTENSIONS`, so the `extract_compressed_chunks` dispatch arm in
the FilesystemSource iterator was actually unreachable — compressed
files were silently being skipped on every scan. Removed those
entries (the gz/zst handler now actually runs).

**Tests.** ~55 new tests covering: 13 merkle_index v2 unit, 12
window-slicing pure-helper unit, 4 FileBytes/mmap-or-bytes unit, 6
pipeline orchestrator unit (including a 6000-chunk recall floor that
proves the threading doesn't drop batches), 9 FilesystemSource
integration covering the windowed path, merkle skip, and gz
end-to-end. Existing 53 scanner lib + 31 sources read unit + 20
filesystem integration all still green on both Windows and Linux.

**Code cleanup.** Removed dead `detector_to_patterns` field + helper
from the scanner (unused since the v0.5.2 perf trim). Tightened the
`Arc` import gate in `crates/sources/src/lib.rs` so docker-only
builds no longer warn about unused imports.

## v0.5.2 — 2026-05-06

Reconciliation pass against the parallel `Legendary Hardening` line
(v0.3.0 → v0.4.0 → v0.5.0) that lived only on the work-linux clone
and was never pushed. Both lines diverged at `013257e` (CI fmt scope)
and independently arrived at near-identical scanner/sources state.

Reviewed every file the work-linux line touched; no salvageable code
was missing from this branch:

- `SensitiveString` migration, `MADV_DONTDUMP` zero-leak buffers,
  proximity-aware multiline reassembly, hardened ratelimiter, AC
  prefilter for `has_secret_keyword_fast` — already present here,
  fmt-clean, with the no-default-features feature gates the v0.6.x
  pass added.
- The 6 secret-laden boundary-test fixtures (`test.txt`,
  `boundary_test.txt`, etc.) accidentally committed in work-linux's
  v0.4.0-finalize commit are intentionally **not** brought in: they
  trip GitHub push-protection and the boundary test that needed them
  was rewritten to use a synthetic `XX_FAKE_*` shape in v0.6.1.
- `crates/sources/src/slack.rs:54` `data: T.into()` syntax bug that
  still exists on the work-linux line was already fixed here in v0.6.0.

Net new: version bump only. No code regressions, no losses.

vendor/vyre is untouched — separate project with its own versioning.

## v0.6.1 — 2026-05-06

Perfection pass on top of v0.6.0.

### Fixed

- `crates/sources/src/binary/{mod,sections}.rs`: 5 type errors (the
  `extract_printable_strings` wrapper claimed `Vec<String>` while the
  underlying call returned `Vec<SensitiveString>`). Any build with
  `--features binary` previously failed to compile.
- `aws-access-key.toml`: dropped `required = true` from the `secret_key`
  companion. A leaked AKIA on its own is still a reportable finding;
  verification correctly downgrades to "unverified" when no co-located
  secret is found instead of silently dropping the match.
- `crates/core/tests/unit/spec.rs`: the `no_detector_uses_singular_companion_table`
  test now mirrors `crates/core/build.rs`'s symlink fallback so it works
  on Windows checkouts where `crates/core/detectors` lands as a literal
  file containing the link target.
- `crates/scanner/tests/performance_regression.rs`: replaced the
  CRC32-invalid `ghp_ABCDEF…` synthetic with an AKIA-shape fixture so the
  test exercises the no-default-features build (where checksum validation
  fails closed).
- 3 adversarial tests gated behind the features they exercise (`ml`,
  `multiline`, `decode`); previously they ran under `--no-default-features`
  and asserted behavior that requires those features.

### Hygiene

- `cargo clippy --workspace --no-default-features --all-targets` clean
  (zero warnings) under both `--no-default-features` and the
  default-minus-simd matrix.
- `cargo fmt --check` clean.
- 596/596 tests pass under both feature configurations.

## v0.6.0 — 2026-05-06

Out-of-band callback verification + broad robustness/detector fixes.

### Added

- **OOB verification** (`--verify-oob`): RSA-2048 + AES-256-CFB interactsh
  client (`oast.fun` by default; `--oob-server HOST` to self-host). Detector
  TOML gains an `[detector.verify.oob]` block with `protocol={dns,http,smtp,
  any}`, `policy={oob_and_http,oob_only,oob_optional}`, and
  `accept={dns,http,smtp,any}`. Probe payloads can interpolate
  `{{interactsh_url}}`, `{{interactsh_host}}`, and `{{interactsh_id}}` to
  embed a unique callback URL per probe; the session waits for a matching
  hit before declaring the credential live. Documented in `docs/OOB.md`.
- `keyhog_core::spec::validate` now audits companion-substitution capture
  groups, reserved companion names (`__keyhog_oob_*`), and that every
  `{{companion.X}}` / auth-field reference resolves to a declared companion.

### Fixed

- `extract_grouped_matches` (scanner): zero-width regex hits no longer
  infinite-loop the matcher; capture-group walk reuses a single
  `CaptureLocations` and aligns to UTF-8 boundaries; out-of-range detector
  index now fails closed instead of panicking.
- Required companions (`required = true`) actually short-circuit: prior
  `unwrap_or_default()` swallowed the "missing required companion" signal
  and shipped the finding anyway.
- `OobSession::wait_for` race: registers the `Notified` waiter via
  `Notified::enable()` before checking observations, so notifications fired
  between the check and the await no longer get lost.
- 8 detector verify specs that referenced undeclared companions or used
  template strings in the auth-field slot would 401 every probe (Twilio
  IoT, Akoya, Razorpay, Braintree sandbox, etc.). Each now declares the
  companion it references.
- Look-behind regex assertions (`(?<=`, `(?<!`) are no longer
  misclassified as named capture groups by the spec validator.
- `crates/sources/src/slack.rs`: `data: T.into()` syntax error in
  `SlackResponse<T>` would have failed any build that exercised the slack
  feature.

### Performance

- Aho-Corasick prefilter for `has_secret_keyword_fast` and
  `has_generic_assignment_keyword` (single-pass).
- `extract_inner_literals` AST walker promotes inner literals into the
  prefilter alphabet (corpus coverage test pins ≥3 patterns promoted).
- `find_companion` splits into a capture-group-free fast path
  (`find_iter`) and a grouped path that reuses `CaptureLocations`.
- Active-fallback bitmap precomputed at scanner construction; per-chunk
  thread-local `ACTIVE_PATTERNS_POOL` avoids reallocation.
- Filesystem reader: two-sided `looks_binary` early exit, streaming
  UTF-16 decode, valid-UTF-8 fast path.
- Slack source fetches per-channel history concurrently (rayon, 8 threads).

### Hardening

- `looks_binary` short-circuit verified against full-scan baseline across
  page-boundary cases.
- `open_file_safe` rejects symlinks on Windows (Unix already enforced).
- Self-suppression list rewritten with `concat!()` to keep example
  credentials out of the repo's literal string table.

## v0.3.0 — 2026-05-01

The "legendary" wave: 18 Tier-A perf wins + 12 Tier-B moat innovations from the
2026-04-26 deep audits, plus a perfection pass that hardened GPU/CPU
auto-routing across every supported OS. Build is green, scanner test suite
229+/0, core 33+/0, hw_probe routing 11/0, doctests 38/0.

### Hardware routing & GPU/CPU saturation (perfection pass)

- `KEYHOG_BACKEND={gpu,simd,cpu}` env var force-pins the scan backend at the
  highest routing priority, used by CI matrix builds and benchmarks to assert
  backend-specific code paths actually run (`ba0e3fc`).
- `KEYHOG_THREADS=N` env var threads the rayon pool size; with `--threads`
  taking absolute priority and physical-core count as the auto fallback
  (`3c4924c`).
- Per-OS wgpu adapter preference replaces `Backends::all()`: Windows → DX12 +
  Vulkan, macOS/iOS → Metal, Linux/BSD → Vulkan + GL — each platform gets its
  first-class native API (`ba0e3fc`).
- Public `hw_probe::thresholds` module exposes the routing crossovers
  (GPU_MIN_BYTES=64 MiB, GPU_PATTERN_BREAKEVEN=2000, GPU_BYTES_BREAKEVEN_SOLO=
  256 MiB) for benchmarks and the inspector subcommand to reference one source
  of truth (`ba0e3fc`).
- 11 routing unit tests pin every documented threshold + the env-override
  branch + the software-renderer skip. Tests serialize through a `Mutex`
  guard since they mutate process env (`ba0e3fc`, `3c4924c`).
- `keyhog backend` subcommand: dumps detected hardware, the active backend,
  the env override (if set), and a routing decision matrix at every
  documented threshold; `--probe-bytes` and `--patterns` for what-if
  simulation (`ba0e3fc`).
- GPU init now requests the adapter's full limits (was capped at wgpu
  `Limits::default()`'s 128 MiB storage-buffer ceiling; an RTX 5090 had its
  batch size throttled to 0.4% of physical capacity) (`e182938`).
- GPU init rejects `device_type == Cpu` adapters at the wgpu layer too
  (catches future software fallbacks not in the llvmpipe/lavapipe name
  list) (`3c4924c`).
- Per-scan `tracing::info!` logs the selected backend; per-chunk
  `tracing::trace!` on `keyhog::routing` for full audit trails
  (`3c4924c`, `ba0e3fc`).
- Verifier gained `danger_allow_http` opt-in flag to support HTTP test
  mocks while keeping production HTTPS-only (`0da1f94`).

### Performance — CPU saturation

- `scan_chunks_with_backend_internal` now uses `rayon::par_iter` on the
  non-GPU paths — was serial, pinned to a single core even on 32-core
  boxes (`a693ba2`).
- `scan_coalesced` parallelizes its `#[cfg(not(feature = "simd"))]` and
  Hyperscan-init-failure fallbacks; multi-core builds without Hyperscan now
  saturate cores (`27caaf9`).
- `[profile.release]` pinned: opt-level=3 + lto=fat + codegen-units=1 +
  panic=abort + strip — was using cargo defaults; the new profile yields
  ~10-20% throughput on hot paths via cross-crate inlining (`3c4924c`).
- `[profile.release-fast]` (thin LTO, 16 codegen-units) for sub-minute CI
  builds; `[profile.bench]` keeps line-tables for flamegraph attribution.

### Performance — Tier-A perf wins (~constant-factor allocations on the hot path)

- Cow-borrowed `normalize_homoglyphs` and `prepare_chunk` — ASCII fast path no
  longer clones (`7e7cd55`).
- `post_process_matches` dedup keys are `Arc<str>`, not `String` (`7e7cd55`).
- Thread-local trigger-bitmask pool — drops ~2.4M allocs on a 100k-file scan
  (`7e7cd55`).
- Phase-1 returns `Option<Vec<u64>>` so empty chunks never allocate (`7e7cd55`).
- `BTreeMap` dedup → `indexmap::IndexMap` for O(1) deterministic ordering
  (`d3b6721`).
- Streaming SARIF reporter — peak memory drops from O(N findings) to O(rules)
  (`3a15fd0`).
- Batched-streaming orchestrator — 4096 chunks / 256 MiB per batch caps peak
  memory on giant scans (`a6c88b2`).
- Sharded `DashMap` for verifier `VerificationCache`, `RateLimiter`, and
  in-flight map (no more global RwLock contention) (`d3b6721`).
- Concurrent rayon-parallel S3 / GitHub-org / Slack source backends
  (8–16 in-flight) (`d3b6721`).
- Shared `Arc<Regex>` compile cache via `shared_regex()` — same regex across
  detectors compiles once (`a38e79c`).
- Pre-built `index_set` once on `Baseline::load` via `OnceLock` (`d3b6721`).
- Bigram bloom prefilter (Layer 0.5) — gates chunks ≥64 bytes before
  Hyperscan (`3a15fd0`).
- Dropped io_uring single-op path (latency regression, kept the multi-op
  batch path) (`d3b6721`).
- Decode-bomb time budget — per-chunk wall-clock ceiling on `decode_chunk`
  (`20d3ef8`).
- Probabilistic gate filled in: distinct-bigram density via FNV-512 (`20d3ef8`).

### Innovations — Tier-B moat features

- **Bayesian Beta(α,β) confidence calibration** — per-detector posterior
  updated from observed TP/FP, multiplier wired into the live scoring path,
  CLI surface (`keyhog calibrate --tp/--fp/--show`) (`34deeb0`, `d5d447e`).
- **Incremental scan** via persisted BLAKE3 Merkle index — unchanged files
  skip the scanner entirely on CI re-runs (`57c4cc8`).
- **Cross-detector dedup at emit** — one secret matched by N detectors
  collapses to one finding with N ranked service guesses (`eab71b2`).
- **Diff-aware severity** — git source pre-walks HEAD's tree, tags chunks
  `git/head` vs `git/history`, and the latter's findings drop one severity
  tier (`410dc0e`).
- **JWT structural validation** — header.payload decode with `alg`/`typ`/`exp`
  inspection and `alg=none` anomaly detection (`43092b6`).
- **CWE-798 + OWASP A07:2021 SARIF taxa** — compliance-grade reporting
  (`5462625`).
- **SARIF v2.2 fixes[]** with deletedRegion/insertedContent and env-var-name
  auto-fix suggestions (`650e599`).
- **Allowlist governance metadata** — `; reason="…" ; expires=YYYY-MM-DD ;
  approved_by="…"` per entry, expired entries auto-drop (`32ff3a8`).
- **`keyhog explain <detector-id>`** — full spec dump, regex breakdown, and
  rotation-guide URLs for major providers (`f56f97e`).
- **`keyhog diff <before.json> <after.json>`** — NEW / RESOLVED / UNCHANGED
  set diff for CI regression detection (`52d7242`).
- **`keyhog watch <path>`** — daemon mode with notify-based file watcher,
  compile-once-scan-many on saves; sub-100ms re-scan (`56c61d6`).
- **`keyhog calibrate`** — α/β counter management with posterior-mean bar
  visualization (`34deeb0`).
- **`keyhog detectors --search <query> --verbose`** — case-insensitive
  filter against id/name/service/keywords; verbose dumps full spec
  (`5951a14`).
- **`keyhog completion <shell>`** — bash, zsh, fish, powershell, elvish
  (`8ab105f`).

### Adversarial coverage

- Reverse-string decoder for tokens stored backwards as evasion (`c462e9c`).
- Caesar / ROT-N decoder for ROT13'd configs (`c462e9c`).
- Hex `_` separator stripping (firmware dumps, embedded configs use
  `A1_B2_C3_…`) (`2980284`).
- Comment-suffix disclaimer suppression — `// not a real key`,
  `# fake credential`, etc. (`2980284`).
- Cross-detector dedup also handles 2-fragment AWS reassembly with
  no-shared-prefix var names (`3327b39`).

### Architecture

- GPU auto-routing — runtime probe selects GPU vs CPU based on adapter type,
  workload size, and pattern count; mandatory build-time presence (no more
  feature gate) (`7feb723`).
- Filesystem source: per-archive-entry uncompressed-size cap; ziftsieve
  gzip/zstd/lz4 4× decompressed-byte budget (`5cc3906`).
- Verifier hardening: SSRF DNS-rebinding defeated via `tokio::net::lookup_host`
  post-resolve check; HTTPS-only no-localhost-exception (`7feb723`).
- AWS SigV4 dates derived from `SystemTime::now` via Howard-Hinnant civil
  arithmetic (no chrono runtime cost) (`7feb723`).
- `fragment_cache` module relocated under `multiline/` where every call site
  lives; re-exported at the crate root for back-compat (`70e35a8`).

### Tests

- Wired adversarial fixtures into `cargo test` (no more skipped corpus)
  (`5cc3906`).
- Aligned `gitleaks_hash_*` allowlist tests with the hardened
  `is_hash_allowed` API (no plaintext fallback) (`b2b405d`).
- Wrapped `?`-using doctests in explicit `fn main() -> Result` so the
  E0277 wave is gone (`19ce4f5`).
- 229 scanner tests / 33 core unit tests / 38 doctests, 0 failed.

### Detector corpus

- Brutal audit of all 896 detectors found schema decay; corrupted entries
  removed, broken logic flagged (`e934144`).
- Schema rename (kimi automated): aligned every detector to the post-audit
  field set (`826d54f`).
- Verifier auth wiring fixes for the corpus (`826d54f`).
- 859 valid detectors after the gate; ~30 still flagged for pure-character-
  class companions (tracked separately).

## v0.2.1 — 2026-04-04

Maintenance release: production-readiness fixes, dependency updates, agent
sweeps. See `git log v0.2.0..v0.2.1` for the commit list.

## v0.2.0 — 2026-03-30

> The fastest, most accurate secret scanner.

First "legendary bar" release. Highlights:

- Embedded 888-detector corpus (no separate `detectors/` directory needed).
- Hyperscan SIMD regex with disk-cached compiled DB.
- Aho-Corasick literal prefilter feeding into the regex layer.
- ML-based confidence scoring (MoE classifier with per-detector calibration).
- Decode-through pipeline: base64, hex, URL, MIME, HTML entities, Z85,
  unicode/octal escapes, quoted-printable.
- Multiline secret reassembly across line-continuation patterns in a dozen
  languages.
- Sources: filesystem, git history, git diff, GitHub orgs, S3, Docker
  images, web URLs (JS/sourcemap/WASM), Slack (admin export).
- Verifier framework with TOML-defined live verification per detector.
- SARIF v2.1.0 + JSON + JSONL + plain-text reporters.

## v0.1.0 — 2026-03-26

- First public release of the KeyHog workspace.
- Production-readiness cleanup for docs, examples, README guidance, and
  release metadata.
- Verified `cargo check`, `cargo test`, and
  `cargo clippy --workspace -- -D warnings`.
