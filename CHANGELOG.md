# Changelog

All notable changes to KeyHog. Versions follow [Semantic Versioning](https://semver.org/).

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
