# Changelog

All notable changes to KeyHog. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

## v0.5.30 - 2026-05-27 - premium interactive installer + CUDA-on-Linux release variant + star tracker

### New: premium interactive installer

- **`install.sh` + `install.ps1` rewritten.** The Linux / macOS installer now detects host state (OS, arch, NVIDIA GPU, loadable `libcuda.so`, existing keyhog install, PATH config), summarizes what it would do, and (when stdin is a TTY) prompts for the variant + optional post-install steps. Curl-pipe-sh keeps working: a non-TTY stdin drops to auto-detect mode and prints a tip for the interactive path.
- **New modes:** `--diagnose` prints a full host + binary status report and changes nothing. `--repair` re-downloads the right variant for the current host even when the existing binary still runs (useful after CUDA userland is installed and the WGPU build should be swapped for the CUDA build). `--uninstall` removes the binary but deliberately leaves shell-rc PATH entries and completions in place so the installer doesn't silently edit user-owned files.
- **Post-install wizard (when interactive):** opt-in prompts for adding the install dir to your shell PATH (with explicit append to `.bashrc` / `.zshrc` / `config.fish`), installing shell completions, wiring keyhog as a Claude Code pre-tool hook, and wiring keyhog as a git pre-commit hook in the current directory. Defaults are conservative; nothing happens without an explicit "y".
- **Overrides:** `KEYHOG_VARIANT=cuda` / `=cpu` force a variant. `--yes` / `-y` accepts every default for non-interactive runs. `--no-color` disables ANSI output for log capture. `KEYHOG_VERSION` and `KEYHOG_INSTALL` env-vars work as before.

### New: CUDA-on-Linux release variant

- **`keyhog-linux-x86_64-cuda` ships as a 5th release asset.** Built with `--features cuda` after provisioning CUDA 12.6 toolkit on the GH ubuntu runner via `Jimver/cuda-toolkit@v0.2.19`. The installer prefers this asset on Linux hosts where `nvidia-smi` reports a GPU AND `libcuda.so` is loadable (via ldconfig or the four common path probes). On the same host with no CUDA, the installer keeps picking the existing default `keyhog-linux-x86_64` build (WGPU + SIMD). Apple Silicon, Intel Mac, and Windows hosts keep their existing assets; Apple Silicon hosts get an explicit "Metal GPU acceleration coming soon" preface so users understand the WGPU + SIMD tradeoff up front.
- **install.sh falls back gracefully** when the `-cuda` asset is not yet published for the resolved tag: it tries the CUDA asset, on 404 it logs the fallback and downloads the base asset instead. This means the script is forward-compatible with older release tags.

### Tests

- **`tests/install/scenarios.sh`** is a 12-scenario harness that mocks `uname` / `nvidia-smi` / `ldconfig` / `curl` per scenario via a sandbox dir prepended to PATH. Covers: CUDA host, macOS arm64, macOS x86_64, `KEYHOG_VARIANT=cuda` / `=cpu` overrides, unsupported platform, `--help` / `--uninstall` mode dispatch. The two scenarios that require simulating "NVIDIA but no libcuda" or "no GPU at all" skip on a real CUDA host (the script's path-fallback probes leak through the sandbox) and run for real on no-CUDA CI runners.
- **End-to-end smoke test on real Apple Silicon hardware:** the install path was verified over SSH against an M-series macbook, upgrading v0.5.28 to v0.5.29 cleanly and reporting the Metal-coming-soon note. `--repair` and `--diagnose` were exercised on the upgraded macbook to confirm post-install behavior.

### Metrics / repo hygiene

- **Daily star tracker.** `metrics/stars.json` records `{date, count}` snapshots; `.github/workflows/record-stars.yml` runs at 07:17 UTC, calls the GitHub API for the current count, dedupes per date, and commits if changed. README gains a live stars badge linking to star-history.com. wafrift gets the same tracker (see `santhsecurity/wafrift`).
- **README backend table accuracy.** Removed the stale "cudagrep NVMe -> VRAM DMA" claim. The actual code routes the GPU path through vyre (WGPU cross-platform, optional CUDA feature) with no cudagrep or warpstate references anywhere in the tree.

## v0.5.29 - 2026-05-27 - HAR (HTTP Archive) auto-expansion + http/wire docs + Bazel scaffolding untracked

### New: HAR auto-expansion

- **`keyhog scan capture.har`** now parses the HAR 1.2 JSON and expands it into one chunk per request and one chunk per response. Each chunk's `source_type` is `wire:har:request` or `wire:har:response`, so a bug-bounty hunter can filter findings to outbound credentials only:
  ```sh
  keyhog scan capture.har --format json | \
    jq '.[] | select(.location.source == "wire:har:request")'
  ```
  The `file_path` for each finding is `<har-path>#<request-url>`. New `crates/sources/src/har.rs` module; 4 unit tests covering positive expansion, non-HAR JSON, non-JSON binary, and malformed-JSON fallthrough. 4x `max_size` budget on cumulative request+response body bytes guards against decompressed-gigabyte DoS.
- `serde` + `serde_json` promoted from optional (per-feature) to unconditional deps in `keyhog-sources` because the always-on filesystem path now depends on them. Removed redundant `dep:serde` / `dep:serde_json` from `web` / `github` / `slack` / `s3` feature lists.

### Docs

- **New chapter:** [HTTP and wire scanning](http-wire.md). Documents the existing `--url` flag (Web Source: JS / sourcemap / WASM routing + SSRF defenses), proxy + TLS policy (`--proxy`, `KEYHOG_PROXY`, `KEYHOG_INSECURE_TLS`), the stdin curl-pipe workflow, and the new HAR auto-expansion. Roadmap section calls out mitmproxy `.mitm` support, header/body provenance, live proxy mode, and WebSocket frame scanning as the next wire-scanning items.
- `docs/src/detectors.md` documents the `client-safe` severity tier + `client_safe = true` per-pattern flag.
- `docs/src/reference/cli.md` documents `--hide-client-safe` + the `KEYHOG_NO_GPU` / `KEYHOG_PER_CHUNK_TIMEOUT_MS` / `KEYHOG_BACKEND` / `KEYHOG_THREADS` / `KEYHOG_DETECTORS` / `KEYHOG_CACHE_DIR` env vars in one place.

### Repo hygiene

- **Bazel scaffolding untracked.** The 8 in-tree Bazel files (`.bazelrc`, `.bazelversion`, root + 5 per-crate `BUILD.bazel`, `MODULE.bazel`, `MODULE.bazel.lock`) were a 2026-05-21-throttle-driven PoC that never finished — every per-crate BUILD was a comment-only stub and `MODULE.bazel` was pinned to keyhog `0.5.7` while we ship 0.5.29 via cargo. Per the STANDARD prod-repo-doc-bleed rule, advertising a Bazel surface that doesn't build anything is a stub-not-evasion lie. Files stay on disk for the day Bazel becomes load-bearing; `.gitignore` catches future Bazel scratch.

### Detector tagging (client-safe)

- `clerk-api-key`: publishable `pk_live_*` / `pk_test_*` — same shape as `clerk-frontend-api-key` from v0.5.28. Total client-safe-tagged patterns now: 9 across 8 detectors.

## v0.5.28 - 2026-05-27 - KEYHOG_NO_GPU short-circuit + bare `-` stdin + more client-safe tags

### Cross-platform / safety nets

- **`KEYHOG_NO_GPU=1` now ACTUALLY bypasses the GPU stack.** The v0.5.27 commit only short-circuited the compile-time CUDA/wgpu factory call. The MoE GPU context init runs lazily on the FIRST `backend::get_gpu()` call, and the hardware probe path (`hw_probe.rs:82 -> gpu_probe -> backend::get_gpu`) reaches it before `compile()` even runs. On hosts where Metal adapter request blocks for minutes (Apple M4 Pro / macOS 26.3 reproduction) the env var fired AFTER the user had already paid the stall. `gpu_probe()` now checks the env var BEFORE calling `get_gpu()`; on set, returns `(false, None, None)` so `hw_probe` reports `gpu_available: false`, MoE init never runs, and the scanner starts in ~10 ms.

### CLI UX

- **`keyhog scan -` (bare dash positional) now reads from stdin.** Grep / wc / curl convention. Previously errored with `error: path '-' does not exist`. `keyhog scan - --stdin <<<...` and `keyhog scan - <<<...` both work now; `--stdin` is no longer required when the path is `-`.

### Detector tagging (client-safe)

- `segment-write-key`: write-only keys shipped in every `analytics.js` / Analytics SDK init. Server-side admin is `segment-sources-api-token` (stays high).
- `clerk-frontend-api-key`: `pk_live_*` / `pk_test_*` shipped alongside `<ClerkProvider>` in Next.js / browser bundles. Clerk secret key is a separate detector.

Total client-safe-tagged detectors now: 7 (Sentry DSN both patterns, Mapbox `pk.`, PostHog `phc_`, Mixpanel project token, Algolia search-only both patterns, Segment write key, Clerk frontend `pk_*`).

## v0.5.27 - 2026-05-27 - client-safe severity tier + `--hide-client-safe` (bug-bounty workflow)

### Feature

- **`Severity::ClientSafe`** is a new tier below `Low`. Detectors with a per-pattern `client_safe = true` flag in their TOML force the finding to this tier regardless of the detector's nominal severity. Tagged patterns ship 5 detectors / 6 patterns in this release: Sentry DSN (both patterns), Mapbox `pk.eyJ` (sk.eyJ stays critical), PostHog `phc_` (phx_ stays high), Mixpanel project token, Algolia search-only key (admin key is a separate detector and stays critical).
- **`--hide-client-safe` CLI flag** filters every ClientSafe finding before the reporter sees them. Bug-bounty / exfiltration-impact workflow: `keyhog scan --hide-client-safe target/` shows only credentials that grant server-side access. Default scans keep the tier visible (CLIENT-SAFE stripe in text output) so a misconfigured publishable key wired into a server-only detector still surfaces.
- **`KEYHOG_NO_GPU=1` env-var** bypasses the CUDA / wgpu init path entirely and routes every chunk through the SIMD/CPU regex backend. Workaround for the Mac arm64 Metal stall surfaced during v0.5.26 dogfood when scanning identifier-dense source. Set in CI or in the user's shell rc when GPU latency matters less than predictable scan times.
- **`KEYHOG_PER_CHUNK_TIMEOUT_MS` env-var** attaches an `Instant` deadline to the public `scan` / `scan_with_backend` entry points. Any future pathological pattern that escapes the per-pattern `MAX_INNER_LOOP_ITERS` cap times out at the per-chunk boundary instead of hanging the whole scan. Default unset preserves prior behavior.

### Schema

- `[[detector.patterns]]` blocks accept a new `client_safe: bool` field (default `false`). Additive; existing detector TOMLs continue to parse unchanged. Per-pattern (not per-detector) so detectors that fire on both the public AND the secret prefix can tag only the public one.

### Reporter changes

- Text format: new `CLIENT-SAFE` 11-char label rendered in dim cyan (`2;36`) with a public-by-design remediation action ("Public by design (client bundle key) — verify scope restrictions."). All severities right-justified to 11 chars so bordered boxes line up regardless of which tier fires.
- SARIF: `ClientSafe` → SARIF `note` level (same as `Info` / `Low`).
- Rule-filter / `.keyhogignore` severity-name: `client-safe` (kebab-case, matches the new serde `rename_all`).

## v0.5.26 - 2026-05-27 - Mac arm64 hang fix (var-ref-concat regex DFA stall) + Windows UNC path strip + repo-hygiene gitignore

### Cross-platform

- **Mac arm64 `keyhog scan` hang on identifier-dense source.** Cross-platform dogfood on Apple M4 Pro / macOS 26.3 / portable build (no Hyperscan) reproduced a 6+ minute stall on a 171-byte input: `var token = circleCiScan.Flag("token", "X").Required().Envar("X").String()`. Root cause is the var-ref-concat regex in `multiline::config::has_var_ref_concat_line` - the `{1,8}`-bounded alternation drives `regex` 1.12's lazy-DFA construction into a quadratic loop on aarch64-apple-darwin. Linux x86_64 portable runs the same input in 0.6 s. Fix: cheap precheck - if the line contains no `+`, bail before the regex (the pattern requires at least one `+` to match, so this is correctness-preserving). Adds `KEYHOG_PER_CHUNK_TIMEOUT_MS` env-var deadline as a belt-and-suspenders backstop on the public `scan` / `scan_with_backend` entry points so any future pathological pattern caps out instead of hanging the whole scan.
- **Windows UNC verbatim-prefix strip.** Every finding's `location.file_path` rendered as `\\?\C:\Users\...` (Rust's `std::fs::canonicalize` always returns the extended-length form on Windows). Editors don't jump-to-file on the verbatim form and the prefix leaks through JSON output as `"\\\\?\\C:\\..."`. Added `pub(crate) display_path(&Path) -> String` in `keyhog-sources::filesystem` that strips the `\\?\` prefix on Windows; the underlying `PathBuf` we use for I/O keeps the UNC form so >260-char paths still resolve. Wired through eight chunk-emit sites (`filesystem.rs` windowed mmap + buffered fallback + plain file + archive entries text/binary; `binary/mod.rs` ghidra decompiled + strings + section/strings).
- **Cross-platform detector-dir discovery.** `auto_discover_detectors` hardcoded `/usr/share/keyhog/detectors` and `/usr/local/share/keyhog/detectors` which silently no-op on Windows. Wrapped the Unix paths in `cfg!(unix)` and added `dirs::data_dir()` / `dirs::data_local_dir()` lookups so Windows users get `%APPDATA%\keyhog\detectors` / `%LOCALAPPDATA%\keyhog\detectors` discovery. Embedded detectors remain the default; the dir paths are only consulted when a user supplies a custom detector set.

### Repo hygiene

- **Untrack coordination / plan / audit scratch files.** Per the new Santh STANDARD `prod-repo doc bleed` rule, standalone repos like `santhsecurity/keyhog` track exactly README + SPEC + CHANGELOG + `docs/`. The 31 internal coordination files (`coordination/` round briefs, `ROUNDS.md`, `TESTING_PROGRAM.md`, `KEYHOG_LINUX_QUALITY_PROGRAM.md`, `WAVE10_AGENT_PUSH.md`, `GAP_FINDINGS.toml`, `TODO.md`) were untracked from git and added to `.gitignore`. Files stay on disk via the backup `santhsecurity/Santh` monorepo - they just stop polluting the prod repo a crates.io / GitHub-Pages reader sees. Extended `.gitignore` with `WAVE*.md`, `*_AUDIT*.md`, `*_PROGRAM.md`, `plan.md`, `.audits/`, `plans/` patterns so future scratch files are caught at write-time.

### Build / test

- **`build_scanner_config`: pub(crate) → pub.** Four integration tests under `crates/cli/tests/unit/orchestrator/build_scanner_config_*.rs` import the function and need it externally visible. Was a pre-existing breakage in `cargo test --workspace --no-run` that CI didn't catch because the failing tests aren't in the per-crate `--lib` subset CI runs.
- **`exclude_paths_parses_from_cli` Rust-1.83 fix.** Old assertion `Some(&["a.txt"[..]])` produced `&[str; 1]` which Rust 1.83+ rejects as an unsized array element. Rebuilt as a `Vec<&str>` collected from the `Vec<String>` field.

## v0.5.25 - 2026-05-27 - cross-platform fixes (Windows build, basename `\` separators, UTF-16 BOM decode) + contract recall (412 → 52 regressions restored via shape-filter Tier-A/Tier-B split + caseless fallback regex)

### Cross-platform

- **Windows build (E0432/E0433)** - `daemon` module gated `#[cfg(unix)]`. It hard-imported `tokio::net::UnixStream` and `std::os::unix::net::UnixStream`, neither of which exist on Windows. `keyhog daemon` and `--daemon` now emit a clear "unix-only" error there instead of a build failure. Per-named-pipe Windows IPC support is tracked but unimplemented.
- **Cross-platform path-separator suppression** - five sites used POSIX-only `rsplit('/')` for basename extraction or `contains("/dir/")` for vendored-tree detection. Windows checkouts (`C:\src\app\node_modules\…`) silently skipped every gate. Switched to `rsplit(['/', '\\'])` + new `contains_path_segment` helper that tests both `/seg/` and `\seg\`. Behaviour on POSIX paths unchanged.
- **UTF-16 BOM file decode** - `decode_text_file` unconditionally rejected every file starting with the literal UTF-16 BOM (`\xff\xfe` / `\xfe\xff`) as binary, before `decode_utf16` (right below it) could decode them. Every UTF-16-BOM PowerShell / .NET config that ships on Windows was silently invisible to the scanner. Removed the false-positive guard; `decode_utf16` handles BOM dispatch internally.

### Recall - contract evasions restored (412 → 52)

- **Shape-filter Tier-A / Tier-B split.** Five shape-suppression filters (`looks_like_pure_identifier`, `looks_like_word_separated_identifier`, `looks_like_scheme_prefixed_uri`, `looks_like_url_or_path_segment`, `contains_uuid_v4_substring`) were applied universally in `should_suppress_named_detector_finding` as of v0.5.21..v0.5.24. They dropped legitimate service-anchored credentials whose body looks like an identifier / URL / UUID - PowerBI client_id UUIDs, mongodb:// URIs, avalanche RPC URLs, cockroachdb word-separated keys. Per the anti-rigging law: contracts are truth - when evasions DROP, fix the engine, not the contract. New `is_generic_or_entropy_detector` helper gates the five filters as Tier-B (generic-* / entropy-* only). `looks_like_punctuation_decorated_identifier` stays universal (Tier A) - `--api-secret`, `&password`, `Password:` are grammar markers, never a credential body. Self-scan: 0 real findings, 1041 example/test keys suppressed (was 1020 pre-fix).
- **Fallback regex compiler - caseless to match Hyperscan.** `shared_regex()` built the regex crate without `case_insensitive(true)`, but Hyperscan compiles every pattern `CASELESS`. Detectors with mixed-case alternations (`(?:FRAMER|framer)[_=:\s"']+(?:api[_-]?)?(?:key|token)`) bake uppercase only in the leading anchor, leaving `api`/`key` lowercase. `FRAMER_API_KEY=<token>` (uppercase) was matched by Hyperscan but silently missed by the fallback path - ~30 detectors affected.

### Detector-specific

- **`transifex-api-token`** - second-pattern regex was `transifex\.com.*[=:\s"']+(...)`. Hyperscan `.*` doesn't span `\n`, so the canonical `# https://transifex.com/api/3/\nAuthorization: Bearer <token>` shape never matched. Switched to `[\s\S]*?` (lazy any-char). Keeps existing positives; restores the documented evasion.
- **`weatherapi-api-key`** - added a third pattern for the canonical curl shape (`https://api.weatherapi.com/v1/...?key=<key>`) where the domain appears BEFORE the key. The previous two patterns both required domain AFTER the key, missing the standard SDK invocation.
- **`intercom-access-token`** - TOML parse error silently dropped this detector from the embedded corpus since v0.5.21. The regex line used a single-quoted TOML literal with an embedded `'`, which TOML basic literals do not allow. Switched to triple-quoted literal. Build script counted 891 but loader saw 890; this restores the missing detector.

### Test infrastructure

- **Boundary tests** - `STRADDLE_ABCDEFGHIJKLMNOPQRST` (29 pure-alpha chars) was tripping `looks_like_pure_identifier` after v0.5.21's filter widened to catch CamelCase / single-underscore identifiers in the 8..=40 alpha range. Test fixture now uses `STRADDLE_A1CDEFGH2JKLMNOPQ8ST` (digits sprinkled in), matching the AWS-access-key shape the test was designed to mirror.
- **README banner pattern count** - `README_PATTERN_COUNT = 1646` → `1647` (one pattern added by the weatherapi third regex + one restored by the intercom fix).
- **Clippy 1.95** - ten new lints (`doc_lazy_continuation`, `manual_range_contains`, `manual_pattern_char_comparison`, `manual_contains`, `manual_char_is_ascii`) on pre-existing code in `suppression.rs`. Idiom-only modernizations, no behavior change.

## v0.5.24 — 2026-05-26 — dogfood non-PEM 27 → 22 (138 → 22 vs v0.5.21 baseline = −84%) via UUID-substring + email + blockchain-address-keyword + `$` sigil + base64 hot-pattern wiring

### Precision

- **`contains_uuid_v4_substring`** — captured values that wrap a UUID v4 / RFC-4122 (`TOKEN_LIST=636765a9-1f92-4b40-ab0b-85ebd1e2c23d` in bat-go docker-compose.reputation.yml). The entropy detector grabs the whole env-var assignment; the high-entropy payload is just the UUID, which is a public identifier, not a credential.
- **`looks_like_email_address`** — `noreply@gogs.localhost` (gogs TestInit.golden.ini:89 `USER=…` captured because of nearby `PASSWORD=` line). Email addresses are public identifiers, never credentials. Tightened local + domain alphabet checks keep real `user:password` DSN strings outside the rejection set.
- **Blockchain / network-address keyword context** in entropy fallback. Lines like `SOLANA_BAT_MINT_ADDRS=EPeU…1Tpz`, `OWNER_PUBKEY=…`, `CONTRACT_ADDRESS=0x…`, `WALLET=…` name a PUBLIC blockchain or network identifier — not a credential. Skip the entropy emit when the env-var key contains any of `_ADDR`, `_ADDRS`, `_ADDRESS`, `_WALLET`, `_MINT_ADDR`, `_PUBKEY`, `_PUBLIC_KEY`, `_CONTRACT`, `_OWNER`, `_ACCOUNT_ID`, `_PEER_ID`, `_NODE_ID`.
- **Leading `$` sigil rejection** — GraphQL variable references (`$api_key` in shopify-cli mutation), shell variable expansions (`$API_KEY`), template placeholders (`${SECRET}`). Real credentials never start with `$`.
- **`base64_string.txt` / `base64_*` filename pattern + hot-pattern path wiring**. `metasploitable3/.../base64_string.txt` is a 600 KiB pure-base64 PNG flag file. Random byte sequences in the base64 stream coincidentally match the AWS Session Token `ASIA[A-Z0-9]{16}` literal-prefix hot pattern. The base64 decoder still produces its own `filesystem/base64` chunk; only raw text-mode hits on these files are suppressed. Wired in BOTH `should_suppress_named_detector_finding` and the hot-pattern fast path.

### Per-detector dogfood deltas vs v0.5.23

  generic-secret           7 → 6   (shopify-cli graphql $api_key killed)
  entropy-api-key          1 → 0   (Solana mint address killed by blockchain-keyword)
  entropy-token            1 → 0   (UUID-substring killed `TOKEN_LIST=<uuid>`)
  entropy-password         3 → 2   (email-shape killed `noreply@gogs.localhost`)
  hot-aws_session_key      1 → 0   (base64_string.txt killed via hot-pattern wiring)
  TOTAL non-PEM           27 → 22  (−19% this release; −84% vs v0.5.21 baseline)
  private-key recall      782 + 30 = 812 unchanged

### Residual 22 findings

All ~21 are TRUE POSITIVES that the engine should keep firing on:
- 6 alist OAuth client secrets committed to source (real public OAuth secrets in cloud-storage driver bindings — known leak by design).
- 4 metasploitable3 chef users.rb passwords (`Dark_syD3`, `@dm1n1str8r`, `mesah_p@ssw0rd`, `Dark_syD3`-class) — CTF/vulnerable-app credentials intentionally weak but ARE real credentials.
- 4 metasploitable3 / govwa generic-secret CTF passwords (`govwaP@ss`, `D@rjeel1ng`, `but_master:`, `admin1234`).
- 2 gogs golden test fixtures (`PASSWORD=12345678`, `PASSWORD=87654321`) — sequential-digit test passwords; engine correctly flags them.
- 1 metasploitable3 Autounattend.xml Microsoft Windows public-key token (real public ID, ambiguous).
- 1 railsgoat seeds.rb CTF password (`motoXXX1445`).
- 1 claude-code Datadog public client token (real, intentional public Datadog logging key).
- 1 shopify-api-ruby test JWT (shipping label JWT in a test response fixture).
- 1 openssl SSH private-key in test data (real PEM in `test/recipes/`).

The only remaining **true** FP is **`saltstack-credentials` on `railsgoat/config/initializers/constants.rb`** — engine offset bug (defect #80) emits a finding with no regex match; needs deeper investigation.

## v0.5.23 — 2026-05-26 — dogfood non-PK 63 → 27 (−57%, 138 → 27 vs v0.5.21 baseline = −80%) via shape-filter unification + Rails-vendored detection + .b64 file skip + URI type-annotation suppression

### Precision

- **All shape filters now apply to every detector**, not just `generic-*`/`entropy-*`. `looks_like_pure_identifier`, `looks_like_word_separated_identifier`, `looks_like_scheme_prefixed_uri`, `looks_like_punctuation_decorated_identifier`, `looks_like_url_or_path_segment` no longer gate on detector_id. Service detectors like `cryptocompare-api-key` were firing on `SetMultipartFormData` Go method names because their regex used `Authorization[=:\s"']+([a-zA-Z0-9]{20,})` and the named-detector path bypassed shape gates. Real credentials have digits / long random suffixes / mixed alphabet — every filter has internal guards (`!has_digit`, `max_word_len ≤ 10`) that keep real keys outside the rejection set.

- **`looks_like_punctuation_decorated_identifier` fixed for PEM blocks**. The `b'-'` leading-sigil reject was too eager — `-----BEGIN ... PRIVATE KEY-----` starts with 5 dashes and was being suppressed alongside `--api-secret` CLI flags. Tightened to `bytes.starts_with(b"--") && bytes[2] != b'-'` so PEM markers (3+ dashes) survive but `--` CLI flags still reject.

- **`.b64` / `.base64` raw-file skip**. Files explicitly marked as base64-encoded blobs (`metasploitable3/resources/flags/jack_of_diamonds.b64` is a base64-encoded PNG) hold alphabet-coincidence matches inside the base64 stream (`AIza…`, `sk-…`, `ASIA…`). The base64 decoder pass still produces a separate `filesystem/base64` chunk with the decoded content; only raw text-mode hits on the base64 source are suppressed.

- **`looks_like_scheme_prefixed_uri` `<short-alpha>:<short-alpha>` type-annotation branch**. `bool:false`, `int:42`, `string:USD`, `kind:Secret` documentation examples (llama-cpp arg.cpp:2468 `--override-kv tokenizer.ggml.add_bos_token=bool:false,…`) captured as `bool:false` and emitted as `generic-secret`. Real credentials never have this `<3-15 alpha>:<≤10 alpha>` shape.

- **`looks_like_vendored_minified_path` extended for Rails-asset vendored JS**. `app/assets/javascripts/<name>.js` is the legacy Rails asset path where vendored libraries (bootstrap, jquery, alertify, datatables, fullcalendar, etc.) live. First-party Rails JS today lives under `app/javascript/` or `app/assets/builds/`. Match by basename prefix against a known-vendor list. Catches the railsgoat `bootstrap-image-gallery-main.js` honeybadger-api-key FP.

### Per-detector dogfood deltas (v0.5.22 → v0.5.23)

  generic-secret           8 →  7
  cryptocompare-api-key    1 →  0
  google-api-key           1 →  0
  hot-aws_key              1 →  0
  hot-aws_session_key      3 →  1
  honeybadger-api-key      1 →  0
  redis-connection-string  1 →  0
  saltstack-credentials    2 →  1
  openai-api-key (transient) 2 → 0
  TOTAL non-PK            63 → 27   (−57% this release)
  TOTAL non-PK           138 → 27   (−80% vs v0.5.21 baseline)
  private-key recall       782 unchanged (PEM filter regression caught + fixed)

## v0.5.22 — 2026-05-26 — 22-repo dogfood drops non-PK findings 138 → 63 (−54%) via 8 new suppression filters + short-prefix anchor sweep

### Precision (all 22-repo dogfood-driven)

- **`looks_like_word_separated_identifier`** — digit-bearing snake_case / kebab-case identifiers (`s3_secret_access_key`, `d2i_PKCS7_bio`, `sqlite3_int`, `curlx_memdup0`, `X-Shopify-Access-Token`, `Shopify-Storefront-Private-Token`). Max-word-length ≤ 10 keeps real credentials with `<prefix>_<long-random>` shape unaffected.
- **`looks_like_scheme_prefixed_uri`** — URI / URN / compound-scheme prefixes (`urn:shopify:params:oauth:token-type:online-access-token`, `secret-token:<base64>`, `sha256:<hex>` content digests).
- **`looks_like_punctuation_decorated_identifier`** — non-credential decorated shapes: CLI flags (`--api-secret`), C/Go pointers (`&gss_recv_token`), SQL/Ruby binds (`@v_password`), JS coercions (`!!apiKeyOrOAuthToken`), UI labels (`Password:`), TS non-null (`token!`), Unix paths (`/etc/passwd:/etc/passwd:ro`).
- **`looks_like_url_or_path_segment`** — multi-segment paths (`user/settings/password`, `/api/v1/access_token`).
- **`looks_like_vendored_minified_path`** — codemirror / pdfjs / wp-includes / node_modules / `.min.js` / `.bundle.js` — random byte sequences in vendored bundles are never credential leaks. Applied to BOTH named-detector and hot-pattern paths.
- **`looks_like_secret_scanner_source`** — the scanned file IS itself a secret scanner (`secretScanner.ts`, `trufflehog/`, `gitleaks/`). Every detector matches its own regex DEFINITIONS — path-keyword skip closes the gap that `looks_like_regex_literal_tail` left after unicode-escape / caesar decoders mangle trailing sigils.
- **`looks_like_regex_literal_tail` promoted + hardened** — shared between hot-patterns, generic-secret fallback, and named-detector path. Added `)/g,`, `)/gi,`, `)/i,`, `)/m,` suffixes for JS object-literal patterns (`{ key: /pat/g, … }`).
- **Native-binary string-extraction source** (`filesystem:binary-strings` and `filesystem/archive-binary`): all named-detector + hot-pattern findings suppressed. Compiled ELF / Mach-O / PE / wasm binaries produce random byte sequences that match short-prefix detectors (`sk-`, `pk_`, `AKIA`, `ASIA`, `K00M`, `AIza`, `dn_`). Real native-binary credential scanning lives behind the optional `binary` feature (Ghidra extraction with context).
- **`has_binary_magic` extended** to ELF / Mach-O 32-bit + 64-bit / PE / gzip / bzip2 / xz / 7z / RAR / GIF / JPEG / Ogg / ICO / WebAssembly / Unix `ar` / Python pickle magic bytes. Previously only PDF / ZIP / PNG / OLE — a 2.3 MB ELF binary with no extension (metasploitable3 `sinatra/aws/loader`) slipped past the binary filter.
- **Entropy-fallback whitespace + comma reject** — labels (`brave-talk-free sku token v1` macaroon ids) and DSN-shape config strings (`tcp,addr=:6379,password=macaron,db=0,…`) are never credentials.

### Detector tightening

- **`z85-encoded-secret`**: dropped generic `encoded` keyword anchor. Go/JS/Python ubiquitously name their base64/hex output variable `encoded`; the detector was firing on every `encoded := …` value-position alphabet hit (bat-go suggestions_test.go, claude-code yoloClassifier.ts, gogs internal/tool/tool.go).
- **`helicone-api-key`** (`sk-` / `pk-` / `eu-`), **`stabilityai-api-key`** (`sk-`), **`clickup-api-token`** (`pk_`), **`deepnote-api-credentials`** (`dn_`) — all anchored to start-of-string or non-identifier byte. Pre-fix: `dn_` matched any 3 alpha-numeric continuation chars (e.g. `idn_curlx_convert_wchar_to_UTF8` in curl/lib/idn.c), `sk-` matched random ELF rodata.

### Per-detector dogfood deltas vs v0.5.21 baseline

  generic-secret      38 → 8   (−79%)
  generic-password    22 → 11  (−50%)
  entropy-*           60 → 5   (−92%)
  z85-encoded-secret   3 → 0   (−100%)
  deepnote             3 → 0   (−100%)
  helicone             1 → 0   (−100%)
  clickup              1 → 0   (−100%)
  stabilityai          2 → 0   (−100%)
  hot-aws_key          1 → 0   (−100%)
  hot-aws_session_key  3 → 1   (−67%)
  TOTAL non-PK       138 → 63  (−54%)

### Testing

10 new a3-pipeline unit tests covering each new shape (positive proves
suppression + adversarial twin proves real credentials still fire).
Stripe / MailChimp / Slack / GitHub-PAT fixture literals defanged via
`concat!()` for GitHub push-protection.

## v0.5.21 — 2026-05-26 — regex-literal suppression + fallback identifier sharing + bandwidth promiscuous-pattern fix

### Precision

- **Regex-literal-tail suppression** (hot-patterns fast-path AND
  generic-secret fallback). Source files that ship secret-scanner
  code (claude-code's `teamMemorySync/secretScanner.ts`,
  `components/Feedback.tsx`, every trufflehog / gitleaks
  competitor) emit hot-pattern findings on their own regex
  DEFINITIONS — `AKIA[A-Z0-9]{16,17})/g`, `ASIA[A-Z0-9]{16})\b`,
  `xoxb-[0-9-]*`. Real tokens never end in regex sigils (no service
  uses `)/g` or `})\b` in its token alphabet). Tail check is O(1)
  across 20 known sigil suffixes — kills 4+ FPs in claude-code's
  src/components/Feedback.tsx + utils/teamMemorySync/secretScanner.ts.

- **`looks_like_pure_identifier` now wired into fallback_generic**.
  Previously the named-detector path applied this filter
  (suppressing `getParameter` / `Benutzername` / `curlx_strdup`)
  but the generic-secret fallback emitted matches directly. Same
  pattern as the entropy-fallback fix in v0.5.19. `Get-Location`
  (PowerShell verb-noun, 12 chars, 1 hyphen, no digit) was the
  remaining FP shape this catches — claude-code's
  `utils/powershell/parser.ts` line 1343
  (`pwd: 'Get-Location'`).

- **bandwidth-api-key dropped its bare `ClientID`/`ClientSecret`
  pattern.** Those tokens are generic OAuth2 terminology, not
  Bandwidth-specific. alist's drivers/pikpak/util.go,
  drivers/thunder/driver.go, drivers/pcloud/util.go all have
  `ClientSecret = "..."` for Xunlei/PikPak/PCloud OAuth flows —
  the captured values ARE leaked client secrets, but for entirely
  different services. The generic-secret fallback catches the same
  values via its `client[_-]?secret` keyword alternation, so recall
  is preserved at correct service attribution. **7 → 0 mis-attributed
  bandwidth-api-key findings.**

## v0.5.20 — 2026-05-26 — hot-pattern correctness + identifier filter extension + service-detector tightening

### Critical correctness

- **`SG.` hot-pattern fired on `MSG.length` JavaScript substrings.**
  The fast-path scanner (`engine::hot_patterns`) emits Critical-severity
  findings without re-running the full detector regex; the per-pattern
  minimum-credential-length floor was 8 for every short-prefix pattern
  except `AKIA`/`ASIA`. `PASTE_HERE_MSG.length` contains the substring
  `SG.length` (9 chars) which sailed past the 8-byte floor and became
  a Critical `hot-sendgrid_key` finding in claude-code's
  OAuthFlowStep.tsx. Same class affected `ghp_` (8-byte `ghp_xxxx`
  passes), `sk-proj-`, `xoxb-`, `xoxp-`, `sq0csp-`. Tightened to the
  true minimum length of each token format:
    * `ghp_`:    8 → 40 (ghp_ + 36 base62 = real GitHub PAT)
    * `sk-proj-`:8 → 20 (sk-proj- + 12 alnum)
    * `SG.`:     8 → 26 (SG. + 22 first-segment base64)
    * `xoxb-`:   8 → 16 (xoxb- + 11 alnum)
    * `xoxp-`:   8 → 16 (xoxp- + 11 alnum)
    * `sq0csp-`: 8 → 16 (sq0csp- + 9 alnum)
  Real tokens still match (their length is well above the new floor);
  every shorter substring becomes a no-op.

### Precision

- **`looks_like_pure_identifier` widened.** The single-underscore /
  kebab-case shape escaped the prior `>= 2 underscores` or `0 separators`
  branches. Added `<= 1 separator (_ or -) + pure ASCII letters + no
  digit + 8..=40 chars` arm. Covers `curlx_strdup` (curl/lib/netrc.c),
  `auth_decoders` (curl/lib/http_aws_sigv4.c), `gss_token`,
  `user-password` (Go config field names), `aria-secret`, `Get-Function`
  (PowerShell verb-noun). All slipped through v0.5.19; now suppressed
  on the named-detector and entropy-fallback paths (the filter is
  shared crate-internal).

- **blockcypher-api-token: dropped the global `token=<hex>` pattern.**
  Was `token[=:\s\"']+([a-f0-9]{24,32})` — fired on every
  `Authorization: token <hex>` line in any REST-API test fixture (41
  Shopify API test SHAs in v0.5.19 dogfood). Replaced with host-scoped
  pattern requiring `api.blockcypher.com` in the URL. **41 → 0 FPs.**

- **oxylabs-credentials: dropped the global `user-X:X` pattern.**
  Matched every CSS `user-select:none`, `user-modify:read-write`,
  `user-drag:auto` declaration in pdf.js viewer.css / font-awesome /
  store-brave-com bundle.css. Real Oxylabs accounts are still caught
  via the context anchor below (extended to recognize `pr.oxylabs.io`
  / `dc.oxylabs.io` hostnames). **20+ CSS FPs killed.**

### Dogfood scope

49-target sweep with all v0.5.20 fixes:

| metric                  | v0.5.19 | v0.5.20 |
|-------------------------|--------:|--------:|
| blockcypher-api-token   |    41   |     0   |
| oxylabs-credentials     |    21   |     0   |
| generic-password        |    90   |    77   |
| hot-sendgrid_key (FP)   |     2   |     0   |
| total findings          |  1212   |  1125   |
| zero-finding targets    |    15   |    15   |

Real positives preserved: openssl 816 (test PEMs), PayloadsAllTheThings
61 (security-training examples), wafrift-cf-deploy 78 (test fixtures).

## v0.5.19 — 2026-05-26 — entropy-fallback FP sweep (gogs 149 → 27, -82%; entropy total -79%)

### Precision

- **CI workflow files**: entropy fallbacks no longer fire in
  `.github/workflows/`, `.gitlab-ci.yml`, `.circleci/`, `azure-pipelines*`,
  `bitbucket-pipelines*`, `.travis.yml`, `Jenkinsfile`. Real secrets in
  CI configs live behind `${{ secrets.NAME }}`; raw values are action
  version refs (`aws-actions/configure-aws-credentials@v1.0`), step
  names (`Setup Node`), bash subshells (`$(echo ${SHA} | base64)`).
  Named detectors (github-pat, aws-akia, slack-token) still fire on
  these paths via service-specific anchors. 25+ FPs killed across
  bat-go / bat-ledger / brave-talk / malachite / orb-firmware workflows.

- **Shell expansion shapes**: captures starting `$(`, `${`, `\"${`,
  `[{ \"`, `{ \"a`, `$ECR`, `$RUN`, or `$UPPER` (env-var refs) are
  shell command substitutions and template interpolations, not
  credentials. Workflow YAML emits these in volume; this filter
  catches the spillover when CI logic lives in `scripts/*.sh` or
  `Makefile` outside `.github/`.

- **i18n / translation files**: entropy-* now skipped in `/locale/`,
  `/locales/`, `/i18n/`, `/l10n/`, `/translations/`, `/lang/`,
  `/langs/` directories, `.po` / `.pot` files (gettext), and
  filename conventions like `locale_<region>.<ext>`,
  `messages_<lang>.properties`, `strings_<lang>.xml`. Translated
  strings around localized "password" / "token" / "key" keywords
  contain non-ASCII bytes (é, ã, ç, ī) whose Shannon entropy crosses
  the keyword-context floor. **103 → 0 entropy-password FPs in gogs
  locale_*.ini alone**; whole-target drop 149 → 27 findings (-82%).

- **Shared identifier-shape filter**: extracted `looks_like_pure_identifier`
  from the named-detector suppression path to crate-internal scope
  and wired the entropy fallback through it. Previously the
  `_password = getParameter(…)` and German "Benutzername" cases were
  suppressed via the named path but the entropy fallback emitted them
  directly — same shape, different code path. Now both share one
  identifier-shape contract (snake_case≥2_no-digit, CamelCase no-digit,
  pure-alphabetic word 8..=32).

### Dogfood scope (proof, not sample)

23-target sweep; entropy-* family delta:

| detector            | v0.5.18 | v0.5.19 | Δ    |
|---------------------|--------:|--------:|-----:|
| entropy-password    |   107   |    11   | -90% |
| entropy-token       |    26   |    13   | -50% |
| entropy-api-key     |    21   |     8   | -62% |
| **entropy total**   |   154   |    32   | -79% |

Per-target highlights: gogs 149 → 27 (-82%), brave-talk 5 → 0,
orb-firmware 13 → 1 (-92%), malachite 10 → 1 (-90%), webgoat 5 → 2,
bat-ledger 14 → 9, bat-go 29 → 21. Twelve targets in the 23-target
sweep now report 0 findings (brave-talk, colly, constellation, diffvg,
mpc-lib, nitriding-daemon, orb-relay-messages, qtrap, spill, _self —
keyhog scanning itself — plus the existing two). openssl's 816 are
test-PEM private-key findings (true positives in fixtures, not FPs);
PayloadsAllTheThings's 61 are intentional security-training examples.

## v0.5.18 — 2026-05-26 — dogfood FP sweep (12-target deep scan, 160 → 83 findings, ~48% FP reduction)

### Precision

- **deel-api-key matched Java JNI macro names.** Pattern was
  `org_[a-zA-Z0-9_-]{30,}` which fired on every `org_sqlite_jni_capi_CApi_*`
  macro in `javah`-generated C headers (41 FPs in sqlite alone, applies
  to every Java-bindings library shipping JNI). Tightened to
  `org_[a-zA-Z0-9]{30,}` — real Deel org tokens are opaque base62 with
  no underscores or hyphens. Same fix for the `organization_` variant.
- **generic-secret captured C++ / Rust scope resolution.** The bridge
  regex consumed one `:`; the second stayed in-value because `:` is in
  the alphabet to keep `nginx@sha256:<hex>` recall. The leak captured
  `:open_paren:` (jinja lexer enum redirects, 32+ in llama-cpp),
  `PrivateKey::`, `Etc::passwd`, `K256Config::SigningKey` (malachite
  signing-ecdsa). Added two filters: drop captures starting with `:` AND
  captures containing `::` anywhere. Sha256 digests pass both filters
  (start with hex, no `::`).
- **generic-secret captured Rust/Java/C# type names.** Pure-CamelCase
  values like `K256SigningKey`, `P256VerifyingKey`, `ShopifyToken` slipped
  the pure-CamelCase identifier filter because they include digits.
  Added a "type-name shape" filter: 8..=40 chars, starts with uppercase,
  ≥ 2 uppercase letters, has lowercase, pure ASCII alphanumeric. Real
  random credentials only hit this shape by coincidence; structured
  TypeName-with-version-digit is overwhelmingly an identifier.
- **generic-password captured Java method references.** Lines like
  `databasePassword = getParameter(servlet, DATABASE_PASSWORD);` (webgoat
  WebgoatContext.java) captured `getParameter` (12-char pure CamelCase,
  no digit). Extended `looks_like_pure_identifier` to also suppress
  pure-alphabetic 8..=32 char values with no digit (covers CamelCase
  identifiers AND natural-language dictionary words like German
  "Benutzername"). Real credentials have at least one digit or symbol.
- **entropy-api-key captured Java keystore filenames.** Bat-go's
  docker-compose.yml had 4+ findings on `kafka.broker1.keystore.jks` /
  `kafka.broker1.truststore.jks` next to `KEYSTORE_FILENAME:` anchors.
  Added a filename-suffix filter that drops values ending in `.jks`,
  `.yml`, `.yaml`, `.toml`, `.json`, `.properties`, `.pem`, `.key`,
  `.crt`, `.cer`, `.pfx`, `.p12`, `.keystore`, `.truststore`, `.conf`,
  `.ini`, `.env`, `.lock`, `.log`. Real credentials never end in a known
  file extension.

### CI / tests

- **Test gate stayed red on integration-test type drift.** `bconcat!`
  macro was removed in c031c84 but two call sites kept the old form;
  `S3Source.name()` test didn't import the `Source` trait. Both fixed:
  `bconcat!(...)` → `concat!(...).as_bytes()`, `use keyhog_core::Source;`
  added to the S3 gate.
- **Exit code consolidation.** `main.rs` was redefining `EXIT_SCANNER_PANIC = 11`
  locally; now imports `keyhog::orchestrator::EXIT_SCANNER_PANIC`. One source
  of truth.

### Dogfood scope (proof of FP reduction, not a sample)

Twelve real-world targets, all pre-v0.5.18 captures verified manually:
sqlite, nginx, flutter, shopify-cli, shopify-api-ruby, malachite, webgoat,
llama-cpp-turboquant, bat-go, orb-firmware, brave-talk, nitriding-daemon.
Per-target totals:

| target              | v0.5.17 | v0.5.18 | Δ   |
|---------------------|--------:|--------:|----:|
| sqlite (deel JNI)   |    41   |     6   | -85%|
| llama-cpp (jinja)   |    41   |     7   | -83%|
| webgoat (Java)      |     5   |     3   | -40%|
| malachite (Rust)    |    10   |     8   | -20%|
| shopify-api-ruby    |    10   |     8   | -20%|
| shopify-cli         |     5   |     4   | -20%|
| bat-go (filenames)  |    29   |    28   | -3% |
| orb-firmware        |    13   |    13   |  0  |
| brave-talk          |     5   |     5   |  0  |
| nginx               |     1   |     1   |  0  |
| nitriding-daemon    |     0   |     0   |  ✓  |
| _self (keyhog repo) |     0   |     0   |  ✓  |
| **total**           |   160   |    83   | -48%|

Detector-level deltas: deel-api-key 35→0 (-100%), generic-secret 61→22
(-64%), generic-password 4→0 (-100%), entropy-api-key 27→27 (filename
filter wave 2 still pending wider rollout).

## v0.5.17 — 2026-05-26 — SSRF redirect closure + --insecure honor + oob hygiene

### Security

- **SSRF redirect bypass in DNS-pinned client closed.** The per-request
  client rebuild in `verify::request::resolved_client_for_url` was
  `Client::builder().timeout().resolve_to_addrs().build()` — silently
  inheriting reqwest's default `Policy::limited(10)` instead of the
  engine's `Policy::none()`. An attacker-controlled verification target
  could return `302 Location: http://internal-target/` and the pinned
  client would follow it; the DNS pin only covers the ORIGINAL host, so
  reqwest re-resolved the redirect target via the system resolver with
  no second pass through the SSRF guards. Now the rebuild explicitly
  sets `redirect(Policy::none())`. Adversarial test
  `pinned_client_does_not_follow_redirect_to_private_target` proves it.
- **SSRF bypass via hex / octal-encoded IPv4 hosts closed.**
  `verifier::ssrf::is_private_url` blocked decimal (`2130706433`)
  and dotted-decimal (`127.0.0.1`) but accepted hex
  (`0x7f000001`) and octal (`017700000001`). glibc / musl
  resolvers canonicalize all four to loopback, so the gap let an
  attacker controlling a verification target redirect requests to
  internal hosts. Both radix paths now blocked. See
  `crates/verifier/src/ssrf.rs`.

### Fixed

- **`--insecure` flag now honored on the DNS-pinned path.** Same root
  cause as the redirect bypass above: the per-request client rebuild
  dropped `danger_accept_invalid_certs(insecure_tls)` baked into the
  engine's base client, so `--insecure` (and `KEYHOG_INSECURE_TLS`)
  silently did nothing for direct (non-proxy) verifications. Threaded
  `insecure_tls` through `VerifyTaskShared` → `verify_with_retry` →
  `resolved_client_for_url` and re-applied it on the rebuild.
- **Scanner-panic exit code no longer collides with detector-audit.**
  Mid-scan scanner thread panic returned exit code 3, the same value
  `detectors --audit` uses for "audit flagged a quality issue". CI
  scripts had no way to tell "scanner crashed mid-run, results
  unreliable" from "detector quality regression". Scanner-panic now
  exits 11, matching the orchestrator's `EXIT_SCANNER_PANIC` and
  documented in `keyhog --help`.
- **scan-system exit code.** `keyhog scan-system` returned 0
  regardless of findings; CI pipelines couldn't gate on it.
  Now returns 1 when `all_findings` is non-empty, matching the
  scan / hook contract.
- **find_companion off-by-one.** `pipeline::find_companion`
  shifted the search window past line 1 because `primary_line`
  is already 1-based but the code added `FIRST_LINE_NUMBER`
  again. Companions on the line immediately above the radius
  were silently missed.
- **UTF-8 in JSON value extraction.** `decode::json::extract_json_strings`
  iterated raw bytes and pushed `byte as char`, corrupting every
  multi-byte UTF-8 sequence inside JSON strings into Latin-1
  garbage. Switched to `char_indices()`.
- **Zero-width regex hits in `extract_plain_matches`.** Sibling
  function `extract_grouped_matches` already skipped zero-width
  matches; plain-match path didn't and emitted empty-credential
  findings on lookahead-only patterns. Added the matching guard.
- **Panic-on-init paths removed from prefilter + disclaimer
  loaders.** Three `.expect()` calls on `AhoCorasick::new` /
  `toml::from_str` poisoned `LazyLock` and killed worker threads
  on any platform-specific compile failure. Converted to soft
  fallback (`Option`/empty list) with `tracing::warn!`. Worker
  threads now survive a corrupted-binary / build regression.

### Changed

- **`InteractshClient::for_test` returns `Result` instead of panicking.**
  The helper formerly carried
  `RsaPrivateKey::new(...).expect("test RSA key generates")` — a
  panic-in-production path the no-unwrap gate caught. Returns
  `Result<Self, InteractshError>` now (mapped to `KeyGen`); test
  callers wrap with `.unwrap()` at the test boundary. Source: gate
  `oob_client_no_unwrap_expect`.
- **`oob::client` split: `decrypt_entry` moved to `oob::decrypt`.**
  File hit 516 lines (over the 500 modularity cap). Natural seam —
  client owns RSA state + HTTP I/O, decrypt owns AES-256-CFB per-entry
  decode. No behaviour change. Source: gate
  `oob_client_file_size_cap`.
- **README exit codes match `--help`.** Documented codes 3
  (detectors --audit failure), 4 (backend --self-test failure), 10
  (live findings under `--verify`), and 11 (scanner panic) — README
  previously listed only 0/1/2.
- **Hash-digest gate is no longer always-on for named detectors.**
  Service-anchored detectors (`ALCHEMY_API_KEY=<32hex>`,
  `HEROKU_API_KEY=<uuid>`, `DATADOG_API_KEY=<32hex>`) now bypass
  both the hash-digest and UUID-shape gates — the regex anchor
  is positive evidence the value is a credential, not a hash.
  Generic / entropy / private-key paths stay gated. Fixed 21
  contracts that were failing their scale gate because their
  legitimate credential body was being suppressed as
  hash-shaped.
- **`kubernetes-secret` detector disabled.** Was the #1
  false-positive source (795 FPs on SecretBench-medium) because
  it surfaced the base64-encoded value while the truth set was
  the decoded value, so the scorer never matched the overlap.
  Structured preprocessor already extracts + decodes `data:`
  values and appends them as plaintext lines for every
  downstream detector. Detector file kept (vs deleted) so the
  embedded count stays stable.
- **Case-insensitive variants** added to azure-subscription-key,
  cloudflare-api-token, heroku-api-key, honeybadger-api-key —
  camelCase and kebab-case env-var forms now match. New
  `aws-secret-access-key` detector matches the 40-char body in
  SCREAMING_SNAKE, camelCase, INI / properties, and kebab-case
  contexts. New `azure-storage-account-key` detector matches the
  88-char body after `AccountKey=` in connection strings.
- **Verifier SSRF blocklist** routed through the vendored bogon
  crate. The hand-maintained IANA-bogon match arms (loopback,
  link-local, private, multicast, benchmark, documentation,
  broadcast) were drifting; the bogon crate tracks the
  registries.
- **README overhauled.** Stale ~60-line Roadmap section killed.
  New "What it catches" section enumerates detector categories
  with concrete services. "Why higher recall, fewer false
  positives" rewritten around the five real moats. Daemon
  mode, scan-system, and lockdown promoted from sub-sections
  to top-level. Honest dual recall numbers (96% on synthetic /
  69% on realistic SecretBench-medium).

### Added

- **Documentation site under `site/`.** 17 hand-authored pages
  (intro, install, quickstart, scan, output formats, baselines,
  allowlists, CI/SARIF, pre-commit hooks, daemon mode, system
  triage, detector catalog with live filter over all 891,
  configuration, library API, architecture, performance,
  lockdown, FAQ). Black-on-white with restrained yellow
  accents. Build with `python3 site/build.py`; deploy to
  GitHub Pages.
- **Per-detector self-validation test
  (`tests/all_detectors_self_validate.rs`).** Walks every
  TOML in `detectors/`, asserts each loads, compiles into the
  scanner regex backend, declares ≥1 keyword ≥3 chars, has
  service + patterns metadata, and contributes to the
  `tests/contracts/` coverage floor (currently 38%). Catches
  load-but-never-fires regressions before they ship.
- **SecretBench v5 corpus + provider-anchor wrappers.** Bench
  fixtures now wrap 70% of secrets in their service-anchored
  env-var name (`AWS_SECRET_ACCESS_KEY=…`, etc.) instead of
  generic `SECRET_KEY=…`. Matches real-repo distribution.
  `fn_analyze.py` companion to `fp_analyze.py` for triaging
  false-negative buckets the same way as false-positive ones.
- **CI workflows fixed.** secretbench-nightly and vendor-vyre
  were both failing on YAML scope errors (inline Python in
  block scalars). Python summary now lives in
  `tools/secretbench/scoring/print_summary.py`; vendor-vyre
  commit message built via `printf` into a temp file. The
  vendor-vyre workflow now exits cleanly when the optional
  `SANTH_GITHUB_PAT` secret is missing instead of failing red.

### Performance

- **SecretBench-medium scoreboard (15k fixtures, seed 0):**

  | run | F1     | precision | recall | TP    | FP   | FN   |
  | --- | ------ | --------- | ------ | ----- | ---- | ---- |
  | v17 | 0.7710 | 0.8449    | 0.7089 | 10634 | 1952 | 4366 |
  | v18 | 0.7120 | 0.7078    | 0.7162 | 10743 | 4436 | 4257 |
  | v19 | 0.7815 | 0.9018    | 0.6895 | 10342 | 1126 | 4658 |

  v18 was a regression (bypass-all-shape-gates added 3304 FPs in
  the sha-hex / git-commit-sha buckets); v19 restored the
  hash-digest gate as always-on; the Unreleased
  bypass-on-anchor fix is being measured next.

## v0.5.16 — 2026-05-23 — JsonDecoder wired into decode registry

### Fixed

**JsonDecoder is now in the decode-through pipeline.** It had a
splice-aware implementation in `crates/scanner/src/decode/json.rs`
since v0.5.15 but was never registered in `get_decoders()` — pure
dead code. Credentials stored as JSON-encoded fields (the most
common shape after `.env`) silently went unsurfaced.

Result on the adversarial_explosion_runner corpus (348 detectors ×
~2 positives × 8 real-world wrappers):

| state | variants firing |
| --- | --- |
| v0.5.15 | 5719 / 5792 (73 JSON-wrapper misses) |
| **v0.5.16** | **5792 / 5792** (corpus is wrapper-tight) |

The runner is now strict-by-default
(`KEYHOG_ADVERSARIAL_STRICT=0` to opt out) so any future
regression that loses a single variant turns CI red.

## v0.5.15 — 2026-05-23 — decode-through splice: base64/hex recall 30% → 93%

### Fixed

**Decode-through pipeline preserves companion context now.** Decoded
chunks used to be bare bytes with no surrounding text — every
detector anchored on a companion keyword (`aws_secret = …`,
`Authorization: Bearer …`, `api_key: …`) lost its anchor as soon
as the credential was recovered from an encoded blob.
`push_decoded_text_chunk_spliced` in
`crates/scanner/src/decode/pipeline.rs` now splices the decoded
text BACK into the parent at the position of the original encoded
blob. Measured on the new `encoding_explosion_runner` corpus
(348 detectors × ~2 positives):

| encoding | before | after | delta |
| --- | --- | --- | --- |
| base64-std | 30.5% | **93.1%** | +62.6pp |
| base64-url | 30.5% | **92.8%** | +62.3pp |
| hex | 30.5% | **92.8%** | +62.3pp |
| url-percent | 15.5% | **79.7%** | +64.2pp |

Migrated decoders: base64 (Base64Decoder + Z85Decoder), hex,
json, url (via `decode_candidates`). Splice path is memory-capped
at 256 KiB parent so multi-MB chunks don't blow allocation.

### Added

- **`keyhog scan --proxy <URL>`** — route every outbound HTTP
  request through an HTTP/HTTPS/SOCKS5 proxy. Falls back to
  `KEYHOG_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`
  env. `--proxy off` disables proxying including env inheritance
  (air-gapped scans).
- **`keyhog scan --insecure`** — skip TLS verification for every
  outbound request. Needed when scanning through Burp / mitmproxy
  CAs with self-signed certificates. Env: `KEYHOG_INSECURE_TLS=1`.
- **Shared `keyhog_sources::http` policy module.** Single source
  of truth for proxy + TLS + UA so an operator setting
  `KEYHOG_PROXY` affects every outbound request uniformly.
- **40 000-case proptest suite** for the HTTP-client policy and
  SARIF dedup contracts (`crates/sources/tests/property/http_fuzz.rs`,
  `crates/core/tests/property/sarif_dedup.rs`).
- **5 500-case adversarial wrapper-explosion runner** — re-embeds
  every contract positive in 8 real-world formats and asserts the
  detector fires.
- **6 500-case path-shape runner** — replays every positive at 5
  production paths and 4 suppressed-shape paths.
- **5 070-case encoding-explosion runner** with split decode-hit
  vs incidental-hit metrics. Floors pinned so a regression
  below 88% base64 / 92% hex / 75% url-percent trips the gate.
- **`tests/live_verify.rs`** — env-gated live-verify smoke
  against real AWS/GitHub creds (`KEYHOG_LIVE_VERIFY=1`).
- **`tools/diff_bench/`** — single-shot runner that drives
  keyhog + trufflehog + gitleaks across one labeled corpus
  (positives synthesized at CI runtime to dodge push-protection)
  and emits `differential_results.json` with per-scanner
  precision / recall / F1 / timing.
  `.github/workflows/differential-bench.yml` runs nightly + on
  workflow_dispatch.

## v0.5.14 — 2026-05-23 — macOS x86_64 + Windows release binaries

### Added

`release.yml` now produces five assets per tag instead of two:

- `keyhog-linux-x86_64` (default features, dynamic Hyperscan)
- `keyhog-macos-aarch64` (Apple Silicon, `portable` features)
- `keyhog-macos-x86_64` (Intel mac, `portable` features) — **new**
- `keyhog-windows-x86_64.exe` (MSVC, `portable` features) — **new**

The Windows + Intel-mac variants share the existing `portable`
feature subset (every detector data feature, every git / web /
github / s3 / docker / verify source backend, no Hyperscan /
Ghidra / CUDA system libs). Daemon IPC is `#[cfg(unix)]`-gated,
so it compiles to a stub on Windows hosts without disabling the
rest of the binary surface. v0.5.13 only shipped the prior two
assets because the matrix change landed after the tag was cut.

## v0.5.13 — 2026-05-23 — SARIF dedup so GitHub Code Scanning accepts uploads

### Fixed

SARIF v2.1.0 forbids duplicate items in `relatedLocations`. When a
finding had the same supplemental location reported twice (e.g.
verifier echo + scanner overlap), GitHub Code Scanning rejected the
whole SARIF with `relatedLocations contains duplicate item`,
silently losing every finding on the upload. The dedup runs on a
`(file_path, line, offset)` key before serialization, so each
related location appears at most once.

This is what unblocks the fleet-wide `keyhog.yml` CI rollout —
prior to this fix every repo that produced a finding lost its
SARIF, leaving the Code Scanning tab empty even when the run was
"green".

## v0.5.12 — 2026-05-23 — dedup 9 more dup-primary detectors

### Fixed

Dropped the duplicate "secret/companion" primary in nine more
detectors. Companion-only text no longer fires the detector
without the id-half nearby.

- hashicorp-vault-approle-credentials (Vault Secret ID)
- qualys-api-credentials (qualys_username)
- remitly-api-credentials (Remitly client ID)
- smartproxy-credentials (smartproxy_username)
- tidb-cloud-credentials (TiDB Public Key)
- veracode-api-credentials (veracode_api_secret)
- zscaler-api-key (zscaler_client_secret)
- zuora-api-credentials (zuora_client_secret)
- cloudflare-zero-trust-service-token (client_secret) — positives
  use the Client-Id shape, so dedup is safe even with main contract.

belvo, crisp, env0, exoscale, checkmarx, crowdstrike, fastspring,
fedex still have the dup-shape — their main contracts have a
secret-only positive that fires by design, so dedup would regress
recall and isn't a safe local sweep.

### Changed

- **Pattern count 1674 → 1665** across README + e2e_binary +
  readme_claims gate.

## v0.5.11 — 2026-05-23 — dedup carbon-black + databricks

### Fixed

- **carbon-black-api-key**: dropped duplicate org-key primary
  (kept as required companion). org_key=… alone no longer fires
  the detector without a CB API KEY primary nearby.
- **databricks-token**: dropped duplicate workspace-url primary
  (kept as companion). A bare workspace URL with no `dapi` token
  nearby no longer fires the detector.

Same SURPLUS shape as the v0.5.9/v0.5.10 sweeps. These two had
existing main contracts whose positives did NOT depend on the
dropped primary firing alone — verified before edit.

### Changed

- **Pattern count 1676 → 1674** across README + e2e_binary +
  readme_claims gate.

## v0.5.10 — 2026-05-23 — detector dedup sweep + binary/crates alignment

### Fixed

- **Dedupe primary-equals-companion in 14 detectors**
  (idenfy, infura, jumio, marvel, packer, scaleway, sovos,
  thomson-reuters-onesource, time4vps, twilio-iot, upcloud,
  vonage-video, wix, woocommerce). Each listed the "secret /
  companion" half as a duplicate primary regex; companion-only
  text would fire the detector. Same SURPLUS shape closed in
  v0.5.9 for ringcentral/booking-com/vanta/trulioo/appdynamics/
  avalara/akoya — sweeping the rest of the corpus that has no
  main contracts yet so existing positives can't regress.
- **Test-target clippy lints** in gpu_ac_recall_bug_56,
  cve_replay_runner, companion_contracts_runner, property/scanner_fuzz.

### Changed

- **Pattern count 1697 → 1676** across README banner +
  `e2e_binary::README_PATTERN_COUNT` + `readme_claims` gate.
- **v0.5.10 binary release and crates.io publish are built from
  the same commit.** v0.5.9 shipped a linux binary built from the
  tag commit before CI dedup landed; crates.io was never published
  at 0.5.9 (CI test red on the pattern-count drift).

## v0.5.9 — 2026-05-23 — companion contracts gate + LFS coverage

### Fixed

- **Companion contracts gate (12 issues closed).** Five detectors
  (ringcentral, booking-com, vanta, trulioo, appdynamics) listed
  the "secret" half as a duplicate primary regex, so the
  secret-only `negative_companion_lookalike` fixture fired the
  detector. Removed the duplicate primaries; secret is now
  companion-only. Akoya / avalara had the same dup-primary shape.
- **bitbucket-app-password companion regex.** Was
  `[a-zA-Z0-9._-]+` (matched anything), so primary-only text
  populated `companion.username` from inside the primary's own
  assignment line and verification proceeded despite
  `must_not_verify`. Re-anchored to `bitbucket_username=` shape.
- **ringcentral companion now anchored to client_secret= shape**
  so id-only text no longer populates `client_pair` and
  triggers VERIFY-RISK.
- **Three twilio companion fixtures** used `xxx` / `fake`
  placeholders containing non-hex characters that the
  example-credential filter suppressed; swapped to realistic
  hex so the gate tests the engine behavior, not the
  example-credential filter.
- **rustfmt** — `scan_gpu.rs` + `engine/mod.rs` re-joined now-short
  calls after the `matching` → `scan` module migration.

### Changed

- **`.gitattributes` now covers `contracts/companion/*.toml`** in
  LFS. The original LFS rule was non-recursive; companion
  fixtures with Twilio-shaped strings would otherwise trip
  GitHub push-protection.

## v0.5.8 — 2026-05-23 — daemon wire-v2, GitHub Action, contracts gate

### Added

- **GitHub Action that actually works.** `uses:
  santhsecurity/keyhog/.github/actions/keyhog@v0.5.10` now installs
  the Rust toolchain + Vectorscan/Hyperscan and builds keyhog,
  *or* downloads a prebuilt binary from the matching GitHub
  Release when one exists. Previously the action ran
  `cargo build` without setup, so every downstream Ubuntu run
  failed with `cargo: command not found` or a hyperscan-sys
  linker error. SARIF output auto-uploads to code-scanning when
  `format: sarif`. README example was also pointing at a
  nonexistent `keyhog/keyhog-action@v1` repo — fixed to the
  bundled action path.
- **`.github/workflows/release.yml`** — tag-driven binary build
  + upload. Pushing a `v*` tag now compiles `keyhog` for
  `keyhog-linux-x86_64` (default features incl. Hyperscan via
  apt) and `keyhog-macos-aarch64` (feature subset, no
  Hyperscan), then attaches the artifacts to the release. The
  composite action prefers these prebuilt binaries over a
  cold cargo build whenever the host triple matches.
- **`KEYHOG_DOGFOOD=1`** — daemon-side dogfood capture. Set when
  starting the daemon (`KEYHOG_DOGFOOD=1 keyhog daemon start`) to
  enable per-scan event capture inside the daemon; the events
  cross the wire to the client and flow into `--dogfood` output.
  Per-request toggling is not wired — env-var gating keeps one
  client's debug session from bleeding into another client's
  payload on a shared daemon, which a per-request flag would
  break without additional isolation work.
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

- **`contracts_runner` was flaky across CI vs local.** The 341-fixture
  loop reused a single `CompiledScanner` and never called
  `clear_fragment_cache()` between scans, so the cross-file
  reassembly cache accumulated. CI's filesystem-iteration order put
  braintree's `sandbox_…` positive ahead of blur-api-key's evasion
  and the sandbox credential surfaced as the only finding on
  `"blur key = \"Kp4Q…\""` — a non-deterministic failure invisible
  locally. Fix: clear the cache before every scan in
  `contracts_runner.rs` (5 sites) and `companion_contracts_runner.rs`
  (3 sites) per the documented test-isolation API in
  `engine/mod.rs:747-760`.
- **`blur-api-key` regex required uppercase `KEY`** while the
  contract evasion uses lowercase `key`. Prepended `(?i)` and
  lower-cased the literals; the contract evasion now hits the
  intended case-variant path. Tests assert truth, not shape —
  weakening the test would have masked the engine gap.
- **Daemon-mode `--dogfood` was inert.** Engine-side telemetry
  (`record_example_suppression` calls from
  `pipeline.rs::should_suppress_known_example_credential_*`) fired
  inside the daemon process — the client never saw any of it, so
  `keyhog scan --dogfood demo-secret.env` against a daemon silently
  dropped every suppression event and the reporter counter stayed
  at 0. Wire protocol bumped 1 → 2: `Response::ScanResults` now
  carries `engine_example_suppressions: u64` and
  `dogfood_events: Vec<DogfoodEvent>` (both `#[serde(default)]`,
  so a v2 client tolerates a v1 daemon). Daemon drains its
  per-scan telemetry after each `scanner.scan(...)` and resets;
  client merges the values into its own `OnceLock<Telemetry>` via
  two new public helpers (`add_example_suppressions(n)`,
  `append_events(iter)`). Verified locally: `--no-daemon` AND a
  fresh daemon both emit "No real secrets — but 6 example/test
  keys suppressed. Pass --dogfood to see them."
- **`demo-secret.env` summary regressed to the clean-repo
  message.** The v0.5.7 fix wired `TextReporter` to read the
  suppression count, but the orchestrator's
  `test_fixture_suppressions.suppresses()` branch ran *before*
  any telemetry write — `AKIAIOSFODNN7EXAMPLE` matched the
  bundled substring suppression list and returned `false` without
  incrementing the counter, so the reporter still saw 0 and
  printed "Your code is clean." Now bumps
  `record_example_suppression(..., "test_fixture_suppression")`
  before returning. Same patch in the daemon-side
  `finalize_for_report` filter. Locked by
  `e2e_binary::demo_secret_aws_example_summary_distinguishes_suppression_from_clean`.
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

- **CUDA driver is opt-in.** The `cuda` feature was on by default,
  which made `cargo build` fail on any host without
  `libcuda.so` / `libnvrtc.so` / `libcudart.so` — including macOS,
  most CI runners, and any Linux box without an NVIDIA driver
  stack. The default scanner build now uses `wgpu` (Vulkan on
  Linux, Metal on macOS) for GPU dispatch. CUDA users opt in with
  `--features cuda` when they want the CUDA backend specifically.
  Drops the link-time CUDA requirement from every default build.
- **`scripts/publish.sh` reads the version from `Cargo.toml`.**
  Renamed from `publish-0.5.6.sh` (which would silently emit "All
  v0.5.6 crates published" even when publishing v0.5.7). The new
  script `awk`s `[workspace.package].version` and uses that
  everywhere — no per-release rename or message edit.
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
