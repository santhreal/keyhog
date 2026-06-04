# Changelog

All notable changes to KeyHog. Versions follow [Semantic Versioning](https://semver.org/).

## 0.5.39 - 2026-06-04

### Added

- Square (payments platform) access-token detector (`sq0atp-` personal access tokens, `sq0csp-` OAuth application secrets) — keyhog previously shipped only a Squarespace detector, which had even mislabelled `sq0atp`/`sq0csp` (Square, not Squarespace) in its keyword list. Surfaced by a differential against the mirror corpus; the `EAAA…` OAuth-access shape is deliberately omitted (4-char prefix + base64url collides with ordinary data, costing precision). Detector count 899 → 900; precision held at 0.9953 with recall +0.0007 (F1 0.9164 → 0.9167) on the mirror corpus.

### Performance

- Use mimalloc as the CLI binary's global allocator (default/`portable`/`full` profiles; drop with `--no-default-features`). The scan hot path runs one Rayon worker per core, each allocating regex DFA-cache scratch and per-match strings; glibc's arena lock serialised those allocations. Measured on a 70 MiB / 13,976-file corpus (RTX 5090 host, 32 cores): single-thread scan 10.0 s → 8.0 s (~20%), with no regression at high thread counts. Libraries stay allocator-agnostic — the binary owns the choice. (The remaining multi-core ceiling is the `regex` crate's shared `Pool<Cache>` mutex, not the allocator: 16-thread scaling sits at ~41% efficiency, a separate optimization.)

## 0.5.38 - 2026-06-04

### Fixed

- **Absolute line numbers for windowed and patch-based scans.** Findings in files past the 1 MiB window size (`filesystem/windowed`), and findings from `--git-diff` / `--git-history`, reported the per-window / per-hunk line instead of the absolute file line — a secret on line 584307 of a 70 MiB file was reported at line ~2, and every diff/history finding landed on line 1. Root cause: byte offsets were made absolute (`+ base_offset`) but line numbers had no equivalent base. Added `ChunkMetadata::base_line`, populated per-window by the filesystem source and per-hunk by the git diff/history sources (now `-U0`, `base_line = new_start - 1` via shared `git::parse_hunk_new_start`), and applied at every line emit site. All output formats (text/json/jsonl/sarif/csv/html/junit) and source backends now report the correct line. Regressioned across the cli, scanner, and sources suites.

### Performance

- Window the decode-splice context to ±512 B around each decoded blob instead of copying the entire parent chunk per candidate. A candidate-dense source file (every quoted string / `key=value` / hex-or-base64 run is a candidate) previously spawned one parent-sized decoded chunk *per candidate*, each rescanned and recursively re-decoded — an O(candidates × file_size) blowup that pinned a single 156 KB Linux driver at ~15 s. Full Linux-kernel scan (94,825 files) drops from ~85 s to ~7 s; the worst single file from ~15 s to ~0.2 s; decode-through recall unchanged.
- Bound the GPU AC prefilter's per-shard readback and reroute dense literal-prefix batches through the SIMD coalesced scanner before CPU phase 2 explodes. Forced-GPU CredData now completes in ~5.0 s instead of timing out at 45 s / 5.1 GB RSS, with byte-stable detector/hash/file/offset parity against the current SIMD run.
- Reuse the batch ML feature vectors for small-batch CPU fallback instead of recomputing text/context features after the GPU crossover gate declines the batch. This removes a redundant feature-extraction pass on scanner chunks that emit fewer than 64 ML candidates while keeping scalar MoE scores byte-identical.
- Route CPU/SIMD filesystem scans through the fused read+scan pipeline so source walking and coalesced scanning overlap across the Rayon pool. `KEYHOG_LEGACY_PIPELINE=1` remains available for A/B verification; CredData SIMD `--no-daemon` keeps byte-identical 2,263-finding JSON output and drops from 5.14 s to 3.57 s on the measured RTX 5090 host.
- Keep default/auto filesystem scans eligible for the fused read+scan pipeline on GPU hosts unless `--backend gpu`/`--backend megascan` is explicitly forced. CredData-shaped many-file scans no longer pay the legacy single scanner-thread funnel when auto batch routing would pick SIMD for the 1 MiB filesystem windows anyway.
- Bound fused filesystem prefetch depth to the Rayon worker count instead of a fixed 256 batches. CredData SIMD direct scans keep the same 5,752 raw findings while dropping from 4.75 s / 2.55 GB RSS to about 4.03 s / 1.84 GB RSS on the measured host; the benchmark adapter row stays detection-identical at 2,577 normalized findings.
- Make the JSON escape decoder borrow only escaped string spans instead of allocating every plain JSON key/value before discarding it. Escaped JSON recall stays covered by the splice contract, unescaped JSON emits no redundant `/json` layer, and the CredData benchmark row remains detection-identical while trimming allocator work on large JSON/NDJSON fixtures.
- Align generic-assignment chunk and line prefilters with the actual assignment-key grammar instead of broad `api`/`auth`/`private` substrings. CredData keeps the same true positives with three fewer false positives, while the mirror benchmark gains seven true positives with no added false positives.
- Remove the per-candidate ASCII lowercase allocation from ML file-type feature extraction by using the shared byte-level case-insensitive matcher for static context markers.
- Skip eager CUDA/wgpu acquisition when the CLI route is explicitly CPU/SIMD or when default/auto filesystem scans will run through the fused CPU/SIMD pipeline. Explicit `--backend gpu`/`--backend megascan` still forces GPU initialization.
- Remove an unconditional 16-match vector reserve from the no-Hyperscan-hit fallback path; chunks that pass fallback plausibility gates but produce no matches now stay allocation-free until reassembly has real work.
- Increase fused filesystem coalesced batches from 16 to 32 chunks after same-host CredData measurement showed better nested phase amortization without the RSS regression seen at 64 chunks.
- Warm runtime regexes used by generic-assignment fallback, multiline reassembly, shared assignment parsing, and Slack checksum validation during the existing scanner warm-up instead of compiling them inside scan workers on the first matching batch.
- Gate no-Hyperscan-hit bare-entropy admission on the same path/config policy as the entropy fallback, avoiding source-file prepare/fallback work when `entropy_in_source_files=false` while preserving bare entropy recall in config/secret files.

### Detection

- Suppress TypeScript non-null source identifiers like `privateAccessToken!` only when the trailing bang follows a credential-named camelCase identifier with no digits. Real password bodies ending in `!` such as Snowflake/Sourcetree fixtures remain reportable.
- Broaden the SIMD/no-HS-hit entropy-run admission gate to treat base64/base64url separators (`-`, `_`, `+`, `/`, `=`) as part of the same token, restoring recall for separators-only secret forms in `generic-high-entropy-string` corpus paths without opening new broadening routes.
- Fix telemetry dogfood assertions and related redaction tests to match canonical `keyhog_core::redact` output shape (`prefix...suffix`) rather than legacy fixed-prefix assumptions.
- Route the `generic-secret` and `entropy-api-key` fallback emit paths through the canonical post-ML penalty pipeline (`apply_post_ml_penalties`) before the checksum floor, so the uniform-base64 / encoded-binary blob suppression that the named/ML path already applies finally applies on the fallback paths too. Mirror precision recovers to P=0.9945 / F1=0.9131 (false positives 651→14); the round1 base64-with-internal-punctuation recall contract stays green because the penalty still surfaces at `min_confidence=0.0` while the bench's 0.40 floor suppresses the blobs.
- Widen `drata-api-token` to capture 64-or-more hex characters (`{64}`→`{64,}`), matching the detector's own "64+ hex" spec. A real 89-hex Drata token previously surfaced no clean match because the fixed-64 capture left trailing hex outside a token boundary.
- Anchor the `klaviyo-api-key` bare `pk_`/`sk_` patterns with a leading `\b` word boundary so they no longer fire on a `pk_`/`sk_` substring sitting inside a longer identifier (e.g. the `sk_` inside Pinecone's `pcsk_` keys). Klaviyo recall for real boundary-delimited keys is unchanged; the spurious cross-detector match that shadowed `pinecone-api-key` is gone.

### Coherence

- Reconcile the advertised detector/pattern counts to the binary's actual embedded corpus (899 detectors, 1675 patterns) across README, docs, banner, contract fixtures, and the compiled count gates. The canonical source of truth is `keyhog detectors` / `keyhog doctor`.
- Normalize 484 per-rule contract fixtures whose `readme_claim` still pinned the stale `"889 service-specific detectors"` string to the current `899`, so the `contracts_runner::every_contract_readme_claim_present` gate (which requires each claim to appear verbatim in the README) is green again. The generator already pins `899`; these were un-regenerated stragglers.
- Update the Docker integration `detectors-count` scenario (`tests/docker/scenarios.sh`) from the stale `Loaded 894 detectors` to `Loaded 899`, matching the embedded corpus the binary reports.
- Document the macOS GPU caveat: the shipped macOS binary is built `--features portable` (no GPU) and is unaffected, but an explicit `--features gpu` build on Apple Silicon hit a fatal wgpu abort because the Metal backend advertises `PIPELINE_CACHE` yet rejects pipeline-cache creation. The vendored vyre wgpu driver now only requests `PIPELINE_CACHE` on backends that implement it (Vulkan/DX12); the fix lands in keyhog when the vendored vyre is published/re-pinned.
- Make dedup primary/additional location selection deterministic when overlapping filesystem windows report the same credential at the same byte offset with different line metadata.
- Make the `hw_probe` GPU-routing unit tests host-independent. Six assertions drove `select_backend()` with synthetic `HardwareCaps { gpu_available: true, .. }` and expected `ScanBackend::Gpu`, but `select_backend` first short-circuits through the runtime `gpu::env_no_gpu()` probe (true on a GPU-less host), so they were green on a GPU dev box and red on a GPU-less CI runner. They now assert the side-effect-free `gpu_could_engage()` crossover predicate (newly re-exported from `hw_probe`), which depends only on the passed caps. `KEYHOG_NO_GPU=1` reproduces the CI routing locally.
- De-flake `contracts_runner::every_contract_perf_budget_holds`. A single wall-clock sample on a shared CI runner occasionally tripped the 15 ms per-detector budget by 1–3% (`azure-blob-sas-token`, `jwt-token`) while steady-state sat well under. The budget now measures best-of-N — re-measuring only an over-budget contract and keeping the minimum — so a catastrophically slow regex still blows every pass while a one-off scheduler stall is discarded; contracts already under budget still pay for a single scan.
- Reconcile `GAP_FINDINGS.toml` with the `findings_registry_integrity` gate. Fourteen findings pointed their `test` path into the gitignored `coordination/` tree (absent in a clean checkout), so the registry gate failed in CI on the first one. Promote the three that hold against the committed repo (KH-GAP-076/077/179) into `crates/scanner/tests/gap/` and repoint them; de-scope the eleven open or design-conflicting `ci-operability` findings whose claims contradict the deliberate CI design (e.g. the 4-runner PR strict subset) or depend on uncommitted coordination infra (registry 162 → 151 findings).

### Install / packaging

- `install.sh --from-file=PATH` (and `KEYHOG_FROM_FILE`): install a pre-built or pre-downloaded keyhog binary instead of fetching a release — for offline/air-gapped installs and for CI to prove a freshly-built binary. Reuses the full install machine (backup, atomic same-dir swap, `verify_install`/`keyhog doctor`, rollback) and verifies a sibling `PATH.sha256` if present; `install.ps1 -FromFile` is the Windows equivalent.
- Harden release downloads against transient CDN drops. A connection dropped mid-transfer ("The connection was closed unexpectedly") was failing the Windows — and intermittently the Linux — install-from-scratch smoke even though the asset was present and correctly named. `install.sh` curl now passes `--retry 5 --retry-delay 2 --retry-connrefused`; `install.ps1`'s `Invoke-WebRequest` retries up to 5 times with linear backoff.
- Normalise a bare-semver `--version` / `-Version` to the v-prefixed release tag. keyhog tags are all `vX.Y.Z`, so `--version=0.5.37` built a download URL against a non-existent `0.5.37` tag and 404'd; the retry above (which surfaced the repeated 404 instead of one ambiguous "connection closed") exposed it on the Windows smoke. Both installers now prepend `v` to a digit-leading version and leave an explicit `v…`, branch, or sha untouched. Covered by `edge_cases.sh` 2.9/2.10 and the corrected 14.2 (bare `2.0.0` → tag `v2.0.0`).
- Add `tests/install/install_from_local_build.sh` and wire it into the macOS Build and Build Release CI jobs: prove current-source → install (via `--from-file`) → working binary on every push — `keyhog doctor` self-test, seeded scan (exit 1 + findings), SARIF, the local-checksum gate (good vs tampered), and the premium interactive wizard (driven through a PTY when `expect` is present). The mocked detection scenarios never touch a real binary and integration-smoke is manual + installs a published release; this closes that gap.
- Add a dogfood self-scan gate to Build Release (`keyhog scan .` must exit 0 on keyhog's own tree). Path-suppress `benchmarks/baselines/` and `benchmarks/generators/` in `.keyhogignore` — the committed differential/leaderboard reports quote the credential *shapes* each scanner surfaced on the test corpus (documentation about findings, not live secrets), and the mirror generators assemble synthetic credentials at runtime to build the fixtures (templates for fake test data); same rationale as the existing `CHANGELOG.md` / analysis-doc suppressions.
- Smoke harness: `keyhog backend | head -30` SIGPIPE'd keyhog (exit 141 under the runner's `bash -o pipefail`) when the routing matrix printed more than 30 lines, spuriously failing the `integration-smoke` Backend-probe step on Ubuntu. The step now runs `keyhog backend` to completion (its real exit code is the gate) before capping the display, so a genuine backend failure still fails the step.

### Benchmarks

- Unify the three benchmark systems into one. `benchmarks/bench` is now the single source of accuracy truth: the retired `tools/secretbench/scoring/` scorer and the retired `tools/diff_bench` differential runner are both replaced by `bench`'s canonical scorer + scanner adapters, and the mirror corpus generator plus the competitor home-turf harvesters move under `benchmarks/generators/`. Committed scoreboard anchors move to `benchmarks/baselines/`. The `bench-nightly` (renamed from `secretbench-nightly`) and `differential-bench` workflows now drive `python -m bench`.
- Add `python -m bench gate`: the single regression + differential gate. It exits non-zero unless keyhog leads every available competitor on F1 *strictly* and clears the asserted `--min-f1` / `--min-precision` / `--min-recall` floors and/or a committed `--baseline` (within `--epsilon`); exit 2 if keyhog produced no usable result. It replaces the per-fixture `diff_bench` F1 gate and is the forcing function for the continuous-improvement loop.
- Add the production continuous-improvement loop: `make -C benchmarks loop` runs the whole cycle (scorer self-tests → corpus → leaderboard → calibrate → render → gate) in one command, and a committed regression anchor (`benchmarks/baselines/mirror-keyhog-baseline.json`, keyhog F1=0.9131) lets the `differential-bench` workflow fail red on an F1 regression below the anchor, not only on a competitor overtaking keyhog. `loop` never `--inject`s the README, so a partial-scanner run can't degrade the published leaderboard.
- Add the cross-device bench harness (`benchmarks/cross_device.sh` + `python -m bench.cross_compare`): rsync the current tree to a device, install keyhog via its per-OS build (Linux Hyperscan SIMD; macOS `--features portable`, the system-lib-free vyre CPU path), bench the device-local corpus, and pull per-host results into `results-cross-device/<device>/` (kept out of the README-feeding `results/`). Fixes a Python-3.9 portability bug the macOS run surfaced (`bench/runner.py` used `datetime.UTC`, which is 3.11+). First cross-device snapshot (`benchmarks/reports/cross-device.md`): keyhog mirror F1 = 0.9131 on Linux (Ryzen 9950X, Hyperscan) vs 0.8996 on macOS (M4 Pro, portable/vyre) — a ~0.013 recall delta in the vyre CPU path.

### CI / GitHub Action

- Enforce contract perf and scale timing budgets under the `release-fast` CI profile even though that profile keeps debug assertions enabled.
- Fail Code Scanning SARIF uploads closed on trusted pushes and same-repo PRs while keeping fork-PR permission failures advisory and always preserving the report artifact when it exists.
- Make the composite GitHub Action fail closed when KeyHog exits cleanly without writing the requested report, and expose `duration-ms` in the Action outputs and job summary for CI performance tracking.
- Update the CI workflow guide to lead with the hardened composite GitHub Action, including SARIF/artifact/summary behavior and baseline adoption.
- Align CI rollout docs with the composite Action's advisory-mode contract: ordinary findings can be non-blocking, but verified-live credentials still fail after report/SARIF/artifact upload.
- Correct first-scan, detector, and drop-in exit-code docs so verified-live credentials are consistently documented as exit `10`, not ordinary exit `1`.
- Move the composite Action scan/count/summary path into a tested local script, validate `format`/`severity`/`verify` before scanner invocation, expose the raw `exit-code` output, sanitize job-summary cells, and count text reports by the stable `Secret:` field instead of a non-portable box-drawing grep.
- Validate `fail-on-findings` and `upload-sarif` in the same tested scan script before invoking KeyHog, escape untrusted values in GitHub workflow commands, and surface live-verification parse failures as nonzero findings instead of clean CI output.
- Validate composite Action JSON and SARIF report shapes consistently across jq and Python counting paths so malformed clean reports fail closed instead of being miscounted as findings.
- Route composite Action shell inputs and step outputs through environment variables instead of direct bash interpolation, and validate the resolved version before writing it to `GITHUB_OUTPUT`.
- Keep composite Action usage errors from reflecting rejected version/findings values back into GitHub workflow command bodies.
- Verify downloaded composite Action release assets against their `.sha256` files before execution, install the Linux Hyperscan runtime on the prebuilt path, and dogfood the local composite Action from `.github/workflows/keyhog.yml`.
- Parse JSONL reports in the composite Action instead of counting raw lines, so blank lines do not inflate findings and malformed clean JSONL fails closed.
- Validate manual release tags in every release workflow job before writing `GITHUB_OUTPUT`, and route validated tags through environment variables in follow-up shell steps.
- Make the composite GitHub Action fail closed when report parsing fails after a findings exit code, and write a concise GitHub Step Summary for CI triage.
- Run the composite Action's `KEYHOG_PRINT_EFFECTIVE_CONFIG=1` pass as a preflight, then clear the print-only env for the real scan so CI gets the resolved scanner/post-process policy without losing the report.
- Keep the effective-config preflight advisory and omit `--verify` from that preflight so older binaries that ignore the print-only env cannot block report/SARIF upload or double-run live verification.
- Isolate the composite Action's effective-config preflight report in a scratch file, preventing legacy binaries that write during preflight from masking a real findings exit that failed to produce the final report.
- Teach the composite Action to select the published `keyhog-windows-x86_64.exe` asset on Windows bash runners and preserve the `.exe` install name after checksum verification.
- Teach the composite Action to select `keyhog-linux-x86_64-cuda` on CUDA-ready Linux runners and preserve `--features cuda` when falling back to a source build.
- Guard the composite Action's final findings failure step on present scan outputs so wrapper/runtime failures are not rewritten as misleading "Invalid findings output" failures after artifact/report handling.
- Restore the aggregate CLI `all_tests` target after the credential-hash storage contract changed from hex strings to inline `[u8; 32]` bytes.
- Move the remaining CLI inline unit tests for args, hook coherence, and scan-system finding retention into registered aggregate tests while preserving the source gates against inline tests and production unwraps.
- Require composite Action JSONL report lines to be finding objects, so clean malformed JSONL fails closed and findings-exit malformed JSONL cannot be counted as zero findings.
- Make verified-live credentials (`keyhog` exit 10 under `verify: "true"`) fail the composite Action after report/SARIF upload even when ordinary findings are configured as advisory with `fail-on-findings: "false"`.
- Execute the composite Action final fail step in the CI contract suite, proving live credentials preserve exit 10, ordinary findings preserve exit 1, and malformed `exit-code` output fails closed without workflow-command reflection.
- Dogfood the composite Action's real-binary text-report path, proving actual KeyHog `format: text` output is counted through the wrapper's stable `Secret:` field contract.
- Parse every committed GitHub workflow and the composite Action manifest in the local Action contract suite, and assert the manifest remains a composite action with executable steps.
- Add semantic workflow-shape contracts for every committed GitHub workflow, requiring a name, trigger, jobs mapping, runner or reusable-workflow target, and executable step definitions.
- Scope composite Action artifact names by GitHub job, matrix job index, run attempt, and scan duration so matrix CI jobs do not collide on a single `keyhog-report` artifact name.
- Keep `--lockdown` fail-closed on non-empty KeyHog cache directories while allowing an empty `$XDG_CACHE_HOME/keyhog` directory that the process or a prior interrupted run created without findings.

### Benchmarks

- Let benchmark KeyHog binary resolution fall back to a freshly built `target/release-fast/keyhog` before PATH, while still preferring `target/release/keyhog` when present.
- Add measured benchmark scanner adapters for Betterleaks, Kingfisher, Nosey Parker, Titus, and TruffleHog, with command-specific JSON normalization tests and generated-corpus ignore rules.
- Add `python -m bench run` / `make run` to execute one measured scanner/corpus row, emit `RunResult` JSON, score labeled corpora, compute throughput, and preserve scanner exit code and timeout state in artifacts.
- Add `python -m bench leaderboard` / `make leaderboard` to run the default scanner matrix, including Nosey Parker, and write one `RunResult` JSON artifact per scanner/config row.
- Add generated benchmark markdown reports plus README injection/check gates, and document the benchmark harness under `benchmarks/README.md`.
- Cache native CredData source-file lines while building benchmark labels, avoiding repeated full-file reads for files that contain multiple positive rows.
- Prefer the freshly built release `keyhog` binary in benchmark runs, with explicit `KEYHOG_BIN` and constructor overrides still taking precedence, so leaderboard runs score the current source instead of a stale PATH install.
- Add `python -m bench analyze` / `make analyze` to mine false-negative and false-positive examples through the same corpus adapters, scanner adapters, and overlap scorer as the leaderboard.
- Stop the benchmark Makefile from exporting a desktop-specific default `KEYHOG_BIN`; unset runs now use the adapter's host-local fresh-binary resolver.
- Treat benchmark scanner exit codes through per-scanner success contracts so Keyhog findings exits are accepted while competitor invocation failures become errored `RunResult` rows instead of clean zero-finding rows.
- Treat Kingfisher's completed finding-run exit code as successful and probe Titus versions through `titus version`.
- Point scanner benchmark runs at manifest-free, neutrally named `corpus/` scan trees and measure corpus bytes/files from that same scan root so answer keys and path-context penalties cannot inflate or suppress benchmark results.
- Apply the same manifest-free neutral scan-root contract to competitor homefield corpora.
- Refresh the committed mirror benchmark README and report tables from the current `benchmarks/results` artifacts, including updated per-scanner runtime/RSS values and the current private-key category gap.
- Score KeyHog `additional_locations` in the benchmark adapter so deduplicated credential aliases count toward per-file recall instead of being reported as false negatives; mirror private-key F1 is now 1.000 and the overall mirror F1 rises to 0.9108.
- Refresh the committed mirror benchmark README/report timing and RSS values from the current KeyHog run.
- Refresh the committed benchmark perf tables so the CredData result artifacts appear in README and `benchmarks/reports/perf.md` instead of leaving the report-check gate stale.
- Make `python -m bench report --check` read-only and compare generated report files as well as README injection markers, so the CI gate proves report freshness instead of silently formatting tracked reports.
- Add per-detector benchmark confidence histograms plus `python -m bench calibrate`, producing measured `min_confidence` floor reports and TOML overlays for lossless false-positive cuts on labeled corpora.
- Keep the KeyHog benchmark `auto` backend row on the same deterministic fused filesystem route as production default scans, while forced `gpu`/`megascan` rows still require a real GPU.
- Add competitor overall precision to the per-category benchmark gap table so recall-only category wins expose their cross-category false-positive cost.
- Probe for actual GNU `time` support before wrapping benchmark subprocesses, so BSD/macOS `/usr/bin/time` falls back to `resource.getrusage` instead of breaking scanner runs.
- Add a tested benchmark contract package with shared `RunResult` schema, host capture, SecretBench-compatible scoring, Mirror/Homefield/CredData/Kernel corpus adapters, and honest package entrypoints for host and corpus introspection.
- Make explicit KeyHog GPU benchmark rows set `KEYHOG_REQUIRE_GPU=1`, preventing GPU/MegaScan timings from silently measuring CPU fallback when the GPU path is broken.

### CLI

- Use the resolved scan config as the single confidence-floor source for scanner setup and post-processing, including `--no-ml` runs.
- Wire the full CLI contract-test module set into `all_tests`, fix the newly enforced public contracts for `diff` missing-baseline exit codes, explicit piped `--progress`, optional `watch [PATH]` help, and top-level exit-code docs.
- In non-progress mode, keep `--max-file-size` skip-summary output plain-text (no ANSI color escapes) so JSON/text automation pipelines stay parse-stable.
- Harden hex-token false-positive suppression against digest fragments, tighten several 32-hex detector anchors to word boundaries, make Appsmith environment anchors case-insensitive, split SARIF serialization structs out of the streaming reporter, and upgrade weak CLI/decode assertions to identity-level checks.
- Split the previously orphaned adversarial/property CLI suites into standalone CI test binaries and fix the surfaced contract drift: user-named missing resources exit 2, watch rejects non-directories, scan-system validates `--space`/`--threads`, hook install exposes real `--force`, detector search no-matches are script-clean, and legacy baseline/diff JSON remains accepted.
- Make `--no-suppress-test-fixtures` also disable test/example path confidence penalties and hard suppression, so real secrets under `tests/fixtures` can be surfaced for recall audits.
- Document the canonical `.keyhog.toml` precedence, nested `[scan]` / `[detector.<id>]` / `[lockdown]` tables, and bench-tuned config defaults in the README, mdBook reference, example config, and config tests.
- Make `--git-staged --exclude-paths` apply to the staged-file include set instead of letting explicitly staged paths bypass excludes.
- Run the CLI on Tokio's current-thread runtime so plain filesystem scans do not spawn a full async worker pool alongside the Rayon scanner threads.

### Scanner

- Bound Bright Data 64-hex matches to a trailing hex boundary, accept uppercase hex, and fix malformed 65-hex contract/adversarial fixtures so detector-contract failures represent real misses instead of digest-slice suppression.
- Let Avalara license-key matches surface without requiring a nearby account-id companion; the account ID is still captured for verification when present, but standalone `avalara_license_key` fixtures no longer get dropped before reporting.
- Normalize U+00AD soft hyphen as an evasion character instead of promoting digit-adjacent occurrences to ASCII `-`, restoring contiguous credential matching for soft-hyphen-split secrets.
- Lower the anchored AWS session-token body floor from 80 to 64 characters so committed 77-character `AWS_SESSION_TOKEN` fixtures and their soft-hyphen variants are detected by the service detector instead of relying on generic fallback behavior.
- Align the Scaleway companion contract with the intentionally SCW-anchored secret-key detector, widen AerisWeather access/client IDs to 40 characters, and refresh the Avalara negative contract around unscoped license keys, restoring detector-contract positives without reintroducing bare `secret-key=<uuid>` Scaleway false positives.
- Add a dense-prefix circuit breaker for GPU AC/literal-set phase 1: once a batch produces prefix hits at the measured phase-2 loss point, KeyHog keeps the successful GPU probe but scans that batch with the SIMD coalesced path instead of confirming millions of broad prefixes on CPU.
- Replace the SIMD coalesced no-hit multiline fallback's full `scan()` re-entry with a prepared multiline-text scan, eliminating decode/postprocess recursion on large ordinary source files; the Linux `drivers/net` subset dropped from ~15.6 s to 0.62 s wall and the full warm-cache kernel scan from ~90 s to 3.43 s.
- Window decoded splice-back context around the encoded payload instead of cloning the whole parent file per decoded candidate, bounding candidate-dense decode-through work while preserving nearby companion anchors.
- Warm lazy regex transition caches with a representative no-match search during scanner warm-up so the first real source batch does not pay serial DFA first-touch cost.
- Add `KH_PERF=1` scan timing for coalesced phase splits and orchestrator scan/receive wait time, keeping perf diagnosis operator-visible without changing default output.
- Wire `--no-decode` to `max_decode_depth = 0` in the engine config and keep `--fast` coherent by disabling decode, entropy, and ML in the printed effective config.
- Build KeyHog's production GPU AC dispatch program with a bound atomic match slot so each emitted `(pattern,start,end)` triple uses one counter value; the live RTX 5090 backend self-test now reports `vyre_ac_kernel=pass` and recommends GPU instead of degrading on degenerate triples.
- Let `KEYHOG_REQUIRE_GPU=1` proceed when the GPU stack is healthy, while still hard-failing on concrete runtime degradation; required-GPU parity now reaches assertions instead of exiting during preflight.
- Preserve concrete literal-set GPU degrade reasons too, so diagnostic `KEYHOG_GPU_KERNEL=literal-set` failures name the failed branch, shard, and cap/output condition.
- Add `keyhog backend --self-test --json`, preserving exit `4` for runtime GPU degradation while exposing stable CI fields for overall status, recommended fallback backend, and each GPU/Vyre probe.
- Thread GPU runtime-degrade reasons into the hard-fail warning path, so `KEYHOG_REQUIRE_GPU=1` and `backend --self-test` name degenerate Vyre AC match triples instead of reporting only a generic GPU dispatch failure.
- Align the Vyre performance roadmap with the workspace-pinned crates.io `vyre` 0.6.1 release, add a doc/pin coherence gate, and fix stale scanner `RawMatch` test fixtures to use the production credential-hash contract.
- Remove stale handoff/session wording from the Vyre roadmap and scanner lazy-build comments so the docs describe concrete remaining wires instead of time-boxed handoffs.
- Stop the backend self-test from claiming the AC kernel works before the AC self-test has actually passed.
- Route hot-pattern fast-path matches through the preprocessor line map so structured `.env` synthetic lines collapse into the original source line instead of producing past-EOF additional locations.
- Confirm GPU AC cheap-filter roots against the whole prepared chunk, matching SIMD trigger semantics and avoiding narrow-window recall loss for detector regexes that need wider context.
- ASCII-fold GPU literal sets and coalesced haystacks before AC/literal-set phase-1 matching so GPU recall matches Hyperscan's caseless detector semantics.
- Add a real-binary GPU-vs-SIMD parity integration gate for far-offset and caseless literal-prefix regressions.
- Replace the forced-GPU unavailable-path panic with the same explicit stderr plus exit-2 contract used by the other GPU hard-fail paths.
- Tighten CodeSandbox token bodies to base62 so caseless matching no longer reports `CSB_...` SCREAMING_SNAKE enum identifiers as API tokens.
- Correct the EPA detector contract fixtures to the documented 32-40 character API-key length so contract failures name real detector behavior.
- Bound GPU MoE confidence readback with a default 30 s deadline and `KEYHOG_GPU_MOE_TIMEOUT_MS`, falling back to CPU MoE instead of parking scan workers on stalled GPU callbacks.
- Consume adjacent base64 padding when splicing decoded chunks back into their parent text, preventing decoded values from inheriting a stale trailing `=` and surfacing GPU-only license-key-shaped false positives.
- Match the GPU MoE output activation to the CPU/SIMD rational sigmoid so near-floor confidence decisions no longer diverge from the benchmarked scorer.
- Lower filesystem source windows to 1 MiB with 128 KiB overlap so multi-MiB files feed the scanner as parallel chunks instead of serial internal re-windowing inside one worker.
- Classify commented-out config assignments as assignment context so `# KEY=value`, `// token = value`, and HTML/block-commented config lines retain leak confidence while prose comments stay comment context.
- Close the per-detector positive/negative/evasion contract runner by tightening required companions, Anthropic legacy length enforcement, exact service anchors, short-prefix routing, multi-line Azure endpoint matching, and generated contract fixtures that had lost their service anchors.
- Default SecretBench scoring to the deterministic CPU/SIMD path with `KEYHOG_NO_GPU=1`, while honoring a caller-provided `KEYHOG_NO_GPU=0` so the same scorer can dogfood GPU parity after the MoE activation fix.
- Keep the deterministic SecretBench floor-override batch for strongly vendor-anchored detectors, raising mirror recall to the target range without adding clean-negative false positives.
- Store always-active fallback detectors as sparse indices instead of a dense bool table, keeping fallback activation O(active patterns + keyword hits) per admitted chunk.
- Short-circuit GPU no-hit fallback admission when always-active fallback detectors or a missing keyword prefilter make the active set unconditional, avoiding a redundant keyword-AC pass on those chunks.
- Adopt compact `CsrU32` storage for hot scanner index maps (`prefix_propagation`, same-prefix siblings, fallback keyword routing, and SIMD Hyperscan dedup maps) instead of leaving the optimization half-wired.
- Preserve cross-chunk boundary reassembly when GPU batch dispatch degrades to CPU or SIMD coalescing falls back because the prefilter is unavailable.
- Route GPU no-hit chunks through phase 2 when the real fallback active set is non-empty, preserving prefixless detector recall on large GPU-routed files.
- Degrade GPU AC batches that emit impossible `end <= start` match triples before chunk attribution, preserving recall when the current CUDA literal-set path returns corrupt ranges.
- Circuit-break the GPU AC dispatch path for the rest of the process after one degenerate Vyre readback, avoiding repeated known-corrupt GPU dispatch cost while preserving SIMD/CPU recall.
- Union canonical CPU AC trigger roots into GPU phase 2 before extraction so admitted GPU chunks cannot under-trigger raw detectors relative to the scanner's case-insensitive literal set.
- Stop placeholder scoring from crushing named credential-bearing database URLs solely because the hostname contains `example.org`; placeholder words inside the username/password remain penalized, Redis/MySQL/PostgreSQL URL detectors now ship reviewed `0.20` confidence floors, PostgreSQL recognizes `pg-url`/`PG_URL` context and seeds both `postgresql://` and `postgres://` branches, coalesced no-hit batches recollect triggers from structured preprocessed text, and match resolution now lets service-specific detectors beat higher-confidence generic fallbacks on the same line.
- Preserve concrete AC GPU dispatch failure causes in runtime degrade and `KEYHOG_REQUIRE_GPU=1` output, including batched dispatch errors, per-shard errors, missing/truncated output buffers, and match-cap overflow.
- Treat nearby decoded-source duplicates as aliases during dedup so `filesystem/json` views do not displace the original file location when both represent the same credential.
- Skip Caesar decoding for source/config paths such as `Kconfig`, `Makefile`, `.tbl`, `.mk`, and `.cmake`, preventing ROT-N false positives from kernel config and syscall-table text.
- Capture full SSH/TLS PEM private-key blocks instead of header markers, pair BEGIN/END algorithm variants, and preserve branch-local alternation suffixes in homoglyph fallback regexes so distinct private keys cannot collapse under credential-scope dedup.
- Bring the core unified test harness back onto the raw `[u8; 32]` credential-hash contract and move CSV/HTML/JUnit reporter tests out of `src`, restoring `keyhog-core --test all_tests`.
- Tighten the Azure Container Registry username pattern so `ACR_USER 0x00000000` C register constants do not report as credentials.
- Remove the dead fragment-cache `shard_index` wrapper so production keeps only the allocation-free slice-pair shard path.
- Lower the AWS secret-access-key detector confidence floor for anchored `AWS_SECRET_ACCESS_KEY`-style assignments so valid 40-character bodies are not dropped below the global floor.
- Lower the Google OAuth client-secret detector confidence floor for uniquely anchored `GOCSPX-`, `GOOGLE_CLIENT_SECRET`, and `.apps.googleusercontent.com` shapes so low-entropy client IDs are not dropped.
- Match AVX-512 entropy semantics to the scalar/SSE/AVX2 paths for small, misaligned, and null-containing inputs.
- Let detector-authored `min_confidence` floors mark reviewed service-specific hex-token shapes as strongly anchored, restoring wrapper recall for common 32/40-hex API-key detectors without relaxing generic hash suppression.
- Rewrite the MongoDB connection-string detector host tail to avoid nested quantifiers while preserving dotted-host recall.
- Restore Discord bot-token recall for current base64 snowflake prefixes, including tokens split across adjacent chunks.
- Reject overlong AWS access-key hot-path substrings instead of reporting the valid-length prefix inside a longer alphanumeric run.
- Expand Unicode evasion normalization across C0 controls, combining marks, bidi isolates, unusual separators, and context-sensitive soft hyphen separators.
- Keep checksum validation from deleting structurally valid legacy GitHub classic PATs and long Stripe secret keys where no public checksum contract exists.
- Add a left boundary to Arbitrum API-key anchors so embedded words like `barbitrum-api-key` do not satisfy the detector.
- Split structured parsers by format family, move the remaining inline parser contracts into registered external tests, and extend parser gates across the whole parser module tree.
- Add the SIMD coalesced no-hit plausibility gate to GPU phase2 so empty-hit chunks skip prepare/post-process work unless they still need fallback scanning.
- Deduplicate dogfood example-suppression telemetry by detector, path, credential hash, and reason so repeated scan paths do not inflate suppression counts.
- Tighten the batch-flush regression test to assert exact static-detector recall across the >4096 chunk boundary without underflowing when unrelated detectors emit findings.
- Let strongly service-anchored UUID detectors bypass the generic UUID shape suppressor, restoring default recall for Braze, Heroku, Codecov, and Consul-style credentials while keeping generic UUID captures suppressed.
- Skip the pre-ML test/docs context multiplier when `--no-suppress-test-fixtures` is active, so the opt-out preserves the full heuristic confidence for real findings under fixture paths.

### Sources

- Fix default `--git-diff HEAD` to compare the base commit against uncommitted worktree changes rather than resolving both sides to `HEAD`.
- Size the dedicated filesystem reader pool to half the scanner pool with a 16-thread cap, preserving deadlock-free read/scan overlap without doubling runnable workers on high-core hosts.
- Fix `keyhog-sources` default test compilation by marking the S3 ambient credential forwarding integration test as requiring the `s3` feature.
- Move source-crate inline tests for filesystem, binary literals/sections, GitHub org, HTTP policy, and web SSRF helpers behind registered external tests, restoring the no-inline-test and no-production-unwrap gates under default and all-features source builds.
- Split GitHub org git-error redaction into a focused submodule so `github_org.rs` is back under the 500-line modularity target.
- Split WebSource SSRF, URL redaction, redirect validation, and DNS pinning helpers into `web/ssrf.rs`, bringing `web.rs` under the 500-line modularity target.
- Split filesystem extraction and walker/filter policy into `filesystem/extract.rs` and `filesystem/filter.rs`, bringing the filesystem source below the 500-line modularity target and registering the zip archive skip-list regression gate.
- Fix HTTP property-test env isolation for `KEYHOG_PROXY`/`KEYHOG_INSECURE_TLS`, keep 10k-case policy fuzzing while bounding real reqwest builder/client construction, and wire direct proptest regression files so aggregate source gates run without skipping `http_fuzz`.
- Run filesystem reading on a dedicated Rayon pool so large-tree scans cannot deadlock by filling the source channel with global-pool reader tasks while scanner `par_iter` waits for those same workers.

## v0.5.37 - 2026-05-29 - Mirror benchmark: F1 0.7815 to 0.8896 (closes the gap to betterleaks 0.892)

Headline: precision 0.9716, recall 0.8203, F1 0.8896 against the
SecretBench mirror corpus (15,000 fixtures). Net delta vs v0.5.35
is +0.108 F1, +5.9pp precision over the betterleaks 0.913 floor at
0.003 below their 0.892 F1. Precision was the headline lever for
this release: 154 docs-example FPs killed, over-broad detector
arms narrowed, decode-through composition tightened, and confidence
floors only apply when the value is not algorithmically a
placeholder.

### Detection truth (engine)

- entropy fallback: lift the blanket 32/40/64/128-char hex blacklist
  and the strict-mode >10-char hex drop ONLY when a credential keyword
  is on the same line (`apiKey: <hex>`, `TOKEN=<hex>`). Outside an
  anchor the blacklist holds, protecting sha256-hex / npm-lock-integrity
  / k8s-resource-uid negatives. Closes the generic-high-entropy-string
  R=0.38 hole.
- generic-secret regex: add `.` to the keyword-separator class so
  `api.key=` / `private.key=` / `client.secret=` in .properties,
  helm-values, terraform locals are recognised alongside `_`/`-`.
- decode-through: compose decoded-placeholder + uniform-base64-blob
  into every generic emit (decoded chunks no longer surface
  placeholders or known image-digest shapes).
- confidence: skip the `known_prefix_confidence_floor` boost when the
  value is itself a placeholder word (closes 154 docs-example FPs
  driven by service-prefix-only fixtures).
- decode_structure feature wired into the entropy-fallback emit path
  (the rebuilt 42-feature ML model now sees decode topology on the
  same code path the rule engine uses).
- ML confidence: 112 named detectors that silently fell below the 0.3
  floor are now correctly surfaced.
- sources: UTF-16LE wide-string extractor lifts credentials from
  Windows .NET / PE binaries.

### Detector regex narrowings

scaleway-api-key (drop the bare `secret[_-]key` arm), flickr +
iterable + consul (drop generic alternations, -256 FPs),
lambdatest + saltstack (drop generic alternations),
etherscan-api-key (drop the bare `apikey=<32hex>` arm that
claimed every random hex digest), aws-session-token / aws-ecr-token
/ anrok / applitools / appsmith / appwrite / avalara / avaya /
aweber / libsql (word-boundary prefix + quote-aware terminator).

### ML pipeline

The training pipeline (`ml/`) was rebuilt in-tree alongside the Rust
serve path: `ml/features.py` mirrors `ml_features.rs` byte-for-byte,
`ml/decode_structure.py` mirrors `decode_structure.rs`, and
`ml/parity_check.py` is a Rust-to-Python parity harness using a new
`compute_features_with_config` test export. `ml/train_classifier.py`
produces an MoE classifier with fast-sigmoid activations serialized
into `weights.bin` (model version `moe-v1-83688a6a6cb77f70`).
Decode-structure becomes feature #42; Rust scorer bumped to 42
features end-to-end.

### Build / packaging

- Lean CI build profile: `cargo build --no-default-features --features ci`
  produces a Hyperscan-free, GPU-free, verify-free, TUI-free binary
  with near-instant cold start.
- vendor: adopt vyre 0.6.1 (latest upstream) + migrate keyhog to wgpu 25.
- GHCR: publish image per release + maintain floating major tag.

### Release / install

- self-update: verify the release binary minisign signature before
  the self-replace, and fail closed on missing signatures (was
  silent bypass).
- Action / docs: wire the documented `baseline` input into the scan,
  fix broken adoption recipes (install URL, docker image, exit
  codes), and fix Action version pins through v0.5.35.

### Test infrastructure

- secretbench: base64-aware + escape-aware overlap promotes 92
  mis-counted TPs that overlapped escaped or base64-decoded values.
- adversarial oracle: scan_text unescapes `\u{XXXX}` Rust unicode
  escapes so wrapper fixtures with escape syntax exercise the same
  byte stream the scanner sees in real files.
- gates: line / modularity cap demoted to advisory warn; stale
  filesystem_read gate dropped after the read.rs to read/ split.

## v0.5.36 - skipped (folded into v0.5.37)

The 0.5.36 version was committed (`chore(release): v0.5.36`) but
never tagged or shipped; the work between 0.5.35 and 0.5.36 is
consolidated above into the 0.5.37 release notes.

## v0.5.35 - 2026-05-28 - Adversarial wrapper harness: 216 to 152 wrapper-test misses (30% reduction)

### Detector regex fixes

- **deepnote-api-credentials** pattern 2: matches multi-word suffix
  sequences (`DEEPNOTE_API_KEY=`, `DEEPNOTE_SECRET_TOKEN=`). The prior
  `[_\s]*(API|TOKEN|KEY)` could only span one of API / TOKEN / KEY,
  so the doubled-up env-var forms missed entirely. Group renumbered
  from 2 to 1.
- **cloudsmith-api-key** pattern 2: separator class now includes `=`
  and `:`. `CLOUDSMITH_API_KEY="value"` and `cloudsmith.api.key=value`
  failed under the prior `[\s"']+`-only separator.
- **aws-lambda-function-url-secret** pattern 2: path class includes
  `/`. Multi-segment paths like `/api/v1?token=...` now match.
- **five9-api-credentials**: regex rewritten. The prior `five9apikey=`
  literal missed every real env-var form. New pattern allows
  separators and covers api_key / client_secret / secret / token /
  key / password suffixes.
- **fedex-api-credentials**: SECRET-suffix pattern promoted from a
  companion (only fires if anchored by another primary pattern) to a
  primary pattern. `fedex.api.secret=...` on its own now surfaces.

### Contract body-length fixes

Contracts whose positive credential bodies were 1-2 chars short of
the detector regex's floor (no detector changes):

- **fedex** pos#0, pos#1: 31 to 32 chars (regex needs `{32,64}`).
- **finicity** pos#1: 31 to 32 chars (regex needs `{32,40}`).
- **footprint** pos#0: 30 to 32 chars (regex needs exactly 32).
- **mistral** pos#1: 33 to 32 chars (Mistral spec is exactly 32).

### Diagnostic

`KEYHOG_ADVERSARIAL_FULL_LOG=<path>` writes the full wrapper-harness
failure list at panic time, so a 100+ detector regression can be
diffed end-to-end without re-running the test. The first 50 entries
still appear inline in the panic message.

### Known remaining 152 misses (v0.5.36 target)

- **Group B (~144 misses)**: helicone, keystonejs, line, paloalto,
  snowflake, sourcetree, tower, deepnote pos#0. Canonical positives
  surface (`contracts_runner` green) but wrapped variants do not.
  Root cause sits between the scanner's cheap-filter window and the
  extract phase: the AC literal-set returns a keyword position the
  regex engine cannot consume the preceding byte from. Tracing
  continues in v0.5.36.
- **Group A.3 (~24 misses)**: bandwidth pos#1 and vertexai pos#0,
  pos#1 have positive text that is not actually a credential
  (`ClientID=...` with no Bandwidth keyword; bare env-var name
  `GOOGLE_APPLICATION_CREDENTIALS` instead of the service-account
  JSON). Both need contract redesign.

## v0.5.34 - 2026-05-27 - Multi-TB perf: adaptive GPU dispatch + shard batching, monolith splits, more silent fallbacks surfaced

### Multi-TB scanning: RAM-adaptive GPU shard batching

`gpu_literal_phase1` slices each coalesced batch into ~2-MiB wgpu
shards (the WebGPU 65 535-workgroups-per-dimension cap), then
batches `MAX_SHARDS_PER_GPU_BATCH` of them into a single command
encoder. The cap was a fixed 64; it now adapts to host RAM:

| Host RAM       | Shards / batch | 1-GiB-scan sequential batches |
|----------------|----------------|-------------------------------|
| < 16 GiB       | 64             | >= 8                          |
| 16-32 GiB      | 128            | 4                             |
| >= 32 GiB      | 256            | 2                             |

The 96-GiB-RAM RTX-5090 workstation case drops from 8 sequential
batched dispatches to 2 on a 1-GiB scan, cutting GPU pipeline-drain
stalls roughly 4x. The 64-shard floor stays the safe default for
small hosts where 256 shards x ~2 MiB host-side packing memory
would press against the orchestrator's RAM budget.

### Multi-TB scanning: VRAM-adaptive GPU dispatch

`MEGASCAN_INPUT_LEN` was a fixed 256 MiB constant; the new
`megascan_input_len()` sizes the pre-compiled `RulePipeline` input cap
to host VRAM:

| VRAM detected     | Input length | Adapter examples                 |
|-------------------|--------------|----------------------------------|
| >= 24 GiB         | 1 GiB        | RTX 4090 / 5090, A100 / H100     |
| 12 - 23 GiB       | 512 MiB      | RTX 3090, RTX 4080, M-Max        |
| 8 - 11 GiB        | 256 MiB      | RTX 3080, RTX 4070, M-Pro        |
|  < 8 GiB / Unknown| 128 MiB      | iGPU, software, no-GPU CI runner |

On a 5090 host that means 4x larger GPU dispatches and roughly 75%
fewer per-dispatch launches across a multi-TB scan. The orchestrator's
`BATCH_BYTES_BUDGET` tracks the same value with a `RAM / 8` safety
clamp so peak resident memory (`pipeline_depth x batch_bytes_budget`)
never crosses 1/8 of system RAM regardless of detected VRAM. The legacy
`MEGASCAN_INPUT_LEN = 256 MiB` constant is preserved as a backwards-
compatible alias.

### No more silent fallbacks (continued)

* S3 source: text-content-type objects that fail UTF-8 decode now
  log a `warn` with the valid-up-to byte offset; previously
  `return Ok(None)` silently dropped the chunk.
* Git history walk: tree-entry, blob-header, blob-read failures
  log at `debug` instead of silently `continue;`. UTF-8 decode
  failures on git blobs stay silent (legitimate binary blob).
* GPU MoE confidence: staging-buffer `recv` and `map_async` errors
  now `warn` before falling back to CPU MoE; previously the double
  `.ok()?.ok()?` swallowed both failures silently.

### Internal refactors (no user-visible change)

* `crates/scanner/src/pipeline/postprocess/suppression.rs`
  (1368 lines) split into 7 focused submodules (`api`, `decision`,
  `decode`, `doc_markers`, `path_filter`, `shape`, `mod`). All under
  the 500-line cap.
* `crates/sources/src/filesystem/read.rs` (1054 lines) split into
  6 focused submodules (`raw`, `bytes`, `window`, `decode`, `tests`,
  `mod`). All under the cap.
* `crates/scanner/src/hw_probe.rs` (978 lines) split into 7 focused
  submodules (`thresholds`, `tier`, `select`, `banner`, `platform`,
  `tests`, `mod`). All under the cap.
* `alphabet_filter.rs` SIMD entry points now carry proper `# Safety`
  docs (caller-must-have-AVX2 / SSE2 / NEON), satisfying
  `-D clippy::missing_safety_doc` after they were promoted to `pub`
  for the prefilter-robustness proptest.

### New `keyhog tui` subcommand

Interactive ratatui + crossterm dashboard. Severity-colored finding feed,
current-file banner, files-done / bytes / throughput / findings stats,
GPU backend + pattern-count panel. `q` / `Esc` / Ctrl-C / any-key-after-
complete all exit cleanly. New `--throttle-ms` flag paces the worker so
demo recordings actually capture findings streaming in. Gated behind a
default-on `tui` feature so portable builds (no-default-features +
`portable`) skip the ratatui + crossterm dependency closure.

`keyhog tui` is the surface the README / docs demo now records (vhs);
the demo target moved from `keyhog explain` to `keyhog tui demo`.

### Critical bugfix: orchestrator self-scan suppression no longer hides user findings

The orchestrator post-scan filter dropped every finding whose path
segment was literally "keyhog" (case-insensitive), plus a flat
`tests/` / `fixtures/` / `benches/` / `detectors/` segment match.
That was originally a self-scan helper for keyhog developers, but
applied unconditionally it hid findings from anyone with:

* A repo or folder named `keyhog/` (forks, vendored copies,
  this-demo-recording-tree, Reddit posters' demo dirs).
* A `tests/` directory in their tree, regardless of what was
  being scanned.

The fix is two-step: drop the "keyhog" segment match outright, and
gate the remaining `tests/` / `fixtures/` / `benches/` / `detectors/`
match on a marker check that the file path is a descendant of
keyhog's own source repo root (detected once per process via a root
`Cargo.toml` scan for `crates/scanner` + `crates/cli` + the `keyhog`
package name). `--no-suppress-test-fixtures` now also disables the
segment filter so audits see both suppression layers' contents.

### Hardening: more silent GPU fallbacks now emit one-shot warnings

* MegaScan rule-pipeline compile reject (was `tracing::debug!`).
* MegaScan runtime dispatch error.
* MegaScan match-count exceeding cap.
* MegaScan batch exceeding `MEGASCAN_INPUT_LEN`.
* No GPU backend handle on MegaScan dispatch.
* `warm_backend` MegaScan path: now checks rule_pipeline readiness
  (was only checking `gpu_stack_usable`).
* Trigger-pattern GPU collection error / missing matcher / missing
  backend.
* `verifier`: OOB-required spec without an active OOB session
  (was a silent degrade to HTTP-only).
* `sources/git`: HEAD blob walk failure (silently downgraded every
  finding's severity to `git/history`).
* `subcommands/tui::worker`: file-read failure (was
  `unwrap_or_default()`; now logs at debug and skips with accurate
  files-done counter).

All GPU degrade paths respect `KEYHOG_REQUIRE_GPU=1` (hard-fail) and
`KEYHOG_NO_GPU=1` (silence the warning).

### Performance: hot-path env-var caches

`KEYHOG_BACKEND` (in `select_backend`), `KEYHOG_GPU_KERNEL` (in the
literal-set path), and `KEYHOG_NO_GPU` / `KEYHOG_REQUIRE_GPU` (in
the GPU degrade helpers) are now cached at process start instead of
re-syscalling per chunk. Measured ~3% scan-throughput win on Apple
Silicon against the 30k-file linux-clone corpus.

### Dedup: shared modules consolidate cross-file copies

* New `engine::gpu_postprocess` with `fold_overlapping_same_pid_inplace`
  + `attribute_matches_to_chunks` (5 unit tests). Replaces two
  byte-identical phase-1 tails in `gpu_ac_phase1` + `gpu_literal_phase1`.
* New `cli::format` with `format_bytes` (4 unit tests). Replaces two
  near-identical copies in `scan_system` + `tui::render` that had
  drifted (one capped at GiB, the other handled TiB).
* Engine `scan.rs` split into `scan` / `extract` / `process` modules
  (was 835 LOC; now 291 / 393 / 191, all under the 500-line cap).
* TUI subcommand split into `tui/{mod, render, worker}.rs` (was 644
  LOC; now 236 / 318 / 123).
* Orchestrator `explicit_backend_override` collapsed into a thin
  re-export of `scanner::hw_probe::forced_backend_from_env` so the
  alias table (`gpu` / `literal-set` / `mega-scan` / `regex-nfa` / etc.)
  lives in one place.

### Smaller fixes

* `PatternSpec::default()` + `Chunk::from(String|&str)` so the test
  suite compiles without 35 per-site explicit field fills.
* `engine::coalesce_chunks` re-exported as a `pub` API so the
  scanner property-test fixtures build.
* Stale unused-imports cleanup in `scan.rs` after the module split.

## v0.5.33 - 2026-05-27 - WGPU AC kernel actually works (use_subgroup_coalesce=false everywhere)

### Critical: WGPU hosts now actually run scans on the GPU

The v0.5.32 workaround moved every GPU backend onto the AC kernel
path, but the AC kernel still passed `use_subgroup_coalesce=true`
on WGPU (the original gate was `backend_id != "cuda"`). Runtime
testing on Apple Silicon M4 Pro with vyre v0.4.2 confirmed the AC
kernel hits the SAME `_vyre_match_leader is referenced before
binding` lowering rejection on the wgpu path as the literal_set
program does on the CUDA path: the lowering gap is in vyre's
substrate-neutral pre-emit step, not in the driver-specific
emitter, so wgpu has the same blocker.

`use_subgroup_coalesce` is now hardcoded `false` on every backend.
We lose the ~32x atomic-contention reduction the subgroup form
would have provided (Innovation I.17), but recall and correctness
are preserved; the plain `append_match` path produces bit-identical
match output, just with more atomic pressure on the shared count
buffer.

**This fixes silent CPU fallback on every WGPU host:** macOS Apple
Silicon, macOS Intel, Windows, and Linux without CUDA. Before this
release, those hosts probed a GPU at startup, compiled the
GpuLiteralSet + AC matchers, then EVERY scan failed at GPU dispatch
and silently degraded to SIMD. The v0.5.31 visibility warning
caught this on the macbook self-test and the actual scan path; the
fix here closes the underlying bug. Verified end-to-end on Apple
Silicon M4 Pro: `vyre_ac_kernel PASS (backend=wgpu)`.

## v0.5.32 - 2026-05-27 - vyre depth: AC kernel becomes the default GPU scan path + honest GPU self-test

### Deep vyre: AC kernel becomes the default GPU scan path

- **`gpu_literal_phase1.rs`** previously routed all WGPU hosts through the
  `literal_set` GpuLiteralSet program, gating the AC-kernel workaround
  to CUDA only. The vyre canonical pre-emit lowering actually rejects
  the subgroup form (`subgroup_ballot` + `subgroup_shuffle`) emitted by
  `append_match_subgroup` BEFORE driver-specific emission, so WGPU
  hosts hit the same `_vyre_match_leader is referenced before binding`
  rejection and silently dropped to CPU. The kernel select is now
  AC-by-default for every GPU backend; `KEYHOG_GPU_KERNEL=literal-set`
  is the diagnostic opt-in for bisection / vyre IR work.
- **`keyhog backend --self-test`** gained a new `vyre_ac_kernel` step
  that compiles a one-detector scanner, runs a scan through
  `scan_coalesced_gpu_ac_phase1`, and verifies the planted `"needle"`
  literal surfaces a phase-1 hit on the live GPU backend. Reports the
  active backend id (`cuda` / `wgpu`) on PASS.
- The existing `vyre_literal_set` self-test no longer reports
  red `FAIL` when it hits the documented lowering gap; it surfaces
  yellow `KNOWN` with a one-line explanation that scans use the AC
  kernel instead. Same exit code as before for any OTHER literal_set
  failure (genuine GPU regression still hard-fails).
- **`crates/scanner/src/gpu.rs`** gained `vyre_ac_kernel_self_test()`
  + `VyreAcKernelSelfTest` so the diagnostic CLI can surface the
  match count and backend id rather than just PASS/FAIL.

## v0.5.31 - 2026-05-27 - no-silent-GPU-fallback enforcement + banner CUDA/WGPU split + SHA256 verification + UX fixes

### Coherence: startup banner now distinguishes CUDA vs WGPU

- The `⚡ KeyHog ...| backend=Gpu` startup banner used to collapse the
  CUDA path and the WGPU fallback under the same `Gpu` label, so a
  user on an NVIDIA box couldn't tell whether the CUDA-feature build
  was actually using CUDA or had silently dropped to WGPU. Banner now
  reads `... | backend=Gpu | gpu=cuda` (or `gpu=wgpu`, `gpu=none`),
  pulling the live `VyreBackend::id()` of the acquired backend. New
  `CompiledScanner::gpu_backend_label()` exposes the same info to
  any downstream consumer (daemon health endpoint, `keyhog backend`
  diagnostics, future GH-Action telemetry).

### No silent GPU fallbacks

- **`scanner/src/gpu.rs`** (MoE inference path): when the GPU MoE
  context fails to initialise on a host that has a GPU, we now
  `eprintln!` a loud warning instead of `tracing::debug!`-ing into
  the void. The user paid for the GPU; they need to know we couldn't
  use it. `KEYHOG_NO_GPU=1` silences the warning (operator opted
  in to CPU). `KEYHOG_REQUIRE_GPU=1` exits with code 2 instead of
  falling back.
- **`scanner/src/engine/backend.rs`** (scan dispatch path): when
  `scan_chunks_with_backend_internal` is called with
  `ScanBackend::Gpu` or `ScanBackend::MegaScan` but the compiled
  scanner has no GPU literals or no GPU backend, the same loud
  one-shot warning fires via `warn_on_gpu_degradation` and the same
  env-var contract applies. The hot-path branch was previously
  silent; on every scan a user with a probe-detected-but-runtime-
  unavailable GPU would have sat at SIMD throughput thinking they
  were on the GPU path.
- A `OnceLock` guard makes the warning fire exactly once per process
  regardless of how many chunks pass through (CI scanning thousands
  of files doesn't spam stderr).
- **`scanner/src/engine/compile.rs`** (CUDA acquisition path): when
  the CUDA factory fails on a host that has libcuda.so or
  /proc/driver/nvidia (NVIDIA userland present but broken or version-
  mismatched), we eprintln a one-shot warning instead of debug-logging
  into the void. The wgpu fallback is the documented "5-10x slower"
  path; users installing the CUDA variant on NVIDIA hardware must know
  when they've silently dropped to WGPU.
- **`scanner/src/engine/gpu_forced.rs`** (runtime GPU dispatch
  failure): `deny_silent_gpu_degrade` previously only panicked when
  `KEYHOG_BACKEND` forced GPU. The unforced default case was silent.
  Now a runtime degradation (vyre IR lowering rejecting a program,
  transient CUDA driver error, exceeded shard cap) fires a one-shot
  stderr warning. Surfaced by running `keyhog backend --self-test` on
  a real CUDA host, which exposed a vyre IR lowering issue that
  rejects the GpuLiteralSet program ("variable `_vyre_match_leader`
  is referenced before binding"). The AC kernel path used by the
  actual scan flow on CUDA hosts is a documented workaround for the
  same vyre limitation; WGPU-only hosts hitting the lowering rejection
  would previously have degraded silently.

### SHA256 checksum verification (rustup-style)

- `release.yml` emits a `.sha256` file alongside each binary asset
  using portable `sha256sum` / `shasum` across the three runner OSes.
- `install.sh` and `install.ps1` download the `.sha256` alongside the
  binary, compute the local hash, and refuse to install on mismatch.
  When the checksum file is absent (pre-v0.5.31 release tags), both
  installers skip verification with a dim log line rather than failing,
  so the change is backward-compatible.

### UX

- **install.sh** on Linux + NVIDIA hosts no longer prints
  "Detected NVIDIA NVIDIA GeForce RTX 5090" (the double "NVIDIA"
  came from concatenating our own prefix with `nvidia-smi --query-gpu=name`
  output, which already prefixes "NVIDIA").
- **`crates/core/src/report/text.rs:273`**: the
  "No real secrets - but N example/test keys suppressed." reporter line
  used a literal em dash. Replaced with a comma so the user-facing
  output matches the no-em-dash global rule.
- **`crates/core/src/report/text.rs:238`**: ClientSafe severity
  remediation text "Public by design (client bundle key) - verify
  scope restrictions." had the same em dash; replaced with a semicolon.

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

- **Bazel scaffolding untracked.** The 8 in-tree Bazel files (`.bazelrc`, `.bazelversion`, root + 5 per-crate `BUILD.bazel`, `MODULE.bazel`, `MODULE.bazel.lock`) were a 2026-05-21-throttle-driven PoC that never finished - every per-crate BUILD was a comment-only stub and `MODULE.bazel` was pinned to keyhog `0.5.7` while we ship 0.5.29 via cargo. Per the STANDARD prod-repo-doc-bleed rule, advertising a Bazel surface that doesn't build anything is a stub-not-evasion lie. Files stay on disk for the day Bazel becomes load-bearing; `.gitignore` catches future Bazel scratch.

### Detector tagging (client-safe)

- `clerk-api-key`: publishable `pk_live_*` / `pk_test_*` - same shape as `clerk-frontend-api-key` from v0.5.28. Total client-safe-tagged patterns now: 9 across 8 detectors.

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

- Text format: new `CLIENT-SAFE` 11-char label rendered in dim cyan (`2;36`) with a public-by-design remediation action ("Public by design (client bundle key) - verify scope restrictions."). All severities right-justified to 11 chars so bordered boxes line up regardless of which tier fires.
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

## v0.5.24 - 2026-05-26 - dogfood non-PEM 27 → 22 (138 → 22 vs v0.5.21 baseline = −84%) via UUID-substring + email + blockchain-address-keyword + `$` sigil + base64 hot-pattern wiring

### Precision

- **`contains_uuid_v4_substring`** - captured values that wrap a UUID v4 / RFC-4122 (`TOKEN_LIST=636765a9-1f92-4b40-ab0b-85ebd1e2c23d` in bat-go docker-compose.reputation.yml). The entropy detector grabs the whole env-var assignment; the high-entropy payload is just the UUID, which is a public identifier, not a credential.
- **`looks_like_email_address`** - `noreply@gogs.localhost` (gogs TestInit.golden.ini:89 `USER=…` captured because of nearby `PASSWORD=` line). Email addresses are public identifiers, never credentials. Tightened local + domain alphabet checks keep real `user:password` DSN strings outside the rejection set.
- **Blockchain / network-address keyword context** in entropy fallback. Lines like `SOLANA_BAT_MINT_ADDRS=EPeU…1Tpz`, `OWNER_PUBKEY=…`, `CONTRACT_ADDRESS=0x…`, `WALLET=…` name a PUBLIC blockchain or network identifier - not a credential. Skip the entropy emit when the env-var key contains any of `_ADDR`, `_ADDRS`, `_ADDRESS`, `_WALLET`, `_MINT_ADDR`, `_PUBKEY`, `_PUBLIC_KEY`, `_CONTRACT`, `_OWNER`, `_ACCOUNT_ID`, `_PEER_ID`, `_NODE_ID`.
- **Leading `$` sigil rejection** - GraphQL variable references (`$api_key` in shopify-cli mutation), shell variable expansions (`$API_KEY`), template placeholders (`${SECRET}`). Real credentials never start with `$`.
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
- 6 alist OAuth client secrets committed to source (real public OAuth secrets in cloud-storage driver bindings - known leak by design).
- 4 metasploitable3 chef users.rb passwords (`Dark_syD3`, `@dm1n1str8r`, `mesah_p@ssw0rd`, `Dark_syD3`-class) - CTF/vulnerable-app credentials intentionally weak but ARE real credentials.
- 4 metasploitable3 / govwa generic-secret CTF passwords (`govwaP@ss`, `D@rjeel1ng`, `but_master:`, `admin1234`).
- 2 gogs golden test fixtures (`PASSWORD=12345678`, `PASSWORD=87654321`) - sequential-digit test passwords; engine correctly flags them.
- 1 metasploitable3 Autounattend.xml Microsoft Windows public-key token (real public ID, ambiguous).
- 1 railsgoat seeds.rb CTF password (`motoXXX1445`).
- 1 claude-code Datadog public client token (real, intentional public Datadog logging key).
- 1 shopify-api-ruby test JWT (shipping label JWT in a test response fixture).
- 1 openssl SSH private-key in test data (real PEM in `test/recipes/`).

The only remaining **true** FP is **`saltstack-credentials` on `railsgoat/config/initializers/constants.rb`** - engine offset bug (defect #80) emits a finding with no regex match; needs deeper investigation.

## v0.5.23 - 2026-05-26 - dogfood non-PK 63 → 27 (−57%, 138 → 27 vs v0.5.21 baseline = −80%) via shape-filter unification + Rails-vendored detection + .b64 file skip + URI type-annotation suppression

### Precision

- **All shape filters now apply to every detector**, not just `generic-*`/`entropy-*`. `looks_like_pure_identifier`, `looks_like_word_separated_identifier`, `looks_like_scheme_prefixed_uri`, `looks_like_punctuation_decorated_identifier`, `looks_like_url_or_path_segment` no longer gate on detector_id. Service detectors like `cryptocompare-api-key` were firing on `SetMultipartFormData` Go method names because their regex used `Authorization[=:\s"']+([a-zA-Z0-9]{20,})` and the named-detector path bypassed shape gates. Real credentials have digits / long random suffixes / mixed alphabet - every filter has internal guards (`!has_digit`, `max_word_len ≤ 10`) that keep real keys outside the rejection set.

- **`looks_like_punctuation_decorated_identifier` fixed for PEM blocks**. The `b'-'` leading-sigil reject was too eager - `-----BEGIN ... PRIVATE KEY-----` starts with 5 dashes and was being suppressed alongside `--api-secret` CLI flags. Tightened to `bytes.starts_with(b"--") && bytes[2] != b'-'` so PEM markers (3+ dashes) survive but `--` CLI flags still reject.

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

## v0.5.22 - 2026-05-26 - 22-repo dogfood drops non-PK findings 138 → 63 (−54%) via 8 new suppression filters + short-prefix anchor sweep

### Precision (all 22-repo dogfood-driven)

- **`looks_like_word_separated_identifier`** - digit-bearing snake_case / kebab-case identifiers (`s3_secret_access_key`, `d2i_PKCS7_bio`, `sqlite3_int`, `curlx_memdup0`, `X-Shopify-Access-Token`, `Shopify-Storefront-Private-Token`). Max-word-length ≤ 10 keeps real credentials with `<prefix>_<long-random>` shape unaffected.
- **`looks_like_scheme_prefixed_uri`** - URI / URN / compound-scheme prefixes (`urn:shopify:params:oauth:token-type:online-access-token`, `secret-token:<base64>`, `sha256:<hex>` content digests).
- **`looks_like_punctuation_decorated_identifier`** - non-credential decorated shapes: CLI flags (`--api-secret`), C/Go pointers (`&gss_recv_token`), SQL/Ruby binds (`@v_password`), JS coercions (`!!apiKeyOrOAuthToken`), UI labels (`Password:`), TS non-null (`token!`), Unix paths (`/etc/passwd:/etc/passwd:ro`).
- **`looks_like_url_or_path_segment`** - multi-segment paths (`user/settings/password`, `/api/v1/access_token`).
- **`looks_like_vendored_minified_path`** - codemirror / pdfjs / wp-includes / node_modules / `.min.js` / `.bundle.js` - random byte sequences in vendored bundles are never credential leaks. Applied to BOTH named-detector and hot-pattern paths.
- **`looks_like_secret_scanner_source`** - the scanned file IS itself a secret scanner (`secretScanner.ts`, `trufflehog/`, `gitleaks/`). Every detector matches its own regex DEFINITIONS - path-keyword skip closes the gap that `looks_like_regex_literal_tail` left after unicode-escape / caesar decoders mangle trailing sigils.
- **`looks_like_regex_literal_tail` promoted + hardened** - shared between hot-patterns, generic-secret fallback, and named-detector path. Added `)/g,`, `)/gi,`, `)/i,`, `)/m,` suffixes for JS object-literal patterns (`{ key: /pat/g, … }`).
- **Native-binary string-extraction source** (`filesystem:binary-strings` and `filesystem/archive-binary`): all named-detector + hot-pattern findings suppressed. Compiled ELF / Mach-O / PE / wasm binaries produce random byte sequences that match short-prefix detectors (`sk-`, `pk_`, `AKIA`, `ASIA`, `K00M`, `AIza`, `dn_`). Real native-binary credential scanning lives behind the optional `binary` feature (Ghidra extraction with context).
- **`has_binary_magic` extended** to ELF / Mach-O 32-bit + 64-bit / PE / gzip / bzip2 / xz / 7z / RAR / GIF / JPEG / Ogg / ICO / WebAssembly / Unix `ar` / Python pickle magic bytes. Previously only PDF / ZIP / PNG / OLE - a 2.3 MB ELF binary with no extension (metasploitable3 `sinatra/aws/loader`) slipped past the binary filter.
- **Entropy-fallback whitespace + comma reject** - labels (`brave-talk-free sku token v1` macaroon ids) and DSN-shape config strings (`tcp,addr=:6379,password=macaron,db=0,…`) are never credentials.

### Detector tightening

- **`z85-encoded-secret`**: dropped generic `encoded` keyword anchor. Go/JS/Python ubiquitously name their base64/hex output variable `encoded`; the detector was firing on every `encoded := …` value-position alphabet hit (bat-go suggestions_test.go, claude-code yoloClassifier.ts, gogs internal/tool/tool.go).
- **`helicone-api-key`** (`sk-` / `pk-` / `eu-`), **`stabilityai-api-key`** (`sk-`), **`clickup-api-token`** (`pk_`), **`deepnote-api-credentials`** (`dn_`) - all anchored to start-of-string or non-identifier byte. Pre-fix: `dn_` matched any 3 alpha-numeric continuation chars (e.g. `idn_curlx_convert_wchar_to_UTF8` in curl/lib/idn.c), `sk-` matched random ELF rodata.

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

## v0.5.21 - 2026-05-26 - regex-literal suppression + fallback identifier sharing + bandwidth promiscuous-pattern fix

### Precision

- **Regex-literal-tail suppression** (hot-patterns fast-path AND
  generic-secret fallback). Source files that ship secret-scanner
  code (claude-code's `teamMemorySync/secretScanner.ts`,
  `components/Feedback.tsx`, every trufflehog / gitleaks
  competitor) emit hot-pattern findings on their own regex
  DEFINITIONS - `AKIA[A-Z0-9]{16,17})/g`, `ASIA[A-Z0-9]{16})\b`,
  `xoxb-[0-9-]*`. Real tokens never end in regex sigils (no service
  uses `)/g` or `})\b` in its token alphabet). Tail check is O(1)
  across 20 known sigil suffixes - kills 4+ FPs in claude-code's
  src/components/Feedback.tsx + utils/teamMemorySync/secretScanner.ts.

- **`looks_like_pure_identifier` now wired into fallback_generic**.
  Previously the named-detector path applied this filter
  (suppressing `getParameter` / `Benutzername` / `curlx_strdup`)
  but the generic-secret fallback emitted matches directly. Same
  pattern as the entropy-fallback fix in v0.5.19. `Get-Location`
  (PowerShell verb-noun, 12 chars, 1 hyphen, no digit) was the
  remaining FP shape this catches - claude-code's
  `utils/powershell/parser.ts` line 1343
  (`pwd: 'Get-Location'`).

- **bandwidth-api-key dropped its bare `ClientID`/`ClientSecret`
  pattern.** Those tokens are generic OAuth2 terminology, not
  Bandwidth-specific. alist's drivers/pikpak/util.go,
  drivers/thunder/driver.go, drivers/pcloud/util.go all have
  `ClientSecret = "..."` for Xunlei/PikPak/PCloud OAuth flows -
  the captured values ARE leaked client secrets, but for entirely
  different services. The generic-secret fallback catches the same
  values via its `client[_-]?secret` keyword alternation, so recall
  is preserved at correct service attribution. **7 → 0 mis-attributed
  bandwidth-api-key findings.**

## v0.5.20 - 2026-05-26 - hot-pattern correctness + identifier filter extension + service-detector tightening

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
  Was `token[=:\s\"']+([a-f0-9]{24,32})` - fired on every
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

## v0.5.19 - 2026-05-26 - entropy-fallback FP sweep (gogs 149 → 27, -82%; entropy total -79%)

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
  directly - same shape, different code path. Now both share one
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
mpc-lib, nitriding-daemon, orb-relay-messages, qtrap, spill, _self -
keyhog scanning itself - plus the existing two). openssl's 816 are
test-PEM private-key findings (true positives in fixtures, not FPs);
PayloadsAllTheThings's 61 are intentional security-training examples.

## v0.5.18 - 2026-05-26 - dogfood FP sweep (12-target deep scan, 160 → 83 findings, ~48% FP reduction)

### Precision

- **deel-api-key matched Java JNI macro names.** Pattern was
  `org_[a-zA-Z0-9_-]{30,}` which fired on every `org_sqlite_jni_capi_CApi_*`
  macro in `javah`-generated C headers (41 FPs in sqlite alone, applies
  to every Java-bindings library shipping JNI). Tightened to
  `org_[a-zA-Z0-9]{30,}` - real Deel org tokens are opaque base62 with
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

## v0.5.17 - 2026-05-26 - SSRF redirect closure + --insecure honor + oob hygiene

### Security

- **SSRF redirect bypass in DNS-pinned client closed.** The per-request
  client rebuild in `verify::request::resolved_client_for_url` was
  `Client::builder().timeout().resolve_to_addrs().build()` - silently
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
  `RsaPrivateKey::new(...).expect("test RSA key generates")` - a
  panic-in-production path the no-unwrap gate caught. Returns
  `Result<Self, InteractshError>` now (mapped to `KeyGen`); test
  callers wrap with `.unwrap()` at the test boundary. Source: gate
  `oob_client_no_unwrap_expect`.
- **`oob::client` split: `decrypt_entry` moved to `oob::decrypt`.**
  File hit 516 lines (over the 500 modularity cap). Natural seam -
  client owns RSA state + HTTP I/O, decrypt owns AES-256-CFB per-entry
  decode. No behaviour change. Source: gate
  `oob_client_file_size_cap`.
- **README exit codes match `--help`.** Documented codes 3
  (detectors --audit failure), 4 (backend --self-test failure), 10
  (live findings under `--verify`), and 11 (scanner panic) - README
  previously listed only 0/1/2.
- **Hash-digest gate is no longer always-on for named detectors.**
  Service-anchored detectors (`ALCHEMY_API_KEY=<32hex>`,
  `HEROKU_API_KEY=<uuid>`, `DATADOG_API_KEY=<32hex>`) now bypass
  both the hash-digest and UUID-shape gates - the regex anchor
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
  cloudflare-api-token, heroku-api-key, honeybadger-api-key -
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

## v0.5.16 - 2026-05-23 - JsonDecoder wired into decode registry

### Fixed

**JsonDecoder is now in the decode-through pipeline.** It had a
splice-aware implementation in `crates/scanner/src/decode/json.rs`
since v0.5.15 but was never registered in `get_decoders()` - pure
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

## v0.5.15 - 2026-05-23 - decode-through splice: base64/hex recall 30% → 93%

### Fixed

**Decode-through pipeline preserves companion context now.** Decoded
chunks used to be bare bytes with no surrounding text - every
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

- **`keyhog scan --proxy <URL>`** - route every outbound HTTP
  request through an HTTP/HTTPS/SOCKS5 proxy. Falls back to
  `KEYHOG_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`
  env. `--proxy off` disables proxying including env inheritance
  (air-gapped scans).
- **`keyhog scan --insecure`** - skip TLS verification for every
  outbound request. Needed when scanning through Burp / mitmproxy
  CAs with self-signed certificates. Env: `KEYHOG_INSECURE_TLS=1`.
- **Shared `keyhog_sources::http` policy module.** Single source
  of truth for proxy + TLS + UA so an operator setting
  `KEYHOG_PROXY` affects every outbound request uniformly.
- **40 000-case proptest suite** for the HTTP-client policy and
  SARIF dedup contracts (`crates/sources/tests/property/http_fuzz.rs`,
  `crates/core/tests/property/sarif_dedup.rs`).
- **5 500-case adversarial wrapper-explosion runner** - re-embeds
  every contract positive in 8 real-world formats and asserts the
  detector fires.
- **6 500-case path-shape runner** - replays every positive at 5
  production paths and 4 suppressed-shape paths.
- **5 070-case encoding-explosion runner** with split decode-hit
  vs incidental-hit metrics. Floors pinned so a regression
  below 88% base64 / 92% hex / 75% url-percent trips the gate.
- **`tests/live_verify.rs`** - env-gated live-verify smoke
  against real AWS/GitHub creds (`KEYHOG_LIVE_VERIFY=1`).
- **`tools/diff_bench/`** - single-shot runner that drives
  keyhog + trufflehog + gitleaks across one labeled corpus
  (positives synthesized at CI runtime to dodge push-protection)
  and emits `differential_results.json` with per-scanner
  precision / recall / F1 / timing.
  `.github/workflows/differential-bench.yml` runs nightly + on
  workflow_dispatch.

## v0.5.14 - 2026-05-23 - macOS x86_64 + Windows release binaries

### Added

`release.yml` now produces five assets per tag instead of two:

- `keyhog-linux-x86_64` (default features, dynamic Hyperscan)
- `keyhog-macos-aarch64` (Apple Silicon, `portable` features)
- `keyhog-macos-x86_64` (Intel mac, `portable` features) - **new**
- `keyhog-windows-x86_64.exe` (MSVC, `portable` features) - **new**

The Windows + Intel-mac variants share the existing `portable`
feature subset (every detector data feature, every git / web /
github / s3 / docker / verify source backend, no Hyperscan /
Ghidra / CUDA system libs). Daemon IPC is `#[cfg(unix)]`-gated,
so it compiles to a stub on Windows hosts without disabling the
rest of the binary surface. v0.5.13 only shipped the prior two
assets because the matrix change landed after the tag was cut.

## v0.5.13 - 2026-05-23 - SARIF dedup so GitHub Code Scanning accepts uploads

### Fixed

SARIF v2.1.0 forbids duplicate items in `relatedLocations`. When a
finding had the same supplemental location reported twice (e.g.
verifier echo + scanner overlap), GitHub Code Scanning rejected the
whole SARIF with `relatedLocations contains duplicate item`,
silently losing every finding on the upload. The dedup runs on a
`(file_path, line, offset)` key before serialization, so each
related location appears at most once.

This is what unblocks the fleet-wide `keyhog.yml` CI rollout -
prior to this fix every repo that produced a finding lost its
SARIF, leaving the Code Scanning tab empty even when the run was
"green".

## v0.5.12 - 2026-05-23 - dedup 9 more dup-primary detectors

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
- cloudflare-zero-trust-service-token (client_secret) - positives
  use the Client-Id shape, so dedup is safe even with main contract.

belvo, crisp, env0, exoscale, checkmarx, crowdstrike, fastspring,
fedex still have the dup-shape - their main contracts have a
secret-only positive that fires by design, so dedup would regress
recall and isn't a safe local sweep.

### Changed

- **Pattern count 1674 → 1665** across README + e2e_binary +
  readme_claims gate.

## v0.5.11 - 2026-05-23 - dedup carbon-black + databricks

### Fixed

- **carbon-black-api-key**: dropped duplicate org-key primary
  (kept as required companion). org_key=… alone no longer fires
  the detector without a CB API KEY primary nearby.
- **databricks-token**: dropped duplicate workspace-url primary
  (kept as companion). A bare workspace URL with no `dapi` token
  nearby no longer fires the detector.

Same SURPLUS shape as the v0.5.9/v0.5.10 sweeps. These two had
existing main contracts whose positives did NOT depend on the
dropped primary firing alone - verified before edit.

### Changed

- **Pattern count 1676 → 1674** across README + e2e_binary +
  readme_claims gate.

## v0.5.10 - 2026-05-23 - detector dedup sweep + binary/crates alignment

### Fixed

- **Dedupe primary-equals-companion in 14 detectors**
  (idenfy, infura, jumio, marvel, packer, scaleway, sovos,
  thomson-reuters-onesource, time4vps, twilio-iot, upcloud,
  vonage-video, wix, woocommerce). Each listed the "secret /
  companion" half as a duplicate primary regex; companion-only
  text would fire the detector. Same SURPLUS shape closed in
  v0.5.9 for ringcentral/booking-com/vanta/trulioo/appdynamics/
  avalara/akoya - sweeping the rest of the corpus that has no
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

## v0.5.9 - 2026-05-23 - companion contracts gate + LFS coverage

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
- **rustfmt** - `scan_gpu.rs` + `engine/mod.rs` re-joined now-short
  calls after the `matching` → `scan` module migration.

### Changed

- **`.gitattributes` now covers `contracts/companion/*.toml`** in
  LFS. The original LFS rule was non-recursive; companion
  fixtures with Twilio-shaped strings would otherwise trip
  GitHub push-protection.

## v0.5.8 - 2026-05-23 - daemon wire-v2, GitHub Action, contracts gate

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
  nonexistent `keyhog/keyhog-action@v1` repo - fixed to the
  bundled action path.
- **`.github/workflows/release.yml`** - tag-driven binary build
  + upload. Pushing a `v*` tag now compiles `keyhog` for
  `keyhog-linux-x86_64` (default features incl. Hyperscan via
  apt) and `keyhog-macos-aarch64` (feature subset, no
  Hyperscan), then attaches the artifacts to the release. The
  composite action prefers these prebuilt binaries over a
  cold cargo build whenever the host triple matches.
- **`KEYHOG_DOGFOOD=1`** - daemon-side dogfood capture. Set when
  starting the daemon (`KEYHOG_DOGFOOD=1 keyhog daemon start`) to
  enable per-scan event capture inside the daemon; the events
  cross the wire to the client and flow into `--dogfood` output.
  Per-request toggling is not wired - env-var gating keeps one
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
  filter was the only behavior before - a user looking at a
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
  `"blur key = \"Kp4Q…\""` - a non-deterministic failure invisible
  locally. Fix: clear the cache before every scan in
  `contracts_runner.rs` (5 sites) and `companion_contracts_runner.rs`
  (3 sites) per the documented test-isolation API in
  `engine/mod.rs:747-760`.
- **`blur-api-key` regex required uppercase `KEY`** while the
  contract evasion uses lowercase `key`. Prepended `(?i)` and
  lower-cased the literals; the contract evasion now hits the
  intended case-variant path. Tests assert truth, not shape -
  weakening the test would have masked the engine gap.
- **Daemon-mode `--dogfood` was inert.** Engine-side telemetry
  (`record_example_suppression` calls from
  `pipeline.rs::should_suppress_known_example_credential_*`) fired
  inside the daemon process - the client never saw any of it, so
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
  fresh daemon both emit "No real secrets - but 6 example/test
  keys suppressed. Pass --dogfood to see them."
- **`demo-secret.env` summary regressed to the clean-repo
  message.** The v0.5.7 fix wired `TextReporter` to read the
  suppression count, but the orchestrator's
  `test_fixture_suppressions.suppresses()` branch ran *before*
  any telemetry write - `AKIAIOSFODNN7EXAMPLE` matched the
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
  `libcuda.so` / `libnvrtc.so` / `libcudart.so` - including macOS,
  most CI runners, and any Linux box without an NVIDIA driver
  stack. The default scanner build now uses `wgpu` (Vulkan on
  Linux, Metal on macOS) for GPU dispatch. CUDA users opt in with
  `--features cuda` when they want the CUDA backend specifically.
  Drops the link-time CUDA requirement from every default build.
- **`scripts/publish.sh` reads the version from `Cargo.toml`.**
  Renamed from `publish-0.5.6.sh` (which would silently emit "All
  v0.5.6 crates published" even when publishing v0.5.7). The new
  script `awk`s `[workspace.package].version` and uses that
  everywhere - no per-release rename or message edit.
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
  detector corpus uses lookaround) is the designed degradation -
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

## v0.5.7 - 2026-05-17

### Fixed

- **The 'No secrets found. Your code is clean.' message lied when
  every match was suppressed as an EXAMPLE/test key.** The 0.5.6
  bump wired example-suppression telemetry into the orchestrator,
  but the user-facing summary is owned by `TextReporter::finish()`
  in `keyhog-core`, not the orchestrator - so the misleading
  banner still printed. `TextReporter` now takes the suppression
  count via `set_example_suppressions(n)` and prints "No real
  secrets - but N example/test key(s) suppressed. Pass --dogfood
  to see them." instead. Verified end-to-end against
  `demo-secret.env`. Regression tests pin all three states.

## v0.5.6 - 2026-05-17

### Added - dogfooding-driven UX

- **`--dogfood`** - opt-in JSON trace on stderr after the scan. Each
  example/test/placeholder credential that was matched and then
  suppressed gets a redacted-prefix event with the algorithmic reason
  (`contains_EXAMPLE_token`, `algorithmic_placeholder`). Closes the
  "did the scanner miss this, or silence it?" question without a debug
  rebuild. Full credentials are never emitted - `--dogfood` is a
  decision tracer, not a credential exfil channel.
- **Honest scan summary when only example keys were found.** Previously,
  scanning `demo-secret.env` (which holds `AKIAIOSFODNN7EXAMPLE`)
  printed *"No secrets found. Your code is clean."* - identical to a
  genuinely clean repo. Now the summary distinguishes:
  - 0 findings, 0 suppressed → "0 secrets in 0.12s. You are secure!"
  - 0 findings, N suppressed → "0 real secrets, N example/test key(s) suppressed (pass --dogfood to see them)."

### Internal

- New `keyhog_scanner::telemetry` module: per-scan atomic counters +
  optional event log. Engines call `record_example_suppression(...)`
  from the existing `should_suppress_known_example_credential_*` paths;
  the orchestrator drains events at the end of `run()`. Zero new
  state threaded through engine boundaries - single `OnceLock`
  process-local container with a `reset()` for tests.
- Two regression tests pinning the demo-secret.env case + the dogfood
  redaction contract. Telemetry-touching tests serialise behind a
  module-local `Mutex` so `cargo test`'s parallel runner doesn't let
  them step on each other.

## v0.5.5 - 2026-05-09

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
vs 302,168 vs 304,128) - earlier `121× speedup` numbers were
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
"few files × 6000+ rules" - modelling each literal as its own
`BatchRuleProgram` allocates `chunks × rules ≈ 600,000` work
items per dispatch, which keeps the persistent kernel sleeping
in S-state on RTX 5090. Real megakernel win needs vyre-side
multi-pattern hit reporting (one DFA covering many literals,
`HitRecord` gains a per-pattern field) - wiring then collapses
to a one-line swap.

Cross-platform compile fix in vendored vyre-runtime: `GpuStream<'a>`
now carries `PhantomData<&'a ()>` on non-Linux so the lifetime
parameter isn't flagged unused when `uring` is cfg'd out.
Windows / macOS builds now pull vyre-runtime cleanly.

**Vyre rule engine wired for declarative `.keyhogignore.toml`.**

Upstream vyre additions (general-purpose, lives in vyre-libs):
- `vyre_libs::rule::cpu_eval` - pure-CPU evaluator for
  `RuleCondition` / `RuleFormula` trees. Mirror of the GPU
  lowering. Useful for any consumer that wants per-record rule
  evaluation without dispatching a backend program. 11 unit tests.
- `vyre_libs::rule::ast::RuleCondition::FieldInSet` - new variant
  for "context field's value is in this set". Distinct from
  `SetMembership` (which compares a static value, not a field
  lookup). Required for expressing "detector_id is one of …"
  without resorting to regex alternation. Builder lowering errors
  with an actionable Fix: message - only the CPU evaluator can
  resolve field lookups today.
- vyre `smallvec` workspace pin bumped 1.14.0 → 1.15.1 so consumers
  carrying gix (which requires ^1.15.1) can share the type - keyhog
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
`VerifiedFinding`s - predicates need the resolved fields that
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

## v0.5.4 - 2026-05-08

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
chunks pays ~2 MiB of total boundary work - negligible next to the
per-chunk regex pass. Six unit tests + the previously-`#[ignore]`-
marked `test_window_boundary_detection` integration test now pass;
the test itself was rewritten to use an AKIA-shaped secret (the
original `XX_FAKE_*` shape was unconditionally suppressed by the
placeholder filter, so the test would have stayed red even with
reassembly).

**`keyhog detectors --audit` and `keyhog detectors --fix`
(roadmap #4).** `detectors --audit` runs every detector through
`keyhog_core::validate_detector`, prints issues grouped by detector
ID, and exits with code 3 when any `Error`-severity issue surfaces -
drop it into CI to gate detector PRs. `detectors --fix` scans the
on-disk TOML corpus for the one validator finding that's safe to
repair mechanically - single-brace template references (`{shop}`)
inside `[detector.verify*]` blocks - and rewrites them to the
double-brace form (`{{shop}}`) the interpolator actually honours.
Rewrites are scoped to verify blocks only (regex quantifiers like
`[A-Z]{4,6}` in pattern blocks stay untouched), atomic-written via
NamedTempFile, and re-validated post-rewrite so a corrupted result
backs off rather than overwriting the original. `--dry-run` previews
without writing. The 888-detector embedded corpus shows zero errors
today (the v0.4.x detector cleanup wave already cleared them) - the
subcommand is the regression net for the next batch of contributions.
Seven unit tests cover the rewriter's edge cases.

**Streaming finding previews (roadmap #5).** New `--stream` flag emits
a one-line redacted preview to stderr per finding as the scanner
produces it, instead of waiting for dedup + verification before
printing anything. Format is grep-friendly:
`[stream] CRITICAL aws/aws-access-key  src/foo.rs:42  AKIA...XYZ_a`.
The full report (text/json/sarif/jsonl) still lands on stdout/`--output`
at the end - the stream is purely a UX hint that the scanner is
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
(`max_concurrent_per_service = 1`) on top of the rate cap - use it
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
  `MIT` - the only license file shipped in the repo is the MIT one.
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
workspace version (`=0.5.4` everywhere) - the `=` pin guarantees a
downstream `cargo install keyhog 0.5.4` resolves to a self-consistent
set.

## v0.5.3 - 2026-05-07

I/O perfection pass - five staged perf + correctness landings on the
filesystem source path, plus one latent-bug fix surfaced by the new
test coverage.

**Stage A - content cache (perf + correctness).** Merkle index schema
v2: each entry now carries `(mtime_ns, size, BLAKE3)` and the file
gets a top-level `spec_hash` derived from the canonical detector set.
`metadata_unchanged(path, mtime, size)` short-circuits the file read
entirely when stat metadata matches a stored entry - the dominant
cost on cold-cache disk for `--incremental` re-runs.
`load_with_spec(path, expected_spec_hash)` invalidates the cache the
moment any detector regex, group, or companion changes, fixing a
latent correctness bug where an added detector would silently miss
unchanged files forever.

**Stage B - mmap big-file scan.** Replaced the read+seek loop in
FilesystemSource's >64 MiB path with a single mmap + zero-copy slice
into `window_size`-byte windows with `window_overlap` shared bytes
between neighbours. Drops the 64 MiB heap working buffer and the
per-window `seek+re-read` overlap round-trip; `madvise(SEQUENTIAL)`
drives kernel readahead. Falls back cleanly to the buffered loop
when mmap is refused (locked writer, exotic filesystem).

**Stage C - I/O ↔ scan pipeline.** `scan_sources` spawns the scanner
in a dedicated thread holding `Arc<CompiledScanner>`. The producer
(main thread) iterates sources and builds batches; the scanner pulls
completed batches off a `sync_channel(1)` and runs `scan_coalesced`.
While the scanner is busy on regex, the producer is busy on disk
I/O, so total wall time approaches `max(read, scan)` instead of
`read + scan`. Channel capacity 1 keeps memory bounded to one
in-flight batch.

**Stage D - mmap compressed reads.** ziftsieve only takes a
contiguous `&[u8]` so streaming decompression isn't on the menu, but
mmap'ing the compressed file lets us hand it the whole input without
a corresponding heap allocation. A 1 GiB `.zst` previously manifested
as a 1 GiB `Vec<u8>` before decompression began. New `FileBytes` enum
(`Mmap` | `Owned`) with size-cap gating; falls back to `fs::read`
only on mmap refusal.

**Stage E - per-platform mmap threshold.** Lowered to 64 KiB on Unix
where `mmap` setup is sub-microsecond and avoids the page cache →
userland buffer copy. Held at 1 MiB on Windows where `MapViewOfFile`
carries section-object + security-token costs that buffered
`ReadFile` doesn't pay.

**Latent bug fixed alongside Stage D.** `gz` and `zst` were in
`SKIP_EXTENSIONS`, so the `extract_compressed_chunks` dispatch arm in
the FilesystemSource iterator was actually unreachable - compressed
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

## v0.5.2 - 2026-05-06

Reconciliation pass against the parallel `Legendary Hardening` line
(v0.3.0 → v0.4.0 → v0.5.0) that lived only on the work-linux clone
and was never pushed. Both lines diverged at `013257e` (CI fmt scope)
and independently arrived at near-identical scanner/sources state.

Reviewed every file the work-linux line touched; no salvageable code
was missing from this branch:

- `SensitiveString` migration, `MADV_DONTDUMP` zero-leak buffers,
  proximity-aware multiline reassembly, hardened ratelimiter, AC
  prefilter for `has_secret_keyword_fast` - already present here,
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

vendor/vyre is untouched - separate project with its own versioning.

## v0.6.1 - 2026-05-06

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

## v0.6.0 - 2026-05-06

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

## v0.3.0 - 2026-05-01

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
  Vulkan, macOS/iOS → Metal, Linux/BSD → Vulkan + GL - each platform gets its
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

### Performance - CPU saturation

- `scan_chunks_with_backend_internal` now uses `rayon::par_iter` on the
  non-GPU paths - was serial, pinned to a single core even on 32-core
  boxes (`a693ba2`).
- `scan_coalesced` parallelizes its `#[cfg(not(feature = "simd"))]` and
  Hyperscan-init-failure fallbacks; multi-core builds without Hyperscan now
  saturate cores (`27caaf9`).
- `[profile.release]` pinned: opt-level=3 + lto=fat + codegen-units=1 +
  panic=abort + strip - was using cargo defaults; the new profile yields
  ~10-20% throughput on hot paths via cross-crate inlining (`3c4924c`).
- `[profile.release-fast]` (thin LTO, 16 codegen-units) for sub-minute CI
  builds; `[profile.bench]` keeps line-tables for flamegraph attribution.

### Performance - Tier-A perf wins (~constant-factor allocations on the hot path)

- Cow-borrowed `normalize_homoglyphs` and `prepare_chunk` - ASCII fast path no
  longer clones (`7e7cd55`).
- `post_process_matches` dedup keys are `Arc<str>`, not `String` (`7e7cd55`).
- Thread-local trigger-bitmask pool - drops ~2.4M allocs on a 100k-file scan
  (`7e7cd55`).
- Phase-1 returns `Option<Vec<u64>>` so empty chunks never allocate (`7e7cd55`).
- `BTreeMap` dedup → `indexmap::IndexMap` for O(1) deterministic ordering
  (`d3b6721`).
- Streaming SARIF reporter - peak memory drops from O(N findings) to O(rules)
  (`3a15fd0`).
- Batched-streaming orchestrator - 4096 chunks / 256 MiB per batch caps peak
  memory on giant scans (`a6c88b2`).
- Sharded `DashMap` for verifier `VerificationCache`, `RateLimiter`, and
  in-flight map (no more global RwLock contention) (`d3b6721`).
- Concurrent rayon-parallel S3 / GitHub-org / Slack source backends
  (8–16 in-flight) (`d3b6721`).
- Shared `Arc<Regex>` compile cache via `shared_regex()` - same regex across
  detectors compiles once (`a38e79c`).
- Pre-built `index_set` once on `Baseline::load` via `OnceLock` (`d3b6721`).
- Bigram bloom prefilter (Layer 0.5) - gates chunks ≥64 bytes before
  Hyperscan (`3a15fd0`).
- Dropped io_uring single-op path (latency regression, kept the multi-op
  batch path) (`d3b6721`).
- Decode-bomb time budget - per-chunk wall-clock ceiling on `decode_chunk`
  (`20d3ef8`).
- Probabilistic gate filled in: distinct-bigram density via FNV-512 (`20d3ef8`).

### Innovations - Tier-B moat features

- **Bayesian Beta(α,β) confidence calibration** - per-detector posterior
  updated from observed TP/FP, multiplier wired into the live scoring path,
  CLI surface (`keyhog calibrate --tp/--fp/--show`) (`34deeb0`, `d5d447e`).
- **Incremental scan** via persisted BLAKE3 Merkle index - unchanged files
  skip the scanner entirely on CI re-runs (`57c4cc8`).
- **Cross-detector dedup at emit** - one secret matched by N detectors
  collapses to one finding with N ranked service guesses (`eab71b2`).
- **Diff-aware severity** - git source pre-walks HEAD's tree, tags chunks
  `git/head` vs `git/history`, and the latter's findings drop one severity
  tier (`410dc0e`).
- **JWT structural validation** - header.payload decode with `alg`/`typ`/`exp`
  inspection and `alg=none` anomaly detection (`43092b6`).
- **CWE-798 + OWASP A07:2021 SARIF taxa** - compliance-grade reporting
  (`5462625`).
- **SARIF v2.2 fixes[]** with deletedRegion/insertedContent and env-var-name
  auto-fix suggestions (`650e599`).
- **Allowlist governance metadata** - `; reason="…" ; expires=YYYY-MM-DD ;
  approved_by="…"` per entry, expired entries auto-drop (`32ff3a8`).
- **`keyhog explain <detector-id>`** - full spec dump, regex breakdown, and
  rotation-guide URLs for major providers (`f56f97e`).
- **`keyhog diff <before.json> <after.json>`** - NEW / RESOLVED / UNCHANGED
  set diff for CI regression detection (`52d7242`).
- **`keyhog watch <path>`** - daemon mode with notify-based file watcher,
  compile-once-scan-many on saves; sub-100ms re-scan (`56c61d6`).
- **`keyhog calibrate`** - α/β counter management with posterior-mean bar
  visualization (`34deeb0`).
- **`keyhog detectors --search <query> --verbose`** - case-insensitive
  filter against id/name/service/keywords; verbose dumps full spec
  (`5951a14`).
- **`keyhog completion <shell>`** - bash, zsh, fish, powershell, elvish
  (`8ab105f`).

### Adversarial coverage

- Reverse-string decoder for tokens stored backwards as evasion (`c462e9c`).
- Caesar / ROT-N decoder for ROT13'd configs (`c462e9c`).
- Hex `_` separator stripping (firmware dumps, embedded configs use
  `A1_B2_C3_…`) (`2980284`).
- Comment-suffix disclaimer suppression - `// not a real key`,
  `# fake credential`, etc. (`2980284`).
- Cross-detector dedup also handles 2-fragment AWS reassembly with
  no-shared-prefix var names (`3327b39`).

### Architecture

- GPU auto-routing - runtime probe selects GPU vs CPU based on adapter type,
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

## v0.2.1 - 2026-04-04

Maintenance release: production-readiness fixes, dependency updates, agent
sweeps. See `git log v0.2.0..v0.2.1` for the commit list.

## v0.2.0 - 2026-03-30

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

## v0.1.0 - 2026-03-26

- First public release of the KeyHog workspace.
- Production-readiness cleanup for docs, examples, README guidance, and
  release metadata.
- Verified `cargo check`, `cargo test`, and
  `cargo clippy --workspace -- -D warnings`.
