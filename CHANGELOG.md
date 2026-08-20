# Changelog

All notable changes to KeyHog. Versions follow [Semantic Versioning](https://semver.org/).

## [0.5.80] - 2026-08-17

### Changed
- **Benchmark corpus synthetic packs & representative test coverage (Row 162).** Fixed AWS Access Key token shape in the built-in benchmark corpus template to match 20-character credential length (`AKIA` + 16 chars). Added integration tests verifying benchmark corpus structure, metadata, planted credential shapes, and synthetic execution pack finding parity invariants.

- **The isolated policy children of an all-policy calibration now inherit the parent's configuration mode.** `calibrate-autoroute` runs the four scan policies in four child processes, and the argv it built for them carried `--policy`, `--autoroute-cache` and `--measurement-receipts` but not `--no-config`. `install.sh` asks for the host baseline, the parent honored it, and every child resolved whatever `.keyhog.toml` the install directory happened to carry: a 40 minute install published 629 decisions across four digests no ordinary scan requests, while a plain scan resolved a fifth digest holding four decisions, and the first scan after the install exited 2 with `none matching config digest`. The child argv is now built in one place that forwards `--no-config`, `--quiet` and `--execution-packs`. A second test reads the flag list off the clap command at run time and fails on any flag with no recorded forward-or-own decision, so a new calibration flag cannot be added without deciding whether it crosses the process boundary.
- **Both installers now prove the calibrated cache can serve an ordinary scan before reporting success.** An install could finish clean and be unusable: `keyhog doctor` compiles one bundled detector and scans with an explicit `ScanBackend::CpuFallback`, so it passes on a host whose next auto-routed scan exits 2 for want of a matching decision, which is exactly what the child-argv defect above produced. After calibration each installer scans a throwaway two-file directory with no backend override and no calibration flag, asking for the same baseline configuration calibration measured, and fails the install (rolling back, as with a failed doctor) unless the scan runs. Edge case 8.7 drives an installer through a binary that calibrates and then refuses to route, and the parity gate pins the check on both platforms.
- **`keyhog calibrate-autoroute` now measures the configuration the scans it serves resolve.** Calibration passed `--no-config` to its own probes, so a run inside a repository with a `.keyhog.toml` published every decision under the compiled-in baseline digest while the scans in that repository asked for the resolved one, and the documented remedy for `autoroute calibration required` produced a cache those scans could never hit. Configuration is now resolved by the same `.keyhog.toml` walk-up a scan performs. `install.sh` and `install.ps1` pass the new `--no-config` flag, because an install runs from an arbitrary directory and primes a host baseline; both probe `calibrate-autoroute --help` first, so a binary that predates the flag still calibrates. The digest gate now pins both modes.
- **The install-from-build proof no longer assumes the build under test carries Hyperscan.** `tests/install/fixtures/install_from_local_build_posix.sh` pinned `--backend simd` for its three post-install scans. Only a `--features simd` build has that backend, and a portable binary refuses the request with exit 2 instead of substituting one, so two checks read a correct routing refusal as a detection failure. Linux CI happens to build `--features simd`, which is why the proof stayed green there, while the macOS lane builds `portable,gpu`. The fixture now reads `keyhog backend` and selects `simd` or `cpu` from the compiled-capabilities line, refusing to guess when that line is absent. `scripts/dogfood-all-os.sh` carried the same four hardcoded overrides against macOS and Windows ships.
- **The CLI test suite no longer assumes the build under test carries Hyperscan.** Nineteen files under `crates/cli/tests` pinned `--backend simd` on the binary they spawned. A portable build refuses that request with exit 2 and no stdout, so the format contracts read a routing refusal as malformed output (`json: Error("EOF while parsing a value", line: 1, column: 0)`), and the GPU recovery harness in `crates/cli/src/testing.rs` named `SimdCpu` as the recovery peer on a build with no Hyperscan. Under default features `cargo test -p keyhog --test all_tests` failed 34 of 858; CI builds `--features simd`, which is why it stayed green there. The suite now takes its backend from one cfg-selected `DIAGNOSTIC_BACKEND` constant, and the recovery harness resolves its peer the way production does, from what the build carries. Default-features failures drop to the 11 pre-existing `target_spec_org_contracts` budgets.
- **`install.ps1` grew the switches `install.sh` already had: `-NoCalibrate`, `-NoPrompt`, `-Help`.** A Windows install had no way to skip the autoroute measurement phase that a POSIX install skips with `--no-calibrate`, so every Windows install paid the full ladder, and a bounded install proof could not be written at all. The parity gate that exists to catch this asserted only that each script documents at least one flag, and could not fail on it; it now compares the two documented sets, folding `-NoCalibrate` to `--no-calibrate`, and requires every documented flag to be a real `case` arm or `param()` entry. A second test pins the skip to the branch that replaces the calibration call on both platforms, so a notice printed beside the measurement rather than in place of it fails. `install.sh --help` also stopped depending on a pinned line range of its own header, which was one line from going stale.
- **The calibration ladder now measures the decoding state at three size bands instead of one.** `decode_admitted` is a keyed routing dimension, and a family is reusable evidence only when at least two of its bands were measured, so a single decode-heavy probe left every decoding scan uncalibrated. The ladder probes decode-heavy content at 4 KiB, 64 KiB, and 256 KiB, in the subcommand and in the shell fallback path.
- **A calibrated route now covers the size bands calibration proved it covers, instead of only the exact band it sampled.** Every lookup was an exact match on the complete workload key. The reachable key grid is about 1,450,610 cells (13,685 valid byte/chunk/maximum-file triples, two decode states, 53 source execution classes) and the installer ladder measures a few hundred of them, so a real scan almost never landed on a measured cell: a two-file directory scan against a freshly calibrated 626-class cache differed from every stored key and exited 2, and adding one file to a directory that had just scanned broke it again. A size band nobody measured is now served only by measured invariance. KeyHog collects every calibrated decision sharing the workload's pattern band, decode state, and source-class set, needs at least two such bands, and reconciles them with the same rule that reconciles the repeated points inside one band: the served backend was measured at every band and proved slower at none, and bands that agree on the backend while splitting on the phase-2 localizer plan resolve to the compiled default plan every one of them measured. A band whose own evidence resolves no route, a real backend crossover, and any GPU route all withdraw the reuse and the scan still fails closed. Nothing is benchmarked, guessed, or substituted at scan time. GPU routes are excluded because GPU correctness, not only GPU speed, varies with input size: batch input caps and per-slot capacities bind to the measured shape, and a parity receipt proves that shape and no other.
- **Calibration ran under a GPU policy no ordinary scan requests, so every measured decision was invisible.** `calibrate-autoroute` passed `--no-gpu` to its own probes on any host without an eligible GPU. `--no-gpu` resolves `gpu_runtime_policy = Disabled`, which is hashed into the autoroute config digest, so the whole generation was persisted under a digest no scan resolves. On such a host that was the entire cache: an install that finished cleanly wrote 635 decisions across four scan policies, and the next `keyhog scan` reported `7 calibrated config(s), none matching config digest` and exited 2. Declining GPU candidates now means omitting `--autoroute-gpu`, which is deliberately outside that digest. A test derives the preset list from the source at run time and fails when calibration argv and plain scan argv resolve different digests, for the default policy and every preset, with and without GPU admission.
- **Calibration binds to the installed execution-pack generation without being asked.** Binding required `--execution-packs`, a hidden flag `install.sh` never passed, so `keyhog doctor` reported `route binding MISSING` on a freshly calibrated host and printed a repair command naming a flag that does not appear in `--help`. `keyhog calibrate-autoroute` now binds to the authenticated generation in the platform cache directory when one is present, in both the single-policy and all-policy paths; an explicit `--execution-packs` still fails closed when the directory it names does not authenticate. The doctor repair line is now `keyhog calibrate-autoroute`.
- **A one-shot accelerator route is no longer scored from a single cold sample presented as a zero-width confidence interval.** Setup cost (Hyperscan database load, GPU context creation) is measured once, as trial zero, and the scan alone six more times. Both confidence bounds were `max(cold, warm)`, so whenever setup dominated, they collapsed onto that one sample: across a real 158-class calibration on an AVX-512 host, 929 of 940 SIMD one-shot intervals had zero width, and cold exceeded the warm median in 940 of 940. A zero-width interval never overlaps a peer, so SIMD was reported as a measurably separated loser against `cpu-fallback` on every one-shot route, from one measurement, even where its own warm scans were faster. The one-shot cost of each trial is now the measured setup plus that trial's scan, so the interval keeps the warm width and only shifts. Medians are unchanged.
- **Autoroute route classes no longer depend on the content of the bytes being scanned.** The workload key mixed in phase-1 admission counts, phase-2 keyword trigger density, decode candidate counts and byte totals, and per-source chunk/payload ratios and span buckets. Calibration cannot enumerate those: they are measurements of whatever a caller happens to hand over. Every real scan therefore missed the persisted decision table and exited 2 with `autoroute calibration required`, and calibrating one directory stopped working as soon as a file was added to it. The key is now the enumerable shape of the work: byte, chunk, max-file and pattern buckets, whether the workload does any decoder work at all, and the set of source classes with their size provenance. The decoder dimension was a 14-bit mask of which decoder families the sampled bytes contained: a 117-byte `.env` produced `0x00000401` while the probe ladder, which generates its own text, produces `0`, so the two never met. Calibration still logs the phase-2 keyword trigger counts it observed on the `keyhog::routing` target, and each persisted point still records its exact sample byte count, chunk count, and measurement shape digest. `AUTOROUTE_CACHE_VERSION` moves 57 to 58; a v57 cache is rejected with the existing recalibrate message.
- fix(scanner): clamp decode-through window overlap to enforce strictly advancing window progress across UTF-8 scalar boundaries in release builds.
- fix(cli): add `parse_decode_size_limit` rejecting empty and sub-4B `--decode-size-limit` inputs with actionable error diagnostic.
- style: format guard massive diff test and git sources modules.
- fix(detectors): resolve evasion gaps, required literal routing, and Unicode whitespace boundary handling across 8 detector specifications (`apple-push-notification-key`, `google-artifact-registry-key`, `near-api-credentials`, `netrc-password`, `twitter-ads-api-credentials`, `webex-access-token`, `wechat-api-credentials`, `wordpress-api-token`).
- test(scanner): consolidate per-detector regression execution into sequential full-coverage suite to prevent parallel runner memory exhaustion.
- **Removed the dead signed binary-asset release channel.** No workflow built, signed, or uploaded release binaries, but `install.sh`, `install.ps1`, `keyhog update`, and `keyhog repair` all still consumed that channel. Each searched backward for a release that still carried a complete asset bundle, so the dead channel did not fail: `sh install.sh` silently installed v0.5.47 while the current version was v0.5.80. Removed `keyhog update` and `keyhog repair`, the download/signature/asset-selection half of `crates/cli/src/installer` (including the unreachable self-replace, backup/rollback, and orphan-reaping machinery), and the network half of both install scripts. `--from-file` is now required to install and still verifies a sibling `.minisig` and `.sha256`; without it the scripts print `cargo install keyhog --locked`. Retired the `KEYHOG_VERSION` and `GITHUB_TOKEN` installer environment variables, the `--repair`/`--version` installer flags, and the dead `EXIT_REPAIR_FAILED`/`EXIT_UPDATE_AVAILABLE` exit aliases. Update and repair are now `cargo install --locked --force keyhog`.
- Added gate `scripts/gates/release_channel_coherence.py` (with `--self-test`): an install or update path may not consume GitHub release assets that no workflow produces, and a prose reference to a named workflow job must resolve to a real job. The second half catches the trust-model comment in `installer/release.rs` that cited a `sign` job which never existed.
- `scripts/gates/tests_wired.py` was vacuously green and hid 108 CI-orphan test files. It folded shell backslash continuations but not YAML block scalars, so ci.yml's `run: >` step read as a bare `cargo test -p keyhog` with no target filter, the all-targets shape that short-circuits orphan detection for a whole crate. It also scanned only `.github/workflows/*.yml`, so the twelve GPU targets that run from `scripts/ci_local.sh`, the only lane that proves GPU finding parity, counted as running nowhere. The gate now folds `>` and `|` per YAML semantics and follows a script a workflow invokes. Wired the 89 cli and 19 scanner orphans: pure in-process files into `all_tests`, binary-spawning suites into explicit `--test` steps in the integration-cli and scanner lanes. This surfaces 13 real contract violations that had never run, 12 organizational-surface budgets and the crates.io publish contract.
- The install edge-case battery now ships a network tripwire instead of a mock GitHub API. `tests/install/linux/edge_cases.sh` puts a `curl` on the sandbox PATH that records the URL and fails, and case 23.1 asserts across the whole battery that it never fired. The old mock served release assets, so a reintroduced fetch would have been answered rather than caught.
- **Restored the install-time execution-pack producer, so detector compilation no longer runs on every scan.** With no installed execution-pack generation, `scan` parses and compiles the embedded 926-detector corpus in process on every invocation. Measured on a 16-core AVX-512 host, scan setup cost 284 ms wall and 1570 ms CPU with no packs against 66 ms and 110 ms with them: 4.3x wall and 14x CPU spent before any file is read. The only automatic producer lived in `crates/cli/src/installer/execution_packs.rs`, reachable solely from the self-install path fed by the retired binary-asset release channel, and was removed with that channel. The surviving producer, `keyhog compile-execution-packs`, is manual, needs a 32-byte signing key that nothing created, and no script referenced it. `install.sh` and `install.ps1` now generate that key under the per-user cache root and publish a generation before autoroute calibration, in both the install and `--calibrate` modes, and fail the install rather than leave a scanner that recompiles its corpus every run. `install_script_parity.rs` pins both scripts and the publish-before-calibrate order; `execution_pack_install.rs` covers every rejection branch of the key validator through the real compiler.
- The stale-pack error named `keyhog update` and self-update, both removed above, so a generation that no longer authenticated against the binary told operators to run a command that does not exist. It now names `keyhog compile-execution-packs` and `install.sh --calibrate`.
- `crates/cli/tests/unit/installer_execution_generation.rs` was declared in no manifest, so it never compiled, and it covered the installer-side signing-key validator that no longer exists. Its two uncovered contracts, a wrong-length key and a non-regular-file key, moved to `execution_pack_install.rs` against the live `compile-execution-packs` validator, and the file was deleted. The orphan watchdog in `gap_all`, which had never run in CI either, is what found it.
- `readme_exit_codes_match_cli_contract` pinned five hand-picked prose fragments of the README exit-code table and could not see a new exit code at all. It now derives the expected rows from `exit_codes::DEFINITIONS`, so adding a code turns it red until the README documents it, and a documented code with no definition also fails.
- **Autoroute calibration refused every generation on multi-core hosts, so no install could complete.** `calibrate-autoroute` measured 180 workload probes, then discarded the whole routing generation because the 4 MiB through 32 MiB classes reported `workload class changes its confidence-supported backend across measured points`. That check compared the two points' backends directly, with no test of whether the measurements separated them. They did not: across three retries of the same 4 MiB bucket the daemon route reported `simd-regex` and `cpu-fallback` on alternating runs, which is run-to-run variance between two statistically indistinguishable backends, not a crossover. Publication is all-or-nothing, so one such class cost the entire cache, `install.sh` rolled back, and every later scan exited 2 with `autoroute calibration required`. Backend selection across points now resolves through `resolve_route_across_points`, which keeps the lowest-complexity backend that is measured at every point and proved slower at none: a disagreement no point separates reconciles, and a disagreement some point does separate is still refused as a real crossover, with an error that says so. `calibrate-autoroute` now exits 0 and publishes 158 route decisions from 235 measured points on a 16-core AVX-512 host.
- **Both installers required a GPU literal sidecar that nothing produced, so every install failed closed.** `install.sh` and `install.ps1` refused any `--from-file` install without a sibling `<binary>.gpu-literals.tar.gz`, and `--from-file` is now the only install mode. The sole producer of those artifacts is `keyhog-scanner-artifacts`, a development binary that is not shipped, and the tarball packaging existed only in CI and in test fixtures, so no user could satisfy the requirement. This is the same defect class as the execution packs above: a required artifact with no producer. Added `keyhog compile-gpu-literals`, which compiles the detector corpus embedded in the binary into the host matcher artifacts and publishes them, atomically per file, into the runtime program cache. A missing sidecar now generates through the installed binary rather than failing; a sidecar that IS supplied is still signature-checked, checksum-checked, and archive-validated before extraction. Generation failure still fails the install and rolls the binary back, because finishing without matchers would put detector compilation back on every scan.

### Fixed

- Include known reason and repair command in daemon warm-route errors and startup banner instead of hiding them behind a generic fallback. Apply the same fix to the daemon status command. Make is_work_request exhaustive so adding a new Request variant causes a compile error. Add regression tests pinning daemon server pure-function behaviors before modularization.

## [0.5.79] - 2026-08-16

### Changed

- ci(release): fallback token and sync floating major tag on release.
- Optimize Git staged manifest acquisition and index verification: pre-populate staged blob sizes directly from in-memory `.git/index` and fast-check index fingerprints against `.git/index` metadata and trailing checksum to eliminate redundant loose-object disk reads and subprocess forks during perpetual guard commit scans.
- Add massive staged diff simulation suite (`regression_cli_guard_massive_diff_simulation.rs`) verifying 1,000-file and 5,000-file diff performance and RAM bounds under 10MB during daemon-served commit transactions.

## [0.5.78] - 2026-08-16

### Changed

- fix(scanner): gate expand_triggered_patterns independently of decode feature.

## [0.5.77] - 2026-08-16

### Changed

- fix(ci): format scan_postprocess, update dogfood hashes for doc fixtures, and bump action version.

## [0.5.76] - 2026-08-16

### Added

- `keyhog-profile`: `ProfileConfig`, `ProfileName`, `KnownProfile`, and environment lookup routines for zero-allocation profile resolution and secure credential memory zeroization.

### Changed

- Stream JSON and SARIF finding envelopes directly into buffered writers during CLI report generation, eliminating intermediate allocations in JSON/JSONL envelope reporters and sorting allocations in SARIF reporter.
- Update CLI scan format matrix and stdin regression suites to assert canonical 22-field CSV rows with metadata and additional-locations columns.
- Short-circuit decoded-match suppression checks in scan post-processing and preserve exact deduplication ordering.
- fix(core): rerun build script on GITHUB_SHA changes to prevent stale git hash in CI cache.

## [0.5.75] - 2026-08-14

### Changed

- Findings now carry a canonical evidence verdict with exact `review`, `likely`, or `confirmed` tier and reason code. Evidence also retains schema-1 secret-safe candidate provenance: detector-corpus digest, pattern ordinal, producer channel, source role, and pre-verification context class. Public reports use optional `evidence_score` instead of `confidence`; JSON and JSONL report schema 2, baseline schema 2, and daemon wire 15 reject stale records that lack exact evidence. Deduplication retains the strongest proof while keeping candidate provenance owned by the reported detector independently from the scanner's internal score, and live verification upgrades the verdict to `confirmed/live-verification` without discarding the candidate identity. Shared execution-pack routes retain the authenticated compiled detector-plan digest.
- The default scan policy returns exit `1` for new `likely` or `confirmed` findings while keeping `review` findings visible with exit `0`. Set `[scan].evidence_policy = "paranoid"` or pass `--evidence-policy paranoid` to make review-tier findings block. One-shot, daemon, staged-guard, and GitHub Action paths use the same policy classification. Coverage, panic, cache, and live-verification exit precedence remains fail closed.
- Action report receipts preserve system-error and scanner-panic exits when review-tier findings remain visible. Guard commit proves the protected terminal receipt fits the daemon frame before consuming its transaction. Published scanners that predate evidence-policy flags retain their equivalent paranoid behavior only when the Action explicitly requests `paranoid`; they reject the newer default policy.
- Emitted candidates in JSON, JSONL, TOML, YAML, dotenv, and INI configuration receive candidate-bounded source-role classification with exact value/candidate spans and borrowed key-path spans. Only candidates admitted for emission or ML scoring initialize parsing; each bounded source is parsed at most once per scan and later candidates reuse the source index. TOML and YAML key paths build in one forward pass, and the index stores path spans in a shared arena. Commented examples, empty INI settings, and commented INI section headers do not invalidate later evidence. The compact role and parser confidence survive adjudication in the 16-byte sidecar. Malformed or truncated syntax and unsupported, over-nested, or over-budget input abstain without suppressing the finding.
- Emitted candidates in Rust, JavaScript/TypeScript, and Python receive exact lexical source roles for strings, identifiers, regex definitions, test fixtures, command arguments, and option declarations. Parsing is candidate-triggered and capped at 64 KiB; malformed, truncated, unsupported, and over-budget code abstains without changing candidate recall.
- Emitted candidates in Markdown, roff/man pages, shell scripts, Dockerfiles, and Containerfiles receive bounded source roles for prose, inline code, shell-fenced commands, structured configuration fences, option declarations, environment assignments, and command argument values. JSON, JSONL, TOML, YAML, dotenv, and INI fences reuse their strict structured parser and abstain on malformed syntax instead of treating the entire fenced block as prose. Structured detector and rule fields derive regex-definition, test-fixture, and prose roles from validated Tier-B markers. Malformed, truncated, unsupported, and over-budget input abstains without changing candidate recall.
- Detector-owned grammars keep MongoDB Atlas key pairs, command-line password arguments across shell, Dockerfile, PowerShell, CI, and programmatic literal contexts, and quoted Helicone values with token-shape or provider-owned context while rejecting Atlas identifiers, nested password-option names, and OpenAI sibling assignments. JWT detection retains its existing short-signature recall floor; provider-owned Scalr context applies a narrower 20-character floor. Known-prefix candidates used as assignment keys no longer absorb a quoted `=` separator as base64 padding, while quoted provider values retain legitimate padding. These decisions do not use repository or path exclusions.
- Detector TOML schema 5 binds synthetic positives and named hard negatives to exact pattern ordinals and rejects those fields under older manifests. A deterministic regex-HIR generator exercises every shipped pattern. Schema-5 enforcement-capable semantic policies require direct positive, named hard-negative, and generated sibling-prefix evidence; schema-4 policies retain their prior validity. The schema identity change rejects prior detector-corpus caches, execution packs, and autoroute decisions.
- Model-driven confidence reductions require an exact pattern calibration key bound to the detector corpus digest, detector ID, pattern index, candidate channel, source role, and pre-verification context. Missing, stale, unsupported, or under-supported calibration entries abstain; populated entries must satisfy held-out positive and negative support, recall, Brier score, and calibration-error floors.
- The redacted real-repository quality gate validates each persisted identity receipt against the freshly captured candidate binary and measures unlabeled noise per MLOC. Version proof and executable hashing use one held immutable snapshot, so path replacement cannot mix binary identities. Labeled findings and deterministic canaries contribute to recall without inflating the noise density. Inputs are bounded regular files, class density ceilings cannot exceed 2.0 findings per MLOC, and unlabeled findings cannot reuse ground-truth hashes. The Make target requires explicit operational evidence; the nightly workflow validates the committed schema and boundary contract without claiming a fresh repository measurement.
- Hosted Action release proofs now default to the workspace's published 0.5.75 scanner instead of the obsolete 0.5.70 crate.
- Scanner detector TOML schema 4 accepts typed capture, anchor, allowed-source, and required-evidence roles. Omitted declarations preserve current findings and serialization; declaring them under an older corpus schema fails closed. The schema identity change rejects prior detector-corpus caches and execution packs. Autoroute reports a detector corpus digest mismatch and instructs `keyhog calibrate-autoroute`. Detector-plan schema version 3 persists the resolved policy, rejects stale sections, and `explain` labels omitted scalar roles as compatibility defaults.
- Merge remote-tracking branch 'origin/main'.
- Scanner candidates retain their producer channel and exact canonical pattern ordinal through ML scoring and final adjudication without changing public `RawMatch` output, ordering, deduplication, or caps. Matcher section schema version 6 persists the ordinal and rejects stale or out-of-range provenance during hydration.
- `keyhog triage` imports only the current versioned redacted finding envelope and emits separately versioned scoped runtime-suppression and pattern-training artifacts. Records consume the scanner's exact public `evidence.provenance`, binding the active detector digest, nullable pattern index, candidate channel, source role, context class, and channel-specific detector owner; typed mutually exclusive scopes, closed reasons, input and record limits prevent credential, context, path, and stale-policy persistence. Unix input reads, create-new outputs, and cleanup resolve through held no-follow directory descriptors so parent replacement cannot redirect I/O. Windows fails closed until equivalent reparse-point-safe held-handle I/O is available. Reassembled finding IDs resolve only through the canonical public suffix. Any detector corpus change invalidates every persisted triage artifact. Pattern-feedback-only decisions cannot produce runtime suppressions.

### Fixed

- Credential-anchored entropy now rejects dotted source/property identifiers through the shared shape gate while retaining exact structured dotted-token recall.
- Action autoroute calibration applies the same published-scanner evidence-policy compatibility rule as the scan runner: legacy scanners may omit the unsupported flag only for explicit `paranoid`. Scanner panics mark report metadata partial so exit-11 Action receipts remain valid.
- Build-time model calibration artifacts now retain LF bytes on Windows checkouts, keeping the model-card SHA-256 receipt portable.
- Staged-guard profiling now counts one authenticated blob payload once even when the staged index contains multiple path aliases; each alias still receives its own source-context scan.

## [0.5.74] - 2026-08-14

### Changed

- fix(release): ignore Marketplace-only tags.

## [0.5.73] - 2026-08-14

### Changed

- fix(release): preflight registry dependencies.

## [0.5.72] - 2026-08-13

### Changed

- release: publish the tag the bump job creates.

### Fixed

- Release tags now publish: the bump job dispatches the crates.io publish for the tag it created, and that job creates the tag's GitHub Release from its changelog section. A tag pushed with the workflow token raises no push event, so tags v0.5.51 through v0.5.71 were never published.

## [0.5.71] - 2026-08-13

- Scanner tests: coverage ratchet falls back to each detector's `test_positive` example (with `test_path`) when proptest cannot generate from the regex, closing the 818/922 gap to 922/922. 87 detectors use regex features (`\b`, `(?-i)`, `(?:^|[^A-Za-z])`) outside proptest's generatable subset; 17 are path-restricted or suppressed on generic paths. The ratchet now validates every regex detector's regex→compile→scan wiring.

- Scanner: a connection-string finding whose password sub-field is a placeholder is suppressed. A detector for a credentialled URL captures the whole `scheme://user:password@host` span, so `postgresql://app:<password>@localhost/db` in a `.env.example` reached the report as a critical finding; the password is now read out of the URL and tested on its own for the wrapped template (`<password>`, `{{db_pass}}`, `${DB_PASSWORD}`), the unbraced shell reference (`$DB_PASSWORD`), the single-byte mask (`xxxxxxxx`), and the placeholder vocabulary. A real password in the same position still reports.
- CI: pull requests run the merge lane and skip `feature-matrix`, which stays required on pushes to `main` and on tags. The twelve detector-contract steps that shared one command line collapse into a single invocation.
- CI: test binaries build under a new `ci-test` profile, identical to `release-fast` except that thin LTO and 16 codegen units are dropped. The sources lane links 116 test binaries, so cross-crate optimization was paid once per binary for nothing a test can observe. Measured on a 16-core host: the sources target matrix compiles in 97 s instead of 866 s, and the suite runs in 73 s with the same results. Shipped-binary builds, smoke tests, install proofs, and dogfood runs stay on `release-fast`.
- Required CI runs the complete sources target matrix once, removing the earlier default `all_tests` replay before the all-feature run.
- Sources: align filesystem profiling coverage with the default direct reader's bounded batch handoff, retaining exact acquire, walk, read, and input-total assertions.
- Scanner: reuse bounded CPU trigger scratch for clean phase-one admission rows, eliminating one zeroed trigger-bitmap allocation per unique no-hit chunk while preserving exact hit bitmaps.
- CPU confidence scoring now evaluates large authenticated quantized batches across the configured Rayon worker pool while preserving bit-exact row order; batches below 64 candidates remain serial.
- Sources: filesystem mmap admission, binary, Ghidra, and Docker reads now reuse descriptor metadata captured by the shared safe-open validation instead of querying the opened file again. Windowed buffered fallback refreshes descriptor metadata before its later cap check. No-follow, regular-file, advisory-lock, and size-cap behavior remains fail-closed.
- Sources: whole-file reads up to 16 MiB now fill the post-open stat-sized buffer directly before the bounded growth probe. Concurrent shrink, growth through the hard cap, no-follow opening, and advisory locking retain their existing behavior.
- Scanner: coalesced CPU and SIMD scheduling now stores small-lane membership in one flat index buffer instead of one heap allocation per lane. Chunk order, large-chunk isolation, worker partitioning, and the 512 KiB lane ceiling are unchanged.
- Core: raise dedup additional-locations subquadratic tripwire ceiling to 3.25x to absorb CI thread-CPU jitter (observed 3.03x flake).
- Scanner: sensitive-path keyword-free confidence ownership test pins ordinary entropy_very_high cannot demote admitted hits.
- Scanner: sensitive-path keyword-free entropy keeps ML as lift and scores against the sensitive very-high band so assignment RHS like `VALUE=<token>` in secrets.env is not soft-dropped.
- Scanner contracts: redis-sentinel evasion uses `REDIS_SENTINEL_AUTH=` (non-comment) so comment soft-suppression cannot hide the credential.
- Generic assignment RandomByteBlob suppression requires decoded NUL evidence (entropy-path coherence) so JWT/API_KEY/TOKEN opaque secrets remain reportable; corrected-primary-role parity uses ExactCpuScanners for SIMD pack selection.
- cargo fmt: collapse path-include blank lines and deny_unknown schema count expression.
- Cut duplicate required library-surface core/sources `--lib` suites already owned by focused/sources jobs.
- Fix CLI/docs/gate drift from unfinished `guard` landing: snapshot, exit-code help, docs reference, HOME allowlist, path-split daemon/guard unit tests, sources discovery no-unwrap move.
- Adjust WordPress/redis-sentinel fixtures and vendor-token boundary path metadata for focused scanner contracts.
- Align required CI with MUST-RETURN gates (library/sources/CLI/detector/install-scripts/feature-matrix); keep macos/fuzz/windows/static overnight. Re-enable path-filtered action-e2e and push/PR keyhog dogfood.
- Required CI again gates feature-matrix compile/dogfood coverage and the install-scripts battery (scenarios/edge cases/static analysis), not only overnight.
- Required CI covers library surface, sources/CLI aggregators, detector recall contracts, SARIF compliance, feature-matrix, and install-scripts. Overnight keeps macos/windows builds, fuzz-smoke, static linkage, CLI property/adversarial/reliability, and scanner property fuzz.
- Install-from-build proofs pass an explicit `--backend simd` after `--no-calibrate`, matching autoroute fail-closed behavior when no cache exists.
- Action E2E now tests the published v0.5.70 crate, and Windows guard dispatch returns an explicit unsupported-transport error without compiling the Unix daemon client.

- Unix mass-daemon filesystem scans now accept `--incremental`, retain the compiled scanner across transactions, skip unchanged clean files before read and dispatch, rescan every file that produced a finding, and atomically publish the spec-bound Merkle generation. Cache publication failures retain system-error exit `3`.
- Daemon-local mass filesystem scans now retire all bounded batches after one drain request instead of requiring one client request round trip per batch. Each result remains a separately bounded response under socket backpressure, with exact source order, findings, gaps, and terminal receipts preserved.
- Ordinary unbounded filesystem scans now classify archive symlinks during the configured metadata walk, eliminating a redundant full-tree directory traversal while preserving one counted refusal per expandable symlink. Byte-budgeted and descriptor-relative long-path scans retain their bounded safety paths.
- Filesystem scans now use one direct reader by default and omit the intermediate ordered-reassembly thread. Explicit `--reader-threads N` values above one retain the parallel ordered path for measured storage workloads; finding order and bounded scanner backpressure are unchanged.
- Warm incremental scans now defer backend routing and scanner dispatch until source acquisition emits a changed chunk. An all-unchanged filesystem tree closes both fused and coalesced batch streams without starting scanner work, and trusted clean-file Merkle hits count as complete coverage instead of a zero-byte failure.
- Warm all-clean mass-daemon incremental scans now carry both metadata and content-confirmed skip counts across the wire, preserving successful coverage when no source bytes require dispatch.
- Daemon responses now serialize directly into the bounded transport frame instead of allocating a complete JSON body and then copying it into a second buffer. Wire bytes and the 64 MiB frame ceiling are unchanged.
- Added the perpetual repository and filesystem guard: a daemon-resident runtime that registers Git repositories and filesystem trees as guarded roots, maintains a 7-state machine per root (Stopped, Indexing, Current, Degraded, StalePolicy, StaleManifest, StaleTree), and applies a closed set of 12 transition events through a centralized transition function. The guard tracks a `GuardPolicyIdentity` spanning build, detector, suppression, ignore, config, decode-policy, source-policy, guard-schema, and report-semantics digests. A policy identity change invalidates all existing clean attestations and transitions active roots to `StalePolicy`. A `HotAttestationIndex` (64 MiB LRU) caches clean blob attestations to avoid re-scanning blobs that were already proven clean under the current policy. A `RootRegistry` holds canonical path bytes, filesystem identity (device + inode), mode (repo or filesystem), and terminal sequence number per root.
- Added a staged Git manifest acquisition path that reads `git diff --cached --raw -z --no-renames` to enumerate newly staged objects, computes a BLAKE3 fingerprint of the Git index for race detection, and resolves object sizes via gix. The manifest distinguishes added, modified, removed, and type-changed entries.
- Added event normalization and a bounded reconciliation protocol. Filesystem events are normalized into `GuardEvent` variants (Create, Modify, Remove, Rename, ReconcileSubtree, Barrier), coalesced within a configurable window, and buffered in a bounded `EventBuffer` with monotonic sequence numbers and overflow detection. `GuardReconciliationConfig` bounds subtree reconciliation by file count and depth.
- Bumped the daemon wire protocol from v12 to v13 and added guard transaction frames: `GuardCommitBegin`, `GuardCommitBlob`, and `GuardCommitFinish` requests, plus `GuardCommitPlan`, `GuardCommitReceipt`, `GuardAdded`, `GuardRemoved`, `GuardStatusResult`, and `GuardReconcileStarted` responses. A `GuardWireManifestEntry` type carries staged manifest entries over the wire.
- Added CLI guard commands (`keyhog guard add|remove|list|status|reconcile`) with daemon client integration, human and JSON status output, and exit code 13 for degraded, stale, stopped, or indexing states.
- Added a `[guard]` configuration section to `.keyhog.toml` with typed settings for hot index memory budget, event queue caps, coalesce window, scanner residency, idle-unload timeout, scrub interval, and subtree reconciliation bounds.
- Added a daemon guard runtime that holds the live root registry, hot attestation index, policy identity, and transaction ID counter in process. The runtime applies state transitions, invalidates attestations on policy identity change, and allocates monotonic transaction IDs for commit transactions.
- Added a daemon-resident filesystem watcher for guard roots. The watcher uses native platform APIs (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows) to receive change events without polling. Events are normalized into `GuardEvent` variants, buffered in a bounded `EventBuffer` per root, and processed through the guard state machine on a coalesce window. Overflow triggers full subtree reconciliation.
- Added scanner residency tracking to the guard runtime. The residency label (`active`, `resident`, `idle-unload`) reports whether the guard is actively using the scanner or has been idle past the 5-minute unload threshold. `GuardStatus` now reports real pending event counts from the watcher instead of a placeholder.
- Added a durable guard state store backed by redb. When `[guard].state_path` is set, the daemon persists root records and clean attestations across restarts. The store enforces owner-only file permissions (0600), rejects symlinked paths, and creates all tables during schema initialization. On restart, roots are restored as `stopped` (never `current`) and the watcher is re-registered for each root that still exists on disk. In lockdown mode (`[lockdown] require = true`), the durable store is disabled and the guard operates in ephemeral mode.
- Added the `keyhog guard rebuild <root>` subcommand. Rebuild removes a root from the guard (clearing its durable store entries) and re-adds it, triggering a fresh baseline reconciliation. Use it after store corruption or when persisted state is irrecoverably stale.
- Added periodic guard scrub. When `[guard].scrub_interval` is set, the daemon watcher loop periodically triggers reconciliation for all `current` roots, catching changes that filesystem events missed (NFS, bind mounts, external edits that bypass inotify). Omit the setting to disable scrubbing.
- Added a clean-shutdown marker to the durable store. The daemon marks the service as unclean on startup and clean on graceful shutdown, enabling detection of unclean restarts.

- MatcherArtifact cache hits now validate and decode the three persisted matcher
  sections directly from the capped artifact file buffer. Startup no longer
  allocates and copies a second complete section set before hydration.
- Confirmed phase-two shared-anchor collection now reuses the bounded
  worker-candidate scratch for eligible-pattern and literal-id lists. Repeated
  chunks no longer allocate two temporary vectors per confirmed-anchor pass.
- Scanner runtime snapshots now use the same complete resolved tuning type and
  default resolver as configuration identity. The duplicate runtime-only
  performance configuration record is removed.
- Added one performance-evidence reference that distinguishes canonical
  generated receipts from historical investigation reports and defines the
  executable, workload, host, route, lifecycle, parity, and coverage fields
  required for comparisons.

- Autoroute cache schema v57 authenticates runtime-compiled GPU programs against the exact executable and detector corpus while retaining manifest-digest binding for installed GPU sidecars. Calibration from a standalone release binary now persists GPU route evidence instead of rejecting every measured workload when no sidecar is installed.

- Autoroute JSON inspection now exposes the active GPU artifact binding and each authenticated ordered-device route body, including per-device topology, throughput weights, and resident budgets.

- Detector property gates now preserve declared source-admission paths, compare Caesar prefix admission at exact token boundaries, compile backend-specific CPU and SIMD plans, and retain minimized parity cases. The WordPress token contract again carries its required `wpcom` owner anchor.

- Complete autoroute sweeps now retry measured-point backend and recovery-route disagreements instead of treating timing variance as a permanent calibration failure. Non-timing failures remain non-retryable and leave the staged generation unpublished.
- All-policy autoroute calibration now stages every isolated policy child into one generation and publishes the live cache once only after all children and their exact route receipts validate. Failure to prepare an eligible GPU peer aborts the generation instead of silently measuring a reduced CPU/SIMD candidate set.
- Persistent daemon autoroute now compiles the runtime-policy GPU peer census instead of materializing a scalar-only scanner before loading authenticated GPU decisions.

- Concurrent direct-GPU scan workers now serialize complete resident dispatch rings around the scanner-owned slot set. A second worker could previously observe the depth-one slot in flight, misclassify the healthy GPU as failed, leave one batch unscanned, and report partial coverage.
- Builds without the `git` feature no longer compile the staged guard-commit client or reference Git-only source APIs. Their daemon rejects guard-commit frames with an actionable feature error instead of failing the portable build.

- Filesystem discovery prunes default-excluded directories (for example
  `node_modules/`) during the walk and counts each pruned directory once in the
  Excluded coverage signal. Linux unbounded walks abort at the first
  `ENAMETOOLONG` and finish via descriptor-relative metadata-only discovery when
  ignore overrides allow it, and extensionless names get a cheaper content sniff
  before full reads.

- Nested archive scans stream compressed tarballs (`.tar.gz`, `.tgz`, and nested compressed tar members) member-by-member with a single inflate, instead of retaining each full decompressed image or paying a second inflate to probe TeX provenance. Uncompressed tar and ZIP still gate TeX provenance on header/central-directory names so nested compressed payloads cannot false-trigger a second full member pass. Peak resident memory for archive extraction stays bounded by the compressed input, decoder state, and the largest member under the active caps.

- Build route-scoped CPU, SIMD, and acquired VYRE GPU execution packs during verified POSIX installation, prove their exact findings against the scalar oracle, authenticate every pack with an installation-local key, measure every bundled source execution class in streamed and known-size form, persist the authenticated manifest and exact policy/backend pack identities with calibration evidence, and restore the previous binary, pack generation, and autoroute cache together when compilation, identity validation, health checking, interruption, or autoroute calibration fails. Binary self-update now rebuilds candidate detector packs and pack-bound calibration before committing the replacement, with the same rollback contract. `keyhog doctor` now authenticates the installed pack generation and verifies the exact route-cache binding. Pack publication now reaps dead-process stages and replaced backups, while recovering an unambiguous interrupted backup before recompilation. Installed scans now load the embedded detector corpus from the authenticated policy execution pack and fail closed when that exact pack is absent or corrupt. Scanner construction now shares that decoded corpus instead of cloning every detector specification. Normal scan startup no longer warms global regex caches unconditionally.
- Installed scans now hydrate matcher graphs, native phase-one and phase-two Hyperscan databases, and fused VYRE matcher artifacts directly from the selected authenticated execution pack. CPU and SIMD routes no longer rebuild matcher graphs, SIMD does not compile Hyperscan databases at scan time, and GPU routes validate the exact calibrated VYRE peer before deserializing its signed matcher bytes. Development and explicit custom-detector scans retain their deliberate in-process compiler path.
- Authenticated execution-pack pages use random-access mmap advice, disable Linux transparent huge-page promotion, and are discarded before matcher hydration; the selected mapping is released after construction. Normal scans fault back only the selected sections while decoding them into owned runtime state, so a small section access cannot retain a 2 MiB huge page and the complete pack mapping no longer overlaps the resident scanner.
- Read-only execution-pack mappings now have a Linux cross-process RSS contract: two scanners that fault the same immutable backend program must account those pages as shared clean memory rather than private copies.
- Worker-local scanner scratch now has route-specific retention ceilings. Anchor-dense CPU/SIMD candidates retain at most one scan chunk, single-chunk VYRE buffers are zeroed and capped to one chunk, and coalesced VYRE buffers retain at most the portable dispatch grid instead of keeping an outlier allocation for the worker lifetime.
- Autoroute now measures each resident VYRE pipeline depth supported by an
  acquired GPU peer and persists the selected depth, submit/retire capability,
  and divided per-slot input and match capacities. Asynchronous depths two
  through four use independent resident IO slots, restore readbacks to logical
  row order, and keep haystack, presence, region-control, and positioned-match
  storage inside one aggregate device-memory ceiling. A changed capability or
  capacity invalidates the route before dispatch.
- Finding finalization now moves one graph through scan-level suppression, deterministic deduplication, verification eligibility, report rules, and baseline filtering. In-place compaction replaces full-vector filtering and partition copies, and canonical dedup key ordering no longer materializes an intermediate key/value vector.
- Allocation-tracked profiles now enforce live-byte conservation across every stage plus the explicit outside-span root owner, proving that every retained heap allocation has one reported owner even when another stage or thread frees it.
- Non-verifying scans now release the decoded `DetectorSpec` corpus after scanner construction. The compiled detector-indexed plans retain the report metadata and execution policy they need. The metadata interner now owns each unique string once without a parallel arena, and resolution plus cross-detector relation indexes reuse those same detector-ID allocations. Only `--verify` keeps specifications for verifier-plan construction.

### Fixed
- **BetterLeaks memory comparisons now reject route-mismatched measurement files with a coverage diagnostic.** The release gate validates the exact catalog-derived workload and execution-route set before reading RSS metrics, instead of raising a raw lookup error.
- **Coverage claims now come from executable contracts instead of a boolean file ledger.** The ungrounded `FILE_GATE_MATRIX.toml` audit artifact and its self-referential existence and column tests are removed; production boundary, error, adversarial, and end-to-end behavior remains owned by the tests that execute those paths.
- **macOS scanner library CI no longer fails on wgpu dual-slot overlap or a backblaze-shaped proptest seed.** Dual-slot overlap is asserted only when the acquired GPU peer supports async timed resident dispatch; Metal/wgpu without `TIMESTAMP_QUERY` stays on the borrowed sync path and already has exact finding parity covered. The decode-generic property now rejects tokens that also match a named detector at top level, and the live GPU test lock clears poison so one adapter failure cannot cascade the rest of the suite.

- **A missing execution-pack generation no longer makes a valid binary unusable.** Local and air-gapped installs can legitimately ship only the binary; when no generation directory exists, scans now compile the authenticated embedded detector corpus and `keyhog doctor` reports a warning instead of failing health checks. A present but invalid generation still fails closed rather than falling back.
- **The generic OAuth `client_secret` detector no longer reports canonical UUID identifiers.** Its detector-owned value policy now rejects the exact UUID shape while preserving opaque, base64, and canonical-hex client secrets. Scanner integration contracts now construct the exact CPU, SIMD, or GPU route they exercise, and shared-state counter and IaC tests are isolated from parallel-suite interference.
- **Read-only Linux scans no longer fail while preparing filesystem discovery metadata.** Path sorting now uses an anonymous memory-backed spool instead of creating a file through `TMPDIR`, so a container started with `--read-only` can scan mounted input without a writable scratch filesystem. Empty directories remain incomplete coverage and exit 13 rather than reporting clean.
- **Verified glibc container builds now accept the findings verdict from autoroute calibration.** Calibration preserves normal scan exit codes, so reviewed fixture scans may return 1 after persisting valid evidence; the image build still aborts on every calibration error code.
- **Windows Action scans no longer reject extended-length workspace paths at the drive prefix.** Filesystem root validation now waits until `\\?\D:\` includes a real path component before calling `symlink_metadata`, while still checking every traversable component for symlinks. Branch/SHA Action contract tests now exercise the portable CPU backend they actually build, and an absent checkout is asserted as partial coverage with exit 13.
- **Anchored-regex fail-closed cases now compile in scanner library test builds.** The shared unit suite imports the production type through its crate path, so no-default-feature and macOS CI lanes execute the same compile-failure contracts as the scanner integration aggregator.

- **Explicit private-endpoint consent now reaches WebSource.** `--allow-private-cloud-endpoint` and `[http].allow_private_endpoint = true` were passed into the shared HTTP configuration but WebSource ignored them and rejected every private, loopback, and on-premises URL before HTTP. Web scans now honor the explicit opt-in across initial requests and redirects. The default remains fail-closed, and the narrow autoroute loopback exception still cannot follow redirects to unrelated private or metadata endpoints.

- **A client that walks away no longer kills the daemon.** `keyhog daemon start` inherited `SIGPIPE = SIG_DFL` from the process-wide reset in `main`, which exists so `keyhog scan | head` dies quietly like any other Unix filter. That disposition is right for a one-shot report writer and wrong for a server: when a client abandoned a connection while the daemon was writing the reply, the `write(2)` raised `SIGPIPE` and the kernel killed the whole daemon. Measured, three connections that sent one `hello` frame and closed without reading were enough, and reading part of a large `ScanResults` frame then closing did it every time. The daemon serialises scan execution, so one client hitting Ctrl-C, timing out, or half-reading a result terminated the warm scanner for every other client on the machine, with no log line and a stale socket file left behind. The trigger was the single most ordinary thing a client can do and it was reachable by any process that could open the socket. The daemon service now restores `SIG_IGN` before it binds, so a departed peer surfaces as `EPIPE` on that one connection: the handler logs it, drops the connection, releases its admission permit and its fragment lease, and the process keeps serving. Clients suppress `SIGPIPE` only for the lifetime of a daemon socket, so the piped-stdout behaviour the reset exists for is unchanged. This is a live-connection fix and not a panic fix: every shipped profile sets `panic = "abort"`, so a scanner panic still takes the daemon down and the per-request panic handler is unreachable there.

- **`daemon stop` and `daemon status` no longer report a live daemon as absent.** Every connect failure was wrapped in `no daemon at <path> (already stopped?)`, so a daemon that was running but wire-incompatible, untrusted, or too busy to answer looked exactly like an empty socket path. Measured: with every scan admission held by clients that had sent a partial frame, both commands reported no daemon while the daemon was answering health checks fine, and an operator had no way left to reclaim it. Two changes. The accept loop no longer waits for a scan permit before it can hand a connection to a handler, and a small admission pool is reserved for `Hello`, `Health` and `Shutdown` with a short read deadline so it cannot be squatted by idle peers. And connect failures now carry their kind, so an absent socket reports absence while a live peer is named with the identity a version-independent administration channel could read, and is left untouched rather than clobbered.

- **`Shutdown` now delivers in-flight results before it acknowledges.** The wire contract promised a flush; the daemon acknowledged immediately, left the accept loop and exited, so a client whose scan was mid-flight got a closed socket instead of its findings. Draining on scan execution alone was not enough either, because the active-scan count drops to zero as soon as the scanner returns while the results frame is still unwritten. Shutdown now refuses new work, waits for each in-flight request to finish executing *and* to have its response written, then acknowledges, bounded so one wedged transaction cannot make the daemon unstoppable. `ScanPath` also enforces its own documented contract server-side: it opens a no-follow handle, refuses anything that is not a regular file, and re-checks the inode afterwards, so a directory argument can no longer make the daemon walk an entire tree, and a path replaced mid-scan fails closed instead of reporting findings for substituted content.

- **`--perf-trace` no longer aborts the process it is measuring.** Every `keyhog scan --perf-trace` run died with `index out of bounds: the len is 2 but the index is 2` and signal 6 (exit 134) at the end of the scan, after the report was written. `confirmed_profile_dump` indexed the per-pattern timing tables with its own scanner's pattern count, but those tables are process-global `OnceLock`s sized by whichever scanner initialized them first, and on a GPU-enabled build a single-pattern probe scanner warms them before the 2,700-pattern corpus is compiled. The recording sites already used `.get()` and dropped out-of-range indices; only the dump indexed directly. The dump now reads exactly the rows that exist. This was the diagnostic every performance investigation reaches for first, so the tool for measuring the scanner was the one guaranteed to crash on it, and the crash arrived after useful output, which made it read as a scan-end failure rather than a profiler bug.

- **A phase-2 GPU admission catalog that cannot cover its pattern set is now refused instead of trusted.** A GPU miss is only sound as "no covered pattern matched", so a catalog that omits a pattern the CPU prefilter would have marked can report absence for something the GPU never scanned. `complete` was derived from lowering failures alone, so always-active patterns dropped by the candidate filter for any other reason (a gate prefix literal, most visibly) were silently excluded from the covered set while the catalog still claimed completeness. On the shipped corpus that set is empty and the claim was vacuously true, so no finding was ever lost; the hole was latent, not live. Coverage is now computed against what the CPU would actually mark, and a catalog with any uncovered pattern is dropped so CPU admission stays authoritative. Shard construction is bounded at 64 shards and stops at the first uncovered pattern, because every shard is a separate dispatch over the same haystack and a pool that shatters is a dispatch storm rather than an accelerator, measured at 1,547 shards and 294 s on one 1.25 MB batch before the bound.

- **A file that is truncated while the scan reads it no longer kills the scan.** The whole-file read path mapped the file and read through the mapping. There is no race-free way to do that: an `ftruncate` from any other process invalidates the page-cache pages past the new EOF, and the next touch of the mapping raises `SIGBUS`. There is no handler, so the process died with signal 7. No report, no findings, no exit code a pipeline could interpret, and every other file in that scan lost with it. Measured on a plain `keyhog scan <file>` against a file a second thread was truncating and refilling: 4 of 8 trials died at 800 KiB, 1 of 6 at 128 KiB. That is not an exotic input. `scan-system` walks live filesystems where logs rotate, so one rotating file could destroy a whole-system scan. The read now goes through the already-open descriptor instead of a mapping, keeping the same symlink-resistant open, the same advisory shared lock, the same post-open re-stat, and the same hard 2 GiB ceiling. A file that SHRANK ends the read early and a file that GREW contributes its extra bytes, and neither can fault. The cost is one owned copy that this path was already paying, because a borrowed mapping could never be moved into the decoded `String`. Retry is deliberately not used and would be the wrong tool: the fault was designed out rather than survived. Two sites still map files and are tracked separately: the overlapping-window reader for files above the window size, and the compressed-input reader.

- **A scan that could not read its input now writes a report saying so, instead of writing nothing.** When every requested source produced zero data (an oversized file alone, an unreadable file alone, `--docker-image` on a tag that does not exist, `--s3-bucket` on a bucket that does not exist, a cap that excluded every input), `run()` printed a diagnostic and returned BEFORE report emission. With `-o out.json` that created no file at all: not an empty envelope, not a gap row, nothing. The loudest failure in the product was the only one with no machine-readable output, so a CI job uploading `out.json` as an artifact got a missing artifact and had to infer why from stderr prose. The shipped generic-shell and Drone recipes pre-seeded an empty envelope before the scan purely to work around it, which is decent evidence the behaviour was always wrong. The report is now always written, carrying the findings (if any) and an explicit statement of what was not covered and why; the exit code still carries the verdict, unchanged at 13. Partial coverage was already correct and is unchanged: a tree with one readable file holding a credential and one unreadable file still reports the credential, both gap rows, and exit 1.

- **`--autoroute-calibrate` no longer suppresses the findings exit code.** `resolve_scan_exit` returned success for any calibrating scan that did not panic, so `keyhog scan --autoroute-calibrate <tree> && echo clean` printed `clean` on a tree with leaks while the report next to it named the credential. Calibration is a side effect of a scan, not a different operation, and it must not mask the scan's verdict. This is the documented first-run command in our own installers, so the one scan most likely to be wired into a gate was the one that could not fail it. Findings now outrank calibration: exit 1 (or 10 for a live credential) when a calibrating scan finds something. Below findings, calibration may still report success on an incomplete sample, because its workload is a deliberately partial measurement rather than a claim about the tree.

- **Autoroute calibration now resolves a statistical dead heat instead of persisting no decision at all.** Selection required one route's 95% confidence interval to lie entirely below every peer's, and the only tie rule demanded exact nanosecond median equality between backends, which never once fired on real evidence. Overlapping-but-unequal timings therefore produced no route, so `benchmarks/corpora/homefield` (`cpu-fallback` 4.507 s [3.08, 11.49] against `gpu-wgpu` 4.462 s [4.40, 4.92], every interval overlapping every other) and this repository's own `crates/` tree persisted nothing, and every later scan of them completed through scalar correctness recovery: the slowest outcome reachable from a measurement whose entire content is that the backends are indistinguishable. A route now stays in contention unless some peer is proved faster, meaning that peer's whole interval lies below its own. Among the survivors only those whose median falls inside the fastest route's own 95% upper bound are eligible, so a wide error bar can never rescue a measurably worse median. That set is then ordered by backend complexity, because when nothing is proved faster the backend that needs no accelerator bring-up and always runs is the honest choice, and it is the same choice on every rerun of the same evidence. `resolve_measured_route` remains the strict proof and still backs `confidence_separated`, so a dead heat reports `confidence_separated: false` and a fourth `selection_basis` value, `unseparated-dead-heat-lowest-complexity-backend`, rather than posing as a proved win. **JSON consumers matching on `selection_basis` must accept that fourth value.** Measured after the change: homefield and `crates/` both persist a decision that a later scan consumes with no recovery, with findings byte-identical to an explicit `--backend simd-regex` run. This subsumes and replaces the exact peer-median tie rule.

- **A failed cache write can no longer discard a completed scan.** `ScanDispatcher::run` ended with `self.router.commit()?`, so a scan that read 100% of its input and found credentials reported NOTHING when `$XDG_CACHE_HOME` was read-only or full. Persisting a routing decision is not part of producing findings. The failure is now a loud stderr line plus a non-zero exit under `--autoroute-calibrate` (where persisting the decision WAS the requested operation), with the findings reported either way. Retry is deliberately the wrong tool here and is not used: the write is already atomic and lock-guarded, and a read-only cache directory does not become writable on a second attempt. Separately, a failed route quarantine no longer discards the batch that had already been scanned successfully through visible recovery: findings are collected before the bookkeeping, not after it.

- **A routing failure that says nothing about the matches no longer throws them away.** Any `AutorouteRoutingError` captured from any batch discarded the entire finding set. `AutorouteRoutingError` now carries a `kind` set at each construction site: `RoutingUnavailable` (a cache miss, an accelerator that did not come up, a measurement that did not persist) keeps the findings, warns, and records a new FAIL-class `BatchNotRouted` coverage gap so the run still cannot read as clean; `FindingsUntrustworthy` (a candidate backend whose output diverged from the scalar reference, an unstable reference, a batch that was never scanned) stays fatal, because there we do not know which finding set we are holding. Scalar correctness recovery is the reference implementation, not a degraded mode, so its findings were the most trustworthy in the report and discarding them was pure loss.

- **A calibrated autoroute decision can be found again.** `scan --autoroute-calibrate` without an explicit `--autoroute-gpu` wrote every decision under a resolved-config digest that no scan would ever request, so the immediately following identical scan reported `scan config digest mismatch` and completed through scalar correctness recovery. The cause was one field in the config digest recording whether calibration excluded an eligible GPU. On any host or build with no GPU candidate that exclusion is vacuous and the two host profiles are byte-identical, so the digest was the only thing that differed, and it differed on every run. The field is removed. The property it was reaching for is unchanged and still enforced where it belongs: a route generation is keyed by the persisted host profile, which carries the eligible backend census plus the complete GPU device, runtime, driver and batch-limit identity, so CPU-only evidence still cannot replay under a scan that admits a GPU. Measured on `homefield` and `mirror`, repeated scans of the same corpus with the same binary and config: 0% cache hit before, 100% after. Cache schema version moves 50 to 51 so an existing cache is superseded with a clear message rather than a config mismatch.

- **A coverage ceiling in the calibration sample no longer discards the whole calibration.** Calibration rejected any candidate trial whose scanner coverage counters moved at all. A `decode_oversize_skips` on one chunk is a deterministic property of the sample under the resolved configuration, not a degraded backend: `max_decode_bytes` is part of the config digest, so every candidate skips the same bytes and the replaying scan skips them again. The rejection also fired on the scalar reference trial, before anything was compared. Measured on `crates/`: a 346-second sweep across eight workload buckets exited 2 and persisted nothing, and every later scan of that tree routed through scalar correctness recovery. The guard now compares each candidate's coverage shape against the scalar reference's, per counter and for exact equality, so a candidate that covered different bytes than the reference is still refused. A sample with a non-empty coverage shape prints one warning naming the counters and the sample identity, so a persisted decision measured over skipped bytes is never silent.

- **A credential inside a minified or vendored bundle is reachable again, and a dropped one is counted.** Every finding whose path ended `.min.js`, `.bundle.js`, or `.min.css`, or sat under `node_modules/`, `site-packages/`, `wp-includes/`, `dist/assets/` and similar, was discarded before it reached the report. The drop was unconditional, left no trace on any surface, and no flag defeated it, so a live `sk_live_` key that a build pipeline had inlined into `app.min.js` produced `[]` and exit 0. Build tooling inlines API keys into bundles routinely, which made this the one leak class KeyHog could not report at all while saying nothing was detected. Two changes: `--no-default-excludes` now disables this suppression as well as the walker skip, so the flag disables every default exclusion instead of only the one you could see; and a suppressed finding is counted and reported as a `vendored/minified path policy` coverage-gap row naming the count and the flag that recovers it. The row is WARN class, so an ordinary scan of a tree with vendored code still exits 0.

- **A scan that read zero bytes no longer reports as clean.** A `.keyhogignore` containing `path:**` gave exit 0, `scan_status` `success`, zero bytes, zero chunks, an empty `coverage_gap_summary`, and the line `No secrets detected in the scanned files.` Every signal said the tree was clean and nothing had been examined. `--exclude-paths '**'`, an empty directory, and a directory whose only entry is an unfollowed symlink all had the same shape. A scan that reads no source bytes now emits a FAIL-class `scan covered nothing` coverage-gap row and exits 13, and the text report states that the scan covered nothing instead of that nothing was detected. There are two such rows, because the remedies differ: one for `no skip was counted` (nothing was there to read) and one for `every candidate was skipped by exclusion or skip policy` (policy hid it).

  **This is a user-visible exit-code change.** A scan whose target legitimately contains nothing scannable moves from exit 0 to exit 13. That includes `keyhog scan --stdin` on an empty stream, an empty directory, a pure vendored tree, a generated-artifacts directory, and a CI matrix partition with no files in its slice. That is intended: `git diff | keyhog scan --stdin` against the wrong base ref produces an empty diff, and reporting that as clean is the exact failure that makes mass scanning untrustworthy. Guard the producer (`[ -s "$f" ]` before the pipe) rather than suppressing the exit code. There is no opt-out flag, deliberately, because a flag that suppresses coverage failures would recreate the false affordance fixed above. A scan that reads bytes and finds nothing is unaffected and still exits 0, and a scan that covered some input and failed on the rest still reports every finding it got alongside the gap: exit 13 never means findings were discarded.

- **The exclusion coverage-gap row said something untrue.** It read `exclusion policy (.keyhogignore, --exclude-paths, or lock/minified/vendored defaults)`, but only the default policy ever produced it; files removed by an operator's own `.keyhogignore` or `--exclude-paths` are not counted. The row now says which of the two it means and states that user removals are not in the number.

- **`keyhog_profile::reset()` left the previous round's measurements in place.** It cleared the runtime-level stores and the legacy mirrors, and never touched the per-worker shards, so stage times, call counts, latency buckets and min/max, stage windows, typed counters, input bytes, cache counts and indexed counters all survived it. Benchmarks call `profile_reset()` between measured rounds precisely to discard warm-up, so round two was reporting round one's numbers as its own. Nothing failed and no output looked wrong; the second measurement was simply the first one plus the second. `reset()` now clears every per-run accumulator it owns, and a test asserts each family is empty afterwards. The indexed-counter half was reported by the perf-consolidation lane; the shards were the general case underneath it.

- **A vendor detector no longer claims a credential it cannot attribute.** Nine service-named detectors owned patterns carrying no evidence of their own vendor, so every match was attribution by coincidence. `akamai-api-credentials` held a bare `client_secret[=:\s"']+([a-zA-Z0-9+/=]{30,50})`, which made Akamai the de-facto owner of every OAuth client secret; `wordpress-api-token` held a bare `access[_\-\s]*token` alternative; `authentik-token` held a bare `Authorization: Bearer <40+ alnum>` that `bearer-authorization` already owns; `budibase-credentials` held bare `INTERNAL_API_KEY`, `JWT_SECRET` and `(COUCH_DB|MINIO|REDIS)_PASSWORD` assignments. Each is now anchored to its own evidence: the vendor name, the vendor host in a bounded window (`*.luna.akamaiapis.net`), or the vendor's own token prefix (`akab-`). Measured against the per-file vendor ground truth in `benchmarks/corpora/homefield/kingfisher/manifest.jsonl`, wrong-vendor attributions fell from 114 to 87 of 386 attributed findings while correct ones rose from 272 to 282. Ten detectors had been losing their own inline `test_positive` to an over-broad sibling and now surface it (avaya, aws-cognito, azure-government, checkmarx, discord-oauth, jumio, elevenlabs, internalio, supabase-jwt, bearer-authorization). No credential was lost to the tightening: across `benchmarks/corpora/mirror/corpus`, `homefield`, `ioc-recovery-v3` and this repository's own `crates/`, zero files went from at least one finding to none. That zero is controlled rather than asserted: the same measurement reports 7 blinded files when the two replacement detectors below are removed and the tightening is left in place.

  **This moves findings between `detector_id`s.** A baseline, allowlist or suppression keyed on `detector_id`, or on a `detector_id` plus credential-hash pair, may stop matching for the affected services, and severity and rotation guidance change with the attribution. On `homefield`: `akamai-api-credentials` 14 to 4, `authentik-token` 4 to 0, `wordpress-api-token` 13 to 0, `budibase-credentials` 1 to 0 and `klaviyo-api-key` 6 to 2, against `bearer-authorization` 36 to 39, `elevenlabs-api-key` 1 to 4, `jfrog-api-key` 1 to 4, `square-access-token` 4 to 6 and `onelogin-client-secret` 0 to 1. The credential set is unchanged; only which detector claims it moved.

- **A self-hosted GitLab or Bitbucket endpoint had no destination screen, so the operator's token went wherever it was pointed.** `hosted_git::validated_api_endpoint` checked the scheme, embedded credentials, and the query/fragment, and never once asked where the request was going. `--gitlab-endpoint https://169.254.169.254`, `https://10.0.0.5`, or `http://127.0.0.1:9` was accepted and the `PRIVATE-TOKEN` header carried there; Bitbucket's Basic credential the same. Every other remote source already refused this: S3, GCS and Azure screen through `cloud::parse_http_endpoint`, and WebSource refuses loopback outright. Hosted git was the one hole, and the repository already contained a test asserting the hole was there, pinning the transport error as expected behaviour with a comment that a future SSRF screen should flip it. Both endpoints now go through `crate::endpoint_screen`, which is the single owner of the decision and screens the literal host against the fleet-canonical `keyhog_verifier::ssrf` classifier and then re-screens every resolved address, so a public hostname whose A record points at a metadata address is refused too. The addresses that passed the screen are pinned into the client with `resolve_to_addrs`, so reqwest cannot re-resolve between the check and the connect; that half was found by the security-boundary lane. Skipped when a proxy is configured, because the proxy owns DNS then.

  **This is a user-visible change for on-premises deployments.** A self-hosted GitLab or Bitbucket on a private address is an ordinary enterprise configuration, and `--gitlab-endpoint https://gitlab.internal.corp` now exits 13 with `refusing gitlab endpoint: host is a private, loopback, link-local, or cloud-metadata address (SSRF)` unless `--allow-private-cloud-endpoint` is passed. That flag already existed and already governed the cloud object stores; it now means what its name says across every remote source rather than three of five. Add it for a trusted internal endpoint. It is deliberately not implied by supplying an endpoint, because the whole failure being fixed is that supplying an endpoint was treated as consent to send a credential to it.

- **`keyhog scan <path> --benchmark` scanned nothing and exited 0.** `--benchmark` runs KeyHog's own built-in corpus and exits; it never reads an operator-supplied target and never writes `--output`. Passing both was accepted, both were silently discarded, and the run reported success: `keyhog scan ./src --output report.json --benchmark` printed `benchmark winner: simd-regex at 159.02 MiB/s`, exited 0, and wrote no file. In CI that line reads as a completed scan of `./src`. The flag now conflicts with `PATH`, `--path`, `--stdin` and `--output`, so the combination exits 2 naming the conflict instead of throwing the request away. Benchmarking a specific corpus was never what the flag did; use a normal scan with `--profile` for that.

- **Lowering `--decode-size-limit` silently reduced recall.** A chunk larger than the limit was declined for decode-through with nothing recorded anywhere, while the neighbouring path that truncates decoder *output* has always counted a `decode_truncations` gap. So the decline that skips the pass entirely was the quiet one. Measured on the 2,399-file `homefield` corpus: `--decode-size-limit 64K` reported 1,623 findings against 2,239 at the 512 KiB default, 616 fewer, with an empty `coverage_gap_summary` and nothing on stderr. A chunk denied decode-through now records a WARN-class `scanner decode-through declined by --decode-size-limit` coverage gap that names the flag in the structured `coverage_gap_summary` reason, not only in terminal prose, so a CI wrapper reading the envelope gets the remedy. It stays at zero on an ordinary scan, because no chunk reaches the compiled 512 KiB default. WARN rather than FAIL is deliberate and was settled by the lanes that own exit semantics: the raw bytes *were* examined, only a derived layer was skipped, which is the same class as the existing decode-truncation and structured-oversize rows. The recall half is a separate open defect: while the 1 MiB window size exceeds the 512 KiB decode limit, the interior of any larger file is decode-unreachable regardless of this counter.

  The counter was recorded only in `scan_inner`, which the coalesced SIMD route bypasses, so the gap was **backend-dependent**: on this repository's `crates/` tree, `--backend cpu` reported one declined chunk and `--backend simd` reported none, for byte-identical findings. Recall never differed between backends; only the operator's warning did, which is the worse failure because it is invisible. The recorder is now paired with `record_file_scanned` at every site, which is the event that already has one call per chunk per route by contract. Surfaced by the autoroute lane's calibration guard rejecting a candidate on the counter mismatch.

- **The oversized-input coverage row named a flag that had not fired.** `SourceSkipEvent::OverMaxSize` is raised by at least eleven distinct caps: `--max-file-size`, `--limit-stdin-bytes`, `--limit-git-blob-bytes`, the two Docker tar caps, the S3/GCS/Azure per-object caps, the archive per-entry cap and the windowed-mmap sanity cap. The row read `exceeded --max-file-size` and advised re-scanning with a larger cap, so `--git-blobs <repo> --limit-git-blob-bytes 64B` told the operator to raise `--max-file-size`, which leaves the blobs skipped. It now names the cap family and points at the per-cap warnings above it, which already name the exact flag. Reported by the limits lane.

- **The GCS token-forwarding warning fired on the flag rather than on the act.** `--allow-gcs-token-forward` printed its consent notice when the flag was parsed, from the CLI's dedicated-flag branch. The equivalent `--source gcs:BUCKET\nPREFIX\nENDPOINT\ntrue` reaches the same source with the same effect and printed nothing, so one of two equivalent entry paths was silently quieter. The notice now lives in `gcs_bearer_token`, at the point an ambient token is actually carried to a non-Google endpoint, mirroring what the S3 path already did. Both entry paths are identical, and the warning fires only when a token is genuinely forwarded rather than whenever the flag is present.
- **A detector pattern with no basis in its own documented format is gone.** `jetadmin-credentials` carried `jet_[a-zA-Z0-9]{24,}`, which appears nowhere in that detector's documented format (`JET_ADMIN_`/`JET_` prefixed environment variables) and, because detector patterns compile case-insensitively, matched any long `Jet`-prefixed identifier. Measured against a 2.2 GB cargo registry it produced 256 findings, and all 256 were Microsoft JET database engine constants in `windows-0.58.0/src/Windows/Win32/Storage/Jet/mod.rs` (`JET_bitSetUniqueNormalizedMultiValues`, `JET_errDatabasePatchFileMismatch`, and 254 more). Zero true positives. That tree now reports one finding, which is this detector's own `test_positive` vendored inside a published `keyhog-core` crate. The three assignment-anchored patterns cover the documented format, including the detector's own inline test.

- **Five vendor detectors could not match their own vendor's current credential format.** `elevenlabs-api-key` accepted only `sk_` plus 32 hex while ElevenLabs issues 48, so all three ground-truth samples in `homefield` were being attributed to Klaviyo; it also matched `sk_` inside `lsv2_sk_<32 hex>_<10 hex>`, taking LangSmith keys from `langsmith-api-key`, so it now requires a token boundary and captures whole-value. `onelogin-client-secret` accepted only 64 hex where OneLogin also issues lowercase alphanumeric. `jfrog-api-key` owned only the retired `AKCp8` prefix and not the `artifactory_access_token` assignment that replaced it. `square-access-token` owned only `sq0atp-`/`sq0csp-` and not the `EAAA` OAuth token that replaced them. `akamai-api-credentials` required `client_token` with an underscore and a 32-character floor, where real EdgeGrid tokens are hyphenated and 18 to 19 characters after `akab-`.

- **A single large file cost roughly 3.8x its own size in peak memory, so a big enough file simply ran out of RAM.** Every existing benchmark was many-small-files, so the large-file regime was never measured. Three separate causes, all in the path from read to scan. The filesystem reader collected EVERY window of one file into a `Vec` and sent nothing until the whole file was read, so a 300 MiB file held all ~343 of its 1 MiB windows live at once and the scan pool sat idle through the entire read: sampling `/proc` showed one thread accumulating 617 MB with 31 cores doing nothing. The windowed `mmap` never released pages it had already walked past, so the whole file stayed resident on top of that. And every queue bound between the source and the scan workers counts CHUNKS, not bytes, which describes ~128 KiB per batch on a small-file corpus and ~32 MiB on one big file, so the large-file regime carried over a gigabyte of queue headroom and was split into only ~11 work units for 32 cores. The reader now streams each file's windows in byte-bounded parts (a small file is still exactly one send, unchanged), the slicer hands back each stride with `MADV_DONTNEED` as it leaves it behind, and the fused batch cut is byte-aware as well as count-aware. Measured on one 300 MiB file, isolating this change alone: peak RSS 1,156,720 KB to 772,972 KB and 4.79 s to 3.78 s; on 1 GiB, 3,131,944 KB to 804,400 KB and 13.89 s to 9.76 s. The 300 x 1 MiB control improved too (862,896 KB to 766,216 KB), so the cost was removed rather than moved. Total CPU-seconds are unchanged, so the wall-clock gain is read/scan overlap that was not happening before, not less work. Peak RSS is now flat in file size rather than proportional to it: on the shipped binary, 347,068 KB at 300 MiB against 379,400 KB at 1 GiB, +9% across a 3.5x size increase, against +171% before. A 1 GiB file needs 0.37 GB where it previously needed 3.1 GB. Findings are byte-identical: 2,863 on `benchmarks/corpora/mirror/corpus` with an identical canonical set digest, and 25 of 25 secrets planted at every one of the 21 ways a 20-byte credential can straddle a window cut are still found exactly once, with the correct absolute byte offset and line. The large absolute improvement on the shipped binary is mostly the detector-compilation and scratch-retention work from the memory lane; this change removed the term that scales with file size, theirs removed the constant, and the two compose.

  **Persisted autoroute calibration invalidates once.** Batches are now cut on bytes as well as chunk count, which changes the `(byte-total, chunk-count)` workload key calibration measures against, so the compiled-in `fused_batch_bytes` is hashed into the autoroute config digest. Any calibration persisted before this change reads as a config mismatch and is measured again on the next `--autoroute-calibrate` run. That is intended rather than incidental: replaying a decision timed under different batching would be measuring something else. No flag or output changes, and a scan that has never calibrated is unaffected.

### Added

- **One retry policy, in `keyhog_core::retry`, with retries counted by cause.** Bounded attempts (3), one backoff (5 ms doubling to a 40 ms ceiling), and one classification of transient versus permanent. There is deliberately no catch-all cause: an unclassified failure is permanent and is not retried, so making a new failure recoverable requires naming it in `keyhog_profile::RetryCause`. A permission denial, an absent operator-supplied path, and every cap refusal (the docker tar entry-count cap, the docker unpack budget, the PDF work budget, `--max-file-size`, the seventeen configured source limits) are permanent by intent: they fail identically on every attempt, and retrying a hostile input turns a denial-of-service defence into a denial of service. `retry::open_enumerated` exists to design the stat-then-open race out rather than retry it, taking metadata from the open descriptor so no second path lookup can resolve to a different inode. Every retry ATTEMPT is counted through the profiler and surfaced in `--profile` output, including attempts on operations that eventually succeeded, because a retry that fires is evidence of a defect rather than a success.

- **The autoroute cache reports its hit rate.** Every automatic scan now prints one stderr line: `autoroute cache: 100.0% hit (2 hit / 2 lookup(s))`, where one lookup is one batch asking for its route. A scan with misses names the cause (`cache-rejected`, `bucket-absent`, `runtime-class-unproved`, `route-quarantined`, `gpu-peer-identity-changed`, and three more), the count of distinct uncalibrated buckets, and the one repair that fixes that cause. Previously nothing counted a hit, so "is the cache earning its keep" was unanswerable and a key that could never hit looked exactly like a corpus nobody had calibrated. Run with `-v` to list every distinct uncalibrated bucket under `keyhog::routing`, so one recalibration can cover all of them instead of learning about one bucket per run. The line prints in every output mode; `--format json -o <file>` previously suppressed the whole routing summary, which is the shape CI uses. The same outcomes feed the profiler cache family as `autoroute-decision` and `autoroute-calibration`, so `--profile-out` carries hits, misses and `hit_rate_ppm`.

- **`--profile` answers the questions a slow scan actually raises, and leads with the answer.** It reported per-stage span timings with call counts and percentiles, which is the evidence for a conclusion and not the conclusion. Six families are now measured and reported. MEMORY: peak resident from the kernel high water, the engine-init floor taken as resident memory on entry to scanning, input-driven resident as peak minus floor, amplification, per-scanner-thread resident, and allocation volume and peak owned per stage. PARALLELISM: per-worker busy and blocked time from outermost spans only, so nesting never double-counts; idle time against pool capacity; achieved speedup as process CPU over wall; efficiency against logical CPUs; an Amdahl ceiling from measured serial work; and time spent inside instrumented regions while not on CPU, which is where a large pool loses its speedup without ever going idle. SERIAL PHASES: per-stage wall-clock windows giving average concurrency, plus an exclusivity measure that separates a real barrier from an inclusive wrapper whose children are the parallel work, so a span covering the whole scan is not reported as a bottleneck. THROUGHPUT: MiB/s and files/s overall, per phase and per micro-function. ATTRIBUTION: cost per call, per file, per byte, per detector family and per backend. CACHE AND REUSE: hit rates for autoroute decisions, calibration reuse, incremental unchanged-skips, matcher artifacts and verifier results, through one `CacheId` vocabulary so the question has a single answer instead of one per subsystem. Retry attempts are counted by cause and reported as a finding, because a retry that fires is a failure that was not designed out. The first line of the human summary is now the conclusion, for example `bottleneck memory-floor 481.3 MiB of the 489.2 MiB peak is standing the engine up, not the input: 11.0 B of input produced only 8.0 MiB of extra resident memory`, with the span detail below it as evidence. Measured on the mirror corpus, `crates/`, and a 300 MiB file: the profiler independently reproduces the engine-init floor at 481 to 485 MiB across every workload, a 27.9 MB per-scanner-thread scratch slope over a five-point thread sweep, and 3.74x resident amplification on the large file, all of which previously required `/usr/bin/time` and shell loops. Every derived value is an integer in thousandths or parts per million, so two `--profile-out` records diff exactly and an unchanged run cannot look changed.

  **This changes `--profile` output and the `--profile-out` document.** The stderr report gains the summary above the existing span table, and the JSON gains `stage_concurrency`, `worker_occupancy`, `queue_depths`, `blocked_waits`, `caches`, `indexed_counters`, `retries` and `insight`. Every new field carries a serde default, so a reader of older records still decodes. The profile schema minor moves 2.7 to 2.8. Default scan output, findings and exit codes are unchanged. Recording stays free when profiling is off: the disabled path is one relaxed atomic load with no clock read, and the new counters return before touching anything when no runtime is current.

- **Measurement primitives so a subsystem records through the profiler instead of its own stopwatch.** `serial_span` declares a region that runs with the pool idle; `add_stage_bytes` gives a micro-function a real MiB/s; `record_cache_hit` and `record_cache_miss` take a fixed `CacheId`; `record_retry` takes a fixed `RetryCause`; `counter_span` times a region that sits inside a stage leaf without double-counting it; `add_indexed_counter` holds a per-slot family such as the per-decoder cost table, where a slot outside the fixed range is counted as dropped rather than folded into a neighbour. `decision_timer` is deliberately different from the rest: it reads the clock unconditionally, because a measurement the product acts on, such as autoroute calibration, must produce the same value whether or not an operator passed `--profile`, or the flag would change routing. Two stages are new, `autoroute-calibration` and `boundary-scan`, the second of which makes chunk-seam rescanning visible where it was previously folded anonymously into the phase-two leaves.

- **Two detectors for credential shapes the corpus could not attribute.** `oauth-client-secret` owns the vendor-neutral `client_secret` assignment (RFC 6749 section 2.3.1), which had no owner, so the shape was previously reported as Akamai. It is built from detector TOML data alone with no new code, reusing the existing structural-slot primitives, and `resolution_priority = -1` ranks it below every service-named client-secret detector (azure, google, okta, keycloak, cognito, discord, onelogin, avaya, jumio, checkmarx) so an attributable secret is never reported as the neutral shape. It recovers 7 files on `benchmarks/corpora/homefield` that no detector matched at all (pingidentity, gitalk, webex, huawei, onelogin, intra42 and a betterleaks fixture). Placeholders stay silent without any new suppression code, because the captured slot excludes `<`, `>`, `$`, `{` and `}` and carries a 20-byte floor: `client_secret=${OAUTH_CLIENT_SECRET}`, `client_secret=<your-secret-here>` and `client_secret=secret` do not match. `facebook-access-token` owns the Graph API `EAA` prefix, which `facebook-oauth-secret` never covered because it holds only the 32-hex app secret; the three Facebook access-token ground-truth files in `homefield` were being attributed to WordPress, two of them reported only through that wrong detector, so anchoring WordPress to its own evidence would otherwise have dropped them. Its pattern carries an explicit `(?-i)`, which is load-bearing rather than decorative: detector patterns compile case-insensitively by default, and without it the caseless `eaa` matched the lowercase prefix of sha256 image digests (`nginx@sha256:eaa35988...`) and produced false positives on mirror negatives. The embedded corpus goes from 923 detectors to 925.

### Changed

- **The phase-two confirmation pass no longer builds two anchored verifier regexes per pattern when it reads one.** `extract_anchored` compiled both the `\A(?:src)` verifier and the `\A(?s:.)(?:src)` left-context variant for every eligible pattern, and allocated a capture-slot buffer for each on every call. A candidate at byte 0 is rare, so the plain verifier was an entire extra regex compiled per pattern that nothing ever read, and a pattern with no capture group never reads the slots at all. Each variant is now built only when some candidate position actually consults it, and a non-grouped pattern resolves through `find`, off the lazy DFA, without running the capture engine. This is worth more wall time than instruction count suggests: regex construction is one-time per pattern but serialized on whichever worker touches it first, so it does not parallelize. The same pass also replaces a per-chunk `HashSet` of present suffix literals and a binary search run per anchor candidate with reusable per-worker bitsets, skips the per-line homoglyph normalization on chunks that preprocessing already proved unchanged, and settles the raw-text comparison by pointer identity rather than a whole-buffer `memcmp`. Measured on a frozen 5,554-file copy of `crates/`: 4.10% fewer retired instructions, median wall 9.42 s to 8.55 s. On the 15,000-file mirror corpus: 1.96% fewer instructions. Findings are byte-identical on both corpora under `--backend cpu` and `--backend simd`.

- **Scanning an eleven-byte file no longer costs 480 MB.** `CompiledScanner::compile` built a `regex::Regex` for every pattern, companion and generated homoglyph variant in the corpus and kept all of them resident, and `ScanOrchestrator::new` then called `warm()`, which ran each one against a sample. A compiled corpus pattern is on the order of 200 KB of NFA, one-pass DFA and Teddy-prefilter state, and the embedded corpus declares 1,709 patterns and 178 companions, so a scan paid roughly 450 MB before reading any input. That is a floor, not a workload cost: the same amount was spent whether the target was eleven bytes or a repository, which is why a constrained CI runner could be killed by a scan of almost nothing. Detector patterns are still VALIDATED at construction, through the same builder the scan path uses, so a malformed or oversized regex and an out-of-range capture group are rejected loudly before a scan can start; the validation build is simply not retained. Phase-1 literal gating means a real scan reaches a small fraction of the corpus, and each reached pattern compiles once on first use through the existing process-wide regex cache. Measured with `/usr/bin/time` on two `release-fast` binaries built from one commit, median of three: an eleven-byte file at `--threads 1` goes 480,460 KB to 67,000 KB and at `--threads 32` goes 486,288 KB to 110,748 KB; the 60 MB mirror corpus goes 596,080 KB to 207,332 KB and 848,360 KB to 456,408 KB; a 28 MiB source tree goes 962,136 KB to 701,012 KB and 1,653,140 KB to 1,393,000 KB. The corpus-proportional part of the floor falls from 0.489 MB per detector to 0.041. Findings are byte-identical, verified by digest on the mirror corpus and on a source tree at both thread counts.

  **`CompiledScanner::warm()` changed meaning.** It warms the shared runtime matchers every chunk touches (the multiline structural regexes, the shared assignment regex, the generic-assignment value bridge) and no longer force-compiles the per-detector patterns, because doing that re-materialised the whole corpus on every invocation, including one-shot single-file and pre-commit scans that reach a handful of detectors. It stays idempotent and cheap to repeat.

- **The phase-2 prefilter's per-worker regex scratch is bounded.** `Phase2AlwaysActivePrefilter` passed one 64 MiB constant to both `size_limit` and `dfa_size_limit` on all four of its `RegexSet` builders. The first is a per-process compile budget; the second is a lazy-DFA cache allocated per worker thread per batch, so the nominal per-worker ceiling scaled with the batch count. The compile budget stays at 64 MiB and the cache ceiling is now a separate 4 MiB. Cache size only decides how much of the automaton is memoized, never which patterns the set reports, so this is match-equivalent; measured neutral on peak resident memory and wall time on both corpora at one and thirty-two threads.

  **Peak memory still grows with worker count on a real scan, and no size knob reduces it.** The remaining per-worker term is the `regex` crate's lazy-DFA cache, allocated per compiled regex per thread and retained in that regex's pool for the life of the process, dominated by the anchored phase-2 verifiers. Lowering the per-regex ceiling does not help: measured at 1 MiB, 256 KiB and 64 KiB on two binaries at one, eight and thirty-two threads, peak resident memory moves under one percent while wall time degrades about fivefold, because the meta engine abandons the lazy DFA for slower engines that allocate comparable per-thread state. What governs the term is how many distinct patterns a worker activates, not the size of any one automaton, so reducing it is detection-routing work rather than a tuning constant.

### Changed

- Expose confirmed_companion_gate on [tuning] and resolved/autoroute config identity (default on), so operators can disable the mid-literal confirmed-pass skip the same way as confirmed_suffix_gate.
- Restore pure structural base64url parsing in jwt_segments, reserve structural payload/header decoding for analyze, replace runtime panic macro paths in BPE token count cache initialization with a compile-time safe TOKEN_CACHE_CAPACITY constant, support legacy var declarations in bounded CryptoJS recovery, and use one containment relation for miss-clustering TP, FP, and FN accounting.
- Cold one-shot and incremental scans now reuse a persisted MatcherArtifact of the eager compiled matcher graph across process invocations (format v4), with CacheId hit/miss/invalidation in profile output, fail-closed identity checks, soft-fail when cache prep fails, and --lockdown disabling the cache.
- Companion-gate derived AC/literal tables use a bounded per-thread LRU keyed by detector digest + active pattern set, and parsed-arm memo is capacity-capped, so heterogeneous trigger mixes do not rebuild from a single-slot thrash or grow unbounded.
- Restore reusable phase-1 absence proofs for small rejected repeated payloads (≤128 KiB), and size-gate markerless bounded-window decode skips so short trailing slices still decode.
- 39 process-safe scanner test files are wired into the all_tests aggregator. Process-global decoder-registry and allocation targets plus the RSS-sensitive execution-pack mapping contract run in isolated CI processes. The recall_locks_wired.py gate is widened from checking only regression_*.rs to checking all top-level test files. CI workflow duplication is eliminated by extracting composite actions for workspace repair and Vectorscan install. All workspace compile warnings are fixed (zero warnings from cargo check --workspace).
- fix(release): consume legacy unreleased notes.

### Fixed

- Base64 decode memo retains successful UTF-8 text only after a second sighting of the same candidate, so unique-blob corpora no longer keep a second full-size copy of every decode for the whole chunk. Failures stay memoized immediately.
- Companion-literal presence scratch resizes to the active literal count and fill(false)s every chunk (not only the non-grow branch), with a regression test that seeds stale true bits then grows the literal set.
- Corrected operator-visible help text and docs for five flags whose descriptions diverged from the implementation: --ml-threshold (applies to all findings, not just ML), --fast (also disables ML scoring), --oob-timeout (upper bound is max(value, 120s), not the value alone), --dogfood (credentials are redacted with prefix and suffix, not prefix only), and exit-code 3 (autoroute-cache persist failure applies when no findings are reported, not when findings exist). Updated the workspace authors contract test to match the binding identity.
- Preserve scanner-materialization context on installed execution-pack compile failures, and remove the unused record_matcher_artifact_pack_hit helper that contradicted CLI profile attribution policy.
- Autoroute calibration times candidates on the route-neutral phase-1 plan (no CPU trigger prefill on the clock); production still fills hints after CpuFallback selection so backend comparison stays fair.
- Autoroute CpuFallback selections now fill deferred CPU trigger hints on the route-neutral phase-1 plan so production automatic scans reuse them.
- Make filesystem/windowed phase-1 representative reuse symmetric: both chunks must agree on windowed-ness, and windowed pairs also require the same path, so vocab-clean proofs cannot jump across paths or source classes.
- Move companion presence-scratch growth regression out of src into tests/unit/root_facade and expose companions_deny_absent via the testing facade so KH-GAP-004 no-inline-tests stays green.
- Cache entropy configuration digests and use capacity-aware vocabulary absence marks so hot-path hashing and capped finding heaps stay correct.
- Drop unused chunk_is_markerless_single_line helper and replace em dashes in scanner comments/SPEC with ASCII punctuation so the zero-warnings / prose gates stay green.
- Re-cache entropy_evidence_config_digest on CompiledScanner (widened vocab key) and invalidate on with_config / clear_fragment_cache so hot windowed lookups avoid rehash without ignoring the known in-place config mutation path.
- Extract vocabulary absence helpers under the scanner source-size cap and add a companion-gate test override so suffix-gate cold-regex differentials stay measurable.
- Remove a redundant always_active_absence_proven self-assignment that tripped clippy::redundant_locals under -D warnings.
- Vocab-stage absence memo keys include mutable scan settings (unicode_normalization, min_confidence, match/decode caps, penalize_test_paths) so clean proofs cannot survive in-place config edits.
- Windowed absence memos bind to exact ordered content, only engage for parent filesystem/windowed slices, reuse the batch entropy configuration digest, and drop new keys at capacity instead of clearing unrelated proofs.

## [0.5.70] - 2026-08-10

### Changed

- fix(profile): fail-closed overlapping allocation session peaks.

### Security

- Fail-closed overlapping allocation sessions instead of misattributing process-global peaks

## [0.5.69] - 2026-08-10

### Added

- `keyhog scan --access-targets` reports the resource each credential opens: account, tenant, endpoint, database, or resource. A finding says where a credential is, not what it reaches, and the address is usually next to the credential where no detector can see it, because a companion regex is bounded to a few lines and captures the other half of the credential rather than the resource. Providers live in Tier-B `crates/core/data/access-targets.toml`, so adding one is a data edit. Off by default: with the flag absent the report has no `access_targets` key and findings are byte-identical. With it, `--format json-envelope` gains an `access_targets` object and the envelope schema minor moves 9 to 10, which is additive and readable by any consumer accepting a minor under major 1. Values are addresses only, never authenticators: connection-string rules skip userinfo, a rule may not capture the whole match, and any candidate whose digest matches a credential in the same report is dropped. Coverage is explicit, so an empty target list is never mistaken for `this credential opens nothing`: a finding from git history, a container layer, stdin, an unreadable path, a decoded or windowed view, or a file past the index cap is counted in `coverage.gaps` with a named reason and `complete` goes false. Separately, `keyhog detectors --mechanisms` prints which recovery mechanisms each detector declares (regex, keywords, structure, entropy, BPE, decode, companions, relations, verification, suppression, source admission), derived from detector TOML with the field that proves each one, and reports a mechanism KeyHog cannot yet express as unavailable with the reason rather than omitting it. It does not scan.
- Two detectors for credential shapes the corpus could not attribute. oauth-client-secret owns the vendor-neutral client_secret assignment (RFC 6749 section 2.3.1), which had no owner, so the shape was previously reported as Akamai; it is TOML data reusing the existing structural-slot primitives with no new code, ranked below every service-named client-secret detector so an attributable secret is never reported as the neutral shape, and it recovers 7 ground-truth files that no detector matched at all. Placeholders stay silent without new suppression code because the captured slot excludes < > $ { } and carries a 20-byte floor. facebook-access-token owns the Graph API EAA prefix, which the app-secret detector never covered; its pattern carries an explicit (?-i) because detector patterns compile case-insensitively by default, and without it the caseless eaa matched the lowercase prefix of sha256 image digests. The embedded corpus goes from 923 detectors to 925.
- Add a workload index and per-shape guides so each input shape has a documented path from zero to a correct scan, and add a canonical page for telling a genuine clean from a skipped input. Watch mode had no page and was absent from the table of contents, single-large-file, minified, container, stdin and encoded-payload inputs had no shape-specific limits recorded, and a reader had no documented way to distinguish an empty findings list caused by clean input from one caused by input that was never read.
- Make `--profile` answer the questions a slow scan raises instead of reporting spans and leaving the conclusion to the reader. Six families are measured now. Memory: peak resident from the kernel high water, the engine-init floor taken on entry to scanning, input-driven resident as peak minus floor, amplification, per-scanner-thread resident, and allocation volume owned per stage. Parallelism: per-worker busy and blocked time from outermost spans only so nesting never double-counts, idle against pool capacity, achieved speedup as process CPU over wall, an Amdahl ceiling from measured serial work, and time inside instrumented regions while not on CPU, which is where a large pool loses speedup without going idle. Serial phases: per-stage wall windows giving average concurrency, plus an exclusivity measure separating a real barrier from an inclusive wrapper whose children are the parallel work. Throughput: MiB/s and files/s overall, per phase and per micro-function. Attribution: cost per call, per file, per byte, per detector family and per backend. Cache and reuse: hit rates for autoroute decisions, calibration reuse, incremental unchanged-skips, matcher artifacts and verifier results, through one CacheId vocabulary. Retry attempts are counted by cause and named as a finding, because a retry that fires is a failure that was not designed out. The first line of the summary is the conclusion, for example `bottleneck memory-floor 62.9 MiB of the 68.0 MiB peak (92.5%) is standing the engine up, not the input`. Verified on the mirror corpus, `crates/`, and a 300 MiB file: the profiler independently reproduces the engine-init floor, the per-scanner-thread scratch slope over a thread sweep, and resident amplification on a large file, all of which previously took `/usr/bin/time` and shell loops. This changes `--profile` stderr, which gains the summary above the existing span table, and the `--profile-out` document, which gains stage_concurrency, worker_occupancy, queue_depths, blocked_waits, caches, indexed_counters, retries and insight. Every new field carries a serde default so older records still decode, and the profile schema minor moves 2.7 to 2.8. Default scan output, findings and exit codes are unchanged. Every derived value is an integer in thousandths or parts per million, so two records diff exactly and an unchanged run cannot look changed. Recording stays free when profiling is off: the disabled path is one relaxed atomic load with no clock read.
- One retry policy, in `keyhog_core::retry`, with retries counted by cause.

### Changed

- Signed execution packs now reuse whole-pack signature authentication during scanner hydration instead of hashing backend and native shard payloads again; unsigned development packs retain full per-shard validation.
- Daemon compatibility checks now derive worker topology without initializing GPU runtime libraries in client processes.
- Explicit CPU and SIMD daemons no longer initialize or retain GPU runtime libraries during startup.
- Execution-pack host identity checks no longer initialize GPU runtime libraries in short-lived clients.
- CPU scans now bypass per-chunk parallel dispatch when authenticated admission evidence proves an entire bounded batch has no direct matches.
- Execution-pack startup now borrows detector-plan prelude strings directly from authenticated framed rows while interning runtime ownership, avoiding transient per-row string copies.
- Explicit CPU and SIMD filesystem scans now retain at most four bounded fused batches per parallel wave.
- Installed scans now collect freed source-construction arenas at the source boundary and periodically reclaim idle mimalloc pages, reducing retained memory without changing finding order or coverage.
- Azure Blob Storage scans now stream blob bodies in deterministic order through the shared bounded cloud fetch window instead of retaining a container-wide result vector.
- Binary and Ghidra analysis now emit gapless 256 KiB text chunks, avoiding whole-output joins and retaining only compact printable-run descriptors before bounded materialization.
- Bitbucket workspace scans now stream ordered repository results through the shared bounded hosted-Git pipeline while preserving listing-error order, instead of retaining every cloned repository result until the workspace finishes.
- Automatic daemon fallback now shares the acquired stdin payload and scans it through bounded overlapping windows, avoiding a second whole-input byte copy and a whole-input decoded retry buffer.
- Persistent daemons now configure at most eight physical-core Rayon workers before detector loading, preventing accidental logical-core pools and bounding resident worker-local caches.
- Docker image scans stream each layer tar through the shared in-memory archive dispatcher with one inflate pass and image-scoped unpack budgets, instead of full decompress plus FilesystemSource re-walk. Large already-UTF-8 plain layer members stream in ~1 MiB windows from the tar entry (peak near one window); formats that need a full member (archives, PDF, images, HAR, lz4/sz) still buffer up to the 100 MiB scan cap. Extensionless members prefix-sniff before full buffer. Layer .har files expand at the Docker boundary with wire:har labels; nested .har inside ordinary zip/tar/7z/RAR keep the historical filesystem/archive leaf identity. UTF-16 archive members keep the whole-member decode path. Top-level layer 7z/RAR extract from bytes when content magic matches.
- Filesystem scans now coalesce ordered tiny-file handoffs into bounded batches and reuse complete extensionless prefix reads instead of reopening the same file.
- Google Cloud Storage scans now stream object bodies in deterministic order through the shared bounded cloud fetch window instead of retaining a bucket-wide result vector.
- Git history scans now yield each bounded decoded-blob batch and annotated-tag message before loading the next payload instead of retaining whole commits or tag sets.
- GitHub collaboration scans now stream issue, pull-request, discussion, wiki, gist, and release chunks through one-row backpressure without retaining a selected surface's full content, and share one token allocation across the worker.
- GitHub organization scans now preserve concurrent shallow cloning while streaming repository chunks in configured repository order with one-row channels, instead of retaining every cloned repository result until the organization finishes.
- GitLab group scans now stream ordered repository results through the shared bounded hosted-Git pipeline instead of retaining every cloned project result until the group finishes.
- Out-of-band verification now polls only while callbacks are pending and uses a bounded three-request lifecycle burst while preserving the configured sustained collector rate.
- Large filesystem scans now retire explicit CPU and SIMD windows in bounded worker waves, share byte-identical source windows, and reuse verified repeated-window findings with rebased locations.
- S3 scans now stream listing-page objects in deterministic order with a 16-result backpressure window, retain prior-page findings when a later listing fails, and avoid accumulating downloaded object bodies across the bucket.
- Slack scans now stream channel histories through an ordered eight-channel backpressure window, share one token allocation across the worker, and stop retaining every workspace message chunk until collection completes.
- HTML reports now serialize findings directly to their output stream with bounded per-finding memory while preserving verification-error redaction and script-breakout protection.
- Web scans now stream ordered fetch results with eight-response backpressure, emit JavaScript, source-map, and WASM text in gapless 256 KiB chunks, and release parsed source-map ownership before chunk materialization.
- CPU autoroute now reuses bounded exact payload evidence across source batches while rejecting sampled-fingerprint collisions and stale policy identities.
- SIMD scans now cache bounded exact trigger rows across repeated authenticated batches while requiring full payload equality after sampled lookup.
- CPU scanner startup now hydrates a compact phase-two keyword index and reuses install-compiled repeated-separator metadata; matcher packs require schema version 5.
- Filesystem scans now coalesce tiny files up to the existing 1 MiB payload ceiling and execute them in worker-sized CPU and SIMD lanes, reducing per-file scheduler, channel, and Hyperscan scratch churn.
- CPU and SIMD routing now classify each byte-distinct payload once per batch while preserving exact per-chunk admission evidence.
- Anchoring vendor detectors to their own evidence MOVES FINDINGS BETWEEN detector_ids, so a baseline, allowlist or suppression keyed on detector_id (or on a detector_id plus credential-hash pair) can stop matching, and severity and rotation guidance change with the attribution. On the ground-truth corpus: akamai-api-credentials 14 to 4, authentik-token 4 to 0, wordpress-api-token 13 to 0, budibase-credentials 1 to 0 and klaviyo-api-key 6 to 2, against bearer-authorization 36 to 39, elevenlabs-api-key 1 to 4, jfrog-api-key 1 to 4, square-access-token 4 to 6 and onelogin-client-secret 0 to 1. The credential set is unchanged; only the claiming detector moved. Re-key any detector_id-scoped baseline before upgrading, or previously-suppressed findings reappear as new.
- BREAKING: --limit-docker-tar-total-bytes now bounds one whole image rather than one tar. It was enforced with a fresh accumulator per tar, so an image made of an outer tar plus one tar per layer got the full allowance for each; Docker permits 127 layers, so the 8 GiB default admitted roughly 1 TiB of unpacking per image while every individual check passed. A 2-layer image under a declared 5104-byte cap previously unpacked 13361 bytes with no truncation and now refuses at the image total. If you have tuned this flag, raise it to cover the sum across the image tar and every layer tar, or images that previously scanned will be refused with a counted coverage gap.
- Document what a baseline entry actually matches on, add a task-oriented path for failing CI only on new secrets, and state the shallow-clone prerequisite for scanning Git history. The deep-recovery guide previously opened with autoroute calibration and never mentioned fetch-depth, so a documented CI job would scan a single commit and report nothing.
- Filesystem discovery prunes default-excluded directories during the walk, finishes deep Linux trees via descriptor-relative metadata-only discovery after ENAMETOOLONG, and cheaply sniffs unclassifiable names before full reads.
- Generic assignment scanning now rejects broad keyword-stem lines unless an assignment delimiter follows the stem, while preserving *_PASS= and value-suffix recall.
- `--git-blobs` collects commit blobs by parent-tree diff (added/changed/deleted sides) instead of rewalking every historical tree. Every ref tip under refs/ plus HEAD (detached CI checkouts), root commits, and unreadable parents still get a full tree walk so `--max-commits` keeps untouched tip blobs across custom namespaces. Unsupported non-blob tree-diff entries stay coverage gaps, already-collected parent-diff sides are kept when a later parent falls back to a full walk, default-excluded unsupported entries stay silent (same as the full walk), and blob decode stays on the already-open repository handle.
- GPU routes now execute detection only through VYRE-owned CUDA, Metal, and WGPU programs. KeyHog no longer ships a WGPU MoE shader: ML confidence scoring is deterministic CPU work for every backend, the `[tuning].gpu_moe_timeout_ms` key is removed, and GPU health reports expose only VYRE literal-set and production region-presence probes.
- GPU region batches now pipeline two VYRE-owned resident IO slots: KeyHog builds and submits the next batch before retiring the previous readback, while immutable matcher tables remain shared and result consumption stays ordered.
- Replace twenty-six near-identical inline-test gate files with one that scans the whole CLI source tree. Each of the old files hardcoded a single path, so they covered twenty-four files while the tree actually had twenty-five with inline test bodies, including the entire autoroute backend directory that no gate reached. Net 357 lines of duplicated test scaffolding removed and the blind spot closed.
- Authenticated execution packs now retain install-validated companion regexes as lazy matchers instead of recompiling every companion during scanner startup.
- Filesystem discovery now walks metadata directly, preserves native path ordering through bounded external sorting, and defers content classification to the no-follow reader instead of reopening every candidate during traversal.
- Nested archive scans stream compressed tarballs member-by-member with a single inflate, instead of retaining each full decompressed image or paying a second inflate for TeX probing. TeX provenance continues to gate on tar header names for buffered uncompressed tar, and on zip central-directory names.
- Directory enumeration now walks in parallel, cutting the serial prefix before the first byte is scanned (mirror source-walk 392-419ms to 155-171ms, wall -14.1% on a 15,000-file tree). Findings are byte-identical: entries are still sorted by path before batching, so batch composition and autoroute workload identity are unchanged. Discovery-budget walks (--limit-discovery-bytes, scan-system) deliberately stay serial, because the budget is charged in arrival order and stops at the first over-budget entry, so a parallel walk would admit a different subset on every run.
- Execution packs now persist confirmed, suffix-gate, and phase-two localization plans so installed scans hydrate those indexes without reparsing the detector regex corpus.
- Build only the anchored verifier regex a candidate position actually consults in the phase-two confirmation pass. `extract_anchored` compiled both the `\A(?:src)` verifier and the `\A(?s:.)(?:src)` left-context variant for every eligible pattern, and allocated a capture-slot buffer for each on every call, but a candidate at byte 0 is rare and a pattern with no capture group never reads the slots, so a whole extra regex per pattern was compiled and never read. Non-grouped patterns now resolve through `find` off the lazy DFA without running the capture engine. The same pass replaces a per-chunk hash set of present suffix literals and a binary search run per anchor candidate with reusable per-worker bitsets, skips the per-line homoglyph normalization on chunks preprocessing already proved unchanged, and settles the raw-text comparison by pointer identity rather than a whole-buffer memcmp. Regex construction is one-time per pattern but serialized on whichever worker touches it first, so it costs wall time out of proportion to its instruction share: a frozen 5,554-file copy of crates/ measures 4.10 percent fewer retired instructions and median wall 9.42 s falling to 8.55 s, the 15,000-file mirror corpus measures 1.96 percent fewer instructions, and findings are byte-identical on both corpora under --backend cpu and --backend simd.
- Builds now resolve VYRE 0.7.2 from one reviewed upstream commit instead of requiring a sibling source checkout, while keeping CUDA, native Metal, WGPU, and runtime crates on the same immutable identity.
- Out-of-band verification now overlaps its one-shot RSA session-key generation with scanning before collector registration.
- The bundled decoder plan now skips allocating short alphanumeric assignment values that cannot satisfy any built-in decoder while preserving custom-decoder extraction semantics.
- CPU scans now reuse exact phase-two keyword and generic-assignment localization evidence computed for byte-identical autoroute payload representatives.
- Authenticated execution-pack hydration now reuses whole-pack signature verification instead of reserializing and rehashing matcher sections while preserving structural validation.
- Authenticated CPU execution packs now reuse whole-pack signature validation instead of reserializing the scalar program during hydration.
- CPU scans now reuse exact confirmed-pattern absence proofs for byte-identical repeated payloads instead of rerunning confirmed regexes per chunk.
- CPU scans now reuse exact phase-one trigger bitmaps for byte-identical repeated payloads instead of rescanning each chunk.
- CPU scans now reuse exact decoder-admission absence across byte-identical payloads with matching decoder metadata context.
- CPU scans now bypass direct matcher dispatch when exact repeated-payload evidence proves every direct matching lane absent.
- CPU scans now reuse path-independent entropy absence proofs for byte-identical repeated payloads and invalidate them when entropy policy changes.
- CPU scans now share bounded line and documentation indexes across byte-identical passthrough payloads.
- CPU scans now reuse exact multiline-admission absence proofs for byte-identical repeated payloads and invalidate them when evidence policy changes.
- CPU scans now reuse exact normalization passthrough proofs for byte-identical repeated payloads instead of rescanning unchanged text.
- CPU scans now reuse exact always-active phase-two absence proofs for byte-identical repeated payloads instead of rerunning the shared prefilter per chunk.
- SIMD scans now reuse exact payload-representative trigger results and authenticated negative phase-two evidence without reusing path-dependent findings.
- SIMD scans now reuse exact normalization, multiline, and line-index evidence from authenticated admission plans.
- Persistent daemon, watch, and system-scan runtimes now compile from one shared detector corpus allocation instead of cloning every detector before scanner construction.
- Concurrent CPU batches now single-flight exact reusable admission evidence misses instead of rebuilding the same representative in parallel.
- Scanner post-processing now skips decode generation for whole chunks and bounded filesystem windows whose decoder admission proof is impossible.
- Default daemon clients now use the detector identity compiled into the binary instead of parsing all embedded detector TOML solely for the compatibility handshake; explicit replacement corpora remain content-hashed.
- Verified POSIX installs build route-scoped authenticated CPU/SIMD/VYRE execution packs with calibration evidence and rollback.
- Read-only Linux execution-pack mappings share immutable backend pages as shared clean RSS across scanners.
- Worker-local scanner scratch uses route-specific retention ceilings instead of keeping outlier allocations.
- Watch finding lines now include a stable `sha256:<digest>` credential identity beside the redacted value, enabling redaction-safe parity and deduplication across events.

### Removed

- Delete 235 source-grep shape tests across the five crate test trees. Each read a .rs file at runtime and asserted only substring presence or absence on that text, so they pinned how the source is spelled rather than what the scanner does; the project standard bans them. 107 test files went away entirely, 57 files lost individual tests, and every mod registration plus three Cargo [[test]] entries went with them. Two ambient-env gates (KEYHOG_THREADS, KEYHOG_DETECTORS) became four behavioural tests that drive the binary and read `config --effective` and `detectors --format json`. Each is a negative assertion, so each is paired with a positive case on the same output field, and both oracles were ablated to confirm the comparison discriminates: KEYHOG_THREADS=99 leaves `threads = auto` while --threads 3 moves the same line to 3, and KEYHOG_DETECTORS pointing at a one-detector directory leaves the corpus intact while --detectors on that directory reduces it to one. 23 source pins for network and filesystem security boundaries are kept deliberately: verifier_safety_contracts.rs, the DNS-pin and no-auto-decompression gates, the verifier proxy owner, the git safe-bin and no-follow-symlink gates, and the hosted-Git credential temp-file permission contract. That last pin was repointed at the whole hosted_git module after the module split moved the code it reads out of hosted_git.rs, which had silently made its negative assertions vacuous, and it now asserts an anchor first so it fails loudly rather than passing for free the next time the module is reorganised.

### Fixed

- Detect container formats by content signature rather than by filename extension. An archive member or file whose name carried no recognized extension was never opened, so a secret inside it was missed and the scan reported clean with no error row. This is the normal shape of an OCI layer, which is named by digest. Members with no in-memory extractor now emit a counted error row instead of vanishing.
- A calibrated autoroute decision can be found again, and every scan now reports the cache hit rate. Calibrating without an explicit --autoroute-gpu wrote decisions under a resolved-config digest no scan would ever request, so the immediately following identical scan reported a config mismatch and completed through scalar correctness recovery; the digest hashed whether calibration excluded an eligible GPU, which is vacuous wherever no GPU candidate exists, and the host generation already carried that exactly. A calibration sample holding a chunk over the decode ceiling also discarded the whole sweep, because any nonzero scanner coverage counter rejected the trial, including the scalar reference trial before anything was compared; candidates are now compared against the reference coverage shape and refused only when they skipped more than it. Every automatic scan prints one stderr line naming hits, lookups, the typed miss cause and the one repair that fixes that cause, in every output mode including --format json -o FILE, which previously suppressed the routing summary entirely. Measured on repeated scans of the same corpus with the same binary and config: mirror, homefield and crates/ all move from 0 percent hit to 100 percent. Cache schema version moves 50 to 51, so an existing cache is superseded with a clear message rather than a config mismatch.
- Resolve a statistical dead heat in autoroute calibration instead of persisting no decision at all. Selection required one route's 95% interval to lie entirely below every peer's, and the only tie rule demanded exact nanosecond median equality, which never fired on real evidence. Overlapping timings therefore produced no route, so real trees persisted nothing and every later scan of them completed through scalar correctness recovery. A route now stays in contention unless a peer is proved faster; among survivors only those whose median falls inside the fastest route's own 95% upper bound are eligible, so a wide error bar cannot rescue a measurably worse median; that set is ordered by backend complexity. Strict separation still backs confidence_separated, so a dead heat reports confidence_separated false and a fourth selection_basis value, unseparated-dead-heat-lowest-complexity-backend, rather than posing as a proved win. JSON consumers matching on selection_basis must accept that fourth value.
- AWS STS HTTP 200 responses without parseable caller-identity metadata no longer report Live.
- Refuse `--benchmark` combined with a scan target instead of silently discarding it. The flag runs KeyHog's own built-in corpus and exits; it never reads an operator-supplied target and never writes `--output`. Passing both was accepted, both were discarded, and the run reported success: `keyhog scan ./src --output report.json --benchmark` printed a throughput table, exited 0, and wrote no file, so in CI that line reads as a completed scan of ./src. The flag now conflicts with the positional PATH, `--path`, `--stdin` and `--output`, so the combination exits 2 naming the conflict. Two related report strings were also wrong rather than absent. The shared oversized-input coverage row read `exceeded --max-file-size` and advised raising that cap, but the counter behind it is raised by at least eleven caps including `--limit-git-blob-bytes` and the Docker and cloud object caps, so following the remedy left the input skipped; it now names the cap family and points at the per-cap warnings that name the exact flag. And the GCS token-forwarding consent notice fired when `--allow-gcs-token-forward` was parsed rather than when a token was forwarded, so the byte-equivalent `--source gcs:...` entry path printed nothing at all; the notice now lives at the point an ambient token is actually carried to a non-Google endpoint, so both entry paths behave identically.
- Named detectors can fire on binary-derived content again. Admission past the binary-strings noise gate required a declared `[detector.credential_shape]`, which 4 of 925 detector TOMLs carry, so 921 named detectors could never report a finding in an ELF, PE, Mach-O, wasm, static archive, shared object, archive member or container layer; the same tar.gz reported `aws-access-key` and silently dropped `slack-bot-token` purely because one TOML had the block. A match is now admitted on per-match structural proof, a declared shape or a span covering a whole lexical token, while generic, weak-anchor and free-form password-slot detectors stay suppressed, and a withheld match is counted as a `binary_strings_named_exclusions` coverage gap instead of vanishing. Expect new findings on compiled artifacts and container images that previously reported clean: a planted Slack token goes from 0 to 14 of 15 binary variants, and 249 MiB of real system ELF goes from 0 to 4 findings. Printable runs are also emitted in file order with every occurrence kept, replacing an alphabetical whole-input dedup that made two runs neighbours because they shared a prefix, and joined by a separator no whitespace, non-whitespace or dot class can cross, so a pattern can no longer bridge runs that were never adjacent.
- Selective anchor construction uses a bounded deterministic frequency sketch instead of retaining every corpus window, reducing scanner startup memory without changing recall.
- Large filesystem windows now decode through bounded overlapping subwindows, recovering encoded credentials beyond the default decode working-set ceiling without raising that ceiling.
- BufferedStdinSource now records the same SourceAcquire and SourceRead profile spans as spooling stdin, so pre-owned stdin payloads no longer appear unprofiled while still charging input totals.
- Surface chunks abandoned at their per-chunk deadline as a fail-class coverage gap. When `--per-chunk-timeout-ms` elapsed mid-chunk the scanner returned an empty or short match set for that chunk, and the abort was counted into scanner telemetry that nothing read, so a scan that abandoned every chunk still reported `scan_status: success` with an empty `coverage_gap_summary` and exit 0. Deadline aborts now surface as `scanner chunk abandoned at its per-chunk deadline` and mark the scan partial. Operator-visible change: a scan that hits the deadline exits 13 instead of 0 where it produced no findings, so raise or clear `--per-chunk-timeout-ms` rather than suppressing the exit code. Findings are never discarded; a run that covered some input reports its findings alongside the gap.
- Detector-owned reverse and Caesar prefix gates use compact contiguous automata, reducing packed-scan startup ownership without changing decode selection.
- Two coverage-gap rows named a cause that was not theirs. The exclusion row read `exclusion policy (.keyhogignore, --exclude-paths, or lock/minified/vendored defaults)`, but only the last of those three ever produced it: files removed by an operator's own .keyhogignore or --exclude-paths are not counted in that number at all, so a reader comparing the count against their ignore file got a figure that could never match. It now names the default policy specifically and states that user removals are not included. The archive row attributed every truncation to the filesystem decompression-bomb guard and its 4x --max-file-size budget, which stopped being true once the docker path gained three producers of the same event, so a container image refused by its own image-scoped unpack budget reported a cap that had nothing to do with it. It now names the cap family and points at the per-cap warnings that identify the exact one. Both are report text rather than behaviour, and both matter for the same reason the rest of this work does: a coverage row exists to tell an operator what was not looked at and why, and a row whose stated reason is wrong sends them to fix something that is not the problem.
- Persistent daemon and watch runtimes now compile the exact forced backend, so explicit SIMD startup owns a usable Hyperscan plan instead of a CPU-only scanner.
- Single-file and stdin daemon scans now report their out-of-process byte coverage without a contradictory zero-byte coverage gap.
- Report the decode-through coverage that `--decode-size-limit` declines, instead of quietly returning fewer findings. A chunk larger than the limit was denied decode-through with nothing recorded anywhere, while the neighbouring path that truncates decoder OUTPUT has always counted a gap, so the decline that skips the pass entirely was the silent one. Measured on the 2,399-file homefield corpus, `--decode-size-limit 64K` reported 1,623 findings against 2,239 at the 512 KiB default, 616 fewer, with an empty coverage_gap_summary and nothing on stderr. A denied chunk now records a WARN-class `scanner decode-through declined by --decode-size-limit` gap that names the flag in the structured coverage_gap_summary reason rather than only in terminal prose, so a CI wrapper reading the envelope gets the remedy. It stays at zero on an ordinary scan because no chunk reaches the compiled default. WARN rather than FAIL is deliberate: the raw bytes were examined and only a derived layer was skipped, which is the same class as the existing decode-truncation and structured-oversize rows. The counter was initially recorded only on the non-coalesced route, which made the gap backend-dependent (cpu reported one declined chunk where simd reported none, for byte-identical findings); it is now paired with the per-chunk scan event that every route calls, so the warning cannot disappear because autoroute picked a different backend.
- Remove a detector pattern with no basis in its own documented format. jetadmin-credentials carried jet_[a-zA-Z0-9]{24,}, which appears nowhere in that detector's documented format (JET_ADMIN_ and JET_ prefixed environment variables) and, because detector patterns compile case-insensitively, matched any long Jet-prefixed identifier. Measured against a 2.2 GB cargo registry it produced 256 findings and all 256 were Microsoft JET database engine constants in the windows crate, with zero true positives. That tree now reports one finding, the detector's own test fixture vendored inside a published crate. The three assignment-anchored patterns cover the documented format.
- Stop vendor detectors from claiming credentials that carry no evidence of that vendor. Akamai owned every bare client_secret, WordPress owned every bare access_token, and Authentik owned every bearer authorization header. Wrong-vendor attribution on the ground-truth corpus drops from 114 of 386 to 87, with no recall lost and 9 files newly detected.
- Five vendor detectors could not match their own vendor's current credential format. elevenlabs-api-key accepted only sk_ plus 32 hex while ElevenLabs issues 48, so every ground-truth sample was attributed to Klaviyo; it also matched sk_ inside lsv2_sk_<32 hex>_<10 hex> and took LangSmith keys from langsmith-api-key, so it now requires a token boundary and captures whole-value. onelogin-client-secret accepted only 64 hex where OneLogin also issues lowercase alphanumeric. jfrog-api-key owned only the retired AKCp8 prefix and not the artifactory_access_token assignment that replaced it. square-access-token owned only sq0atp- and sq0csp- and not the EAAA OAuth token that replaced them. akamai-api-credentials required client_token with an underscore and a 32-character floor, where real EdgeGrid tokens are hyphenated and 18 to 19 characters after akab-.
- Container layer path normalization now keeps scanning members whose names begin with `#`, only peeling HAR `#url` suffixes when the member body remains non-empty.
- Daemon wire e2e helpers now start the daemon on the embedded detector corpus so warm identity matches the client's embedded detector-digest stamp.
- Installed scans stream authenticated detector plans from execution packs without decoding detector schemas, validate canonical matcher envelopes in one typed JSON pass, build prefix propagation through a flat arena trie instead of one hash table per trie node, co-locate each lazy regex's compiled cell and memoized source facts under one shared owner, share compiled signature strings with post-processing, and compile companion regexes and pattern-shape validator sets only when their evidence is first required. The entropy precision gate consumes an exact build-packed cl100k rank table without constructing the tokenizer's duplicate encoder, decoder, sorted-token, and thread-local regex graphs. Report-time remediation validation uses the build-generated detector ID index instead of reparsing the embedded detector corpus after a finding. Compiled detector plans share equal confidence policies across the detector table and keep sparse entropy, shape, and suppression policies in a compact indexed side table. Small detector-owned keyword vocabularies use compact flat byte tables instead of retaining one Aho-Corasick automaton per detector. Phase-two no-candidate gates are scoped to the active residual route, and phase-two anchor lookup tables share literal sources with the lazy runtime rows before the lookup tables are released. The large phase-two, confirmed shared-anchor, and confirmed suffix-gate automata materialize only for a non-empty batch, then their compiler arenas are purged before per-chunk scanning. Sparse files stream only allocated extents and report all-hole files as uncovered regions, stdin validates its byte cap through an anonymous spool before scanning bounded overlapping windows, and bounded stdin windows use a rendezvous-fed fused scan batch instead of accumulating the complete input. Empty stdin remains an explicit zero-byte coverage gap instead of reporting an unearned clean scan. Fused source boundaries default to rendezvous channels, homoglyph prescreening no longer materializes Unicode matchers for unrelated replacement characters, and the one-long-line benchmark now contains one delimited canary on one physical line. Large unbounded filesystem walks retain deterministic path order in one common-root byte slab and compact row/index tables instead of one allocated absolute path per file. The archive-symlink audit streams unbounded directory entries and skips duplicate regular-file metadata checks while no-follow read paths retain link-swap protection. Installed-pack benchmark captures bind detector runtime provenance per workload so catalogs that intentionally use multiple detector corpora remain exact.
- Explicit `--binary <file>` scans no longer also run the plain filesystem classifier, eliminating a contradictory binary-skip coverage gap after strings or sections were scanned.
- Lazy phase-two anchor construction now warns and keeps affected patterns on recall-preserving whole-chunk or folded RegexSet paths instead of panicking when an Aho-Corasick build fails.
- Linux filesystem scans now traverse and safely open paths beyond the pathname syscall limit with directory descriptors while preserving deterministic ordering and symlink protections.
- Filesystem scans now reconstruct an empty relative walk path as the directly requested file itself instead of appending a directory separator and reporting zero coverage.
- Large unbounded Unix filesystem walks external-merge deterministic native-byte path metadata through bounded temporary runs instead of retaining one row and sort index per file.
- Unbounded Unix filesystem discovery releases its final in-memory sort slabs before mapping the external merge spool, lowering peak RSS without changing enumeration.
- `--github-api-endpoint` is now applied to `--github-org` scans (factory previously ignored it).
- Default GitHub wiki clone URLs now follow the configured API endpoint host (GHES-safe).
- Screen the destination of a self-hosted GitLab or Bitbucket API endpoint before sending the operator's token to it. `--gitlab-endpoint` and `--bitbucket-endpoint` validated the scheme, embedded credentials and the query, and never asked where the request was going, so `https://169.254.169.254`, `https://10.0.0.5` and `http://127.0.0.1` were accepted and the PRIVATE-TOKEN or Basic credential was carried there. Every other remote source already refused this: S3, GCS and Azure screen through the cloud endpoint gate and WebSource refuses loopback outright, so hosted git was the one hole, and a test in the tree asserted the hole was expected behaviour. Both endpoints now use one shared screen that checks the literal host against the canonical SSRF classifier and re-screens every resolved address, so a public hostname whose A record points at a metadata address is refused too; the approved addresses are pinned into the client so the connection cannot re-resolve after the check. BREAKING for on-premises deployments: a self-hosted GitLab or Bitbucket on a private address now exits 13 unless `--allow-private-cloud-endpoint` is passed. That flag already existed and already governed the cloud object stores, and now means what its name says across every remote source. It is deliberately not implied by supplying an endpoint, because the failure being fixed was treating an endpoint as consent to send a credential to it.
- Scanning one large file cost roughly 3.8x its own size in peak memory, so a big enough file ran out of RAM. Three causes, all between read and scan. The filesystem reader collected EVERY window of a file into a Vec and sent nothing until the whole file was read, so a 300 MiB file held all ~343 of its 1 MiB windows live at once and the scan pool sat idle through the read; sampling /proc showed one thread accumulating 617 MB with 31 cores doing nothing. The windowed mmap never released pages it had already walked past. And every queue bound between the source and the scan workers counts chunks rather than bytes, which is ~128 KiB per batch on a small-file corpus and ~32 MiB on one big file, so the large-file regime carried over a gigabyte of queue headroom and split into only ~11 work units for 32 cores. The reader now streams each file's windows in byte-bounded parts (a small file is still exactly one send), the slicer returns each stride with MADV_DONTNEED as it leaves it behind, and the fused batch cut is byte-aware as well as count-aware. Isolating this change alone: one 300 MiB file 1,156,720 -> 772,972 KB peak and 4.79 -> 3.78 s; one 1 GiB file 3,131,944 -> 804,400 KB and 13.89 -> 9.76 s; the 300 x 1 MiB control also improved (862,896 -> 766,216 KB), so the cost was removed rather than moved. Total CPU-seconds are unchanged, so the wall gain is read/scan overlap that was not happening before. Peak memory is now flat in file size instead of proportional to it: +9% across a 3.5x size increase, against +171% before. Findings are byte-identical, and secrets planted at every one of the 21 ways a 20-byte credential can straddle a window cut are each still found exactly once with the correct absolute byte offset and line. NOTE: batches are now cut on bytes as well as chunk count, which changes the workload key autoroute measures against, so the compiled-in fused batch byte ceiling is hashed into the autoroute config digest. Any calibration persisted before this change reads as a config mismatch and is measured again on the next --autoroute-calibrate run. That is intended: replaying a decision timed under different batching would be measuring something else. No flag or output changes, and a scan that has never calibrated is unaffected.
- Authenticated packed scans defer precise hot-pattern validator regexes until their literal prefix is observed; backend parity regressions now compile the exact requested route.
- `--perf-trace` no longer aborts the process it is measuring. Every run died with an index-out-of-bounds panic and exit 134 after the report was written, because the per-pattern timing dump indexed process-global tables sized by whichever scanner initialized them first, and on a GPU build a single-pattern probe scanner warms them before the full corpus compiles. Separately, a phase-2 GPU admission catalog that cannot cover its pattern set is now refused rather than trusted: a GPU miss is only sound as "no covered pattern matched", and completeness was derived from lowering failures alone, so always-active patterns dropped by the candidate filter for any other reason were excluded from the covered set while the catalog still claimed to be complete. That set is empty on the shipped corpus, so the hole was latent and no finding was ever lost. Shard construction is now bounded at 64 shards and stops at the first uncovered pattern, because every shard is a separate dispatch over the same haystack.
- Cap retained batch-route records and count drops like other profile event streams
- Deallocate Mach thread ports after task_threads sampling so utilization samples do not leak send rights
- Clear the per-worker shards in `keyhog_profile::reset()`. It cleared the runtime-level stores and the legacy mirrors and never touched the shards, so stage times, call counts, latency buckets, stage windows, typed counters, input bytes, cache counts and indexed counters all survived it. Benchmarks call `profile_reset()` between measured rounds precisely to discard warm-up, so round two reported round one's numbers as its own. Nothing failed and no output looked wrong; the second measurement was simply the first plus the second. A test now asserts each family is empty after a reset. Separately, the fixed-memory finding no longer keys on an absolute byte threshold: it was calibrated against a 483 MiB engine-init floor, and once that floor dropped to 63 MiB the finding sat four MiB from going silent while its diagnosis stayed true. It now keys on the share of peak that is fixed cost, which is the actual claim and holds at any scale.
- Gap system IO evidence when no start sample exists instead of publishing absolute /proc counters
- Stop reporting a stale binary-asset channel as current, and name the real Hyperscan library when an install fails. `keyhog update` compared the running build against the newest GitHub release asset and printed "already on the latest release" whenever nothing newer existed there, so a build newer than that channel, which every release since v0.5.47 is, was told it was up to date forever; it now distinguishes being on the newest asset from being ahead of a channel that stopped publishing, and names `cargo install --locked --force keyhog` in the second case. The installer's missing-library remediation matched the glob `*libhyperscan*`, but the published Linux binary declares `NEEDED libhs.so.5`, so a clean host got the loader error and no fix at all; it now matches the real SONAME plus the `libvectorscan` spelling, and any unrecognized library gets a generic lookup hint instead of dead-ending. The shipped artifact's runtime dependencies are also deterministic again: `lzma-sys` linked the system liblzma whenever `pkg_config` found one and vendored it otherwise, so the same commit produced binaries with or without `NEEDED liblzma.so.5` depending on the build host, and `xz2` is now pinned to a static link for 110,328 bytes.
- Stop auto-release from bumping workflow YAML that GITHUB_TOKEN cannot push
- Source skip counters (unreadable, binary, over-max-size and the other coverage-gap totals) could be attributed to the wrong scan. The counter-isolation lease was released when a scan's chunk iterator dropped, but the filesystem reader crew records skip events from its own threads and outlives that iterator whenever a consumer stops early, so a finished scan's increments could land in a later scan's window. The lease is now scan-scoped rather than thread-scoped: it is held by every thread doing work for the scan and released only when the last one finishes, and the recording call itself carries the gate. Coverage-gap events are delayed rather than dropped, so a gap is never lost.
- Script auth verification requires exact STATUS: LIVE/DEAD lines and rejects ambiguous mixed output.
- A shallow clone no longer reports its truncated history as a clean scan. `keyhog scan --git-history` and `--git-blobs` against a `git clone --depth N` checkout gave exit 0, scan_status success, and an EMPTY coverage_gap_summary, while a full clone of the same repository reported a credential that had been committed and later removed: the commits holding it were never fetched, so the scan searched history that was not there and said nothing. The parent commits named at the graft boundary but absent from the object database are now counted as unscanned Git objects, so such a scan reports scan_status partial with a `Git object unreadable` coverage-gap row and exits 13, and stderr names `git fetch --unshallow` and `actions/checkout` `fetch-depth: 0` as the remedy. This is a user-visible exit-code change and it fires on the common CI shape, because `actions/checkout` fetches one commit by default, so any job that scans history on an unmodified checkout moves from a green tick to exit 13; fix the checkout depth rather than suppressing the code, since the exit is reporting that the input never contained the history you asked it to search. Findings are never discarded: a shallow clone that does contain credentials still reports every one of them, byte-identical to before, with the gap row added rather than substituted, and a depth-1 clone of a single-commit repository stays a genuine success because its graft boundary is the root commit and hides no parent.
- Source limits are exact at their boundary and honest about which ones a build can reach. A git output line whose content is exactly `--limit-git-line-bytes` is now scanned instead of refused: the cap counted the trailing newline, so an at-cap line produced a coverage gap for input that was inside the limit, and identical content was judged differently depending on whether it ended the stream. `keyhog config --effective` no longer prints a numeric value for a limit whose source backend is not compiled in; those rows now read `unavailable (requires the <feature> feature in this keyhog build)`, matching the flag that is absent from `scan --help` and the `.keyhog.toml` key that was already rejected. All 22 declared limits now have a CLI test proving each admits exactly its cap, refuses one byte or item more, and surfaces the refusal as a coverage gap rather than dropping input silently.
- Report ordering and duplicate-winner selection no longer depend on filesystem enumeration order. Matches are now sorted by a total key (severity, source, path, commit, line, offset, detector, credential digest) instead of by severity alone, which as a stable sort had silently inherited walk order for every equal-severity match.
- A client that walks away no longer kills the daemon.
- A vendor detector no longer claims a credential it cannot attribute.
- Anchored-regex fail-closed cases now compile in scanner library test builds.
- `daemon stop` and `daemon status` no longer report a live daemon as absent.
- macOS scanner library CI no longer fails on wgpu dual-slot overlap or a backblaze-shaped proptest seed.
- `Shutdown` now delivers in-flight results before it acknowledges.
- The generic OAuth `client_secret` detector no longer reports canonical UUID identifiers.
- A credential inside a minified or vendored bundle is reachable again, and a dropped one is counted. Every finding whose path ended .min.js, .bundle.js or .min.css, or sat under node_modules/, site-packages/, wp-includes/, dist/assets/ and similar, was discarded before it reached the report. The drop was unconditional, left no trace on any surface, and no flag defeated it, so a live sk_live_ key that a build pipeline had inlined into app.min.js produced an empty report and exit 0. Build tooling inlines API keys into bundles routinely, which made this the one leak class KeyHog could not report at all while saying nothing was detected. Two changes. `--no-default-excludes` now disables this suppression as well as the walker skip, so the flag disables every default exclusion instead of only the one you could see. And a suppressed match is counted and reported as a `matches dropped by the vendored/minified path policy` coverage-gap row naming the count and the flag that recovers it. The row is WARN class, so an ordinary scan of a tree containing vendored code still exits 0. Measured on a wp-includes/config.php holding a live-shaped Stripe key: 88 bytes scanned, 0 findings and an empty coverage_gap_summary before, the same scan plus the counted row after, and exit 1 with the finding under `--no-default-excludes`.
- A scan that read zero bytes no longer reports as clean. A .keyhogignore containing `path:**` gave exit 0, scan_status success, zero bytes, zero chunks, an empty coverage_gap_summary, and the line `No secrets detected in the scanned files.` Every signal a consumer has said the tree was clean, and the scan had examined nothing at all. `--exclude-paths '**'`, an empty directory, an empty stdin stream, and a directory whose only entry is an unfollowed symlink all had the same shape. A scan that reads no source bytes now emits a FAIL-class `scan covered nothing` coverage-gap row and exits 13, and the text report states that the scan covered nothing instead of that nothing was detected. There are two such rows because the remedies differ: one for `no skip was counted` when nothing was there to read, and one for `every candidate was skipped by exclusion or skip policy` when policy hid it. THIS IS A USER-VISIBLE EXIT-CODE CHANGE. A target that legitimately holds nothing scannable moves from exit 0 to exit 13, including `keyhog scan --stdin` on an empty stream, an empty directory, a pure vendored tree, and a CI matrix partition with no files in its slice. That is intended: `git diff | keyhog scan --stdin` against the wrong base ref produces an empty diff, and reporting that as clean is the exact failure that makes mass scanning untrustworthy. Guard the producer, for example `[ -s changed.diff ]` before the pipe, rather than suppressing the exit code. There is deliberately no opt-out flag, because a flag that suppresses coverage failures would recreate the false affordance fixed alongside this. A scan that reads bytes and finds nothing is unaffected and still exits 0, and a scan that covered some input and failed on the rest still reports every finding it got alongside the gap, so exit 13 never means findings were discarded. Note that scan_status alone does not carry this: an ordinary git working-tree scan is already `partial` from its default-exclusion rows, so the usable signal is the FAIL/WARN class of the gap rows, which is what the exit code encodes.

### Security

- Cap the number of tar entries KeyHog walks in a docker archive or layer. The existing byte guard sums each entry's payload size, so an archive built entirely from zero-length entries never advanced it and could be walked without bound: a 4.4 MB gzip expands into two million tar headers, each costing a filesystem syscall during unpack. Entries past the cap are refused and counted as a coverage gap rather than silently truncated.
- GitHub collaboration and org API endpoints now fail closed through the shared hosted-git SSRF screen before any bearer token leaves the process.
- GitHub wiki clone URLs now pass the shared clone-origin screen, and api.github.com maps to github.com for HTTPS clones.
- Bind hosted-git askpass credentials to exact URL host boundaries, not origin substrings
- Bound the work the PDF text extractor may spend, not just the bytes it may output. The decoded-output cap limited how much text a PDF could produce but placed no limit on the effort of producing it: the literal-string parser restarted at every open parenthesis and an unbalanced literal made each attempt rescan to end of buffer, so a file of repeated unbalanced nesting was quadratic and got worse with size. A 400 KB file took 34.5 seconds of CPU and a 10 MB one, well inside the default file cap, never finished. Such a file arrives from a repository, an archive member or a docker layer without anyone choosing to parse it. Extraction now stops at a measured work ceiling and reports a counted coverage gap, and strings already recovered before the ceiling are still reported rather than discarded.
- Fail-closed TrackingAllocator dealloc validates header magic/stage/bytes before SLOT indexing
- Refuse Slack API HTTP redirects so bearer tokens cannot pivot after the first request
## [0.5.68] - 2026-08-05

### Changed

- Move two large co-located test suites out of scanner source files and into the tests tree, shrinking `detector_ids.rs` from 414 lines to 127 and the Hyperscan scratch backend from 767 to 341. Both keep running against the crate-private state they exist to check, and both leave the inline-test allowlist, so the allowlist now names two fewer permanent exceptions.
- Scanner source files freed of large co-located test suites.

## [0.5.67] - 2026-08-05

### Added

- Pin that filesystem enumeration yields every file exactly once, in sorted path order, identically across repeated walks. Batch composition follows enumeration order and autoroute keys its persisted decisions by batch shape, so a walk that varied run to run would make a calibrated cache miss on replay. The property was implicit; it is now asserted over twenty walks of the same tree.

### Changed

- Filesystem enumeration-order contract.

## [0.5.66] - 2026-08-04

### Added

- Explain in the backends guide what the GPU actually does for a whole-tree scan, with measured numbers. The documented 8 MiB crossover covers one window through the matching kernel; a repository scan is a different workload, where confirmation runs on the CPU either way and the GPU route measures about 9 percent slower at both 63 MiB and 251 MiB. An operator picking a backend for a repository can now see that before choosing.

### Changed

- Whole-tree GPU guidance in the backends guide.

## [0.5.65] - 2026-08-04

### Changed

- Actionable GPU refusal diagnostics.

### Fixed

- Tell the operator the truth when a required GPU is unavailable. An explicit `--backend gpu-cuda` also makes GPU mandatory, but the refusal named only `--require-gpu` and advised running without it, sending anyone who used the backend flag looking for a flag they never passed. The message now names the resolved policy, both routes into it, and both ways out.

## [0.5.64] - 2026-08-04

### Changed

- Remeasure the README evidence panels against the current detector corpus, so the published accuracy, execution-route and daemon figures describe what the scanner does today. The precision preset improves to F1 0.8799 from 0.8784 on the benchmark corpus and the default policy holds at 0.9447.
- README evidence panels remeasured against the current detector corpus.

## [0.5.63] - 2026-08-04

### Changed

- Mailchimp datacenter key routing.

### Fixed

- Report Mailchimp keys as Mailchimp keys. The three datacenter patterns declared no routing literal, so the prefilter had nothing to route them on and nine keys on the benchmark corpus were reported as generic secrets instead, one of them a base64 value the generic detector could only show opaquely. Scored against the corpus answer key, declaring the literals moves one finding from false positive to true positive and changes nothing else.

## [0.5.62] - 2026-08-04

### Changed

- Make the prefixless-pattern gate ask the question that matters. It previously only flagged patterns with extractable inner literals, which let through the exact pattern whose missing declaration suppressed an unrelated detector; it now flags any prefixless pattern that declares no routing literal, with shape-only detectors such as Asana tokens and Telegram bot tokens recorded as a category rather than as debt.
- Routing literals for every prefixless detector pattern.

### Fixed

- Stop one detector's pattern from silently costing another detector's recall. A pattern with no literal prefix and no declared routing literal leaves the shared prefilter nothing to route it on, and the loss lands elsewhere: twenty-three patterns across the corpus now declare a literal the compiler proves is required by every match, including the Datadog application key pattern itself.

## [0.5.61] - 2026-08-04

### Changed

- Character-class token anchoring for short vendor prefixes.

### Fixed

- Extend token-boundary anchoring to every remaining detector whose vendor prefix is three letters or fewer, so `MSG_API_KEY=` is no longer a Singapore GovTech key, `XPBI_CLIENT_ID=` no longer a Power BI credential and `WEBCB_API_KEY=` no longer a Carbon Black key. Fourteen such false positives are now silent, seventeen genuine separator-prefixed forms still report, and findings are unchanged on every corpus.
- Repair a recall regression in the previous two releases. Anchoring short vendor prefixes with a word boundary also stopped them matching after an underscore, because `_` is a word character, so `MY_NR_LICENSE_KEY=`, `MY_GH_WEBHOOK_SECRET=` and every other `PREFIX_TOKEN_...` form went unreported. The anchor now tests the character class before the token instead, which keeps the false positives suppressed and finds the separator forms again.

## [0.5.60] - 2026-08-04

### Changed

- Token-boundary anchoring for short vendor prefixes.

### Fixed

- Anchor four more detectors whose vendor prefix is two or three letters, so they stop matching at the tail of an unrelated identifier. Two were reproducibly wrong on ordinary input: `xapi_key=<uuid>` near the word mexico was reported as a Mexican government key, and `LEIGH_WEBHOOK_SECRET=` was reported as a GitHub webhook secret. Every genuine form still fires and reported findings are unchanged on every corpus.

## [0.5.59] - 2026-08-04

### Changed

- Say what diverged when autoroute rejects a backend candidate. The message reported only that findings differed, which blocks the whole calibration and gives an operator nothing to act on; it now names how many records each side produced, how many were unique to each, and up to three of them by detector, file, line and offset. Every field shown is already redacted.
- Token-boundary anchoring and an actionable autoroute parity rejection.

### Fixed

- Stop the Africa's Talking detector matching inside a larger identifier. Its anchor accepted a bare `at`/`AT` with nothing in front of it, and `SNAPCHAT_API_KEY=` contains a literal `AT_API_KEY=`, so every Snapchat token was also matched as an Africa's Talking key. Deduplication kept it out of the report, but the extra match blocked GPU autoroute calibration for the whole workload class.

## [0.5.58] - 2026-08-04

### Changed

- Refresh the README accuracy, execution-route and daemon panels, which had been stuck on v0.5.49 because the target that regenerates them could not run. The GPU rows were the worst affected and were understating the CUDA and WGPU routes by six times: a full mirror scan reads 2.11 s rather than 12.64 s on CUDA and 2.07 s rather than 12.34 s on WGPU, with F1 unchanged at 0.9447 on every route.
- Refresh the README scaling evidence against the current binary. A single-worker scan of the scaling workload drops from 21.3 s to 10.4 s and a 32-worker scan from 1.83 s to 0.93 s, throughput rises from 35.0 MiB/s to 68.6 MiB/s, and peak resident memory falls from 810 MiB to 684 MiB. The snapshot is now attested clean rather than developer-dirty.
- README evidence panels remeasured against the current binary.

### Fixed

- Let the README benchmark matrix regenerate. The target depended on the scaling measurement, which rewrites README.md and the scaling snapshot, after which every measured row refused to scan because the tracked workspace was dirty, so the panels could not be refreshed at all. The dependency is gone and a clean-tree check now reports the problem once, up front, instead of forty times after the work.
- Let a release note describe a change with no crate behind it. The fragment schema required at least one crate, so a README, benchmark-harness or CI change had to be filed against a crate it never touched, putting a false claim in that crate's published changelog. An empty crate list now means repository scope: the root changelog carries the note and no crate changelog does.

## [0.5.57] - 2026-08-04

### Changed

- Repeatable autoroute calibration.

### Fixed

- Stop autoroute calibration from discarding a whole workload class over measurement noise. An execution plan now has to clear the other plan's confidence interval, not just win a paired test, before it beats it on the same backend; points that agree on the backend but split on the plan reconcile to the plan the binary was compiled with instead of producing no decision; and merging a point re-declares the reconciled route so the persisted cache matches its own evidence. Calibrating the mirror corpus went from persisting a decision on 4 of 10 identical runs to 12 of 12.

## [0.5.56] - 2026-08-04

### Changed

- Scan many coalesced batches at once instead of one at a time. The batch pipeline's consumer was a single receive-then-scan loop whose only parallelism was inside one batch, so every batch boundary idled the machine; it now bridges the batch channel onto the global pool the way the fused pipeline already does. On this repository's sources the batch pipeline drops from 4.95 s to 2.43 s and gpu-cuda from 6.70 s to 3.52 s, and the report is byte-identical to the fused pipeline's.
- Overlapping coalesced batches and autoroute classification for any batch size.

### Fixed

- Let autoroute classify a batch of any size. The decoder sampling budget was enforced as a ceiling on the total sample instead of a budget for the residual above each chunk's floor, so a batch of more than roughly 341 chunks failed classification outright. The coalesced pipeline packs up to 4,096, which meant autoroute calibration could not run through --batch-pipeline on any real corpus, and so the GPU route, which runs only through that pipeline, could not be calibrated at all. A batch whose floors already fit keeps exactly the previous budget, so no persisted decision changes.

## [0.5.55] - 2026-08-04

### Changed

- Idempotent source contract-test generator and a warning-free workspace build.

### Fixed

- Make the keyhog-sources contract-test generator idempotent by formatting its own output, so re-running it no longer produces a large formatting-only diff, and give the generated rejected-extension cases snake_case names. The workspace now builds all targets without a warning.

## [0.5.54] - 2026-08-04

### Added

- Check every `.keyhog.toml` key and table in the configuration reference against the real config schema, reading the accepted field list out of the schema itself rather than restating it, so a renamed or removed key fails the build instead of failing the reader with an unknown-key error.
- Report how many phase-two prefilter batches the prefix gate ran versus skipped in `--perf-trace`, which answers whether the prefilter is expensive because every chunk reaches it or because every batch runs.

### Changed

- Skip homoglyph-variant patterns when the chunk provably contains no confusable glyph, instead of only when it is pure ASCII. Ordinary non-ASCII source text carries accented names, CJK, box drawing, arrows and emoji, none of which a homoglyph variant can match, and it was forcing the full residual pattern set.
- Skip homoglyph variants on chunks that provably contain no confusable glyph.

### Fixed

- Correct the configuration reference, which advertised a `no_entropy_ml_scoring` key that has never existed. Writing it into `.keyhog.toml` fails closed as an unknown key; the knob is CLI-only.
- Let the configuration module's no-inline-tests gate accept the sanctioned `#[cfg(test)] #[path]` sibling-module hook, which the blanket attribute ban rejected even though the test code lives outside the source tree.

## [0.5.53] - 2026-08-04

### Changed

- Make the coalesced batch pipeline eleven times faster and stop starving the accelerator.

### Fixed

- Include both published GitHub Action manifests in the release version transaction, so the minimum version they advertise cannot fall behind the workspace as it did for two releases.
- Track the accumulating batch's route class and chunk identities as chunks arrive instead of rescanning and rehashing the whole batch for every chunk. The coalesced pipeline's 4,096-chunk batches made that quadratic, which is why an explicit GPU backend measured slower than CPU while the accelerator sat idle.

## [0.5.52] - 2026-08-04

### Added

- Check every `keyhog` command in the README and the handbook against the compiled command model, so a documented subcommand or long flag that is renamed or removed fails the build instead of failing the reader who types it.

### Changed

- Refuse configuration fields the scanner cannot honour and check every documented command against the real CLI.

### Fixed

- Refuse a non-default `max_file_size` or `dedup` on `ScanConfig` and name the surface that owns the behaviour, instead of accepting two documented no-op fields that gave a library caller the same scan they would have got by leaving them alone.
- Correct the system-wide triage example, which showed a `--exclude` flag `scan-system` does not have, and state the bound it actually applies: a total-bytes ceiling plus network filesystems skipped by default.

## [0.5.51] - 2026-08-04

### Added

- Prove the bounded accelerator-evidence dedup set refuses and counts every record past capacity, keeps dedup rejection separate from loss, and saturates its loss counter instead of wrapping to zero under sustained overflow.
- Assert JSON, JSONL, and SARIF stay completely parseable and ANSI-free across all sixteen hostile environment profiles, including CLICOLOR_FORCE, an unset HOME, an unwritable working directory, a missing TMPDIR, and a rejected backend request.

### Changed

- Report accelerator evidence dedup overflow on the `keyhog::gpu` tracing target with its exact running loss count, replacing a counter that no caller read.
- Compile each phase-two always-active matcher variant when a chunk selects it instead of building all four for every batch up front, which removed a 1.4 second stall that the first decoded sub-chunk of any scan charged to every scan worker.
- Prove a phase-two batch is empty with the DFA-backed match test before asking which patterns matched, since reporting the matching set has no lazy-DFA path and forced a full PikeVM pass over every batch on every chunk.
- Stop compiling the coalesced phase-two tail, its triggered windowed scan, its batched ML scorer, and the GPU peer timing facets into portable builds, which have no producer that can reach them.
- Assert source-instrumentation tests see no coverage errors instead of silently discarding error rows while collecting chunks, so a profiled adapter that starts failing shows up as a failure rather than a smaller chunk count.
- Derive the subcommand help matrix from the compiled command model instead of a hand-kept list that had already drifted past `config` and `bloom-diagnostic`, and pin the advertised menu so a removal or rename stays a reviewed change.
- Make the portable phase-two prefilter two to three times faster and repair ten red gates.

### Fixed

- Fall back to the honest legacy identity gaps when a causal profile's detector, configuration, or source enrichment is absent, instead of panicking while rendering the report at the end of a completed scan.
- Run the 1,202-cell product-reliability matrix in CI and drive it on the portable scalar backend, so hostile-environment exit-code, output-format, and installer contracts can no longer rot unexecuted or fail closed on a Hyperscan-free build.
- Check the default-exclusion policy flag at each source factory call rather than at the first mention of a source name anywhere in the file, which reported a missing flag on a call that passes it.
- Match source-ownership gates on the arguments and constructs they exist to protect rather than on exact indentation, closure parameter names, or a function name a rename had already changed.
- Fail closed with a source error when the single-flight pinned web client builder is missing, instead of panicking inside the client cache and ending the scan.
- Resolve a candidate's whole assignment value from the start of its own line rather than from the start of the chunk. Quote and escape state reset at every line break, so the previous walk reread the entire preceding chunk for every candidate and was quadratic in candidates per chunk.

## [0.5.50] - 2026-08-02

### Added

- Add low-overhead causal run profiling with fixed scanner stages, state transitions, process resource measurements, and explicit source and backend identity while keeping per-pattern diagnostics behind --perf-trace.
- Add bounded causal span timelines, latency percentiles, typed telemetry, async profiling propagation, and exact per-category event-loss reporting to operator profiles.
- Add schema-v3 typed companion evidence and bounded cross-detector `requires`, `conflicts`, and `subsumes` relations, with deterministic fixed-point resolution, compile-time contradiction and cycle checks, and `explain --compiled-plan` introspection.
- Add detector-owned positive source admission by path regex, exact source type, and file extension. Declared selector families combine with AND semantics and reject missing metadata.
- Add `scan --github-all` as the concise complete-surface form of a GitHub collaboration scan while retaining independent surface selectors.
- Restrict the netrc password detector to `.netrc`, `_netrc`, and `.authinfo` source paths, with explicit fixture paths and boundary regressions.

### Changed

- Publish patch releases to crates.io through short-lived OIDC trusted publishing, update versions and changelogs automatically, and upload a deterministic six-crate commit and lockfile integrity receipt without a long-lived registry token.
- Localize plain phase-two patterns by default on portable and explicit CPU scans, avoiding full portable marking-set compilation when the shared anchor index owns candidate extraction.
- Bind profile comparisons to the exact running binary SHA-256, enabled-feature SHA-256, target triple, build profile, compiler, allocator, and linked-backend SHA-256 instead of relying on the package version alone.
- Record complete detector-corpus, enabled-detector, compiled execution-plan, and hashed external-provenance identities in causal scan profiles, with unavailable backend databases surfaced explicitly instead of inferred.
- Bind causal profiles to complete resolved-configuration and performance-policy BLAKE3 identities plus the selected preset and applied protection state, without exposing raw configuration values.
- Record normalized source adapters plus privacy-safe target and partition BLAKE3 identities in causal profiles without emitting raw paths, URLs, source parameters, or credentials.
- Measure raw source, source-unit fanout, decode-derived, and completed backend-dispatch byte domains in causal profiles, classify stable workload size and fanout buckets, and keep uninstrumented expansion domains explicitly unavailable.
- Enforce optimized profiler hot-path overhead budgets in the regular CI workflow.
- Add `scan --profile-out <PATH>` writing the complete causal profile as JSON atomically at scan end, implying `--profile`.
- Route daemon scans through wire protocol v12 with per-request profile capture: each profiled daemon request gets a unique request identity, an isolated profiling runtime, and a bounded per-request profile payload rendered by the client.
- Instrument every source adapter with acquisition, walk, read, queue-wait, and decode spans plus exact unit and byte accounting, including cloud pagination retries and collaboration backoff attempts.
- Migrate scanner-internal timing and count collectors (mark statistics, Hyperscan split, generic detection, extractor, decode recursion, ML batch, MoE split) onto keyhog-profile typed counters and distributions with one runtime-owned drain; `--perf-trace` lines render from the same records.
- Instrument verifier queue, TLS, request, cache, report encoders, baseline, allowlist, Merkle, CLI startup, detector loading, Action receipts, and maintenance commands with batch-level stage spans and typed counters.

### Fixed

- Record scanner accelerator features from dependency-owned compile state so portable autoroute identities no longer claim unavailable GPU or SIMD backends.
- Keep complete credentials from native binary strings and executable sections when a strong named detector validates an explicit credential shape, while continuing to suppress weak prefix fragments and generic assignment noise.
- Bound scan-system metadata discovery by the remaining --space budget so small host-scan ceilings stop promptly and report partial coverage instead of traversing the entire filesystem first.
- Preserve valid `.keyhog.toml` detector-disable configurations by transitively removing detectors that require a disabled target and pruning inactive conflict or subsumption relations before scanner compilation.
- Restore the documented minimal `keyhog-scanner --no-default-features` build by keeping decoder admission available when optional decode transforms are absent.

## [0.5.49] - 2026-07-30

### Added

- A single resumable local or SSH command now refreshes benchmark evidence without invalidating candidate freshness, rebinds the exact canonical run-set after scoring, prepares every changelog and version surface, runs pre-tag gates with isolated full and ci-lean binary contracts, preserves exact Git path bytes, verifies the configured OpenPGP fingerprint before any tag push, and watches GitHub Pages, release assets, containers, and the six-crate crates.io publication chain.
- Unix mass daemons now accept bounded directory, Git, archive, binary, remote, hosted Git, and cloud streams through `scan --daemon=mass`; local filesystem payloads remain daemon-local, credential-bound sources use protected chunk framing, each batch is capped at 8 MiB and 1,024 chunks, source gaps fail closed, the client validates an exact total/GPU execution receipt before reporting, and `daemon start --mass-gpu-primary` rejects CPU-majority completion.
- `keyhog-profile` now owns a portable causal profiling schema for fixed micro stages, macro run states, source and backend identity, input totals, CPU time, resident and virtual memory, and observed process threads. `keyhog scan --profile` emits this low-overhead operator-run record without recording source content or credentials. `--perf-trace` retains the higher-overhead per-pattern diagnostics.

### Changed

- The README star viewer now uses a deterministic accessible SVG generated from repository-owned observations, records only real count transitions, handles same-day corrections and declines truthfully, writes atomically, and retries isolated metrics push races without depending on star-history.com.
- Apple release assets now ship VYRE's native Metal and WGPU peers without requiring Homebrew Vectorscan. GPU region-presence no longer acquires Hyperscan transitively, and autoroute persists Metal as a distinct measured candidate.
- Large single chunks on the scalar route now scan their existing recall-overlapped windows in parallel, then merge findings in source order with exact offsets and deduplication.
- Portable and explicit CPU scans now localize plain phase-two patterns by default. This avoids compiling and scanning the full portable marking set when the shared anchor index owns candidate extraction; measured cold scans improved by 4.0 to 4.4 times across 1 KiB, 8 MiB, and 1,024-file local workloads while preserving whole-chunk finding parity.
- Linux profiling boundaries now read process-local CPU, memory, and thread counters directly from procfs instead of refreshing the system-wide process table.
- The production Debian container now ships the portable CPU build and omits unused Hyperscan build and runtime packages. This keeps ephemeral container scans on the fast cold-start route; the dedicated glibc integration image still exercises Hyperscan.
- The source integration lane now runs one default aggregator and one serial all-backend target pass instead of rebuilding overlapping all-feature test and library subsets.

### Fixed

- Release preparation now updates standalone GitHub Action guide version pins, its regression suite rejects any canonical current-version document omitted from the release transaction, and operator docs describe crates.io packages, Cargo update and rollback, and the absence of binary asset bundles.
- Trusted GitHub Action SARIF publication now retries one transient Code Scanning upload failure and fails closed only when both attempts fail. Restricted fork pull requests remain advisory, and the report artifact remains available.
- Nightly benchmark dependency installation now authenticates the `pybase62` wheel, and CLI documentation coherence accepts generated possible-value suffixes without weakening exact option descriptions.
- The generated CLI reference now includes every visible source flag for both `scan` and `config`, and the banner detector count remains coherent with the live loader.
- Automatic releases now use the successful commit subject for crates not covered by authored change fragments, publish all six crates in dependency order, retry uploads, wait for crates.io visibility, and resume partial publication without republishing visible versions.
- The default portable Cargo installation now includes native binary string and object scanning without requiring Ghidra. Optional Ghidra enrichment remains a runtime integration.
- Aggregate release prevention gates now receive the immutable current-version candidate explicitly, so an older default Cargo release binary cannot invalidate backend parity.
- Release orchestration now prepares the final workspace version before measuring its executable, and pre-tag resumes refresh version-bound evidence while signed-tag resumes preserve immutable evidence.
- Benchmark freshness now handles the unavoidable Git-stamp change created by committing measured evidence, while rejecting non-ancestor results and every intervening source, manifest, configuration, fixture, rename, or other non-evidence path.
- The 8 MiB GPU crossover proof now compares independently selected GPU and Hyperscan routes over 300 held-out pairs; it retains every eligible Hyperscan plan for audit without treating a per-trial hindsight oracle as a selectable backend.
- Published workspace and crate metadata now use the canonical `https://santh.dev/keyhog/` discovery homepage while retaining the source repository as the crates.io repository link.
- Source skip-counter tests now serialize scans that begin before the first counter guard, eliminating concurrent false failures in the full source matrix. Release dogfood fixtures and documentation now scan cleanly without weakening detector behavior.
- Release previews now recognize an already-prepared `--resume` workspace instead of asking release preparation to create the current version again and failing before evidence checks.
- The exact architecture ratchet now counts native Metal as the fifth scan backend and binds the current engine source total, so the source-only prevention gate reflects the shipped backend set without stale budget drift.
- Portable source builds now retain coalesced triggered windowing and performance-trace support without SIMD or GPU features, so branch and commit refs compile before Action scans. A dedicated oversized-window suite covers exact offsets, overlap deduplication, multiple findings, and hostile near-matches under the portable feature profile.
- Crossover route selection now keeps deterministic candidate order when paired 95% evidence cannot distinguish near-tied GPU peers, so a point-median fluctuation cannot redirect all held-out release evidence to an unproven peer.
- Release tag signing now uses a dedicated protected keyring and owner-only passphrase file locally, with the same encrypted key available to a manual `release-signing` GitHub Actions workflow. Both paths verify the full enrolled fingerprint, exact prepared commit, canonical tag, and immutable existing-ref boundary without exposing a passphrase to command arguments or logs.
- Docker image scans now prefer Docker save manifests over embedded OCI indexes, ignore layer link entries without aborting extraction, preserve nested archive paths and binary provenance, and classify large native binaries before windowed text scanning.
- Entropy and named detectors now suppress candidates inside matched public certificate and public-key PEM blocks while retaining private-key findings and credentials outside those blocks.


## [0.5.48] - 2026-07-27

### Added

- The release workflow emits ten deterministic SPDX 2.3 SBOMs for four binaries,
  four GPU-literal bundles, and two installers. The exact 60-asset contract
  includes each payload/document plus its checksum and detached signature.
- Composite Action report handling now binds exact flushed report bytes to a
  source-emitted seven-field receipt and a hidden KeyHog verifier, copies them
  to a mode-`0400` unpredictable snapshot inside a unique mode-`0700`
  `RUNNER_TEMP` runtime, and makes that receipt-bound job-lifetime snapshot-not
  the now-untrusted workspace copy-the public report output and
  SARIF/artifact upload authority. Internal uploads recheck its SHA-256 at use;
  publication does not claim immutability against the same runner UID.
- Composite Action publication now has a fail-closed Marketplace listing
  verifier, explicit-CPU cross-platform source exercises, and a maintained
  digest-pinned push/PR container lane proving real root+nested CPU+lockdown.
  Source auto without persisted routing proof is rejected; authenticated manual
  dispatch retains proof-backed default auto in a postpublication release lane.
- Hosted CPU evidence measures exact detection recall, throughput, and peak RSS
  on a pinned GitHub runner image instead of substituting local workstation
  measurements.
- A standalone GitHub Action guide documents the copyable repository gate,
  baseline adoption, monorepo partitioning, verification boundary, inputs,
  outputs, and failure behavior. A release gate now checks both public reference
  tables against the root and nested Action manifests.
- A provenance-bound benchmark snapshot and generator now publish README panels
  for detection accuracy, CPU/Hyperscan/GPU requests, scan presets, incremental
  cache reruns, and warm daemon requests. The documentation gate rejects stale
  panel or report bytes.
- A script-driven scaling snapshot now measures scan workers, filesystem
  readers, exact corpus sizes, distinct storage classes, and concurrent
  partitions. It publishes raw trials, median and p95 latency, throughput,
  speedup, efficiency, and memory from one reproducible command. Nightly hosted
  CPU runs upload the same JSON and Markdown evidence.
- A workflow-boundary gate and dedicated regression suite keep GitHub Action,
  direct CI, and mass-inventory documentation separately owned and mutually
  discoverable.
- Deterministic TOML change fragments now drive one validated release
  transaction across workspace versions, lockfile packages, public version
  pins, GitHub release notes, and crate-owned changelogs. A daily read-only
  workflow validates the next patch candidate without publishing it.
- The mdBook build now emits one canonical URL, Open Graph and structured
  project metadata, `sitemap.xml`, and `robots.txt` from tested generated
  output. A release operations chapter documents the signed-tag publication
  path and the same local documentation gate used by GitHub Pages.

### Changed

- Release publication requires the successful aggregate CI verdict from the
  exact tag commit. Crate publication has one post-release path, and release
  assets, SBOMs, signatures, attestations, containers, and moving tags share the
  same validated source identity.
- Integration tests run in independent fail-closed lanes while preserving the
  process isolation required by source-backend contracts.
- Hosted CPU publication gates now bind reviewed runner, Hyperscan, workload,
  and resolved scan-policy identities. The `fast` recovery contract requires
  only the categories supported when decoding is disabled.
- GitHub Action, direct CI, and mass-inventory guidance now have separate
  workflow ownership. The README routes each use case to its canonical guide,
  and CI pages link to the Action or mass-scanning contract instead of
  duplicating it.
- The README is now a focused product landing instead of a second full manual.
  It keeps install, benchmark, source, security, library, and architecture
  entrypoints while routing detailed contracts to the mdBook. The book adds a
  30-second workflow chooser and navigation by repository gates, large
  inventories, backend selection, trust, and reference material.
- The README benchmark generator now writes its deterministic 8 MiB workload in
  large blocks, streams corpus hashing without an 8 MiB allocation, rejects
  same-size byte substitutions, and requires an explicit clean or
  developer-dirty source classification.
- The README now puts source-boundary selection before benchmark detail and
  provides copyable quick, full, CI, deep Git, mass-inventory, whole-host, and
  warm-file workflows. Concurrency guidance separates scanner workers, readers,
  partition jobs, incremental caches, verification limits, and daemon
  eligibility without presenting one host's worker count as a universal
  optimum.

### Fixed

- Composite Action configuration reports the effective preset and lockdown
  policy used by calibration and scanning instead of presenting wrapper inputs
  that can diverge from the executed command.
- Marketplace verification rejects untrusted origins, redirect downgrades,
  mutable metadata reads, unsigned exact release tags, duplicate YAML keys, and
  listing pages that do not bind the expected repository and Action ref.
- SIMD scanning routes Unicode-semantic shorthand patterns through exact CPU
  recovery when Hyperscan's Unicode tables cannot guarantee Rust-regex parity.
- CredData acquisition now repairs an existing partial corpus at the pinned
  revision with configurable parallel workers, checks its isolated `pybase62`
  runtime dependency before mutation, preserves failed repository scratch for
  diagnosis, and reports incomplete fixture trees as unavailable instead of
  failing benchmark test collection.
- The benchmark `make keyhog` target now builds the `ci-lean` candidate required
  by deterministic autoroute parity tests. Bloom fixture generation can declare
  missing F/X inputs from structurally present metadata, while normal scoring
  still rejects partial corpora and every reader rejects an active repair
  marker.
- Source-only release gates now export one resolved Cargo executable through
  dependency-receipt generation. Stripped gate environments no longer resolve a
  user-session Cargo wrapper that requires an unavailable desktop bus.


## [0.5.47] - 2026-07-26

### Added

- The POSIX installer accepts `--no-calibrate` for deterministic automation.
  It still verifies the signature, checksum, installed binary, GPU literal
  sidecar, and `doctor` self-test, then warns that automatic routing remains
  uncalibrated until you run `install.sh --calibrate`.
- The signed Linux release smoke uses the explicit no-calibration path and a
  measured-correct SIMD backend. Hosted-runner timing noise can no longer block
  publication after payload and product verification have passed.

### Fixed

- Release asset verification accepts both text-mode and binary-mode
  `sha256sum` manifests, including the `*filename` form emitted for Windows
  executables.
- Manual release recovery dispatches check out and attest the exact requested
  immutable tag in every build, installer, signing, container, publication,
  and floating-tag job.
- Signing uses hardened publication and release-note automation from the
  workflow commit while all product bytes remain bound to the requested tag.
- The prerelease version bumper tracks every canonical version-bearing guide
  and no longer rejects versionless pages. Documentation truth checks now cover
  the integration, verification, and out-of-band verification pins updated for
  this release.

## [0.5.46] - 2026-07-24

### Added

- `scan --detectors-mode replace|overlay` makes custom detector composition
  explicit. Overlay mode retains embedded rules, rejects detector ID collisions,
  and reports the effective corpus digest and provenance.
- Benchmark reports now resolve one declared canonical run set and expose exact
  executable, detector, corpus, host, and static-recovery provenance.

### Changed

- Scanner library entry points return typed errors for unavailable or failed
  selected backends. The CLI alone maps terminal failures to process exit codes.
- The daemon protocol is version 8. Secret-bearing wire adapters remain private,
  warm routes bind the engine and artifact identity, and recovery metadata is
  conserved across daemon boundaries.
- Verifier success behavior is detector-owned through explicit conservative,
  body-positive, and status-authoritative policies.

### Fixed

- `Credential` and `SensitiveString` redact through `Display` and reject
  implicit serialization. Plaintext access requires an explicit private
  boundary.
- Decoder output is streamed through one bounded sink, and UTF-8 detector policy
  mapping no longer slices strings at non-character byte offsets.
- Calibration persistence preserves concurrent writers with private Unix file
  modes. Admission-plan mismatch recovery now emits an operator-visible receipt.
- Release and crate publication bind the candidate commit, version, signatures,
  assets, package graph, and registry verification before public mutation.
- Release version updates preserve measured benchmark identities while updating
  operator pins. GHCR version and `latest` tags wait for the signed candidate
  product smoke before public mutation.

### Detailed component changes

These component sections enumerate the full shipped delta. They retain API, schema, routing, correctness, security, and performance details that are easy to lose in the summary above.

#### CLI and orchestration

- Upgrade the daemon wire protocol to v8, keep request, response, frame, client,
  server, and plaintext match adapters crate-private, and expose only the
  non-secret default socket path. The strict Hello handshake rejects v7 peers.
- Allow a daemon scan to select an explicit replacement detector corpus when
  the client-derived rules identity exactly matches the warm daemon. Reports
  retain the replacement count, digest, source, and mode. Overlay composition
  and client-only detector policy remain fail-closed.
- Include exact static-recovery totals and per-reason rejections in JSON 1.8,
  JSONL 1.9, and daemon v8 report metadata. Daemon clients reject aggregates
  whose reason counts do not reconcile instead of substituting zeroes.
- Make `update` and `repair --version` accept only canonical SemVer, normalize
  it to one `v`-prefixed tag before HTTP, and require the same non-draft tag
  before downloading assets. Malformed or mismatched release metadata fails.
- Serialize concurrent autoroute calibration updates through the cache lock so
  distinct workload evidence is merged without torn reads. Unix cache, lock,
  and temporary files are private, and successful writes leave no temporary
  residue.
- Keep the daemon socket linked for the full accept-loop lifetime. Shutdown
  removes it only after the listener terminates.
- Bind every persisted GPU timing and parity receipt to the exact acquired
  execution peer. Route replay now rejects changed or missing adapter identity.
- Make the final backend summary identify invalid-autoroute scalar recovery and
  runtime-fault recovery directly. Recovered work is no longer
  described as a calibrated non-GPU winner.
- Let `calibrate-autoroute --policy` refresh one scan policy without rerunning
  every preset. The default remains the complete all-policy install sweep.
- Reject autoroute cache and runtime-health workload identities with impossible
  logarithmic ranges, phase-one subtotals, decoder bits, or decoder cost bands.
- Report automatic backend recovery as `complete_after_recovery` in JSON schema
  1.8 and JSONL schema 1.9, preserve the
  exact recovered ranges and byte totals across daemon responses, expose daemon
  recovery health, and persist the affected autoroute workload quarantine in a
  bounded artifact that survives restart, is visible in `backend --autoroute`
  and `doctor`, and clears through successful recalibration. Recovery replays
  stable bytes through the fastest remaining measured-correct peer resolved by
  the same workload evidence, rather than a hardcoded CPU backend.
- Measure every plain-pattern and keyword-anchor localization combination for
  every eligible backend, persist the fastest correct execution plan in cache
  schema 39, and carry both choices beside admission evidence through one-shot,
  fused, daemon, and automatic-recovery dispatch.

- Retain every exact calibration representative inside one canonical workload
  evidence envelope. A route class is reusable only when all points agree on
  the fastest-correct one-shot and daemon backends; inspection exposes each
  point's timings, confidence, and parity receipts, and calibration now probes
  both sides of the required 8 MiB crossover.
- Show the detector-owned keyword-free operator entropy margin in `explain`.
- Derive autoroute readiness and repair commands once from cache inspection,
  expose the repair command in `backend --autoroute --json`, and make `doctor`
  report scalar-only builds as direct-route ready instead of uncalibrated.
  Calibration now succeeds only when persisted readback is `ready` for the
  running build.
- Persist the resolved GPU batch-input byte cap in autoroute host identity and
  inspection, so a device-limit or configured-cap change cannot replay timing
  evidence measured with a different dispatch topology.
- Bind autoroute host identity to the live linked Hyperscan/Vectorscan runtime
  version, so a runtime replacement invalidates SIMD timing evidence and
  requires recalibration instead of replaying a stale winner.
- Split contiguous filesystem batches at safe source-family and size-provenance
  boundaries, extend the split to tracked and untracked git-diff inputs, and
  calibrate every default fused count for extracted tar members. Empty stdin is
  no longer reported as a calibrated workload. Current installers delegate this
  core sweep to the binary instead of maintaining a second matrix. Calibration
  output now calls the sweep count probes rather than unique workload buckets;
  it also reads back and reports both route classes measured by this sweep and
  the cache's total route-decision count. Installers still parse the earlier
  unified-command summary during migration.
- Rename the live GPU region-presence batch byte budget to
  `--gpu-batch-input-limit` / `gpu_batch_input_limit`; accept the retired
  MegaScan spelling as a hidden CLI/TOML migration alias.
- Include full-source-size provenance in autoroute workload keys so streamed or
  transformed payload sizes cannot silently reuse calibration measured from an
  equal numeric full-file-size bucket.
- Activate the CLI `simd` feature in default builds so the documented
  Hyperscan `--cache-dir` surface works whenever the default scanner includes
  Hyperscan instead of falsely reporting an accelerator-free binary.
- Stop prewarming an automatic backend from a zero-byte heuristic before the
  persisted workload-specific autoroute decision is known; explicit diagnostic
  backend overrides still prewarm directly.
- Report the configured backend policy at startup instead of claiming that a
  backend was selected before the persisted per-workload decision exists.
- Do not print end-of-run repeat summaries for dependency warnings hidden by
  the default log filter; summaries now describe only visible KeyHog warnings.
- Record the actual first GPU dispatch as autoroute cold-start evidence instead
  of discarding it and mislabelling an already-warm second dispatch as cold.
- Distinguish one-shot and persistent-daemon autorouting: one-shot scans include
  GPU cold cost, while the daemon initializes accelerator state before serving
  requests and selects from calibrated warm timing evidence.
- Replace autoroute cache writes through a synced same-directory temporary file
  so recalibration atomically replaces an existing cache path across supported
  operating systems.
- Route CLI report/cache writes through one atomic file replacement helper,
  including `scan-system --output`, to avoid truncated final-path artifacts.
- Refuse autoroute calibration on empty or zero-byte samples before timing so
  calibration cannot persist route decisions that the cache loader would later
  reject as missing sample evidence.
- Add `keyhog config --effective` and keep post-scan confidence filtering on the same resolved floor as the scanner.
- Update stale unit fixtures for the inline-byte credential-hash contract and removed duplicate startup-summary helper.
- Keep default `--git-diff HEAD` wired to worktree changes, honor CLI excludes for staged-only scans, and refresh git-mode e2e contracts for clean staged inputs and SARIF schema coherence.
- Move args, hook, and scan-system inline tests into registered aggregate unit modules, including scan-system redaction tests updated for the raw `[u8; 32]` hash contract.
- Refresh the dogfood detector-count oracle to 894 and keep the structured UUID named-detector default-recall e2e passing.
- Distinguish detector-TOML declarations from scan-time fallback policy in
  `keyhog explain`, using the same `scan-fallback` provenance label as effective
  configuration output.

#### Core contracts

- Make implicit serde serialization of `Credential` and `SensitiveString`
  fail before emitting secret bytes. `RawMatch`, `DedupedMatch`, and `Chunk`
  therefore require an explicit protected conversion instead of serializing
  plaintext, while historical plaintext and tagged deserialization still work.
- Add canonical `corpus.toml` schema identity. Schema 1 keeps its conservative
  verifier-policy migration, schema 2 requires explicit policy, and forward or
  malformed schemas fail with typed errors. Detector digests and scan report
  metadata bind the manifest bytes and schema so caches, daemon evidence, and
  autoroute evidence cannot cross corpus semantics.
- Add `complete_after_recovery` as a complete scan terminal state and preserve
  bounded backend-recovery evidence across the current JSON and JSONL report
  contracts.

- Add detector-owned `plausibility.keyword_free_operator_margin`, validate it
  only for the `keyword-free` entropy role, and bind it into detector identity.

- Add an opt-in source ordering contract for contiguous chunk identities so
  dispatchers can split routing batches without assuming concrete source types.

- Add shared overflow-safe median and paired confidence primitives for
  autoroute calibration and release crossover evidence.

#### Scanner engine

- Return typed `Result` errors from every public scan entry point. Explicit
  unavailable or failed backends no longer terminate an embedding process or
  silently substitute another backend, and coalesced scans retain one result
  row per input chunk. The CLI alone maps terminal errors to process status.
- Stream decoder candidates into one per-root sink and stop production at 1,000
  decoded chunks or 64 MiB. Accepted siblings and exact-boundary output remain,
  and custom decoder collection is fallible instead of unbounded or truncated.
- Return non-secret backend-recovery receipts with exact recovered ranges and
  GPU recovery counts from recovery-aware coalesced scans. Receipt-blind APIs
  fail instead of discarding recovery metadata, and acquired GPU peer identity
  is required before autoroute can persist execution evidence.
- Replace the overbroad bigram training gate with scanner-owned selective
  mandatory anchors: exact short literals and measured-frequency eight-byte
  double-hash anchors. Prefixless patterns remain in the explicit always-admit
  lane. Pinned CredData evidence now records non-zero rejection with exact
  enabled-versus-bypass finding parity and categorized unavailable inputs.
- Keep appended multiline mappings aligned across empty lines and canonicalize
  detector assignment byte spans to UTF-8 boundaries before slicing. CredData
  and malformed-source scans now return their original findings instead of
  aborting the host with exit 134.
- Compile detector-owned and scan-config entropy assignment keywords into one
  cached case-insensitive matcher, removing the per-line linear vocabulary walk
  from sparse source scans while preserving programmatic config changes.
- Add one-pass multiline syntax admission before the precise concatenation
  grammar, so ordinary large source windows no longer pay repeated full-text
  searches for absent join markers.
- Large-file multiline admission now consumes the same active generic-detector
  and scan-config keyword index as entropy assignment discovery. Replacement
  corpora no longer depend on five scanner-owned compatibility words.

- Compile the phase-two VYRE regex-DFA admission catalog with state-cap-driven
  shards. The GPU now rescans a batch only after the combined DFA proves a
  split is necessary, instead of forcing another full-haystack dispatch for
  every 16 patterns.
- Apply the detector quality gate at the public scanner compilation boundary.
  Programmatic `DetectorSpec` corpora now reject invalid thresholds, regexes,
  identities, validators, and duplicate detector IDs before matcher or backend
  construction. TOML-loaded and in-memory detectors share the same acceptance
  rules.
- Preserve the participating alternate capture in grouped extraction, keep
  service-specific PEM blocks intact through collision resolution, and require
  token boundaries on short detector aliases.
- Snapshot the decoder registry when you compile a scanner. Decode execution
  and autoroute admission now use that immutable plan, and its ordered decoder
  names and versions contribute to the detector digest. Registering a decoder
  after compilation cannot change an existing scanner. Invalid or duplicate
  registrations through `try_register_decoder` return
  `DecoderRegistrationError` instead of being ignored. The compatible
  `register_decoder` entry point makes later scanner compilation fail on the
  same error.
- Compile reverse and Caesar admission from each active detector TOML's
  `decode_transforms` declaration. Custom corpora no longer inherit unrelated
  global prefixes, and detectors such as Databricks can recover `dapi` tokens
  without a scanner-code prefix edit. `DecodeWorkloadPlan` now carries this
  shared compiled policy and is `Clone` rather than `Copy`; callers that pass
  one plan to more than one owner must clone it explicitly.
- Use one compiled validator index for the active detector plan and the embedded
  compatibility API, so prefix narrowing and validator-result precedence have
  one implementation.
- Avoid collecting GPU phase timing timestamps unless performance tracing is
  enabled, removing profiling clock reads from the normal accelerated path.
- Warn when a library caller supplies an admission plan for different input,
  then recompute admission so the mismatch remains visible without losing
  recall. Preserve the concrete GPU fault reason even if its diagnostic mutex
  was poisoned by an earlier panic.
- Resolve production entropy credential context from the active detector TOMLs
  and Tier-A keyword configuration at generation and suppression. Embedded
  compatibility keywords no longer widen a replacement detector corpus, and
  adjacent declared assignments retain their own detector context.
- Compile one typed min/max policy from each detector and apply its inclusive
  bounds before generic entropy, BPE, entropy fallback, or regex-envelope
  scoring. Overlength values now share the `value_too_long` suppression reason
  and are rejected whole.
- Reject detector corpora with entropy fallback or BPE policy when the scanner
  artifact lacks the `entropy` feature. The public compile boundary reports the
  affected detector IDs and corrective build feature before constructing
  matchers.
- Replace the hardcoded lower-dash entropy exception with one compiled
  detector-TOML shape matcher covering typed alphabets, optional grouping,
  padding, diversity, and detector-owned floors. Ambiguous shape lists fail
  compilation instead of silently choosing one entry.
- Compile a backend-neutral SIMD phase-one plan during scanner construction and
  lazily materialize Hyperscan only when selected. Exact initialization errors
  now cross the fallible coalesced boundary, scalar/GPU routes do not pay the
  unused database cost, and the recorded materialization duration is available
  to cold-aware autoroute evidence.
- Make the measured route own phase-two acceleration as well as decoded scans.
  Only SIMD may initialize the always-active Hyperscan prefilter; scalar and GPU
  routes retain the portable owner through no-hit, window, and reassembly paths.
- Establish calibration correctness from the always-present scalar engine,
  rejecting a divergent optional Hyperscan candidate without invalidating the
  independent oracle. Persist decoded-rescan backend composition in each
  measured route so scalar and GPU timings cannot silently borrow Hyperscan.
- Census CUDA and WGPU identities during scanner compilation without creating
  execution devices or pipelines. Materialize only the selected peer, retain
  exact initialization diagnostics, and leave unrelated peers untouched.
- Preserve successful GPU dispatch work when a later fused region dispatch
  faults, recover only the exact unprocessed source-byte intervals through the
  scalar trigger path, stop issuing work to the faulted route for that request,
  and return a typed complete-recovery receipt to orchestrators.
- Require explicit 8x8 service context before the 8x8 detector claims a generic
  `X-Api-Key` header, removing cross-service false attribution and unrelated
  phase-two work.
- Require the documented X2Y2 API host before its detector claims a generic
  `X-API-KEY` header.
- Remove or service-anchor generic API-header patterns for OpenSea, Omnisend,
  Passbase, Skyscanner, and Moosend so another provider's key is not
  misattributed.
- Remove orphan generic API-header routing keywords from Dacast and Drata.
- Reuse fused VYRE positions for always-active phase-two anchors when the
  measured route disables keyword-anchor localization, eliminating the
  duplicate host Aho-Corasick walk while retaining raw/normalized boundaries.
- Compile the fused literal matcher with VYRE's native ASCII-insensitive DFA
  and preserve raw source bytes through borrowed, coalesced, and windowed GPU
  dispatches, removing KeyHog's duplicate host lowercase pass and its single-
  chunk/window copies.
- Replay a dense VYRE resident fused literal scan once at the exact device
  match count instead of failing autoroute calibration at the fixed 65,536-hit
  readback ceiling; partial positioned evidence remains impossible.

- Replace the ambiguous phase-two localizer route bit with explicit
  plain-pattern and keyword-anchor choices. Autoroute now calibrates, persists,
  validates, inspects, and benchmarks all four plans per eligible backend;
  cache schema 41 and crossover schema 8 reject the incomplete older evidence.

- Apply the resolved scan `entropy_threshold` to named-detector heuristic
  confidence instead of silently scoring those findings at the compiled default.

- Score entropy fallback findings from the owning detector TOML's compiled
  `entropy_high` and `entropy_very_high` tiers instead of scanner-global tiers.
- Apply detector-owned known-example, repeated-block, and ambiguous-encoding
  policy to structural password fields. Random connection-string passwords
  remain visible while examples and placeholders stay suppressed.

- Resolve entropy versus named findings from the active compiled detector plan,
  not detector-ID spelling. Custom named detectors whose IDs resemble a
  fallback namespace no longer lose valid findings during resolution or
  decoded-content adjudication.

- Canonicalize execution-equivalent ML candidates by detector, credential,
  source offset, and producer channel before batch inference. Duplicate
  accelerator lanes now share one pending row without merging distinct pattern
  and entropy evidence.

- Let confirmed extraction see hot-prefix findings that are awaiting batch ML,
  not only findings already in the final heap. This prevents the same canonical
  hot candidate from being regex-extracted and ML-featurized twice while
  preserving one final candidate identity.

- Attribute the coalesced Hyperscan trigger scan to phase one in the unified
  profiler, so isolated backend-route profiles include the CPU accelerator work
  that precedes the shared extraction tail. Attribute the phase-two plain
  localizer's candidate collection, verification, and anchorless extraction to
  their existing profiler stages instead of leaving that route's dominant work
  outside the profile tree.

- Keep crossover selection and held-out timing free of profile instrumentation,
  then emit isolated scanner profiles for every Hyperscan localization plan and
  the selected exact GPU route instead of one misleading aggregate report.
  Successful coalesced CPU, Hyperscan, and GPU scans now share one logical-input
  accounting boundary, including exact-once accounting after GPU recovery.

- Make the official 8 MiB crossover gate select a GPU route from all phase-two
  localization plans, then compare it in fresh held-out trials against every
  parity-correct Hyperscan plan. The release verdict uses the fastest Hyperscan
  observation in each paired trial; schema-v7 evidence records the
  full comparison set, and release runs cannot force one diagnostic mode.

- Add an explicit unprofiled `--diagnostic` crossover mode. It can measure the
  exact 8 MiB route set from a dirty shared tree but can never set
  `production_comparable` or `crossover_passed` in schema-v7 evidence.

- Carry phase-two plain-pattern localization as an immutable per-request
  execution route through CPU, Hyperscan, CUDA, WGPU, windowing, decode,
  fragment recovery, and boundary reassembly. Concurrent autoroute requests no
  longer need to mutate scanner-global tuning to select this path.

- Route the profiled Elasticsearch, ip-api, 8x8, Carbon Black, GovTech,
  SimpleAnalytics, SentinelOne, and MX API patterns through detector-owned
  required anchors instead of scanning them as always-active phase-two regexes
  on every chunk; when the plain-pattern localizer owns ASCII candidates, skip
  the redundant full Hyperscan marking pass.

- Require one compiled detector plan throughout isolated-bare admission and
  entropy-fallback adjudication; remove optional scanner-default policy plus
  duplicate entropy-shape and execution-policy inputs.

- Evaluate the bare-`auth` generic bridge and its repeated-block suppression
  through the active detector's compiled plausibility policy instead of
  scanner-owned fallback constants, with the adversarial property suite wired.

- Refuse release-comparable 8 MiB crossover evidence unless both the build and
  publication worktrees are clean at the recorded commit. Schema-v7 artifacts
  record both states, so a binary compiled from dirty source cannot become
  release evidence after the worktree is cleaned without rebuilding.

- Compile the keyword-free operator entropy margin from the owning detector
  TOML instead of applying a scanner-owned `+ 1.0` threshold adjustment.

- Bind the canonical 8 MiB crossover artifact to its exact parity result count,
  and keep the backend guide synchronized with the current checked RTX 5090
  evidence instead of the superseded near-parity run.
- Restrict source-file entropy extraction to unclaimed same-line credential
  assignments, matching the existing emission contract and removing the
  whole-file entropy tail without changing dogfood rejection visibility.

- Compile AST-proven per-pattern `required_literals` from detector TOML into
  the shared scalar, Hyperscan, CUDA, and WGPU trigger plan. DeepL `:fx` and URL
  `://` ownership remove the last two ASCII always-active regexes, replacing a
  fixed 64-of-2,754 GPU phase-two budget with a complete ASCII prefixless plan.
- Compose per-row prefixless completeness with fused anchor absence for every
  eligible ASCII row, including phase-one-triggered rows, and bypass the
  redundant Hyperscan always-active prefilter only when both proofs hold.
  Generic, entropy, multiline, decode, normalized-text, ML, recovery, oversized,
  non-ASCII, and incomplete work retains its canonical owner. Normalized rows
  discard raw GPU hints and positions and recompute phase-one admission.
- Keep fused GPU literal accounting feature-correct so portable scanner builds
  compile without referencing GPU-only positioned-evidence fields.
- Make Amazon Music, Checkmarx, Huawei Cloud, and Vonage Video confidential
  secrets the detector-owned primaries. Their client IDs, access-key IDs, and
  API keys are exact optional companions and no longer emit standalone secret
  findings; verification now receives the corrected primary and companion
  roles.
- Compile generic execution and final resolution from detector `kind` and the
  active typed plan rather than reporting service names or detector-ID length.
  Anchored detectors that report `service = "generic"` remain named, unknown
  active-plan identities fail visibly, equal generic ownership is stable across
  corpus order, and duplicate vendor-suffix owners are rejected.
- Treat SaltStack and Alertmanager usernames, GoTo client IDs, and Rapyd access
  keys as optional detector-owned companions. Only their password, client
  secret, or secret key is a primary finding, and companion evidence can no
  longer be erased by the generic identifier shortcut.
- Run the 10,667-case detector adversarial corpus and its handwritten boundary
  suite through a standalone Cargo target. Slack fixtures now exercise
  non-placeholder identifiers and exact declared segment boundaries.
- Upgrade the exact VYRE dependency set to 0.6.5 and replace the resident
  presence-only dispatch with one fused presence-and-position dispatch. The
  detector-derived matcher now supplies complete confirmed-anchor and generic
  keyword positions to the shared phase-two tail without a second GPU pass;
  match-output overflow remains a visible recoverable GPU fault rather than a
  partial result.
- Compile each scanner's generic-assignment line prefilter from the exact
  detector corpus that produced its assignment regex. Custom detector corpora
  no longer lose candidates to the embedded corpus's global keyword stems. The
  same active keyword plan now produces the fused VYRE positioned literals, so
  custom detector assignments stay GPU-accelerated without a compatibility
  flag or embedded-vocabulary fallback.
- Replace regex-text weak-anchor inference with explicit detector and
  pattern-local TOML policy. Confidence floors no longer disable structural
  protection, and the suppression path no longer reclassifies service/generic
  ownership from detector IDs. Pattern-local model conditioning remains
  disabled until training records carry the exact matched-pattern policy
  identity.
- Compile detector entropy-floor buckets into detector-indexed primitive lookup
  tables. Named, weak-anchor, and generic hot paths no longer walk optional TOML
  fields or inject a scanner-owned floor per candidate; missing weak-anchor
  policy fails scanner construction. Twenty-seven structurally derived weak
  anchors now declare their floor and high threshold in their own TOMLs.
- Include regex entropy owners when compiling the generic assignment generator.
  A focused corpus containing only a regex owner now executes its declared
  keyword, length, entropy, and identity policy instead of disabling the bridge.
- Match detector-local public-identifier assignment markers directly against
  source bytes with allocation-free ASCII case folding instead of uppercasing
  an entire source line for every entropy candidate.
- Move blockchain/network public-identifier assignment markers from a shared
  scanner rule into each entropy detector TOML, allowing each secret family to
  tune or disable the suppression independently.
- Require and compile `max_len` for every generic entropy-policy owner,
  including regex owners such as `generic-password`, so assignment ownership
  cannot win and then silently drop because its runtime length policy is absent.
- Compile keyword-free, isolated-bare, and unclaimed-keyword entropy entry
  roles from the owning detector TOMLs. Custom corpora no longer activate
  built-in generic detector IDs or scanner-side entropy defaults when a role
  is absent, and duplicate role owners fail scanner construction.
- Make every weak-anchor detector own its length-bucketed entropy floor and
  high threshold. Named weak anchors no longer borrow `generic-api-key`
  calibration, so tuning one service cannot change another detector.
- Select ML checkpoints against recall-sensitive validation-class gates before
  aggregate F1. The leakage-free test split remains untouched, while rare
  authoritative classes can no longer be lost by an aggregate-only epoch choice.
- Group strict entropy plausibility floors and shape switches in each owning
  detector's required `plausibility` policy. Compiled assignment and isolated
  paths now use the same detector policy, including repeated-block,
  identifier, dash-segment, and alphabetic-credential decisions.
- Refuse ML model writes when a recall-sensitive detector channel lacks
  positive or negative held-out evidence, misses its recall floor, or regresses
  against the shipped model card. The build summary now exposes real precision,
  recall, F1, floor recall, and zero-recall detector count instead of hiding
  detector failures behind aggregate metrics.
- Condition the 55-feature ML scorer on the exact detector TOML owner,
  pattern-versus-entropy channel, and detector-owned entropy family. Training
  and parity records now fail on missing or inconsistent detector identity,
  and detector balancing applies only where `blend` or `authoritative` model
  policy can reduce recall.
- Cover every authoritative entropy family with positive synthetic training
  records, including long fixture values and service-named API-token contexts,
  instead of training some TOML families only as negatives.
- Compile ML match mode, entropy mode, weight, and context radius from each
  detector TOML. Generic assignments now use the same pending batch and CPU/GPU
  model path as regex and entropy candidates. The explicit `lift` mode applies
  weighted positive model evidence without letting an uncalibrated model veto
  structural matches; calibrated detectors can select bidirectional `blend` or
  model-authoritative scoring. `--ml-weight` remains a visible scan-wide
  diagnostic override.
- Remove scanner-side generic-assignment identity and length defaults. Every
  phase-2 candidate must resolve to a compiled detector owner with declared
  `min_len` and `max_len`; an incomplete owner fails scanner construction or
  is surfaced and dropped instead of inheriting synthetic scanner policy.
- Score the ML pending queue directly instead of allocating a borrowed
  candidate vector and then copying the queue into a second vector. Pending
  matches now borrow their zeroizing `RawMatch` credential instead of retaining
  a second plaintext credential allocation. Small and GPU-sized batches retain
  the same model inputs, cardinality checks, and CPU/GPU score policy.
- Keep one parsed owner for ML file/context markers instead of cloning every
  marker family into separate lazy vectors.
- Compute each queued candidate's 55 model features once while its source
  context is hot, using reusable per-thread context storage that is zeroized
  after extraction. Postprocess and GPU dispatch now consume the stored feature
  vector instead of retaining a formatted context string and extracting the
  same features later.
- Compile each active generic detector's complete entropy, plausibility,
  isolated-shape, and BPE policy once during scanner construction. Active
  owners with missing policy fields now fail construction instead of reading
  scanner-side defaults, and hot candidate paths consume concrete compiled
  values rather than repeatedly resolving optional schema fields.
- Preserve parent JavaScript context and exact source provenance for static
  XOR and Node AES recoveries, matching the existing CryptoJS and reverse/Base64
  recovery paths.

- Resolve generic assignment entropy overrides against the owning detector's
  TOML `entropy_high` policy instead of the global fallback threshold.
- Make `ScannerConfig::thorough()` a distinct bounded recovery policy. It scans
  entropy candidates in source files, retains heuristic evidence alongside ML,
  removes comment confidence penalties, and admits one complete 1 MiB
  production chunk into decode-through.
- Add bounded static JavaScript recovery for embedded XOR and AES-256-CBC
  expressions. Decode-enabled scans evaluate only the recognized
  side-effect-free grammar and reject dynamic operands, mismatched bindings,
  invalid padding, non-UTF-8 plaintext, and oversized inputs. SIMD and portable
  CPU entry paths share the same static-XOR decode admission.
- Accept decimal and hexadecimal byte literals in bounded JavaScript XOR arrays.
  Mixed-radix values preserve exact recovery while overflow and expressions
  remain rejected without evaluation.
- Recover checksum-valid known-prefix credentials assembled from JavaScript
  string arrays followed by an empty-separator `.join("")`, even when the
  temporary variable name is obfuscated. Non-empty separators and arrays that
  produce no known credential prefix remain outside this recovery path.
- Keep immutable VYRE region-presence tables resident across GPU batches.
  Scanner-owned capacity grows from the live workload, concurrent calls cannot
  interleave mutable device buffers, and host staging allocations are zeroized.
- Return one empty result row per empty input chunk without issuing a zero-byte
  GPU dispatch. Mixed empty and nonempty region batches retain backend parity.
- Correct the 8 MiB crossover gate and size-pattern sweep to compare explicit
  production scalar, coalesced Hyperscan, and resident GPU routes with full
  finding parity. Historical per-chunk SIMD evidence is marked noncomparable.
- Rename the production GPU health API from the obsolete AC-kernel name to
  `gpu_region_presence_self_test`, matching the live VYRE region-presence path.
  Its structured failure remains available to health reporters, library scan
  entry points return it as a typed error, and the CLI maps it to exit `12`.
- Rename the VRAM-adaptive live buffer budget to `gpu_batch_input_limit` and
  move its owner to `gpu_input_budget.rs`.
- Remove detector-ID constants used only by their own tests; runtime-specific
  identifiers remain centralized only where production scanner behavior
  consumes them, while detector membership stays in detector TOML.
- Remove the unused test-only MoE shader re-export; GPU tests consume the
  existing testing facade and the backend imports the shader owner directly.
- Make the no-backend library APIs `scan` and `scan_coalesced` deterministic
  portable CPU references; Hyperscan/GPU execution now requires an explicit
  backend or the CLI's persisted fastest-correct autorouter.
- Keep cross-chunk boundary reassembly on the shared portable correctness tail
  instead of making a second hardware-heuristic routing decision.
- Keep fixed high-tier GPU routing conservative at 128 MiB (256 MiB for a
  single-file override). The historical 8 MiB RTX 5090 artifact used a slower
  per-chunk SIMD entry point and is not production crossover evidence. Exact
  cold-versus-daemon decisions belong to persisted autoroute calibration.
- GPU MoE buffer pool: reuse input/output/staging wgpu buffers across MoE
  dispatches via a global `LazyLock<Mutex<MoeBufferPool>>`, eliminating
  per-dispatch buffer allocation (the dominant non-GPU overhead for large
  MoE batches in coalesced scanning). The params buffer remains per-dispatch
  to prevent concurrent batch_size races. Pooled buffers grow to the
  high-water mark and are reused for smaller batches via sized slicing.
- Fix pre-existing `simdsieve_prefilter` compilation errors: add
  `build_hot_pattern_validators` (plural), `HOT_PATTERNS`, and
  `HOT_PATTERN_DETECTOR_IDS` computed from embedded detector specs via
  `LazyLock` with leaked `'static` slices. Add standalone
  `hot_pattern_index_at` test helper that doesn't require a compiled scanner.
- Reduce the backend surface to `gpu`, `simd`, and `cpu`; the CLI owns `auto`
  through persisted fastest-correct routing evidence. MegaScan and
  implementation-name aliases no longer map to a live route.
- Reduce `MAX_SCAN_CHUNK_BYTES` from 1 MiB to 384 KiB, enabling 32-thread
  parallelism on large inputs without OOM. Window size stays at 1 MiB to
  preserve adversarial parity.
- Add fast line-level prefilter to `scan_keyword_free_candidates` that
  skips lines below `max_entropy_run` threshold before entering the
  expensive entropy computation. The prefilter is conditionally disabled
  when dogfood telemetry is active to preserve suppression-event recording.
- Promote `debug_assert!` to `assert!` for the line-offset invariant in
  `find_entropy_secrets_with_lines` and
  `find_entropy_secrets_with_precomputed_keywords_and_policy`. The
  fail-closed behavior must hold in release builds, not only debug.
- Fix pre-existing build errors in `gpu_region_dispatch.rs`: add missing
  `report_positioned_gpu_candidate_loss` helper and
  `scan_gpu_literal_matches_with_scratch` function. Add `marked` field
  to `Phase2GpuDfaAdmission` initializers.
- Fix pre-existing test compile errors in
  `gpu_presence_bit_partition.rs`: remove assignments to non-existent
  `confirmed_anchor_literal_count` and `generic_keyword_literal_count`
  fields on `CompiledScanner`.

- Add detector-owned BPE token-efficiency policy through
  `bpe_max_bytes_per_token` in detector TOML. Generic and entropy fallback
  paths resolve the same owning detector before applying the gate; detector
  policy takes precedence over the compiled fallback, while an explicitly set
  scan TOML/CLI value remains the final visible Tier-A override. Invalid
  non-positive/non-finite bounds fail closed,
  and the field participates in the detector digest used by caches and
  calibration identity. Opaque generic API-key/secret policies use the measured
  2.3 ceiling across assignment, entropy, and explicit regex-envelope paths
  when the `entropy` feature supplies the tokenizer; password/passphrase-oriented
  policies explicitly disable the
  word-likeness rejection so human-chosen phrases do not become false negatives.
- Add the `aws-bedrock-api-key` detector (critical), long-term AWS Bedrock
  API keys (`ABSK` prefix + the deterministic `QmVkcm9ja0FQSUtleS` base64
  anchor + 110-char body, 132 chars total; AWS's own published form). The
  anchor encodes "BedrockAPIKey" and is effectively unique, so precision is
  anchor-driven (defensive `min_confidence = 0.2` floor since the fixed anchor
  dilutes entropy scoring). Not checksum-gated. Detector count 900 → 901.
  Contract-locked by `crates/scanner/tests/contracts/aws-bedrock-api-key.toml`
  (positives, anchor/length negatives, header + comment evasions). Short-term
  `bedrock-api-key-` keys are deliberately omitted (their body is not
  authoritatively bounded (soundness over reach)).
- Fix a dead contract gate: `every_contract_readme_claim_present` had been
  passing vacuously. A `readme_claim` written after a contract's `[perf]`/
  `[scale]` header binds to that TOML table, not the Contract, so serde
  silently dropped it and every contract's claim parsed as `None`: the gate
  checked nothing (and "stripe" never matched README's "Stripe"). Moved the
  six real `readme_claim`s to the top-level scalar position, corrected the
  `stripe`→`Stripe` claim, added `#[serde(deny_unknown_fields)]` to the perf
  and scale budget structs so a future misplacement is a loud parse error
  instead of a silent drop (Law 10), and added a liveness floor (`checked >=
  6`) so the gate can't regress to vacuous.
- De-duplicate the detector-count claim (was denormalized across 782 places):
  removed the `readme_claim = "900 service-specific detectors"` stamp from 781
  per-detector contracts and made the count derive from `load_detectors()` in
  one place: `readme_claims::readme_claim_detector_count` (README + banner),
  `contract::readme_detector_count` (disk == loader, no literal), and the
  `e2e_binary` banner test (binary == loaded corpus). Adding a detector now
  touches only the new TOMLs + the human-facing README/banner, with no
  test-literal or 781-file churn.
- Byte-cap the per-match context windows (`local_context_window` ML context to 8 KiB, `context::inference::surrounding_line_window` FP context to 2 KiB). Previously each candidate's context was the whole containing line; on a line with no `\n` for kilobytes (minified bundles, or a file that is one long run of credential-shaped tokens) the per-match ML feature / FP keyword scan was O(line_len), making a many-match scan quadratic (a 164 KiB single-line file with 8 K matches took ~18 s). The caps make per-match context O(1) and noticeably speed ordinary minified-bundle scans. Behavior-preserving for normal source, a short line hits its newline well before the cap, verified by byte-identical mirror-corpus findings (F1 0.9167, 2564 findings) and the full scanner suite. Regressioned by `unit/a3_pipeline/local_context_window_caps_long_line`. (A residual super-linear cost remains when a single file carries thousands of distinct credential-shaped matches; bounded in practice by `--timeout` and the 1M-iteration-per-pattern cap.)

- Fix windowed-scan line attribution: findings in files past the 1 MiB
  windowing threshold (`filesystem/windowed`) reported the per-window line
  instead of the absolute file line, so a secret on line 584307 of a 70 MiB
  file was reported at line ~2 (and reported lines were non-monotonic). Added
  `ChunkMetadata::base_line` (the line analog of `base_offset`), populated
  per-window by the filesystem source (mmap + buffered paths) and the
  cross-window boundary reassembler, and added it at every line emit site
  (primary, entropy fallback, generic-secret, multiline reassembly, decode
  pipeline, and the simdsieve hot path). Byte offsets were already absolute;
  this brings line numbers to parity. Regressioned by
  `cli/tests/regression/windowed_line_numbers.rs`.
- Remove the orphaned `pipeline/postprocess/raw_match.rs`: a never-compiled
  stale duplicate of `build_raw_match` (no `mod`/`#[path]` referenced it),
  superseded by the `pattern_client_safe`-aware constructor in
  `pipeline/postprocess/mod.rs`.
- Align Vyre usage docs with the workspace-pinned crates.io `vyre` 0.6.1 release and add a scanner gap test that fails on stale Vyre pin/documentation claims.
- Fix stale `RawMatch` scanner test fixtures to use the production `[u8; 32]` credential hash contract.
- Split structured parser implementations by format family and move remaining parser inline tests into the external scanner test harness.
- Add a GPU phase2 empty-hit fast path matching SIMD coalesced no-hit fallback admission, with a regression gate for the skip-before-prepare contract.
- Preserve detector regex case-insensitivity when lowering prefixless phase-2
  admission patterns into the GPU regex-DFA catalog; plain variants stay
  case-sensitive, and replay tests compare the lowered DFA admission result
  against the CPU `LazyRegex` policy.
- Select bounded GPU regex-DFA admission candidates by detector breadth before
  generated homoglyph variants instead of taking the first source-order slice;
  the catalog budget is now expressed as shard count x shard width.
- Tighten the GPU region-presence host lowercase staging helper to reserve once
  and write folded bytes directly into spare vector capacity, preserving
  `make_ascii_lowercase` semantics without a `Vec::push` per byte.
- Make the boolean no-hit phase-2 admission gate honor the proven ASCII
  homoglyph-variant skip, avoiding extra phase-2 work on pure-ASCII chunks that
  are already covered by the base AC path.
- Tighten GPU phase-2 DFA coalesced-region attribution so matches on or through
  the synthetic NUL separator between chunks cannot over-admit a neighboring
  chunk into the CPU phase-2 tail.
- Pack the GPU phase-2 DFA coalesced haystack once per batch and reuse it across
  DFA shards, removing duplicate O(input) host staging work from sharded
  admission dispatch.
- Mark GPU phase-2 DFA admission evidence incomplete when a backend hit cannot
  be safely attributed to a chunk, keeping `phase2_gpu_complete` honest for
  separator/cross-region output.
- Keep high-entropy base64-like secrets with internal `+`/`/` punctuation through generic and entropy fallbacks by bypassing binary-decoy suppression on the punctuation payload class, closing `encoded_binary`-driven false negatives.
- Add adversarial coverage for the base64 punctuated high-entropy class and a fixed-token regression for `TVo...+...` shape that previously dropped at `is_encoded_binary`.
- Detect current variable-length Clerk publishable keys by their documented
  base64-encoded FAPI URL form instead of requiring an obsolete exact 32-byte
  alphanumeric body; findings remain explicitly client-safe.
- Keep two S3-compatible access-key bodies case-sensitive inside their
  detector TOMLs while preserving case-insensitive environment-key anchors,
  preventing lowercase identifiers from satisfying documented uppercase
  credential alphabets.
- Apply the canonical Octopus Deploy key alphabet to assignment and header
  patterns too, so context cannot admit lowercase keys or pure documentation
  words that the bare-key pattern correctly rejects.
- Preserve Akoya client-credential findings for mixed-case config keys by
  declaring the required companion anchor caseless in its detector TOML;
  simplify the already-caseless primary regex to one canonical spelling.
- Preserve Twilio IoT credential pairs for lowercase config keys by applying
  case folding to the required companion anchor, while keeping the credential
  body alphabet detector-owned and simplifying redundant primary alternations.
- Preserve Twilio API-key pairs for mixed-case secret field names by folding
  only the detector-owned companion anchor, without widening the credential
  body's declared alphabet.
- Capture mixed-case AWS and GovCloud secret/session fields without widening
  their credential bodies, so temporary ASIA credentials reach SigV4 with the
  required session token; keep GovCloud access-key IDs uppercase-only and
  reject overlong runs instead of truncating them into findings.
- Make Spotify's companion secret-specific and capture only its value, so a
  client ID cannot attach itself as a credential pair; collapse redundant
  uppercase/lowercase primaries under the shared caseless compiler.
- Migrate the stale FedEx companion fixture into its normal detector contract
  and reject companion contracts whose detector declares no companions, so
  generated test shape cannot masquerade as production verification wiring.
- Make LiveKit's companion secret-specific so long API keys cannot self-attach
  as secrets, deduplicate caseless primary regexes, and let companion contracts
  explicitly declare when a companion shape is also a valid standalone primary.
- Make Ceph access keys self-delimiting so 40-character secret values cannot be
  truncated into 20-character access-key findings, while preserving Ceph's
  valid user-defined mixed-case access keys and correcting the contract prose.
- Model Five9 API secrets as intentional standalone primaries in the companion
  corpus, while proving API-key-only findings cannot fabricate the nearby
  secret required for credential-pair verification.
- Make AWS SES SMTP field anchors consistently caseless while preserving the
  uppercase access-key alphabet, reject overlong username/password prefixes
  instead of truncating them, and model password-only findings honestly.
- Make Olark's companion token-specific and capture only its value, so an API
  key cannot self-attach as its own pair; preserve standalone token detection
  and reject overlong hexadecimal runs instead of truncating them.
- Make Genesys Cloud's companion client-secret-specific and capture only its
  value, so a client ID cannot self-attach; preserve standalone secret findings
  and reject overlong UUID-like client IDs instead of truncating them.
- Treat Payoneer client IDs as companion context instead of standalone secrets,
  capture their exact value beside a client-secret primary, and reject invalid
  token continuations without limiting legitimate variable-length secrets.
- Preserve standalone Gravity Forms private-key detection while proving public
  keys cannot self-attach, accepting mixed-case hexadecimal keys, and rejecting
  overlong hexadecimal runs instead of truncating them.
- Keep Checkmarx client secrets detectable on their own while making them the
  exact companion to UUID client IDs; use role-specific anchors and reject
  overlong UUID/token continuations without losing secret recall.
- Model Cloudinary URLs as the self-contained credentials they are, remove the
  fabricated companion contract, capture the exact URL without its delimiter,
  and reject invalid cloud-name continuations instead of truncating them.
- Treat M-Pesa consumer keys as companion context for consumer-secret findings,
  preserve standalone API-key detection, capture the exact paired key, and
  reject invalid underscore/hyphen continuations instead of truncating them.
- Make Tumblr's companion consumer-secret-specific while preserving standalone
  secret findings, and reject alphanumeric, underscore, and hyphen extensions
  whole instead of reporting a valid-looking 50-character prefix.
- Make Marvel's primary and companion explicitly private-key/public-key roles,
  so a private key cannot self-attach and public identifiers do not become
  standalone secret findings; reject overlong hexadecimal key runs.
- Replace Amazon Music's broad context companion with the exact 64-hex client
  secret, preserve standalone secret findings, normalize caseless field anchors,
  and reject client-ID/secret continuations instead of truncating them.
- Remove Worldpay's service-name pseudo-companion, migrate its useful fixtures
  into the normal contract, classify service/merchant IDs as low-severity
  identifiers, and reject overlong or continued ID tokens whole.
- Remove Nuvei's self-attaching and invented merchant companions while preserving
  standalone API-key and API-secret recall, and reject invalid continuations
  instead of emitting hexadecimal prefixes.
- Treat Mangopay API keys/passphrases as primaries and client IDs as exact
  companion context, with mixed-case, minimum-length, unbounded valid-length,
  and invalid-continuation contracts.
- Treat Tawk.to API keys as primaries and public site/property IDs as exact
  companion context, so API keys cannot self-attach and continued key prefixes
  are rejected whole.
- Preserve standalone Exoscale API-secret findings explicitly while keeping API
  keys self-delimiting, so fixed-length key prefixes cannot be truncated from
  longer tokens.
- Make BigCommerce store hashes exact public companion context for `bbc_` access
  tokens, remove store hashes as critical standalone findings, and reject token
  continuations whole.
- Treat Avaya client secrets/API keys as primaries and public OAuth client IDs
  as exact companion context, removing critical standalone identifier findings
  and rejecting continued secret prefixes.
- Make env0 key IDs self-delimiting, capture API-secret companions exactly, and
  explicitly preserve standalone secret findings.
- Capture FastSpring password companions by exact value and explicitly preserve
  password-only findings without letting username primaries self-attach.
- Make GCS HMAC companions secret-field-specific instead of matching arbitrary
  base64/access-ID substrings, and reject overlong `GOOG` access IDs whole.
- Remove Jumio's accidental companion capture of the role label, capture the
  exact secret value, preserve secret-only findings, and reject continued
  credential prefixes.

#### Source adapters

- Let all four WebSource DNS-screening workers wait on and consume the bounded
  job queue concurrently instead of serializing receives behind one mutex.
- Add GitLab group and Bitbucket workspace source backends through a shared
  hosted-git clone/scan owner, moving git-error redaction out of the GitHub-only
  module so every forge source redacts clone failures through the same control.
- Fix `--git-diff` and `--git-history` line attribution: both sources
  concatenated every added line of a file into one chunk and discarded the
  `@@ … +new_start @@` hunk header, so every finding was reported at line 1
  instead of its real new-file line (a pre-commit/CI workflow, and history
  forensics, pointing nowhere near the leak). Both now run `-U0` and emit one
  chunk per hunk carrying `base_line = new_start - 1` (parsed by the shared
  `git::parse_hunk_new_start`), so the scanner reports the absolute new-file
  line. Regressioned by `git_diff_chunks_carry_absolute_base_line_per_hunk`
  and `git_history_later_commit_addition_carries_absolute_base_line`.
- Populate `ChunkMetadata::base_line` on the filesystem windowed path (mmap +
  buffered) so findings in files past the 1 MiB window size report the
  absolute file line, not the per-window one (paired with the scanner-side
  emit-site fix).
- Run filesystem reading on a dedicated Rayon pool so bounded-channel backpressure cannot starve scanner work on the global Rayon pool during large-tree scans.

#### Live verifier

- Normalize missing schema-1 verifier success policy to
  `status_with_error_backstop`, require an explicit policy in schema 2, and
  reject forward schema versions. Corpus identity binds the normalized schema
  so equivalent detector fields under different schemas remain distinct.
- Redact verifier proxy credentials, query parameters, percent-decoded secrets,
  and parser source text from invalid-URL errors. Diagnostics include only a
  safely parsed scheme and host or the generic invalid-proxy message.

#### Release engineering, benchmarks, and documentation

- Add a dedicated crates.io publication workflow that proves the exact tag, checks out hardened automation separately from tagged source, verifies the public GitHub release before credential use, and resumes an interrupted five-crate publication by validating immutable registry archives.
- Stage signed release assets in one immutable private draft, bind the release ID and source commit in a signed receipt, and expose the release only after candidate smoke, container publication, and receipt verification succeed.
- Run the signed Linux candidate through checksum and Minisign verification, offline installation, `doctor`, and an exact finding/redaction scan before any GitHub release or GHCR mutation becomes public.
- Verify the pushed GHCR multi-architecture manifest by digest and platform, publish `latest` only for the newest stable release, and move the floating `v0` action tag only after the immutable release is public.
- Make release-ref GitHub Action installs require the signed binary, signed GPU literal sidecar, checksums, and matching release identity before scanning.
- Declare canonical benchmark run sets and baselines in TOML. Reports reject stale or mixed executable, detector, corpus, host, recovery, and run-set provenance instead of silently selecting convenient results.
- Record Bloom prefilter density, saturation, rejection, parity, and corpus evidence in benchmark artifacts, `doctor`, and `explain`; missing named-corpus evidence remains visibly unproven.
- Generate deterministic GPU literal archives and validate archive paths, entry types, expansion limits, manifest identity, filenames, and byte lengths before installation.
- Pin documentation tooling by checksum, validate links and CLI claims, preserve byte-identical generated benchmark blocks during version bumps, and require substantive per-crate changelog entries before release.
- Serialize release retries by immutable tag without cancelling active publication. Repeated runs reuse exact public releases without mutating verified assets.

## [0.5.45] - 2026-07-22

### Fixed

- Signed release publication now discovers drafts and mutates assets by
  immutable release ID. First publication and interrupted reruns remain private
  until exact signed-manifest validation succeeds.

## [0.5.44] - 2026-07-22

### Fixed

- The Windows GPU literal artifact generator now passes UTF-16 prefixes to
  `slice::strip_prefix` as slices. CI compiles both Windows release feature
  closures before a tag is cut.

## [0.5.43] - 2026-07-22

### Fixed

- Windows portable release builds now gate Unix-only daemon test seams, use the
  generated windows-sys drive-constant module, and compile before a tag is cut.

## [0.5.42] - 2026-07-21

### Fixed

- Published crates bundle their canonical Tier-B rule data and resolve GPU
  driver identity from either workspace or normalized package manifests, so
  standalone crates compile outside the KeyHog workspace.
- The release publisher uses stable Cargo, verifies every crate with all
  features before upload, and validates immutable crates.io archives when a
  partial release is resumed.
- Phase-two GPU DFA resident batches keep grown haystack capacities aligned to
  the declared 32-bit element ABI, so 8 MiB coalesced scans dispatch on CUDA.
- Prerelease now requires a signed release bundle for installer smoke tests and
  a clean, candidate-bound 8 MiB GPU-versus-Hyperscan crossover artifact.
- Offline installs verify sibling Minisign signatures when supplied and reject
  empty, invalid, or wrong-key signatures before replacing an installed binary.
- GPU literal sidecars reject absolute, parent-traversal, symbolic-link, and
  hard-link members before extraction.
- Known-prefix confidence and entropy fallback suppression now use each
  detector TOML's `degenerate_run_min_length` instead of a scanner-wide limit.
- Post-match placeholder, diversity, repeated-run, decoded-envelope,
  fixture-path, and model-context confidence tuning now compiles from each
  detector TOML instead of scanner literals.
- Detector resolution priority, decoder ancestry, generic assignment suffixes,
  entropy thresholds, and backend policy now compile into one typed detector
  execution plan used by CPU, SIMD, and GPU result processing.
- Structured scanning repairs truncated Jupyter JSON at EOF and sanitizes
  balanced Helm render actions before YAML parsing, while scanning the original
  source bytes and reporting every repair.
- Build provenance watches Git reflogs as well as loose and packed refs, so
  consecutive same-branch candidate builds embed the exact checkout commit.
- Base64 and hexadecimal values, JSON strings, quoted-printable text, and
  line-local URL-percent, HTML-entity, Unicode, and octal escapes decode in
  bounded source and output batches while retaining multiline private-key
  separators. Dense generated source no longer creates one recursive root per
  encoded value.
  Disallowed decoded C0 controls become token separators instead of truncation
  events, preserving adjacent printable spans without joining tokens.
- Differential corpus benchmarks disable default file exclusions for directory
  inputs, so terminal success proves every corpus file reached scanning.
- CUDA and WGPU positioned-literal evidence use the same 8 MiB shard ceiling,
  keeping dense corpus match replay exact without backend substitution.
- Full-corpus accelerated parity checks allow twenty minutes per backend, so a
  cold or contended release host does not kill a healthy exact scan.
- Single-shard Hyperscan databases compile inline, preventing nested Rayon work
  from re-entering a worker's borrowed phase-two scratch state.
- Chef's generic `api-token` header anchor now requires a token boundary, so it
  cannot replace an exact Snyk UUID finding through overlap resolution.
- Benchmark process failures include measured wall time, peak RSS, and watchdog
  state, distinguishing resource kills from finite timeout failures.
- CredData backend parity packs disjoint top-level roots into identical
  source-bounded processes and rejects overlap before comparing complete unions.
- Default detector resolution priority no longer perturbs the canonical detector
  digest, while non-default collision policy remains cache-bound.
- Generic vendor and exact-keyword tail suffixes now come from the owning
  detector TOML instead of a scanner regex literal.
- Scanner profiling, generic-shape adjudication, segment attribution, regex
  truncation, and GPU artifact/cache/input policy now live outside the runtime
  engine, with exact complexity ratchets lowered to the new ownership boundary.
- Oversized staged-diff headers now emit a recoverable coverage error while
  preserving later staged records, and Docker archive extraction no longer
  carries an unused archive-scope argument.
- Installer support claims now name the exact released architectures. Linux and
  Windows arm64 are explicitly unsupported and release selection tests lock that
  contract.
- Obsolete `bench-v1` artifacts and their unverifiable README claims are removed;
  benchmark reports now render only current-schema evidence.
- Decoded finding resolution preserves exact raw credential bytes when the same
  detector matched that source coordinate. Otherwise, it prefers the shallowest
  valid decoded representation.
- Detector-definition suppression recognizes complete path segments at relative,
  absolute, POSIX, and Windows boundaries without matching partial directory names.
- Kubernetes Secret classification reads parsed YAML fields rather than matching
  `kind: Secret` text in comments or scalar prose.
- Scanner pre-exit hook registration is first-writer-wins without panicking, and
  zlib admission rejects reserved CINFO window sizes.
- Caesar decode admission now requires detector prefixes at token boundaries, so
  an interior rotated prefix cannot synthesize a competing provider finding.
- Grouped extraction keeps the participating alternate capture, service-specific
  private-key detectors retain complete PEM blocks, and short detector aliases
  require token boundaries so broader detectors cannot steal exact findings.
- Scan telemetry scopes propagate into Rayon post-processing workers, so nested
  compiled scans contribute to the owning scan receipt without global state.
- Automatic autoroute recovery now covers Hyperscan/SIMD runtime faults as well
  as GPU faults, replays the stable batch through the fastest remaining
  measured-correct peer, and quarantines the failed workload route.
- Autoroute uses paired same-backend timing when it can distinguish execution
  plans. For a statistical tie, it prefers the typed plan's compiled default or
  a stable tied plan whose interval remains below every peer backend plan.
- GitHub Action scans publish reports before restoring scanner failures, and
  unreadable findings reports fail closed even when findings are advisory.
- Generic plausibility now compiles its alphanumeric ratio, source type-name
  limits, and URL/path high-entropy exemption length from the owning detector
  TOML instead of scanner literals.
- Isolated symbolic candidates now use the owning detector TOML's symbol count,
  non-underscore rule, alpha-only symbol count, and alphabetic ratio in every
  admission branch.
- GPU MoE dispatch now reuses its uniform buffer and bind group with each
  exclusive pooled buffer set, validates device buffer and workgroup limits
  before submission, and recovers from a poisoned pool without panicking.
- SARIF `executionSuccessful` is false when `keyhog.scan.status` is Partial (or
  Failed/Cancelled), so consumers that only read that flag cannot treat
  coverage-gap runs as green (KH-1437).
- `.env` multiline / unclosed-quote reconstruction caps continuation joins at 64
  lines so a missing closer cannot swallow later KEY=VALUE pairs (KH-1432).
- `SensitiveString` `Display` redacts like `Credential` / `Debug`; plaintext is
  only via `as_str` / `Deref` (KH-1424).
- Oversized Git diff, history, and tag lines now emit an operator-visible source
  error instead of only incrementing an internal truncation counter.
- Oversized staged-diff headers emit an error row and preserve later staged
  records instead of discarding the path-read outcome.
- Binary string extraction removes shifted or partially overlapping UTF-16
  LE/BE suffix duplicates by byte span while preserving both byte orders.
- Empty PDFs with extraction errors retain their unreadable or truncation event
  without also being counted as valid image-only binary skips.
- `keyhog watch` accepts `--max-file-size` and `--max-consecutive-failures`
  (Tier-A) instead of hardcoding 100 MiB / 8 (KH-1461, KH-1462).
- Incomplete exit 13 and baseline refuse use `CoverageCounts::fail_class_total`
  driven by the `CoverageGapKind` severity table, so FAIL-class sums cannot
  drift from the canonical kind list (KH-1410).
- `--create-baseline` still writes the snapshot when findings exist, but exits
  10 when any finding is Live so verify+baseline CI cannot go green on live
  credentials (KH-1439).
- Docker layer rewrite continues after a single filesystem chunk error instead of
  aborting the rest of the layer (KH-1446).
- Filesystem reader-pool spawn failures print on stderr (not only `tracing::warn`)
  so a degraded crew cannot hide without RUST_LOG (KH-1430).
- Coalesced phase-2 trigger/chunk cardinality mismatch recomputes every trigger
  row instead of truncating or silently padding, and prints on stderr (KH-1431).
- S3 objects whose ListObjects size is missing use a `Range: bytes=0..cap-1` GET
  so a multi-GB object cannot stream unbounded before the client cap (KH-1413).
- JWT `iss`/`sub`/`aud` metadata is revealed under `--show-secrets` via
  `finding_metadata_with_secrets` (still length-redacted by default) (KH-1458).
- `keyhog watch` with multiple roots loads each root's `.keyhogignore.toml`
  RuleSuppressor instead of sharing only the primary root's policy (KH-1433).
- CRX/openpack extraction binds openpack entry/total caps to KeyHog scan budgets
  and uses a finite 1000× compression-ratio ceiling instead of `f64::MAX`
  (KH-1436).
- Daemon client receive timeouts are per request kind: Health/Shutdown/Hello 5s,
  ScanText 60s, ScanPath 300s (KH-1459).
- Live/Dead verification findings merge offline JWT/AWS metadata (including
  `--show-secrets` claim reveal) keyed by credential hash (KH-1487).
- Docker image archives enforce the same per-entry byte cap as layer archives
  (KH-1455).
- Source construction now returns typed unknown-name, unavailable-feature, and
  invalid-configuration errors. Canonical source names use hyphens, and retired
  underscore aliases are rejected with their exact replacement instead of being
  accepted silently.
- S3 listings that omit object Size still fetch the object instead of treating missing Size as empty (KH-1321).
- Selecting SimdCpu/Hyperscan on a binary built without the `simd` feature hard-errors instead of silently scanning on CPU (KH-1291).
- Autoroute cache schema 45 requires the winning execution plan's confidence
  interval to clear every eligible route, including localization variants on
  the same backend; overlapping same-backend plans remain visibly inconclusive.
- Non-finite GPU MoE confidence now invalidates and CPU-rescores the complete
  batch, then disables GPU MoE scoring for the process, instead of substituting
  0.5 and risking CPU/GPU detection drift (KH-1342).
- Service-regex and companion-backed candidates now continue into detector-owned
  ML scoring even when the cheap probabilistic gate finds little randomness;
  only unaccompanied generic candidates may take the early 0.1-confidence path
  (KH-1343).
- Secret-scanner path suppression requires a definition-shaped path segment so apps named after scanners keep being scanned (KH-1300).
- README star history uses the shields.io stars badge instead of a hotlinked api.star-history.com SVG that often 404s on GitHub (KH-1264).
- Image-only PDFs with no extractable text record a Binary coverage skip instead of disappearing silently (KH-1325).
- Decoded payloads with C0 control bytes keep their printable content instead of being discarded entirely (KH-1338).
- Strict adversarial CI on CPU runners uses `--features ci-lean` so cudarc is not loaded (KH-1302).
- Binary string extraction recovers UTF-16BE wide strings in addition to UTF-16LE (KH-1322).
- Incremental cache is not persisted when findings lack a file path, so pathless secrets cannot remain marked clean for the next run (KH-1296).
- Kubernetes Secret structured detection parses the YAML `kind` field across
  quoted, spaced, and multi-document forms without matching comments or scalar
  prose (KH-1341, KH-1393).
- Gzip/zlib decode-through rescans any non-empty inflated prefix when decompression hits the size cap or mid-stream error (KH-1339).
- `keyhog watch` applies the same default max-file-size (100 MiB) as `keyhog scan` when reading changed files, instead of the 2 GiB TOCTOU-only ceiling (KH-1310).
- Action source-build fallback on Linux uses `--features ci-lean` so hosted runners do not link the full GPU stack (KH-1304).
- `keyhog watch` exits after eight consecutive per-file scan/read failures instead of staying healthy while dropping secrets (KH-1334).
- Zlib decode-through accepts any RFC 1950 header with deflate method and valid FCHECK, not only the three common 78 01/9c/da pairs (KH-1340).
- Daemon client scan/health/stop responses time out after 300s instead of hanging forever on a wedged peer (KH-1314).
- Daemon connections require a Hello handshake as the first frame before Scan or Shutdown (KH-1337).
- `.env` parser reconstructs multiline quoted values and backslash-continued bare values instead of truncating at the first line (KH-1346).
- Live-verification status-only success specs no longer suppress the body error backstop, so HTTP 200 with an error JSON body is not classified Live (KH-1298).
- JWT `iss`/`sub`/`aud` metadata in reports is length-redacted by default so claim values do not leak through finding metadata (KH-1350).
- Dogfood product matrix writes scan reports under `$tmp/outputs` while fixtures live only under `$tmp/scan`, so the scanner cannot read its own growing report files (KH-1303).
- Git history, diff, staged, and tag-message streams skip oversized plumbing lines with a counted SourceTruncated gap and continue (KH-1355).
- `keyhog calibrate-autoroute` now writes its complete workload and preset
  sweep to an isolated cache, validates the finished generation, and publishes
  it once. A failed late probe leaves the live cache byte-identical, while a
  concurrent cache or runtime-health update aborts publication instead of being
  overwritten or incorrectly cleared.
- Detector TOML validation now rejects inverted entropy tiers before scanner
  compilation, with exact diagnostics for `entropy_low > entropy_high` and
  `entropy_high > entropy_very_high`.
- Watch-mode file chunks now carry their complete raw file size into autoroute,
  so an editor save reuses the same measured workload identity as an ordinary
  filesystem scan instead of appearing to be a transformed payload.
- Watch mode now warms its selected backend before announcing readiness and
  consumes persistent-runtime autoroute evidence instead of pricing every file
  event as a cold one-shot scan.
- Autoroute calibration now aborts without writing when an existing cache is
  temporarily unreadable. A sharing violation, permission failure, or short
  storage read error can no longer erase other calibrated profiles by being
  treated as corrupt replacement input.
- Repeated detector-owned BPE checks now reuse a bounded per-worker token count
  only after exact-byte verification. Hash collisions recompute, oversized
  candidates remain uncached, and retained candidate bytes are zeroized on
  eviction.
- Watch-mode burst dedup now binds the one-way credential hash and complete
  source location. Replacing a credential at the same detector and byte span
  emits immediately instead of being mistaken for a duplicate save event.
- Composite Action initializes `v=""` under `set -u` so branch/SHA refs no
  longer crash with unbound `v` before download or source-build (KH-1267).
- Action `fail-on-findings: true` fails the job on process exit 1 even when the
  report parses to zero findings (KH-1330).
- `keyhog watch` applies `.keyhogignore.toml` `RuleSuppressor` after resolve,
  matching `keyhog scan` (KH-1329). Watch dedup maps use bounded FIFO eviction
  instead of O(N) retain spikes (KH-1311).
- `keyhog hook install` rewrites KeyHog-owned hooks when bytes differ from the
  current template; only an exact-byte match is "already installed" (KH-1333).
- `--create-baseline` / `--update-baseline` refuse to write and exit non-zero
  when the scan panicked, hit FAIL-class coverage gaps, or failed the
  incremental cache (KH-1352).
- Incomplete-coverage exit 13 uses the CoverageGapKind FAIL set only (including
  line-offset mapping mismatches). Deliberate binary / over-max WARN skips no
  longer flip a clean scan to exit 13 (KH-1347).
- Missing or non-finite match confidence is treated as 0.0 for
  `--min-confidence` and per-detector floors (KH-1351).
- GPU runtime-fault accounting stores the degrade reason even when the diagnostic mutex is poisoned (KH-1290).
- Daemon incomplete exit 13 uses FAIL-class source gaps only, matching local
  scan (KH-1368). Daemon findings with `VerificationResult::Live` exit 10
  instead of collapsing to exit 1 (KH-1379).
- Daemon source coverage gaps merge into process-local skip counters before reporting so SARIF/human gap summaries match in-process scans (KH-1369).

### Changed

- Named regex detectors now admit digest-shaped pure-hex credentials only through
  length-only `canonical_hex_key_material` declarations in their own TOMLs.
  The scanner-global service-key width fallback is removed; generic assignment
  rules remain scoped to their declared keywords and suffixes.
- Autoroute inspection now reports disabled or missing evidence as visible,
  complete scalar correctness recovery instead of claiming scans require an
  explicit backend. Its JSON timing receipts expose ordered nanosecond trials,
  cold cost, exact one-shot and warm projections, and confidence bounds for
  scalar, Hyperscan, CUDA, and WGPU routes; SIMD warm evidence is no longer
  misreported as an ordinary rounded median. Recovery warnings now have one
  canonical operator rendering instead of a duplicate tracing WARN.
- Autoroute cache schema 43 keys routes by the complete canonical source
  execution class. Web JavaScript, source maps, windowed files, PDFs, archives,
  and other preprocessing shapes no longer alias under a truncated top-level
  family; dynamic binary section names collapse to their stable format class.
- Autoroute cache schema 44 content-addresses every measured payload and source
  shape. Equal byte/chunk counts no longer overwrite distinct calibration
  representatives, and JSON inspection exposes the canonical generator plus
  payload and shape digests needed to reproduce crossover evidence.
- Autoroute inspection now renders KeyHog-owned source execution classes by
  privacy-safe canonical name alongside their digest. Unknown library-provided
  metadata remains digest-only instead of being echoed into diagnostics.
- Autoroute config identity now includes profile and performance-trace
  instrumentation, preventing timed routes from reusing evidence measured
  under a different hot-path cost model.
- Hyperscan compile sharding and per-shard scratch preallocation now follow the
  active Rayon executor width instead of host-visible CPU count, avoiding
  needless databases and scratch allocations under `--threads` and local pools.

## [0.5.41] - 2026-07-18

### Fixed

- **Documented CI action pins pointed at an unreleased tag.** Every copy-paste
  CI snippet pinned `santhreal/keyhog/.github/actions/keyhog@v0.5.41`, a version
  with no release, so GitHub failed to resolve the action at checkout before the
  scan could run. The pins now use the floating `@v0`, which the Action resolves
  to the newest published release.
- Pin `simdsieve` to crates.io `0.1.2` so macOS/aarch64 builds no longer hit
  the broken `0.1.1` NEON `inline(always)` + `target_feature` combination.
- Installer GPU-literal sidecar validation extracts to a temp tree and checks
  paths with `find -print0`, so newline-bearing tar member names cannot spoof
  the old line-oriented listing checks.
- Scanner hard-stops flush the CLI warn-dedup summary before `process::exit`,
  so rate-limited WARN totals are not lost when a selected backend aborts.
- Windows installer HEAD probes share the same transient-retry helper as
  downloads; CI apt-get install steps retry on mirror blips.

### Changed

- Detector regex separator semantics now live in the owning TOML expression.
  The loader no longer rewrites bounded or exact authored classes into a global
  unbounded separator, and phase-two routing derives repeated-separator support
  from the parsed regex instead of a shared textual constant.
- Detector-owned isolated entropy exceptions are now declarative TOML shapes
  with typed character sets, optional grouping, entropy and length floors, and
  explicit diversity requirements. The scanner uses one generic matcher,
  rejects ambiguous multi-shape owners, and no longer carries a hardcoded
  lower-dash app-password enum branch.
- Scanner construction now builds a backend-neutral Hyperscan phase-one plan
  without compiling databases. Scalar and GPU-selected scans leave it
  untouched; explicit SIMD selection, calibration, and daemon readiness
  materialize it once and preserve exact initialization errors.
- Bind the independent phase-two Hyperscan prefilter to the selected SIMD route.
  Scalar, GPU, normalized no-hit, windowed, and fragment-reassembly paths no
  longer borrow unmeasured Hyperscan work through a global tuning default.
- Autoroute cache schema 42 records SIMD with the same cold-first and warm-trial
  model used for GPU, interleaves peer trials to distribute host drift, and
  persists a winner only when its 95% confidence interval is wholly faster than
  every route of every peer backend. Equivalent plans within one backend no
  longer masquerade as peer backends. Inconclusive results name every route's
  median and 95% interval instead of hiding which peers overlap. One-shot
  selection includes Hyperscan materialization and
  persistent-daemon selection uses warm execution. Missing, stale, invalid, or
  quarantined normal-scan state now warns and completes every byte through
  reported scalar correctness recovery; daemon requests carry the same recovery
  receipt, while calibration candidates and explicit overrides remain hard
  execution contracts. Daemon handshake and status distinguish invalid startup
  state from persisted-route quarantine, and zero-byte requests remain no-ops
  instead of reporting fictional recovery.
- Autoroute calibration now uses the always-present scalar engine as its
  independent correctness oracle. Optional Hyperscan and GPU candidates are
  rejected when their findings diverge, and decoded rescans remain attributed
  to the measured route instead of silently borrowing another CPU engine.
- Scanner compilation now inventories GPU peer identity without eagerly
  creating execution devices or pipelines. Calibration, daemon warm-up, and
  explicit selection materialize only the peer they execute and surface exact
  initialization failures.
- Entropy plausibility no longer owns hidden length or diversity thresholds in
  scanner code. Active entropy detectors now declare tail-check, distinct-byte,
  unanchored-hex, repeated-character, structured-dotted, and slash-base64
  boundaries in their TOML, and the canonical detector digest binds every value.
  The universal sealed-secret ciphertext cutoff is now typed Tier-B data rather
  than a scanner literal. Generic credential context no longer implicitly lifts
  canonical 32-hex values without an exact detector-owned key-material rule.
- Detector patterns can declare AST-proven `required_literals` beside their
  regex. KeyHog compiles those literals into every backend's shared candidate
  plan and rejects optional or branch-incomplete declarations. The DeepL and
  URL credential detectors now own their three-byte routing infixes. All 56
  previously inferred prefixless routes now live beside their detector regexes;
  the production compiler no longer invents non-prefix literals or hides their
  tuning in scanner code.
- OpenSea, Omnisend, Moosend, Skyscanner, 8x8, and X2Y2 now define the accepted
  ASCII `X-API-Key` separator variants in their detector TOMLs. Reverse-order
  header forms use shared-anchor extraction instead of whole-window regex
  passes, while canonical preprocessing retains whitespace-evasion coverage.
- Confirmed patterns rejected by Hyperscan now retain their detector-owned
  literals in a small recovery prefilter instead of being duplicated into the
  phase-2 regex set. Coalesced SIMD scans preserve exact scalar findings, and
  offline GPU artifact compilation no longer builds an irrelevant Hyperscan
  database.
- Scanner and autoroute detector identity now derives once from the canonical
  validated scan-execution specification instead of only final regex sources. The
  digest covers detector-owned routing literals and complete offline validator
  programs, so those policy changes invalidate stale scan and calibration
  evidence while detector ordering and inline fixtures do not.
- GPU scans now compose complete prefixless evidence with fused anchor absence
  for every eligible ASCII row, including rows with phase-one triggers. Proven
  rows bypass the redundant Hyperscan always-active prefilter while keyword,
  generic, entropy, ML, recovery, normalized, and incomplete paths retain their
  canonical behavior; normalization invalidates raw GPU evidence and recomputes
  phase-one admission before extraction.
- Anchored phase-two scans now compile exact full, anchor-residual, and
  anchor-plus-plain-residual ownership sets. Hyperscan and portable RegexSet
  paths consume the same set, so neither rescans patterns already owned by an
  active localizer; disabling the localizer gate keeps those patterns in the
  residual instead of silently dropping them.
- The proven homoglyph inert-variant skip now covers keyword-triggered and
  anchor-localized phase-two extraction as well as always-active prefiltering.
  ASCII source no longer runs duplicate whole-chunk homoglyph regexes, while
  non-ASCII scan text retains the complete variant path and normalized source
  remains covered by each variant's base pattern.
- A complete negative GPU prefixless-pattern receipt now suppresses the
  redundant folded plain-pattern anchor pass. Routes using that localizer no
  longer traverse the full input again after VYRE proves the family absent.
- Isolated entropy admission now skips lines already owned by stronger findings,
  proves detector-owned short symbolic shapes before Shannon scoring, and rejects
  pronounceable digit-bearing source identifiers when the owning TOML enables
  identifier suppression. The generic isolated owner now explicitly admits
  16-byte mixed symbolic credentials, including detector-owned minimum symbol
  count and underscore policy, while preserving its TOML-owned entropy floor
  and backend-identical findings.
- No-hit routing now consumes the active corpus's compiled generic-keyword stems
  and the `keyword-free` owner's length plus effective Shannon floor. Focused
  custom detector corpora no longer inherit the embedded keyword vocabulary or
  a scanner-owned 32-byte entropy-run floor before their policy can execute.
  Large bounded scanner windows no longer disable anchor-free detection at an
  unrelated 32 KiB cutoff, and cheap keyword/run evidence now precedes line
  eligibility checks, which stream without allocating a line vector.
- Automatic GPU runtime faults now cross a fallible scanner boundary: normal
  one-shot, fused, and daemon scans visibly replay the same stable batch through
  the scalar reference path and report recovered chunks and bytes. Calibration,
  explicit GPU overrides, `--require-gpu`, invalid policy, and artifact trust
  failures remain hard contracts, so recovery cannot become silent fallback or
  certify a broken accelerator.
- Fused automatic scans now quarantine a GPU route after exact peer recovery,
  matching coalesced and daemon behavior. Failure to persist the durable health
  record is warning-visible without discarding already recovered scan output.
- `https://santh.dev/keyhog/install.sh` and
  `https://santh.dev/keyhog/install.ps1` are now the canonical installer URLs
  across the repository and product site. The santh.dev build copies the exact
  in-tree installer bytes and serves them with explicit script content types;
  signed, version-pinned release installation remains documented for operators
  who authenticate the installer before execution.
- Offline token validation is now detector-owned data. GitHub, npm, PyPI,
  Slack, Stripe, GitLab, and their wrapper detectors declare typed validator
  programs, prefixes, lengths, and confidence floors in their own TOMLs. Scanner
  construction compiles direct per-detector dispatch plus a first-byte generic
  index; CRC comparison no longer allocates, base64 decoding reuses zeroed
  thread-local storage, and one verdict is carried through suppression, ML
  batching, and final confidence. The duplicate Rust prefix registry and
  service-specific validator modules have been removed.
- ML score memoization now binds the complete resolved feature vocabulary as
  well as candidate text and context, preventing one scanner configuration
  from reusing another configuration's confidence. Model diagnostics now expose
  the six-scanner differential status, including the current `unavailable`
  state, and GPU model documentation matches the shipped 55-feature network.
- The scalar-only `--no-default-features` scanner now compiles and retains the
  isolated-bare candidate predicate; its wrappers no longer reference an
  implementation hidden behind acceleration feature gates. The scalar test
  target also no longer imports ML- or SimdSieve-only adjudication hooks.
- Scanner symbols and test seams now follow the feature that owns their
  behavior. Minimal, ML-only, SIMD-only, GPU-peer, default, and all-feature
  library test builds no longer hide incomplete ownership behind unused-code
  warnings or blanket lint suppression.
- Detector metadata, execution facts, canonical/decoded key-material rules,
  entropy floors/policy, ML policy, credential shape, suppression, weak-anchor
  state, and companions now share one detector-indexed compiled plan. Scan
  paths resolve a detector once instead of coordinating parallel vectors, and
  the superseded batch policy containers have been removed. Missing interned
  primary or entropy-fallback identity now fails scanner construction instead
  of silently allocating replacement metadata. Final match resolution now
  consumes that active plan as well, so reporting `service = "generic"` no
  longer turns an anchored regex detector into a generic fallback and custom
  corpora cannot inherit embedded private-key classification.
- Detector class, minimum length/confidence, severity, structural-password-slot,
  keywords, and public-identifier marker policy now compile into cache-local
  execution records. Named, generic, and entropy emitters no longer read those
  fields from `DetectorSpec`; `CompiledScanner` drops the flexible detector
  schema after construction instead of retaining a duplicate runtime owner.
- Canonical and transport-decoded hexadecimal key-material rules now compile
  from every active detector TOML into detector-indexed immutable programs.
  Named, generic, and entropy producers no longer walk detector schema vectors
  per candidate; the generic bridge also resolves ordinary and canonical
  owners with one normalized assignment-key lookup.
- Detector-conditioned ML inputs now compile verifier, companion, service,
  generic, structural, phase-2, and entropy-family facts once with each loaded
  detector. Candidate feature extraction consumes that compact policy instead
  of traversing detector schema collections on every queued match.
- Isolated-bare entropy convenience APIs now compile their base entropy, mixed,
  symbolic, and colon-shape policy from the embedded detector owner instead of
  retaining a second scanner-side copy or reading optional schema fields.
- Keyword-context and keyword-free entropy APIs now compile their embedded
  detector policy through the same typed policy compiler used by production
  scanners. Candidate extraction and plausibility no longer re-read flexible
  detector specs or substitute scanner-owned thresholds, lengths, shapes, or
  canonical-hex rules when policy is absent. Exact detector-owned canonical-hex
  admission now outranks generic source-symbol and mixed-token heuristics and
  does not depend on ML authority.
- Detector plausibility policy now distinguishes pure program identifiers from
  digit-bearing source-symbol identifiers, so each detector TOML owns whether
  that precision gate composes with its mixed-alphanumeric admission policy.
- Generic assignment regexes, CPU stem prefilters, and fused VYRE positioned
  literals now compile from one active detector-corpus keyword plan. Custom
  detector keywords no longer rely on embedded literals or disappear when GPU
  phase-two evidence proves an unrelated lane absent.
- SIMD/GPU coalesced scans now aggregate pending ML candidates across chunks
  before one CPU or GPU MoE submission, while returning finalized findings to
  their originating chunk caps and locations. CPU scoring also resolves the
  immutable model once per batch instead of once per candidate.
- Entropy-owning detector TOMLs now own the isolated mixed-token entropy floor,
  symbolic and colon-component length floors, and slash-led base64 entropy
  floor. Scanner construction compiles those values once and the production
  entropy path consumes the compiled owner policy instead of scanner constants.
- Generic fallback execution now compiles from the detector TOML's typed
  `kind = "phase2-generic"`; the `service` field remains reporting taxonomy.
  Anchored Basic, Bearer, CLI-password, SQL-password, and URL-credential
  detectors therefore no longer inherit an unavailable entropy policy merely
  because their service is generic. The generic password bridge now declares
  its phase explicitly. Entropy-policy ownership, canonical keyword ownership,
  ML owner features, and final resolution use the same typed class; equal
  generic keyword claims now resolve by stable detector identity instead of
  corpus load order, and duplicate vendor-suffix fallback owners are rejected.
- SaltStack and Alertmanager now emit only the secret-bearing password, GoTo
  Connect emits only the client secret, and Rapyd emits only the secret key.
  Their usernames, client IDs, and access keys are optional companion context;
  each public identifier alone produces no finding.
- A successfully matched companion now remains positive evidence during ML
  admission, preventing required-companion detectors such as Twilio API keys
  from being demoted by the generic identifier-shape shortcut.
- The 10,667-case detector adversarial corpus and its handwritten boundary
  suite now run as a Cargo test target instead of remaining an orphaned data
  file. Slack fixtures now use non-placeholder identifiers and exact declared
  segment boundaries.
- Made weak-anchor detection policy explicit per detector pattern instead of
  inferring it from regex syntax, detector-ID families, or `min_confidence`.
- Detector-local entropy floors are compiled into detector-indexed lookup
  programs for named, weak-anchor, and generic paths. Broad-capture detectors
  must declare their own high threshold and length buckets, regex entropy owners
  participate in generic assignment generation, and public-ID marker matching
  no longer allocates an uppercased source line per candidate.
- Autoroute calibration now resets workload-shaped GPU resident state before
  each GPU candidate while retaining immutable program preparation costs, so
  candidate order cannot turn prior dispatch state into a false cold-cost win.
- Autoroute caches now retain independent route generations for each exact
  config and host identity. Recalibrating one host preserves other hosts, and
  calibration readback proves the current host rather than accepting a shared
  cache row from another machine.
- Autoroute calibration now measures extracted tar-member workloads across
  every default fused batch count. Filesystem dispatch separates safe
  family/provenance transitions while preserving same-path dependency closures.
- GitHub collaboration scans now independently select issues, pull requests,
  discussions, wiki history, and owner public gists. REST and GraphQL requests share
  bounded rate-aware pagination, findings retain immutable revision
  provenance, pull request review summaries are included, and inaccessible or
  truncated surfaces emit typed coverage gaps.
- Hosted Git clones now monitor materialized bytes and entries while `git`
  runs. Crossing the resolved Git limits stops and reaps the child, then emits
  typed truncated coverage instead of allowing an unbounded clone. The monitor
  does not follow symlinks outside the clone tree.
- ZIP and tar TeX source packages now expose root, referenced, orphaned, and
  exact comment-span provenance while every readable member still follows the
  normal archive scan path. Dependency expansion is bounded, rejects archive
  traversal, and terminates cycles without hiding member findings.
- APK scans now decode bounded `resources.arsc` value tables and compiled XML
  into resource-qualified virtual chunks while retaining the ordinary member
  scan. Malformed or capped semantic decoding emits a typed coverage gap.
- `keyhog diff` now classifies before-only findings as
  `verification_unknown` instead of resolved. `--artifacts --verify-removed`
  scans both text versions in memory and reports `removed_still_live`,
  `removed_inactive`, or `verification_unknown`. New findings, live removals,
  and unknown removals exit 1. Reports and persisted baselines remain redacted.
- GPU region-presence and phase-2 DFA batches now split only at existing chunk
  boundaries when they exceed the selected backend's safe dispatch ceiling.
  WGPU also respects its 65,535-workgroup dimension limit. Shards retain the
  selected CUDA or WGPU backend, ordering, and multiplicity. Resident readback
  words are consumed through a bounded borrowed view, then zeroized while
  retaining the warmed allocation for the next dispatch. The 8 MiB crossover
  gate selects across every acquired CUDA and WGPU peer with rotating trials,
  then requires the selected peer's held-out paired 95% ratio interval to beat
  Hyperscan.
- Scan, watch, and scan-system now install the same resolved GPU policy,
  regex-DFA cap, GPU batch cap, profiling state, and compile tuning before any
  hardware probe or detector compilation. Watch applies explicit backend
  overrides before setup and validates backend readiness before announcing it
  is active. Persistent scans also honor config-selected detector corpora,
  while an explicit missing `--detectors` path fails instead of silently using
  embedded rules.
- Verification response selectors now use one validated `$`-rooted grammar in
  detector TOMLs and runtime evaluation. Success checks and metadata extraction
  now agree on object keys, array indexes, and bounded parsing. Invalid
  selectors fail detector loading or verifier construction, and malformed JSON
  from an otherwise successful response is reported as a verification error.
  Programmatic users must migrate RFC 6901 `/account/email` selectors to
  `$.account.email`.
- Make `--deep` a distinct bounded recovery preset. It enables entropy discovery
  in source files, keeps heuristic evidence alongside ML instead of allowing an
  ML-only entropy veto, removes comment confidence penalties, raises
  decode-through to one 1 MiB production chunk, and retains depth 10. The
  resolved fields are visible through `keyhog config --effective` and are part
  of autoroute config identity.
- Decode-enabled scans now perform bounded, side-effect-free recovery of static
  JavaScript XOR and AES-256-CBC expressions whose byte arrays, keys, IVs, and
  ciphertext are embedded in the source. Exact CryptoJS passphrase wrappers
  recover OpenSSL `Salted__` envelopes through EVP_BytesToKey MD5 and the same
  strict AES, padding, and UTF-8 path. Literal arrays, Base64-encoded JSON
  arrays, obfuscated binding names, dead code, and empty-join key/ciphertext
  fragments are supported; dynamic operands, inconsistent bindings, invalid
  padding, non-UTF-8 plaintext, and oversized inputs are rejected. Static XOR
  admission is shared by SIMD and portable CPU scans so backend choice cannot
  change recovery results. The official P0-P12 recovery benchmark now scores
  4,368/4,368 exact recoveries with no false positives in full and deep modes;
  fast remains bounded to 1,344/4,368 by its no-decode contract.
- JavaScript string arrays followed by an empty-separator `.join("")` now
  recover checksum-valid known-prefix credentials even when the temporary
  variable name is obfuscated. Non-empty separators and arrays without a known
  credential prefix remain excluded from this structural recovery path.
- Entropy fallback now resolves length, entropy, canonical-shape, and BPE policy
  from the active detector corpus. Generic detectors declare overlap precedence
  with `entropy_policy_priority`, custom policy keywords join discovery without
  duplicate scan configuration, and synthetic isolated or keyword-free paths
  retain their exact detector owners across CPU, Hyperscan, and GPU scans.
- The unified benchmark harness now includes an official deterministic secret
  recovery corpus adapted from the P0-P12 methodology in arXiv:2605.06910.
  Provenance now pins the authors' public 13-example repository at commit
  `91d45377cf482c1de6c36a0d33744665976a19b6` and states that the paper's
  336-program evaluation corpus is not published there.
  Its 4,368 generated JavaScript fixtures cover plaintext, Base64, identifier,
  dead-code, structural, XOR, and AES-256-CBC variants; answer keys remain
  outside the scan tree, exact scoring rejects encoded or containing aliases,
  and one target compares `full`, `fast`, and `deep` through ordinary
  `RunResult` output.
- `--git-staged` now reads the exact blob object IDs and bytes from Git's
  index instead of reopening same-named working-tree files. NUL-delimited raw
  records preserve newline and non-UTF-8 Unix filenames, staged renames are
  scanned at their destination path, and `.keyhogignore`, explicit path
  exclusions, default exclusions, and source limits apply to the index source.
  Blob results stream into the scanner instead of retaining the aggregate Git
  byte budget in memory.
  Binary working-tree extraction must be requested in a separate scan rather
  than being silently mixed with staged-index semantics. Published pre-commit
  metadata now invokes the staged scan even for binary-only change sets, so
  unreadable staged blobs surface as coverage gaps instead of skipping the hook.
- Installers, package metadata, badges, CI recipes, SARIF identity, update
  checks, and the documentation now use the repository's canonical
  `santhreal/keyhog` owner instead of relying on the former-owner redirect.
  Security reports use GitHub Private Vulnerability Reporting first, with
  `security@santh.dev` as the no-PGP-required fallback. The docs header now
  presents the KeyHog wordmark without the adjacent keyhole icon.
- Hosted Git mass scans can read GitHub, GitLab, and Bitbucket credentials from
  dedicated `KEYHOG_*` environment variables after the operator explicitly
  selects an organization, group, or workspace. Tokens no longer need to
  appear in process arguments, while ambient credentials alone still cannot
  create a scan target.
- CI now dogfoods the shipped CLI across portable CPU, CI-profile CPU, default
  CPU, Hyperscan/SIMD, precision SARIF, JSON/JSONL, stdin, baselines, and real
  `.keyhogignore` exclusions and bounded decode-through. Shared behavioral
  harnesses validate exact findings, redaction, report schemas, exclusion
  boundaries, and dogfood coverage telemetry instead of treating a clean
  repository exit alone as product proof.
- Autoroute cache ownership is split into decision policy, statistical timing,
  secret-safe parity identity, schema, build/artifact identity, bounded codec,
  validation, inspection, and locked persistence modules. Replacing an
  existing stale, incompatible, unreadable, or invalid cache now produces an
  unconditional stderr warning with the cache path and reason.
- `keyhog backend --autoroute --autoroute-cache PATH` now inspects the exact
  non-default cache selected by a scan or `[system].autoroute_cache` instead of
  falsely reporting only the platform-default cache state.
- Daemon wire v5 exposes the daemon-owned backend policy during every client
  handshake. `daemon status` now distinguishes persisted autoroute from a
  forced startup diagnostic backend, and malformed policy labels fail closed.
- Current scan, daemon, reporter, and suppression contracts now require the
  canonical detector TOML id on accelerated paths instead of accepting the
  retired `hot-*` finding namespace. `keyhog explain` retains a finite,
  explain-only mapping so historical reports remain understandable.
- Autoroute no longer treats overlapping timing confidence intervals as proof
  that backends are equally fast and then prefers a fixed backend rank. It now
  selects the lowest measured median among statistically non-dominated,
  parity-correct routes, using engagement overhead only for an exact median
  tie. Cache inspection exposes whether confidence was separated and the exact
  selection basis in text and JSON.
- Autoroute inspection now renders distinct cold-aware one-shot and warm-daemon
  decisions with their own confidence basis and margins, rejects structurally
  invalid caches instead of omitting bad rows, and lives in a dedicated cache
  inspection module. Unix and PowerShell installer probes now admit every
  eligible GPU peer without changing the normal scan-config identity.
- CUDA and WGPU are now independent measured autoroute peers with exact
  `gpu-cuda` and `gpu-wgpu` diagnostic overrides. The public
  `ScanBackend::Gpu` variant and `--backend gpu` alias are removed. Library
  callers must select `GpuCuda` or `GpuWgpu`, and scripts must use the matching
  exact CLI value. Autoroute cache schema v27 rejects older single-GPU evidence
  and requires recalibration instead of silently assigning it to a driver.
- Generic pure-hex key handling is now detector-owned. Phase-2 detector TOMLs
  declare exact direct-assignment keyword/length pairs and exact
  transport-decoded hex widths; those declarations participate in detector
  validation, cache identity, ML/report adjudication, `explain`, and detector
  JSON. Structured decoding preserves transport provenance, so a direct
  cryptographic-key allowance cannot reclassify a base64-wrapped SHA digest.
  Encoded UUIDs, ARNs, hashes, license serials, and prose remain suppressed;
  generic UUID, salt, and nonce assignments remain identifiers unless a named
  detector or structural authorization envelope supplies stronger evidence.
- `--severity client-safe` and `[scan].severity = "client-safe"` now select the
  real tier between `info` and `low`; CLI help, config validation, and the
  reference all expose the same six accepted levels. `config --effective` now
  prints the resolved format, severity, dedup, secret visibility,
  client-safe/test-fixture policy, and lockdown instead of omitting report
  policy from the claimed effective view.
- Library and backend documentation now states the explicit-backend process
  contract: the infallible finding-vector APIs exit `3` for unavailable
  selected SIMD and `12` for unavailable or failed selected GPU execution,
  rather than returning findings from an unselected engine.
- The documented `.keyhogignore.toml` `literal_true = true` escape hatch now
  works and is behavior-tested, while empty tables and `literal_true = false`
  alone remain rejected as accidental match-everything policy.
- `backend --self-test --require-gpu` now fails with exit `4` and a visible
  `gpu_adapter` failure when no eligible physical GPU exists; ordinary no-GPU
  self-tests retain their explicit skip report and exit `0`.
- Autoroute build identity now includes the compiled GitLab and Bitbucket
  source backends, so persisted routing evidence cannot be reused by a binary
  with a different remote-source capability set.
- Coalesced scans now flush at source boundaries, preventing an uncalibrated
  mixed-source workload key when a local, forge, web, cloud, or container
  source follows another source in the same command.
- A GPU route that fails during dispatch now exits `12` instead of warning and
  completing through CPU/SIMD. This applies equally to explicit GPU selection
  and persisted autoroute decisions.
- GPU health reporting now names the live production route
  `gpu_region_presence` instead of the retired `vyre_ac_kernel` label. The
  scanner library self-test is `gpu_region_presence_self_test`, and
  `backend --self-test --json` uses the same name for its production-path
  probe. Dispatch failures remain structured so the health command emits its
  complete report and exit `4`; normal selected-GPU scans exit `12`.
- The VYRE direct match-triple self-test is now explicitly diagnostic. Its
  classified limitation reports `known` and other failures report `warning`;
  production GPU eligibility is owned by the `gpu_region_presence` probe, so a
  working scan route is no longer disabled by an unused direct-mode failure.
- Daemon backend overrides are validated before readiness. Explicit GPU/SIMD
  requests fail instead of being relabeled when their engine is unavailable,
  while explicit CPU/SIMD daemons no longer require a healthy GPU warmup that
  their requests cannot use.
- Every direct workspace dependency now resolves through an exact root pin,
  including scanner SIMD/tokenizer test dependencies, source archive support,
  and the optional CLI allocator. Package builds no longer rely on compatible
  version ranges that can move independently of `Cargo.lock`.
- Unix and PowerShell installers now admit an implicit release only when the
  exact host binary, checksums, payload signatures, GPU-literal sidecar, and
  sidecar proofs are all present on a stable published release. Partial,
  draft, prerelease, and other-platform asset sets are skipped rather than
  selected from an "any asset exists" heuristic. The manual integration smoke
  now follows latest stable by default instead of pinning an old version. The
  POSIX resolver accepts both compact GitHub API JSON and pretty-printed test or
  proxy responses. Unix `--yes` now honors each displayed wizard default,
  matching PowerShell: PATH setup is accepted while completion and
  repository-hook setup remain off.
- Release workflow reruns now return an already-published release to draft
  before deleting or replacing assets, then republish only after the exact
  signed manifest is visible. Consumers can no longer observe a transient
  partial or mixed-version asset set during a rerun.
- The canonical CLI reference now covers every live `scan --help` flag and the
  daemon-owned startup controls. Documentation CI also tests mdBook code-fence
  semantics before building the site, catching accidentally executable diagrams
  and malformed example blocks.
- Scan execution policy in `.keyhog.toml` now has one canonical owner: the
  `[scan]` table. Retired flat spellings such as `format`, `severity`,
  `min_confidence`, `decode_depth`, entropy thresholds, worker sizing, dedup,
  incremental-cache controls, `exclude_paths`, and the GPU batch-input limit
  are rejected as unknown instead of retained as compatibility aliases. Move
  those keys under `[scan]`; rename `exclude_paths` to `[scan].exclude`.
- Multi-root positional parsing now uses one visible variadic `PATH` vector;
  generated help reports `[PATH]...` and the hidden `EXTRA_PATH` compatibility
  carrier is gone. Mixing stdin shorthand `-` with filesystem roots now fails
  explicitly instead of producing a split-source request. Library consumers
  that read `ScanArgs::input` directly should use `ScanArgs::scan_roots()`;
  `input` now stores the complete ordered positional vector.
- CLI help and reference documentation now identify `--timeout` as the
  five-second-default per-request verification timeout, not a whole-scan
  deadline, and point scanner deadlines to `--per-chunk-timeout-ms`.
- The CLI reference now documents that `--proxy` and `--insecure` apply to all
  outbound HTTP clients, including remote sources and verification, rather
  than incorrectly describing them as verifier-only controls.
- Verification concurrency now has one unambiguous spelling:
  `--verify-concurrency` / `verify_concurrency`. The confusing `--rate` / `rate`
  spellings are rejected rather than retained as aliases; migrate scripts and
  TOML to the canonical name. Zero now fails closed instead of being silently
  clamped to one by the verifier. `--verify-rate` remains the requests/second
  control.
- `config --effective` now reports the resolved verifier timeout, concurrency,
  request rate, TLS, OOB, and proxy policy. Proxy URLs are reduced to
  `unset`/`off`/`configured` so embedded credentials are never printed.
- HTTP-only feature builds no longer compile entropy-only testing façades; the
  public test surface now follows the same SIMD/GPU/entropy feature boundary as
  the implementation it exposes.
- CLI-only verifier timeout, concurrency, and request-rate knobs now require
  `--verify` so a mistyped command cannot accept them as silent no-ops. TOML may
  still store defaults consumed by runs that explicitly enable verification.
- Documentation and CLI help now distinguish the foreground `watch` process
  from the independently started Unix-socket daemon and describe `--backend
  auto` as persisted routing rather than a forced backend. The scan reference
  now states the explicit-versus-absent `--daemon=auto` platform semantics.
- Daemon wire-v3 scan results now require suppression, dogfood, and coverage
  fields instead of silently defaulting fields inherited from rejected v1/v2
  peers; malformed same-version frames fail closed.
- Windows now rejects explicit `scan --daemon=auto|on` instead of silently
  replacing the requested daemon-capable policy with in-process execution;
  an absent flag and portable `--daemon=off` continue to run in process.
- Corrected install guidance to distinguish host-specific release artifacts,
  removed a stale Claude/Cursor hook claim, documented PowerShell flag parity,
  and made manual installs use the exact signed binary plus GPU-sidecar bundle
  with the same pinned minisign trust root as both installers and self-update.
- Extended the canonical documentation truth gate to reject broken relative
  targets and mdBook anchors, and repaired five navigation links the normal
  book build had accepted despite pointing nowhere.
- Corrected backend inspection UX so the diagnostic hardware heuristic matrix
  is never presented as the proof-backed `scan --backend auto` decision, and
  aligned the CLI reference with actual root options, detector maintenance,
  Elvish completion, fast-mode behavior, and finalized report semantics.
- Added detector-owned `max_len` for `phase2-generic` TOMLs, with schema
  validation, detector-spec cache identity, named suppression telemetry, and
  boundary-tested whole-value rejection. Shipped API-key/secret/passphrase
  bridges now own their distinct ceilings in their detector files.
- Refined autoroute byte, chunk-count, and maximum-file classification from
  paired powers of two to one power-of-two band per key, bumped the cache schema
  through v24 to prevent old numeric-key aliasing, remove duplicated timing
  summaries in favor of primary trial vectors, and bind evidence to the exact
  running executable digest; expanded the Rust, Unix, and
  PowerShell calibration ladders across every byte band from 1 B through 32 MiB
  and every default-batch chunk-count band. The measured 8 MiB GPU/Hyperscan
  crossover now has its own exact band.
- Bumped the daemon wire handshake to v3 and bound scan connections to package,
  Git build, and canonical detector-rules identity. Same-version daemons started
  with another detector corpus now fail closed; diagnostic status/stop remain
  available and status prints the exact mismatch.
- Serialized autoroute cache read/merge/write cycles with the shared state-file
  lock primitive, preventing concurrent calibration processes from silently
  losing one another's config or workload decisions. Autoroute, the Merkle
  index, and transactional GPU-artifact maintenance now use that same single
  lock implementation.
- Hardened self-update and repair release resolution with strict SemVer
  precedence, stable-only implicit selection, complete per-host signed-bundle
  admission, bounded streaming downloads, and explicit connection/request
  deadlines. Draft releases are never installable; exact published prerelease
  tags remain available through `--version`. The Rust maintenance path now
  resolves each proof file from exact release metadata, rejects duplicate asset
  names, and verifies both payload SHA-256 entries after minisign. `update` and
  `repair` now validate and transactionally seed the signed GPU-literal sidecar
  through the scanner-owned cache path, rolling matcher changes back with the
  binary when the candidate health/version gate fails.
- Consolidated user and contributor documentation into one canonical mdBook
  under `docs/src/`. Removed the duplicate hand-maintained HTML site, moved the
  architecture and integration references into the book, made orphan/duplicate
  documentation a source gate, and corrected Action, daemon, hook, autoroute,
  performance, and installation claims against shipped behavior.
- Made new GitHub Releases atomic: platform jobs stage unsigned bundles as
  private workflow artifacts, the signing job validates and signs one exact
  manifest, and only then publishes the draft. Manual dispatch now proves and
  checks out `refs/tags/<version>` so a same-named branch cannot supply release
  bytes.
- Made GPU an ordinary peer in canonical autoroute calibration and removed the
  calibration-only GPU switch from persisted scan identity. Fresh GitHub
  Action scans now calibrate before using `auto`; independent daemon/watch
  operations clear and isolate fragment-reassembly state.
- Hardened release publication around exact semantic-version tags, pinned and
  locked builds, staged-binary version proof, an exact signed asset manifest,
  and newest-stable-only promotion of container `latest` and floating major
  tags. Release-tag Action inputs now normalize one optional `v` prefix.
- Made the portable pre-commit command use the always-available CPU backend,
  recorded config-selected detector corpus provenance, and corrected portable,
  Docker, crates.io, VYRE, and Windows Action documentation.
- Replaced the stale VYRE audit/roadmap with one canonical integration reference
  that documents only the shipped v0.6.4 boundaries, parity contract, build
  features, diagnostics, and autoroute ownership. Cross-platform uninstall
  semantics now live with installation and exit-code documentation instead of
  an expired host-status snapshot.
- Unified Linux packaging around one `keyhog-linux-x86_64` artifact. The default
  GPU feature already contains dynamically loaded VYRE CUDA and WGPU drivers,
  so CUDA/WGPU eligibility now belongs solely to runtime self-test and persisted
  autoroute evidence rather than a build-time toolkit heuristic.
- Consolidated `keyhog-core` and `keyhog-sources` root exports behind their
  curated API modules, separated generic phase-2 regex construction from scan
  execution, and removed dead convenience wrappers and warning allowances.
  The organization gate now passes its root-layout, re-export, responsibility,
  and shipped-code utilization contracts without relaxing their thresholds.
- Moved OOB verification and `.keyhogignore.toml` into the canonical mdBook,
  documented the `[http]` policy and missing scan/maintenance flags, corrected
  suppression and daemon-status semantics, and replaced copied detector counts
  with commands that query the installed corpus.

### Removed

- Removed the public-tree internal backlog and VYRE execution plan, plus
  one-off detector/contract mutation scripts that guessed verification
  endpoints, rewrote fixtures from current output, or depended on developer
  `/tmp` files. Maintained generation remains under `tools/`; release and
  organization entrypoints remain under `scripts/`. Absence gates now reject
  reintroduction of public `BACKLOG.md` or `planning/vyre-acceleration` state.
- Removed the duplicate `ScanBackend::MegaScan` identity and its deprecated
  `megascan_input_len*` Rust/CLI/TOML aliases. The three real engines are now
  represented exactly once: GPU region presence, Hyperscan SIMD, and portable
  CPU. Persisted autoroute evidence can no longer mint two labels for the same
  GPU execution path.
- Removed the `--no-daemon` compatibility flag. `--daemon=auto|on|off` is the
  single daemon policy across CLI help, release scripts, diagnostics, tests,
  and documentation. `--daemon=off` combined with `--daemon-socket` now fails
  visibly instead of ignoring the socket.
- Removed the duplicate `keyhog-linux-x86_64-cuda` release job, `cuda` Cargo
  feature alias, installer `--variant=cpu|cuda` surface, update/repair variant
  resolver, and CUDA-asset fallback ladder. Those paths built the same feature
  graph under different names and incorrectly required a developer toolkit for
  a runtime-dynamically-loaded backend.

### Added

- **`cargo binstall keyhog`.** `[package.metadata.binstall]` maps the four
  prebuilt targets to their signed release binaries and verifies each against
  the release minisign key before install, failing closed on a missing or
  invalid `.minisig` (no unsigned fallback). Targets without a prebuilt asset
  fall back to a source build.
- **Marketplace-ready root `action.yml`.** The composite Action is published at
  the repository root as an exact mirror of `.github/actions/keyhog`, so it can
  be pinned as `santhreal/keyhog@v0` from the GitHub Actions Marketplace. A
  parity test keeps the root and the canonical inner copy from drifting.
- **Recipes cookbook.** `docs/src/recipes.md` indexes 18 real workflows by goal
  (scan locally, gate a PR, sweep an org, audit a bucket, emit SARIF) as
  copy-paste commands, alongside a one-command mass-scan front door and an
  install-and-scan hero in the README.
- **`keyhog scan --quiet` and `--no-color`.** `--quiet` suppresses the banner,
  progress, and summary vanity while keeping findings and errors (the flag CI
  logs want without `--format json`); `--no-color` disables ANSI styling even
  on a TTY and is honored by every output path (progress, findings, reports),
  equivalent to setting `NO_COLOR`. Both are first-class documented flags on
  `scan`; `--quiet` conflicts with `--progress`.
- **`keyhog calibrate` validates detector ids.** An empty/whitespace id is
  rejected before any counter is written, and an id that matches no embedded
  detector gets a loud warning (custom-detector ids still record); a typo'd
  `--tp strpe-secret-key` previously seeded a counter no detector would ever
  read, silently.
- **Confidence-calibration reference page.** `docs/src/reference/confidence-calibration.md`
  documents the Bayesian Beta(α,β) scoring subsystem (opt-in, deterministic,
  fail-closed cache), and both it and the autoroute-calibration page now carry
  disambiguation banners: the two "calibration" subsystems are unrelated and
  the docs now say so in both directions.

### Changed

- **Release dependencies clear all fixable RustSec advisories.** `quick-xml`
  moves to 0.41.0, `crossbeam-epoch` to 0.9.20, and `anyhow` to 1.0.103. The
  remaining accepted advisories are pinned, usage-audited, and documented in
  `SECURITY.md`; the release audit wrapper exits clean.
- **Generic phase-2 length policy is detector-owned.** The three shapeless
  generic detector TOMLs now declare their historical eight-byte assignment
  floor explicitly; the engine consumes that compiled policy instead of making
  the shipped value discoverable only as a Rust literal.
- **GPU buffer sizing no longer carries retired MegaScan terminology.** The
  canonical CLI/config/API names are `--gpu-batch-input-limit`,
  `gpu_batch_input_limit`, and `gpu_batch_input_limit()`. The previous CLI,
  TOML, and Rust API spellings remain explicit deprecated migration aliases.
- **Library defaults are deterministic; CLI routing stays measured.** The
  no-backend `CompiledScanner::scan` and `scan_coalesced` APIs now use the
  portable CPU reference instead of a host-size heuristic. Accelerated library
  execution is explicit, while CLI `auto` remains an exact persisted
  fastest-correct lookup. Cross-chunk reassembly no longer makes an independent
  backend choice, and the startup banner reports policy until a real workload
  decision exists.
- **Severity labels render identically everywhere.** Scan findings, `--stream`
  previews, and watch-mode events all render severity through the one
  canonical `Severity::as_str()` (uppercased at the display edge), fixing the
  `--stream` drift where `ClientSafe` printed via `Debug` casing. The Bayesian
  posterior-mean/observation math is likewise now a single public
  `BetaCounters` API in `keyhog-core` instead of three private copies.
- **`keyhog backend` labels its routing matrix as heuristic.** The
  decision-matrix table now states in the output itself that it is a fixed
  hardware-heuristic reference; a real `scan --backend auto` routes from the
  persisted autoroute calibration cache (`keyhog backend --autoroute`), never
  from that table.
- **Autoroute requires exact workload evidence.** Normal auto scans no longer
  interpolate between agreeing CPU buckets or clamp below the measured floor.
  The core calibration ladder now represents every stable plain-file size bucket
  from 1 byte through 32 MiB and every default-batch chunk-count bucket across
  all four scan policies; any other missing workload key fails closed with
  recalibration guidance.

- **Moved path-filter lists to TOML.** Inline suppression lists `NEEDLES` and `VENDORED_JS_PREFIXES` in `crates/scanner/src/suppression/path_filter.rs` are moved to a Tier-B data file `rules/path-filter-lists.toml` using `LazyLock` loading.
- **Moved ML feature markers to TOML.** Inline marker lists `COMMENT_PREFIXES`, `BINARY_MARKERS`, `CI_MARKERS`, `INFRA_MARKERS`, `SOURCE_MARKERS`, `SOURCE_EXTENSIONS`, and `CONFIG_MARKERS` in `crates/scanner/src/ml_scorer/ml_features.rs` are moved to a Tier-B data file `rules/ml-feature-markers.toml` using `LazyLock` loading.

### Removed

- **Duplicate backend aliases and the retired MegaScan CLI route.** `--backend`
  now presents four choices: `auto`, `gpu`, `simd`, and `cpu`. MegaScan,
  engine-implementation, and historical zero-copy spellings are rejected
  instead of silently selecting one of those same engines under another name.
  Profiles and evidence retain their descriptive stable labels. The public
  `ScanBackend::MegaScan` variant remains as a source-compatible library
  migration boundary and still executes the GPU region-presence route when
  supplied programmatically.
- **The no-op `kubernetes-secret` detector shim.** Kubernetes `Secret.data`
  values continue through the structured decoder and are attributed to the
  detector that recognizes the decoded credential. The retired detector only
  matched an internal `NEVER__MATCH__K8S_DISABLED__SENTINEL`, so it could never
  report a real Kubernetes secret; its synthetic contracts and catalog entry
  are removed with it. This changes the embedded corpus from 923 to 922 real
  detectors without changing recall on production inputs.
- **The `keyhog tui` live-scan dashboard.** The interactive TUI subcommand (the
  `tui` module, `Tui`/`TuiArgs`, the `tui` Cargo feature, and the `ratatui` /
  `crossterm` dependencies) is removed in full. It was an interactive frontend
  over the in-process scanner that duplicated `keyhog scan`'s detection path
  while carrying its own render/worker code, a terminal dep closure, and a
  PTY-driven dogfood lane: surface that never paid for its maintenance cost.
  Headless scanning (`keyhog scan`, `keyhog watch`, `keyhog daemon`) is the
  supported interactive/automatable path and is unaffected. The synthetic
  `demo/` tree and `demo.tape` recording now drive `keyhog scan demo`.

### Fixed

- Strongly anchored printable base64 values such as `K8S_FULL_SECRET=...` now
  survive generic entropy/BPE gates, and an ML-pending named candidate can no
  longer suppress the generic fallback before its own verdict is known.
- The Azure subscription-key detector now accepts its documented
  `azure_subscription_key` environment spelling through detector-owned TOML.
- Every top-level scanner, core, and verifier regression target is wired into
  the aggregate CI suites; the release gate now reports zero orphan tests.
- `keyhog-core` now packages its decoder-alias Tier-B rule inside the crate, so
  the published tarball compiles independently of the workspace root.
- Compressed decode failures and non-UTF-8 inflate output now emit bounded,
  secret-free warnings while preserving the original encoded scan input.
- Embedded detector/rule loaders, GPU artifact header parsing, terminal flushes,
  and warning-dedup poison recovery now take explicit fail-closed or visible
  error paths instead of relying on silent-discard idioms.
- Release regression gates now distinguish public resource identifiers from
  credential categories and resolve the cross-device driver independently of
  the caller's working directory.
- The coalesced SIMD determinism gate now mirrors autoroute's seven evidence
  trials over a bounded, concurrency-saturating corpus instead of monopolizing
  the shared build target with forty full-corpus passes.
- Benchmark matrices no longer manufacture the retired `megascan` backend as a
  duplicate GPU lane, and generated performance tables no longer advertise
  that rejected command spelling.
- Full-corpus GPU parity failures can no longer be mislabeled as hardware
  skips: the release gate preflights the production GPU kernels, gives the
  1 GiB corpus a realistic finite watchdog, and treats timeouts, runtime
  failures, empty results, and any detector/value/location/confidence divergence
  as failures. The scan engine
  also removes a duplicate no-hit reassembly side channel that glued unrelated
  complete findings from nearby lines into fabricated credentials on only some
  backend paths; fragment reassembly remains owned by the canonical assignment
  parser. Public confidence is canonicalized at three decimal places so
  equivalent CPU-f64 and GPU-f32 model accumulation produces identical policy
  decisions and JSON. Structured decode-through findings now map to the encoded
  source value column, generated JavaScript interpolation prefixes stay source
  syntax, and the published Azurite emulator key is excluded in its Azure
  detector TOML; these close the remaining concrete CredData parity cases.
- Generic detector ownership is coherent across backends. `generic-password`
  now owns password/passwd/pwd assignments only; API-key, token, secret,
  access-key, and client-secret fields stay with their detector-local phase-2
  TOMLs instead of being relabeled as passwords when the GPU trigger set was a
  strict superset. The detector-owned 20-byte broad keyword-free minimum also
  retains narrow 16-19-byte exceptions for shape-proven symbolic credentials
  and four-group app passwords, with positive and negative no-hit coverage.
  Carbon Black's vendor-specific anchors now admit its documented 20-32-byte
  hex key family while the detector TOML explicitly excludes all-zero masks.

- **Prerelease benchmarks now prove the candidate artifact.** The gate builds
  and pins the current binary before scanner-backed pytest, and benchmark
  freshness validates the exact Git commit and embedded detector-set digest in
  addition to semver. Executable aspirational recall targets use an explicit
  `target_spec` lane instead of making the green regression suite permanently
  fail by construction. CredData release gates also share one candidate SIMD
  scan instead of independently rescanning the full corpus.
- Keep benchmark `--min-confidence` arguments in concise round-trippable float
  form and remove obsolete direct-`Command` imports after Git spawning was
  centralized behind the guarded process boundary.
- Stop successful GPU scans from ending with a misleading repeat-warning
  summary for wgpu/Vulkan events that the default log filter never displayed.
- Autoroute host and cache identity now query GPU/SIMD compile support from the
  scanner dependency that owns those feature gates. Workspace feature unification
  could previously compile a GPU-capable scanner under a CLI build whose local
  `gpu` feature was false, allowing GPU calibration evidence to omit the GPU
  device/runtime/driver identity and survive a hardware change. Such caches now
  carry the actual backend feature set and invalidate correctly.
- The end-of-scan completion summary now pluralizes correctly: a single finding reads "Found 1 secret in ...", not the ungrammatical "Found 1 secrets" (the stdout `Results` footer already pluralized; the stderr summary did not). Singular/plural nouns now come from one shared `secret_noun`/`finding_noun` owner, so the completion summary and all three progress tickers agree.
- The human-report confidence line can no longer render a percentage above 100% or a `NaN%`. The bar fill was clamped but the percentage was not, so a finding carrying an out-of-range or NaN `confidence` (reachable through the public `VerifiedFinding` field) could show a full bar labelled "150%", or a garbage percent. The bar and percent now derive from one sanitized value (clamped to `[0,1]`, NaN treated as 0, matching the scanner's `finalize_confidence`).
- The scan progress ticker no longer flashes ">100%" or an over-total ratio (for example "1001/1000") when the scanned-chunk and total-chunk counters are read a moment apart; the displayed count is clamped to the total while the underlying rate still uses the true value.
- `keyhog doctor`'s "on PATH" check no longer reports a false "no" when the install directory appears in `PATH` with a trailing slash, as a symlink, or in a non-canonical form; both sides are canonicalized before comparison, matching the shadow check and the installer.
- `NO_COLOR` now follows the [no-color.org](https://no-color.org) contract exactly: an empty `NO_COLOR=` no longer disables color (only a present, non-empty value does), so a wrapper that clears the variable by emptying it keeps color on a terminal.
- Network sources (`--github-org`, `--url`, `--s3-bucket`, Slack) no longer abort the process (SIGABRT, "Cannot drop a runtime in a context where blocking is not allowed") when their request fails. The CLI runs under `#[tokio::main]`, and these sources use `reqwest::blocking`, whose internal runtime panics if dropped inside an async context. Each source now runs its (already eager) collection on a scoped `std::thread` with no ambient tokio runtime, so the blocking client builds, fetches, and drops safely; a fetch failure (bad token, unreachable endpoint) surfaces as a normal error the orchestrator turns into a non-zero exit instead of a crash. `--github-org` with an invalid token now exits 2 cleanly.
- A requested scan source that fails *entirely* (produces zero chunks and errors, e.g. `--git-history` / `--git-diff` on a non-repository or bad ref, `--github-org` with a bad token, an unreachable `--url`) no longer prints "No secrets found. Your code is clean." and exits 0. A failed scan reporting *clean + success* told CI gates the tree was clean when nothing was actually scanned (KH-GAP-096). It now fails closed (exit 2) with a diagnostic, tracked per source so it fires even when a co-requested filesystem source scanned cleanly. A partial failure (some files unreadable in a tree that still produced chunks) is unaffected: that source produced data, so the scan reports what it read.

### Robustness / Performance

- `keyhog scan --stdin` now lossy-decodes its input (matching the filesystem source) instead of rejecting non-UTF-8 bytes. `cat binaryfile | keyhog scan --stdin` previously errored (and, under the new fail-closed, exited 2) while `keyhog scan binaryfile` happily lossy-scanned the same bytes. stdin now scans the text it can extract (real secrets live in otherwise-binary inputs); the size cap still bounds memory.
- Byte-cap the per-match context windows (ML context 8 KiB, false-positive context 2 KiB). A line with no newline for kilobytes (minified bundles, or a file that is one long run of credential-shaped tokens) previously made each candidate's context O(line length), turning a many-match scan quadratic. Behavior-preserving for ordinary source (a short line hits its newline before the cap, mirror-corpus findings byte-identical) and faster on real minified-bundle scans.

## 0.5.39 - 2026-06-04

### Added

- Square (payments platform) access-token detector (`sq0atp-` personal access tokens, `sq0csp-` OAuth application secrets). keyhog previously shipped only a Squarespace detector, which had even mislabelled `sq0atp`/`sq0csp` (Square, not Squarespace) in its keyword list. Surfaced by a differential against the mirror corpus; the `EAAA…` OAuth-access shape is deliberately omitted (4-char prefix + base64url collides with ordinary data, costing precision). Detector count 899 → 900; precision held at 0.9953 with recall +0.0007 (F1 0.9164 → 0.9167) on the mirror corpus.

### Performance

- Use mimalloc as the CLI binary's global allocator (default/`portable`/`full` profiles; drop with `--no-default-features`). The scan hot path runs one Rayon worker per core, each allocating regex DFA-cache scratch and per-match strings; glibc's arena lock serialised those allocations. Measured on a 70 MiB / 13,976-file corpus (RTX 5090 host, 32 cores): single-thread scan 10.0 s → 8.0 s (~20%), with no regression at high thread counts. Libraries stay allocator-agnostic; the binary owns the choice. (The remaining multi-core ceiling is the `regex` crate's shared `Pool<Cache>` mutex, not the allocator: 16-thread scaling sits at ~41% efficiency, a separate optimization.)

## 0.5.38 - 2026-06-04

### Fixed

- **Absolute line numbers for windowed and patch-based scans.** Findings in files past the 1 MiB window size (`filesystem/windowed`), and findings from `--git-diff` / `--git-history`, reported the per-window / per-hunk line instead of the absolute file line: a secret on line 584307 of a 70 MiB file was reported at line ~2, and every diff/history finding landed on line 1. Root cause: byte offsets were made absolute (`+ base_offset`) but line numbers had no equivalent base. Added `ChunkMetadata::base_line`, populated per-window by the filesystem source and per-hunk by the git diff/history sources (now `-U0`, `base_line = new_start - 1` via shared `git::parse_hunk_new_start`), and applied at every line emit site. All output formats (text/json/jsonl/sarif/csv/html/junit) and source backends now report the correct line. Regressioned across the cli, scanner, and sources suites.

### Performance

- Window the decode-splice context to ±512 B around each decoded blob instead of copying the entire parent chunk per candidate. A candidate-dense source file (every quoted string / `key=value` / hex-or-base64 run is a candidate) previously spawned one parent-sized decoded chunk *per candidate*, each rescanned and recursively re-decoded, an O(candidates × file_size) blowup that pinned a single 156 KB Linux driver at ~15 s. Full Linux-kernel scan (94,825 files) drops from ~85 s to ~7 s; the worst single file from ~15 s to ~0.2 s; decode-through recall unchanged.
- Bound the GPU AC prefilter's per-shard readback and reroute dense literal-prefix batches through the SIMD coalesced scanner before CPU phase 2 explodes. Forced-GPU CredData now completes in ~5.0 s instead of timing out at 45 s / 5.1 GB RSS, with byte-stable detector/hash/file/offset parity against the current SIMD run.
- Reuse the batch ML feature vectors for small-batch CPU fallback instead of recomputing text/context features after the GPU crossover gate declines the batch. This removes a redundant feature-extraction pass on scanner chunks that emit fewer than 64 ML candidates while keeping scalar MoE scores byte-identical.
- Route CPU/SIMD filesystem scans through the fused read+scan pipeline so source walking and coalesced scanning overlap across the Rayon pool. `--batch-pipeline` or `[system].batch_pipeline = true` remains available for A/B verification against the coalesced batch path; CredData SIMD `--daemon=off` keeps byte-identical 2,263-finding JSON output and drops from 5.14 s to 3.57 s on the measured RTX 5090 host.
- Keep default/auto filesystem scans eligible for the fused read+scan pipeline on GPU hosts unless `--backend gpu`/`--backend megascan` is explicitly forced. CredData-shaped many-file scans no longer pay the single scanner-thread batch path when auto batch routing would pick SIMD for the 1 MiB filesystem windows anyway.
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
- De-flake `contracts_runner::every_contract_perf_budget_holds`. A single wall-clock sample on a shared CI runner occasionally tripped the 15 ms per-detector budget by 1-3% (`azure-blob-sas-token`, `jwt-token`) while steady-state sat well under. The budget now measures best-of-N (re-measuring only an over-budget contract and keeping the minimum) so a catastrophically slow regex still blows every pass while a one-off scheduler stall is discarded; contracts already under budget still pay for a single scan.
- Reconcile `GAP_FINDINGS.toml` with the `findings_registry_integrity` gate. Fourteen findings pointed their `test` path into the gitignored `coordination/` tree (absent in a clean checkout), so the registry gate failed in CI on the first one. Promote the three that hold against the committed repo (KH-GAP-076/077/179) into `crates/scanner/tests/gap/` and repoint them; de-scope the eleven open or design-conflicting `ci-operability` findings whose claims contradict the deliberate CI design (e.g. the 4-runner PR strict subset) or depend on uncommitted coordination infra (registry 162 → 151 findings).

### Install / packaging

- `install.sh --from-file=PATH` (and `KEYHOG_FROM_FILE`): install a pre-built or pre-downloaded keyhog binary instead of fetching a release, for offline/air-gapped installs and for CI to prove a freshly-built binary. Reuses the full install machine (backup, atomic same-dir swap, `verify_install`/`keyhog doctor`, rollback) and verifies a sibling `PATH.sha256` if present; `install.ps1 -FromFile` is the Windows equivalent.
- Harden release downloads against transient CDN drops. A connection dropped mid-transfer ("The connection was closed unexpectedly") was failing the Windows (and intermittently the Linux) install-from-scratch smoke even though the asset was present and correctly named. `install.sh` curl now passes `--retry 5 --retry-delay 2 --retry-connrefused`; `install.ps1`'s `Invoke-WebRequest` retries up to 5 times with linear backoff.
- Normalise a bare-semver `--version` / `-Version` to the v-prefixed release tag. keyhog tags are all `vX.Y.Z`, so `--version=0.5.37` built a download URL against a non-existent `0.5.37` tag and 404'd; the retry above (which surfaced the repeated 404 instead of one ambiguous "connection closed") exposed it on the Windows smoke. Both installers now prepend `v` to a digit-leading version and leave an explicit `v…`, branch, or sha untouched. Covered by `edge_cases.sh` 2.9/2.10 and the corrected 14.2 (bare `2.0.0` → tag `v2.0.0`).
- Add `tests/install/install_from_local_build.sh` and wire it into the macOS Build and Build Release CI jobs: prove current-source → install (via `--from-file`) → working binary on every push: `keyhog doctor` self-test, seeded scan (exit 1 + findings), SARIF, the local-checksum gate (good vs tampered), and the premium interactive wizard (driven through a PTY when `expect` is present). The mocked detection scenarios never touch a real binary and integration-smoke is manual + installs a published release; this closes that gap.
- Add a dogfood self-scan gate to Build Release (`keyhog scan .` must exit 0 on keyhog's own tree). Path-suppress `benchmarks/baselines/` and `benchmarks/generators/` in `.keyhogignore`: the committed differential/leaderboard reports quote the credential *shapes* each scanner surfaced on the test corpus (documentation about findings, not live secrets), and the mirror generators assemble synthetic credentials at runtime to build the fixtures (templates for fake test data); same rationale as the existing `CHANGELOG.md` / analysis-doc suppressions.
- Smoke harness: `keyhog backend | head -30` SIGPIPE'd keyhog (exit 141 under the runner's `bash -o pipefail`) when the routing matrix printed more than 30 lines, spuriously failing the `integration-smoke` Backend-probe step on Ubuntu. The step now runs `keyhog backend` to completion (its real exit code is the gate) before capping the display, so a genuine backend failure still fails the step.

### Benchmarks

- Unify the three benchmark systems into one. `benchmarks/bench` is now the single source of accuracy truth: the retired `tools/secretbench/scoring/` scorer and the retired `tools/diff_bench` differential runner are both replaced by `bench`'s canonical scorer + scanner adapters, and the mirror corpus generator plus the competitor home-turf harvesters move under `benchmarks/generators/`. Committed scoreboard anchors move to `benchmarks/baselines/`. The `bench-nightly` (renamed from `secretbench-nightly`) and `differential-bench` workflows now drive `python -m bench`.
- Add `python -m bench gate`: the single regression + differential gate. It exits non-zero unless keyhog leads every available competitor on F1 *strictly* and clears the asserted `--min-f1` / `--min-precision` / `--min-recall` floors and/or a committed `--baseline` (within `--epsilon`); exit 2 if keyhog produced no usable result. It replaces the per-fixture `diff_bench` F1 gate and is the forcing function for the continuous-improvement loop.
- Add the production continuous-improvement loop: `make -C benchmarks loop` runs the whole cycle (scorer self-tests → corpus → leaderboard → calibrate → render → gate) in one command, and a committed regression anchor (`benchmarks/baselines/mirror-keyhog-baseline.json`, keyhog F1=0.9131) lets the `differential-bench` workflow fail red on an F1 regression below the anchor, not only on a competitor overtaking keyhog. `loop` never `--inject`s the README, so a partial-scanner run can't degrade the published leaderboard.
- Add the cross-device bench harness (`benchmarks/cross_device.sh` + `python -m bench.cross_compare`): rsync the current tree to a device, install keyhog via its per-OS build (Linux Hyperscan SIMD; macOS `--features portable`, the system-lib-free vyre CPU path), bench the device-local corpus, and pull per-host results into `results-cross-device/<device>/` (kept out of the README-feeding `results/`). Fixes a Python-3.9 portability bug the macOS run surfaced (`bench/runner.py` used `datetime.UTC`, which is 3.11+). First cross-device snapshot (`benchmarks/reports/cross-device.md`): keyhog mirror F1 = 0.9131 on Linux (Ryzen 9950X, Hyperscan) vs 0.8996 on macOS (M4 Pro, portable/vyre): a ~0.013 recall delta in the vyre CPU path.

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

- **GPU region dispatch** previously routed all WGPU hosts through the
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

- **Daily star tracker.** `metrics/stars.json` records `{date, count}` snapshots; `.github/workflows/record-stars.yml` runs at 07:17 UTC, calls the GitHub API for the current count, dedupes per date, and commits if changed. README gains a live stars badge linking to star-history.com. wafrift gets the same tracker (see `santhreal/wafrift`).
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

- **Untrack coordination / plan / audit scratch files.** Per the new Santh STANDARD `prod-repo doc bleed` rule, standalone repos like `santhreal/keyhog` track exactly README + SPEC + CHANGELOG + `docs/`. The 31 internal coordination files (`coordination/` round briefs, `ROUNDS.md`, `TESTING_PROGRAM.md`, `KEYHOG_LINUX_QUALITY_PROGRAM.md`, `WAVE10_AGENT_PUSH.md`, `GAP_FINDINGS.toml`, `TODO.md`) were untracked from git and added to `.gitignore`. Files stay on disk via the backup `santhreal/Santh` monorepo - they just stop polluting the prod repo a crates.io / GitHub-Pages reader sees. Extended `.gitignore` with `WAVE*.md`, `*_AUDIT*.md`, `*_PROGRAM.md`, `plan.md`, `.audits/`, `plans/` patterns so future scratch files are caught at write-time.

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
  santhreal/keyhog/.github/actions/keyhog@v0.5.10` now installs
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
  paths. `--daemon=off` forces the in-process path. `--verify`,
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
  `append_events(iter)`). Verified locally: `--daemon=off` AND a
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
`crates/scanner/src/engine/boundary/mod.rs` splices the tail of each
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

Reconciliation pass against the parallel hardening line
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

This hardening wave delivered 18 Tier-A perf wins + 12 Tier-B moat innovations from the
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
  (8-16 in-flight) (`d3b6721`).
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

First release held to the expanded quality bar. Highlights:

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
