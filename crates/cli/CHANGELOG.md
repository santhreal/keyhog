# Changelog

## 0.5.80 - 2026-08-17
- feat(guard): derive effective root GuardPolicyIdentity digests across .keyhogignore, .keyhogignore.toml, .keyhog.toml, and suppression files, transitioning active roots to StalePolicy and invalidating attestations upon policy modifications (Row 142).
- Benchmark corpus synthetic packs & representative test coverage (Row 162). Fixed AWS Access Key token shape in the built-in benchmark corpus template to match 20-character credential length (`AKIA` + 16 chars). Added integration tests verifying benchmark corpus structure, metadata, planted credential shapes, and synthetic execution pack finding parity invariants.

- bench(cli): add criterion benchmarks for CLI startup latency, git hook execution lifecycle, and guard status protocol roundtrips (Row 147).
- feat(guard): implement continuous guard transition feed / event log surface with causal attribution across registered roots (`keyhog guard feed`, `GuardFeed` protocol frame) (Row 146).
- feat(cli): enhance pass-gate terminal output craft with structured volume, blob counts, bytes scanned, and execution timing (Row 143).
- fix(daemon): filter out ignored and excluded paths (.git, target, node_modules, ignore_paths, default excludes) in guard filesystem watcher matching scan path semantics (Row 141).
- fix(daemon): filter out ignored and excluded paths (.git, target, node_modules, [scan].exclude, .gitignore, .keyhogignore, default excludes) in guard filesystem watcher matching scan path semantics with dynamic ignore matcher reloading (Row 141).
- feat(guard): offline guard status and list inspectability reading durable store from disk with optional root summary (Row 140).
- feat(cli): optimize startup execution path for informational commands with fast zero-allocation dispatch, deferred runtime initialization, and zero detector corpus parsing (Row 138).
- feat(installer): multi-dimensional artifact invalidation and regeneration across detector corpus changes, configuration updates, and calibration changes (Row 135).
- feat(installer): update recommendation parity and complete artifact generation on binary replacement (Row 134).
- feat(build): audit and enforce release binary symbol stripping and zero DWARF debuginfo bloat via Cargo.toml [profile.release] and profile divergence gates (Row 139).
- feat(installer): acceptance gate for clean install on empty cache with zero runtime compilations across all surfaces (Row 130).
- feat(artifacts): fail closed with EXIT_USER_ERROR and repair command on stale execution-pack identity inputs (Row 129).
- feat(hook): utilize prepared execution pack in pre-commit hook run for zero runtime compilations and sub-second execution (Row 145).
- feat(gates): consolidate structural assertions into unified workspace gates and eliminate duplicate per-crate gap tests (Row 149).
- fix(backend): GPU route explanation parity reporting compiled-in feature state when GPU hardware is physically present rather than false probe misses (Row 156).
- feat(compiler): install-time compilation and zero scan invocation for small compilers across entropy, assignment keywords, and detector metadata (Row 128).
- feat(cache): load-only scan execution and zero compilation fallback on prepared artifact caches (Row 127).
- feat(installer): unified installed artifact registry connecting installer production, updater regeneration, and scan loading (Row 126).
- feat(profile): compile surface runtime counters across all 13 compiler surfaces (Row 125).
- fix(cli): eliminate noisy internal execution-pack fallback warning on clean scan passes and enforce unpolluted structured output (Row 144).
- feat(cli): fail closed on in-process detector compilation during scan; execution packs must be prepared via keyhog install or update, with --developer-compile-embedded-detectors available as a hidden developer escape hatch (Row 124).
- feat(gates): validate allowlists across reality and enforce meta-gate audit against unvalidated bypasses (Row 137).
- feat(profile): directional queue attribution distinguishing producer backpressure from consumer starvation (Row 133).
- feat(daemon): filesystem authority probe and default periodic scrub for unauthoritative filesystems (Row 132).
- feat(config): add guard configuration section to example TOML and docs truth (Row 131).
- feat(daemon): report active watcher backend, latency tier, and polling interval in guard status (Row 123).
- fix(daemon): attribute multi-path watcher events across all enclosing roots and trigger subtree reconciliation on pathless events (Row 121).
- fix(daemon): fail-closed reconciliation and root degradation on watcher channel disconnection (Row 120).
- feat(cli): 3-layer configuration governance and runtime metadata enumeration for Tier-A operational performance constants (Row 113).
- feat(cli): single canonical owner of byte size parsing across CLI, daemon, and config (Row 112).
- fix(profile): wire queue depth tracking, blocked wait attribution, and per-worker blocked time across fused and coalesced dispatch pipelines (Row 107).
- test(cli): assert incremental Merkle cache detection across four adversarial change kinds and verify interrupt recovery without state corruption (`incremental_rescan_reports_unchanged_secret`, `sigint_mid_scan_exits_130`).
- test(cli): enforce exit code totality through real binary execution across all scan-reachable codes and assert corrective action guidance on error enum variants (`regression_exit_code_matrix`).
- fix(daemon): wrap daemon request dispatch and filesystem drain in `catch_unwind` isolation boundaries under shipped `panic = "unwind"` release profile, preventing server crash on internal request panics.
- feat(cache): hook detector plan save operations into `keyhog_scanner::evict_cache_dir_with_policy` using `CacheKind::DetectorPlans`.
- Include known reason and repair command in daemon warm-route errors and startup banner instead of hiding them behind a generic fallback. Apply the same fix to the daemon status command. Make is_work_request exhaustive so adding a new Request variant causes a compile error. Add regression tests pinning daemon server pure-function behaviors before modularization.
- Removed `keyhog update` and `keyhog repair`, and the download, signature-verification, asset-selection, self-replace, backup/rollback, and orphan-reaping code behind them. They installed from a signed binary-asset release channel that no workflow produces; because each searched backward for a release that still carried a complete bundle, the dead channel installed a 33-version-stale binary instead of failing. Update and repair with `cargo install --locked --force keyhog`. `EXIT_REPAIR_FAILED` and `EXIT_UPDATE_AVAILABLE` are gone; exit 4 is now produced by `doctor` and `backend --self-test` only.
- Exit code 10 now means exactly one thing, a live credential confirmed by `scan --verify`. Its second meaning, a newer release found by `update --check`, went with the retired channel. Exit code 4 drops `repair` from its producer list.

## 0.5.79 - 2026-08-16

- ci(release): fallback token and sync floating major tag on release.
- test(daemon): add 30 regression tests encoding daemon server pure-function behaviors and file-type label coverage.

## 0.5.78 - 2026-08-16

- fix(scanner): gate expand_triggered_patterns independently of decode feature.

## 0.5.77 - 2026-08-16

- fix(ci): format scan_postprocess, update dogfood hashes for doc fixtures, and bump action version.

## 0.5.76 - 2026-08-16

- fix(core): rerun build script on GITHUB_SHA changes to prevent stale git hash in CI cache.

## 0.5.75 - 2026-08-14

- Added default and paranoid evidence exit policies. Default blocks `likely` and `confirmed`; paranoid also blocks `review`, without hiding non-blocking findings. Baseline schema 2 stores required evidence and secret-safe candidate provenance and rejects v1 and the removed `status` alias. Daemon wire 15 carries exact evidence plus staged-guard blocking counts, preserving one-shot, daemon, and guard exit semantics.
- `explain` renders typed detector semantic policies and labels omitted capture and anchor roles as compatibility defaults. Autoroute rejects prior detector-corpus identities with a detector digest mismatch and directs `keyhog calibrate-autoroute`.
- Detector parse-cache writes and hits reapply the selected corpus schema's validation rules. Schema-5 per-pattern evidence cannot be bypassed by a cache hit, and legacy schema semantics remain valid.
- Added `keyhog triage` with bounded redacted input, the 16-hex active detector digest and authoritative scanner provenance, distinct create-new runtime-suppression and pattern-feedback outputs, typed scopes, and fail-closed path handling. Unix reads, creates, and cleanup resolve through held no-follow parent descriptors; Windows fails closed until equivalent reparse-point-safe held-handle I/O is available.
- Merge remote-tracking branch 'origin/main'.
- Action autoroute calibration now probes published scanners before passing `--evidence-policy`, matching the scan runner's paranoid-only legacy migration. Scanner-thread panics mark report metadata partial so exit-11 receipts remain internally consistent.
- Staged-guard profiling counts one authenticated blob payload once across path aliases while retaining one source-context scan per alias.

## 0.5.74 - 2026-08-14

- fix(release): ignore Marketplace-only tags.

## 0.5.73 - 2026-08-14

- fix(release): preflight registry dependencies.

## 0.5.72 - 2026-08-13

- Release tags now publish: the bump job dispatches the crates.io publish for the tag it created, and that job creates the tag's GitHub Release from its changelog section. A tag pushed with the workflow token raises no push event, so tags v0.5.51 through v0.5.71 were never published.

## 0.5.71 - 2026-08-13

- Warm incremental scans now skip backend routing and scanner dispatch startup when source acquisition emits no changed chunks. Trusted clean-file Merkle hits remain complete coverage, while changed workloads retain the same bounded fused and coalesced batch paths.
- Daemon responses now serialize directly into the bounded transport frame. This removes the second full response-body allocation and copy while preserving exact JSON bytes, length prefixes, rollback on serialization failure, and the 64 MiB ceiling.

- Mass-daemon filesystem scans now persist spec-bound incremental state, skip unchanged clean files before read and dispatch, and rescan finding-producing files. Cache publication failures retain system-error exit `3`.
- Warm all-clean mass-daemon incremental scans now retain successful coverage by carrying metadata and content-confirmed Merkle skip counts in the terminal response.
- Daemon-local mass filesystem scans now stream bounded batch responses after one drain request, eliminating per-batch client request round trips while preserving response bounds, ordering, coverage, and execution receipts. The incompatible request/response cardinality moves the daemon wire protocol to v14.
- `--reader-threads` now defaults to one direct filesystem reader instead of a scan-pool-derived crew. Explicit values above one retain deterministic ordered reassembly.
- Daemon guard and bounded batch dispatch now propagate authenticated ordered GPU selections into the shared scanner boundary, restoring GPU-feature builds and preserving multi-device route ownership.
- Autoroute help and operator documentation now describe deterministic dead-heat resolution and fail-closed invalid-state behavior instead of claiming overlapping timings always fail or that missing evidence silently recovers through scalar execution.
- Autoroute cache schema v57 distinguishes runtime-compiled GPU programs from installed GPU sidecars. Standalone release binaries can persist authenticated GPU calibration without weakening manifest binding for installed artifacts.
- `keyhog backend --autoroute --json` now exposes the active GPU artifact binding and complete authenticated ordered-device route bodies.
- Windows keeps the `keyhog guard` command visible but returns an explicit unsupported-platform error without compiling the Unix-only daemon client.

- Expose confirmed_companion_gate on [tuning] and resolved/autoroute config identity (default on), so operators can disable the mid-literal confirmed-pass skip the same way as confirmed_suffix_gate.
- Cold one-shot and incremental scans now reuse a persisted MatcherArtifact of the eager compiled matcher graph across process invocations (format v4), with CacheId hit/miss/invalidation in profile output, fail-closed identity checks, soft-fail when cache prep fails, and --lockdown disabling the cache.
- 39 process-safe scanner test files are wired into the all_tests aggregator. Process-global decoder-registry and allocation targets plus the RSS-sensitive execution-pack mapping contract run in isolated CI processes. The recall_locks_wired.py gate is widened from checking only regression_*.rs to checking all top-level test files. CI workflow duplication is eliminated by extracting composite actions for workspace repair and Vectorscan install. All workspace compile warnings are fixed (zero warnings from cargo check --workspace).

- Corrected operator-visible help text and docs for five flags whose descriptions diverged from the implementation: --ml-threshold (applies to all findings, not just ML), --fast (also disables ML scoring), --oob-timeout (upper bound is max(value, 120s), not the value alone), --dogfood (credentials are redacted with prefix and suffix, not prefix only), and exit-code 3 (autoroute-cache persist failure applies when no findings are reported, not when findings exist). Updated the workspace authors contract test to match the binding identity.
- Preserve scanner-materialization context on installed execution-pack compile failures, and remove the unused record_matcher_artifact_pack_hit helper that contradicted CLI profile attribution policy.
- Autoroute calibration times candidates on the route-neutral phase-1 plan (no CPU trigger prefill on the clock); production still fills hints after CpuFallback selection so backend comparison stays fair.
- Autoroute CpuFallback selections now fill deferred CPU trigger hints on the route-neutral phase-1 plan so production automatic scans reuse them.

## 0.5.70 - 2026-08-10

- fix(profile): fail-closed overlapping allocation session peaks.

## 0.5.69 - 2026-08-10

- `keyhog scan --access-targets` reports the resource each credential opens: account, tenant, endpoint, database, or resource. A finding says where a credential is, not what it reaches, and the address is usually next to the credential where no detector can see it, because a companion regex is bounded to a few lines and captures the other half of the credential rather than the resource. Providers live in Tier-B `crates/core/data/access-targets.toml`, so adding one is a data edit. Off by default: with the flag absent the report has no `access_targets` key and findings are byte-identical. With it, `--format json-envelope` gains an `access_targets` object and the envelope schema minor moves 9 to 10, which is additive and readable by any consumer accepting a minor under major 1. Values are addresses only, never authenticators: connection-string rules skip userinfo, a rule may not capture the whole match, and any candidate whose digest matches a credential in the same report is dropped. Coverage is explicit, so an empty target list is never mistaken for `this credential opens nothing`: a finding from git history, a container layer, stdin, an unreadable path, a decoded or windowed view, or a file past the index cap is counted in `coverage.gaps` with a named reason and `complete` goes false. Separately, `keyhog detectors --mechanisms` prints which recovery mechanisms each detector declares (regex, keywords, structure, entropy, BPE, decode, companions, relations, verification, suppression, source admission), derived from detector TOML with the field that proves each one, and reports a mechanism KeyHog cannot yet express as unavailable with the reason rather than omitting it. It does not scan.
- Make `--profile` answer the questions a slow scan raises instead of reporting spans and leaving the conclusion to the reader. Six families are measured now. Memory: peak resident from the kernel high water, the engine-init floor taken on entry to scanning, input-driven resident as peak minus floor, amplification, per-scanner-thread resident, and allocation volume owned per stage. Parallelism: per-worker busy and blocked time from outermost spans only so nesting never double-counts, idle against pool capacity, achieved speedup as process CPU over wall, an Amdahl ceiling from measured serial work, and time inside instrumented regions while not on CPU, which is where a large pool loses speedup without going idle. Serial phases: per-stage wall windows giving average concurrency, plus an exclusivity measure separating a real barrier from an inclusive wrapper whose children are the parallel work. Throughput: MiB/s and files/s overall, per phase and per micro-function. Attribution: cost per call, per file, per byte, per detector family and per backend. Cache and reuse: hit rates for autoroute decisions, calibration reuse, incremental unchanged-skips, matcher artifacts and verifier results, through one CacheId vocabulary. Retry attempts are counted by cause and named as a finding, because a retry that fires is a failure that was not designed out. The first line of the summary is the conclusion, for example `bottleneck memory-floor 62.9 MiB of the 68.0 MiB peak (92.5%) is standing the engine up, not the input`. Verified on the mirror corpus, `crates/`, and a 300 MiB file: the profiler independently reproduces the engine-init floor, the per-scanner-thread scratch slope over a thread sweep, and resident amplification on a large file, all of which previously took `/usr/bin/time` and shell loops. This changes `--profile` stderr, which gains the summary above the existing span table, and the `--profile-out` document, which gains stage_concurrency, worker_occupancy, queue_depths, blocked_waits, caches, indexed_counters, retries and insight. Every new field carries a serde default so older records still decode, and the profile schema minor moves 2.7 to 2.8. Default scan output, findings and exit codes are unchanged. Every derived value is an integer in thousandths or parts per million, so two records diff exactly and an unchanged run cannot look changed. Recording stays free when profiling is off: the disabled path is one relaxed atomic load with no clock read.

- Daemon compatibility checks now derive worker topology without initializing GPU runtime libraries in client processes.
- Explicit CPU and SIMD daemons no longer initialize or retain GPU runtime libraries during startup.
- Execution-pack host identity checks no longer initialize GPU runtime libraries in short-lived clients.
- Explicit CPU and SIMD filesystem scans now retain at most four bounded fused batches per parallel wave.
- Installed scans now collect freed source-construction arenas at the source boundary and periodically reclaim idle mimalloc pages, reducing retained memory without changing finding order or coverage.
- Automatic daemon fallback now shares the acquired stdin payload and scans it through bounded overlapping windows, avoiding a second whole-input byte copy and a whole-input decoded retry buffer.
- Persistent daemons now configure at most eight physical-core Rayon workers before detector loading, preventing accidental logical-core pools and bounding resident worker-local caches.
- Large filesystem scans now retire explicit CPU and SIMD windows in bounded worker waves, share byte-identical source windows, and reuse verified repeated-window findings with rebased locations.
- Filesystem scans now coalesce tiny files up to the existing 1 MiB payload ceiling and execute them in worker-sized CPU and SIMD lanes, reducing per-file scheduler, channel, and Hyperscan scratch churn.
- GPU routes now execute detection only through VYRE-owned CUDA, Metal, and WGPU programs. KeyHog no longer ships the retired hand-written WGPU MoE shader, the `[tuning].gpu_moe_timeout_ms` key is removed, and GPU health reports expose only VYRE literal-set and production region-presence probes. The separately retired quantized VYRE confidence program is described below.
- Replace twenty-six near-identical inline-test gate files with one that scans the whole CLI source tree. Each of the old files hardcoded a single path, so they covered twenty-four files while the tree actually had twenty-five with inline test bodies, including the entire autoroute backend directory that no gate reached. Net 357 lines of duplicated test scaffolding removed and the blind spot closed.
- Builds now resolve VYRE 0.7.2 from one reviewed upstream commit instead of requiring a sibling source checkout, while keeping CUDA, native Metal, WGPU, and runtime crates on the same immutable identity.
- Out-of-band verification now overlaps its one-shot RSA session-key generation with scanning before collector registration.
- Persistent daemon, watch, and system-scan runtimes now compile from one shared detector corpus allocation instead of cloning every detector before scanner construction.
- Default daemon clients now use the detector identity compiled into the binary instead of parsing all embedded detector TOML solely for the compatibility handshake; explicit replacement corpora remain content-hashed.
- Watch finding lines now include a stable `sha256:<digest>` credential identity beside the redacted value, enabling redaction-safe parity and deduplication across events.

- Delete 235 source-grep shape tests across the five crate test trees. Each read a .rs file at runtime and asserted only substring presence or absence on that text, so they pinned how the source is spelled rather than what the scanner does; the project standard bans them. 107 test files went away entirely, 57 files lost individual tests, and every mod registration plus three Cargo [[test]] entries went with them. Two ambient-env gates (KEYHOG_THREADS, KEYHOG_DETECTORS) became four behavioural tests that drive the binary and read `config --effective` and `detectors --format json`. Each is a negative assertion, so each is paired with a positive case on the same output field, and both oracles were ablated to confirm the comparison discriminates: KEYHOG_THREADS=99 leaves `threads = auto` while --threads 3 moves the same line to 3, and KEYHOG_DETECTORS pointing at a one-detector directory leaves the corpus intact while --detectors on that directory reduces it to one. 23 source pins for network and filesystem security boundaries are kept deliberately: verifier_safety_contracts.rs, the DNS-pin and no-auto-decompression gates, the verifier proxy owner, the git safe-bin and no-follow-symlink gates, and the hosted-Git credential temp-file permission contract. That last pin was repointed at the whole hosted_git module after the module split moved the code it reads out of hosted_git.rs, which had silently made its negative assertions vacuous, and it now asserts an anchor first so it fails loudly rather than passing for free the next time the module is reorganised.

- A calibrated autoroute decision can be found again, and every scan now reports the cache hit rate. Calibrating without an explicit --autoroute-gpu wrote decisions under a resolved-config digest no scan would ever request, so the immediately following identical scan reported a config mismatch and completed through scalar correctness recovery; the digest hashed whether calibration excluded an eligible GPU, which is vacuous wherever no GPU candidate exists, and the host generation already carried that exactly. A calibration sample holding a chunk over the decode ceiling also discarded the whole sweep, because any nonzero scanner coverage counter rejected the trial, including the scalar reference trial before anything was compared; candidates are now compared against the reference coverage shape and refused only when they skipped more than it. Every automatic scan prints one stderr line naming hits, lookups, the typed miss cause and the one repair that fixes that cause, in every output mode including --format json -o FILE, which previously suppressed the routing summary entirely. Measured on repeated scans of the same corpus with the same binary and config: mirror, homefield and crates/ all move from 0 percent hit to 100 percent. Cache schema version moves 50 to 51, so an existing cache is superseded with a clear message rather than a config mismatch.
- Resolve a statistical dead heat in autoroute calibration instead of persisting no decision at all. Selection required one route's 95% interval to lie entirely below every peer's, and the only tie rule demanded exact nanosecond median equality, which never fired on real evidence. Overlapping timings therefore produced no route, so real trees persisted nothing and every later scan of them completed through scalar correctness recovery. A route now stays in contention unless a peer is proved faster; among survivors only those whose median falls inside the fastest route's own 95% upper bound are eligible, so a wide error bar cannot rescue a measurably worse median; that set is ordered by backend complexity. Strict separation still backs confidence_separated, so a dead heat reports confidence_separated false and a fourth selection_basis value, unseparated-dead-heat-lowest-complexity-backend, rather than posing as a proved win. JSON consumers matching on selection_basis must accept that fourth value.
- Refuse `--benchmark` combined with a scan target instead of silently discarding it. The flag runs KeyHog's own built-in corpus and exits; it never reads an operator-supplied target and never writes `--output`. Passing both was accepted, both were discarded, and the run reported success: `keyhog scan ./src --output report.json --benchmark` printed a throughput table, exited 0, and wrote no file, so in CI that line reads as a completed scan of ./src. The flag now conflicts with the positional PATH, `--path`, `--stdin` and `--output`, so the combination exits 2 naming the conflict. Two related report strings were also wrong rather than absent. The shared oversized-input coverage row read `exceeded --max-file-size` and advised raising that cap, but the counter behind it is raised by at least eleven caps including `--limit-git-blob-bytes` and the Docker and cloud object caps, so following the remedy left the input skipped; it now names the cap family and points at the per-cap warnings that name the exact flag. And the GCS token-forwarding consent notice fired when `--allow-gcs-token-forward` was parsed rather than when a token was forwarded, so the byte-equivalent `--source gcs:...` entry path printed nothing at all; the notice now lives at the point an ambient token is actually carried to a non-Google endpoint, so both entry paths behave identically.
- Named detectors can fire on binary-derived content again. Admission past the binary-strings noise gate required a declared `[detector.credential_shape]`, which 4 of 925 detector TOMLs carry, so 921 named detectors could never report a finding in an ELF, PE, Mach-O, wasm, static archive, shared object, archive member or container layer; the same tar.gz reported `aws-access-key` and silently dropped `slack-bot-token` purely because one TOML had the block. A match is now admitted on per-match structural proof, a declared shape or a span covering a whole lexical token, while generic, weak-anchor and free-form password-slot detectors stay suppressed, and a withheld match is counted as a `binary_strings_named_exclusions` coverage gap instead of vanishing. Expect new findings on compiled artifacts and container images that previously reported clean: a planted Slack token goes from 0 to 14 of 15 binary variants, and 249 MiB of real system ELF goes from 0 to 4 findings. Printable runs are also emitted in file order with every occurrence kept, replacing an alphabetical whole-input dedup that made two runs neighbours because they shared a prefix, and joined by a separator no whitespace, non-whitespace or dot class can cross, so a pattern can no longer bridge runs that were never adjacent.
- Surface chunks abandoned at their per-chunk deadline as a fail-class coverage gap. When `--per-chunk-timeout-ms` elapsed mid-chunk the scanner returned an empty or short match set for that chunk, and the abort was counted into scanner telemetry that nothing read, so a scan that abandoned every chunk still reported `scan_status: success` with an empty `coverage_gap_summary` and exit 0. Deadline aborts now surface as `scanner chunk abandoned at its per-chunk deadline` and mark the scan partial. Operator-visible change: a scan that hits the deadline exits 13 instead of 0 where it produced no findings, so raise or clear `--per-chunk-timeout-ms` rather than suppressing the exit code. Findings are never discarded; a run that covered some input reports its findings alongside the gap.
- Two coverage-gap rows named a cause that was not theirs. The exclusion row read `exclusion policy (.keyhogignore, --exclude-paths, or lock/minified/vendored defaults)`, but only the last of those three ever produced it: files removed by an operator's own .keyhogignore or --exclude-paths are not counted in that number at all, so a reader comparing the count against their ignore file got a figure that could never match. It now names the default policy specifically and states that user removals are not included. The archive row attributed every truncation to the filesystem decompression-bomb guard and its 4x --max-file-size budget, which stopped being true once the docker path gained three producers of the same event, so a container image refused by its own image-scoped unpack budget reported a cap that had nothing to do with it. It now names the cap family and points at the per-cap warnings that identify the exact one. Both are report text rather than behaviour, and both matter for the same reason the rest of this work does: a coverage row exists to tell an operator what was not looked at and why, and a row whose stated reason is wrong sends them to fix something that is not the problem.
- Persistent daemon and watch runtimes now compile the exact forced backend, so explicit SIMD startup owns a usable Hyperscan plan instead of a CPU-only scanner.
- Single-file and stdin daemon scans now report their out-of-process byte coverage without a contradictory zero-byte coverage gap.
- Report the decode-through coverage that `--decode-size-limit` declines, instead of quietly returning fewer findings. A chunk larger than the limit was denied decode-through with nothing recorded anywhere, while the neighbouring path that truncates decoder OUTPUT has always counted a gap, so the decline that skips the pass entirely was the silent one. Measured on the 2,399-file homefield corpus, `--decode-size-limit 64K` reported 1,623 findings against 2,239 at the 512 KiB default, 616 fewer, with an empty coverage_gap_summary and nothing on stderr. A denied chunk now records a WARN-class `scanner decode-through declined by --decode-size-limit` gap that names the flag in the structured coverage_gap_summary reason rather than only in terminal prose, so a CI wrapper reading the envelope gets the remedy. It stays at zero on an ordinary scan because no chunk reaches the compiled default. WARN rather than FAIL is deliberate: the raw bytes were examined and only a derived layer was skipped, which is the same class as the existing decode-truncation and structured-oversize rows. The counter was initially recorded only on the non-coalesced route, which made the gap backend-dependent (cpu reported one declined chunk where simd reported none, for byte-identical findings); it is now paired with the per-chunk scan event that every route calls, so the warning cannot disappear because autoroute picked a different backend.
- Daemon wire e2e helpers now start the daemon on the embedded detector corpus so warm identity matches the client's embedded detector-digest stamp.
- Installed scans stream authenticated detector plans from execution packs without decoding detector schemas, validate canonical matcher envelopes in one typed JSON pass, build prefix propagation through a flat arena trie instead of one hash table per trie node, co-locate each lazy regex's compiled cell and memoized source facts under one shared owner, share compiled signature strings with post-processing, and compile companion regexes and pattern-shape validator sets only when their evidence is first required. The entropy precision gate consumes an exact build-packed cl100k rank table without constructing the tokenizer's duplicate encoder, decoder, sorted-token, and thread-local regex graphs. Report-time remediation validation uses the build-generated detector ID index instead of reparsing the embedded detector corpus after a finding. Compiled detector plans share equal confidence policies across the detector table and keep sparse entropy, shape, and suppression policies in a compact indexed side table. Small detector-owned keyword vocabularies use compact flat byte tables instead of retaining one Aho-Corasick automaton per detector. Phase-two no-candidate gates are scoped to the active residual route, and phase-two anchor lookup tables share literal sources with the lazy runtime rows before the lookup tables are released. The large phase-two, confirmed shared-anchor, and confirmed suffix-gate automata materialize only for a non-empty batch, then their compiler arenas are purged before per-chunk scanning. Sparse files stream only allocated extents and report all-hole files as uncovered regions, stdin validates its byte cap through an anonymous spool before scanning bounded overlapping windows, and bounded stdin windows use a rendezvous-fed fused scan batch instead of accumulating the complete input. Empty stdin remains an explicit zero-byte coverage gap instead of reporting an unearned clean scan. Fused source boundaries default to rendezvous channels, homoglyph prescreening no longer materializes Unicode matchers for unrelated replacement characters, and the one-long-line benchmark now contains one delimited canary on one physical line. Large unbounded filesystem walks retain deterministic path order in one common-root byte slab and compact row/index tables instead of one allocated absolute path per file. The archive-symlink audit streams unbounded directory entries and skips duplicate regular-file metadata checks while no-follow read paths retain link-swap protection. Installed-pack benchmark captures bind detector runtime provenance per workload so catalogs that intentionally use multiple detector corpora remain exact.
- Explicit `--binary <file>` scans no longer also run the plain filesystem classifier, eliminating a contradictory binary-skip coverage gap after strings or sections were scanned.
- Scanning one large file cost roughly 3.8x its own size in peak memory, so a big enough file ran out of RAM. Three causes, all between read and scan. The filesystem reader collected EVERY window of a file into a Vec and sent nothing until the whole file was read, so a 300 MiB file held all ~343 of its 1 MiB windows live at once and the scan pool sat idle through the read; sampling /proc showed one thread accumulating 617 MB with 31 cores doing nothing. The windowed mmap never released pages it had already walked past. And every queue bound between the source and the scan workers counts chunks rather than bytes, which is ~128 KiB per batch on a small-file corpus and ~32 MiB on one big file, so the large-file regime carried over a gigabyte of queue headroom and split into only ~11 work units for 32 cores. The reader now streams each file's windows in byte-bounded parts (a small file is still exactly one send), the slicer returns each stride with MADV_DONTNEED as it leaves it behind, and the fused batch cut is byte-aware as well as count-aware. Isolating this change alone: one 300 MiB file 1,156,720 -> 772,972 KB peak and 4.79 -> 3.78 s; one 1 GiB file 3,131,944 -> 804,400 KB and 13.89 -> 9.76 s; the 300 x 1 MiB control also improved (862,896 -> 766,216 KB), so the cost was removed rather than moved. Total CPU-seconds are unchanged, so the wall gain is read/scan overlap that was not happening before. Peak memory is now flat in file size instead of proportional to it: +9% across a 3.5x size increase, against +171% before. Findings are byte-identical, and secrets planted at every one of the 21 ways a 20-byte credential can straddle a window cut are each still found exactly once with the correct absolute byte offset and line. NOTE: batches are now cut on bytes as well as chunk count, which changes the workload key autoroute measures against, so the compiled-in fused batch byte ceiling is hashed into the autoroute config digest. Any calibration persisted before this change reads as a config mismatch and is measured again on the next --autoroute-calibrate run. That is intended: replaying a decision timed under different batching would be measuring something else. No flag or output changes, and a scan that has never calibrated is unaffected.
- Stop reporting a stale binary-asset channel as current, and name the real Hyperscan library when an install fails. `keyhog update` compared the running build against the newest GitHub release asset and printed "already on the latest release" whenever nothing newer existed there, so a build newer than that channel, which every release since v0.5.47 is, was told it was up to date forever; it now distinguishes being on the newest asset from being ahead of a channel that stopped publishing, and names `cargo install --locked --force keyhog` in the second case. The installer's missing-library remediation matched the glob `*libhyperscan*`, but the published Linux binary declares `NEEDED libhs.so.5`, so a clean host got the loader error and no fix at all; it now matches the real SONAME plus the `libvectorscan` spelling, and any unrecognized library gets a generic lookup hint instead of dead-ending. The shipped artifact's runtime dependencies are also deterministic again: `lzma-sys` linked the system liblzma whenever `pkg_config` found one and vendored it otherwise, so the same commit produced binaries with or without `NEEDED liblzma.so.5` depending on the build host, and `xz2` is now pinned to a static link for 110,328 bytes.
- Source limits are exact at their boundary and honest about which ones a build can reach. A git output line whose content is exactly `--limit-git-line-bytes` is now scanned instead of refused: the cap counted the trailing newline, so an at-cap line produced a coverage gap for input that was inside the limit, and identical content was judged differently depending on whether it ended the stream. `keyhog config --effective` no longer prints a numeric value for a limit whose source backend is not compiled in; those rows now read `unavailable (requires the <feature> feature in this keyhog build)`, matching the flag that is absent from `scan --help` and the `.keyhog.toml` key that was already rejected. All 22 declared limits now have a CLI test proving each admits exactly its cap, refuses one byte or item more, and surfaces the refusal as a coverage gap rather than dropping input silently.
- Report ordering and duplicate-winner selection no longer depend on filesystem enumeration order. Matches are now sorted by a total key (severity, source, path, commit, line, offset, detector, credential digest) instead of by severity alone, which as a stable sort had silently inherited walk order for every equal-severity match.
- A credential inside a minified or vendored bundle is reachable again, and a dropped one is counted. Every finding whose path ended .min.js, .bundle.js or .min.css, or sat under node_modules/, site-packages/, wp-includes/, dist/assets/ and similar, was discarded before it reached the report. The drop was unconditional, left no trace on any surface, and no flag defeated it, so a live sk_live_ key that a build pipeline had inlined into app.min.js produced an empty report and exit 0. Build tooling inlines API keys into bundles routinely, which made this the one leak class KeyHog could not report at all while saying nothing was detected. Two changes. `--no-default-excludes` now disables this suppression as well as the walker skip, so the flag disables every default exclusion instead of only the one you could see. And a suppressed match is counted and reported as a `matches dropped by the vendored/minified path policy` coverage-gap row naming the count and the flag that recovers it. The row is WARN class, so an ordinary scan of a tree containing vendored code still exits 0. Measured on a wp-includes/config.php holding a live-shaped Stripe key: 88 bytes scanned, 0 findings and an empty coverage_gap_summary before, the same scan plus the counted row after, and exit 1 with the finding under `--no-default-excludes`.
- A scan that read zero bytes no longer reports as clean. A .keyhogignore containing `path:**` gave exit 0, scan_status success, zero bytes, zero chunks, an empty coverage_gap_summary, and the line `No secrets detected in the scanned files.` Every signal a consumer has said the tree was clean, and the scan had examined nothing at all. `--exclude-paths '**'`, an empty directory, an empty stdin stream, and a directory whose only entry is an unfollowed symlink all had the same shape. A scan that reads no source bytes now emits a FAIL-class `scan covered nothing` coverage-gap row and exits 13, and the text report states that the scan covered nothing instead of that nothing was detected. There are two such rows because the remedies differ: one for `no skip was counted` when nothing was there to read, and one for `every candidate was skipped by exclusion or skip policy` when policy hid it. THIS IS A USER-VISIBLE EXIT-CODE CHANGE. A target that legitimately holds nothing scannable moves from exit 0 to exit 13, including `keyhog scan --stdin` on an empty stream, an empty directory, a pure vendored tree, and a CI matrix partition with no files in its slice. That is intended: `git diff | keyhog scan --stdin` against the wrong base ref produces an empty diff, and reporting that as clean is the exact failure that makes mass scanning untrustworthy. Guard the producer, for example `[ -s changed.diff ]` before the pipe, rather than suppressing the exit code. There is deliberately no opt-out flag, because a flag that suppresses coverage failures would recreate the false affordance fixed alongside this. A scan that reads bytes and finds nothing is unaffected and still exits 0, and a scan that covered some input and failed on the rest still reports every finding it got alongside the gap, so exit 13 never means findings were discarded. Note that scan_status alone does not carry this: an ordinary git working-tree scan is already `partial` from its default-exclusion rows, so the usable signal is the FAIL/WARN class of the gap rows, which is what the exit code encodes.

## 0.5.68 - 2026-08-05

- Scanner source files freed of large co-located test suites.
- Reduced KeyHog-owned Rayon worker stack reservations from 8 MiB to the standard 2 MiB after moving scanner traversal to bounded iterative state.
- Keep verifier detector graphs, candidate queues, caches, HTTP clients, and OOB state absent unless live verification is enabled.
- Report a completed admission-plan recovery as `complete_after_recovery` when the protocol reports scanned bytes, instead of consulting unrelated process-global byte counters.
- Restore execution-pack signing-key, rollback, stale-stage, ambiguous-backup, and symlink cleanup regression coverage.
- Prove separate installations create distinct execution-pack signing keys through the installer-owned key path.
- Bind every GPU-capable autoroute decision to the verified installer-owned matcher manifest, while excluding unrelated lazy runtime-cache files from calibration identity.
- Require exactly seven positive, round-paired timing trials for every autoroute candidate.
- Keep autoroute cache validation regressions under the centralized CLI unit-test tree enforced by the source-layout gate.
- Document the chunk-lane scheduling threshold and require every accepted tuning key to remain present in the configuration reference.
- Version autoroute caches for authenticated ordered GPU device-set evidence. Calibration measures each required device and the complete route, while normal scans acquire that exact live set and dispatch its contiguous weighted shard ranges without runtime benchmarking.

## 0.5.67 - 2026-08-05

- Filesystem enumeration-order contract.

## 0.5.66 - 2026-08-04

- Whole-tree GPU guidance in the backends guide.

## 0.5.65 - 2026-08-04

- Actionable GPU refusal diagnostics.

## 0.5.64 - 2026-08-04

- README evidence panels remeasured against the current detector corpus.

## 0.5.63 - 2026-08-04

- Mailchimp datacenter key routing.

## 0.5.62 - 2026-08-04

- Routing literals for every prefixless detector pattern.

## 0.5.61 - 2026-08-04

- Character-class token anchoring for short vendor prefixes.

## 0.5.60 - 2026-08-04

- Token-boundary anchoring for short vendor prefixes.

## 0.5.59 - 2026-08-04

- Say what diverged when autoroute rejects a backend candidate. The message reported only that findings differed, which blocks the whole calibration and gives an operator nothing to act on; it now names how many records each side produced, how many were unique to each, and up to three of them by detector, file, line and offset. Every field shown is already redacted.

## 0.5.58 - 2026-08-04

- README evidence panels remeasured against the current binary.

## 0.5.57 - 2026-08-04

- Stop autoroute calibration from discarding a whole workload class over measurement noise. An execution plan now has to clear the other plan's confidence interval, not just win a paired test, before it beats it on the same backend; points that agree on the backend but split on the plan reconcile to the plan the binary was compiled with instead of producing no decision; and merging a point re-declares the reconciled route so the persisted cache matches its own evidence. Calibrating the mirror corpus went from persisting a decision on 4 of 10 identical runs to 12 of 12.

## 0.5.56 - 2026-08-04

- Scan many coalesced batches at once instead of one at a time. The batch pipeline's consumer was a single receive-then-scan loop whose only parallelism was inside one batch, so every batch boundary idled the machine; it now bridges the batch channel onto the global pool the way the fused pipeline already does. On this repository's sources the batch pipeline drops from 4.95 s to 2.43 s and gpu-cuda from 6.70 s to 3.52 s, and the report is byte-identical to the fused pipeline's.

- Let autoroute classify a batch of any size. The decoder sampling budget was enforced as a ceiling on the total sample instead of a budget for the residual above each chunk's floor, so a batch of more than roughly 341 chunks failed classification outright. The coalesced pipeline packs up to 4,096, which meant autoroute calibration could not run through --batch-pipeline on any real corpus, and so the GPU route, which runs only through that pipeline, could not be calibrated at all. A batch whose floors already fit keeps exactly the previous budget, so no persisted decision changes.

## 0.5.55 - 2026-08-04

- Idempotent source contract-test generator and a warning-free workspace build.

## 0.5.54 - 2026-08-04

- Check every `.keyhog.toml` key and table in the configuration reference against the real config schema, reading the accepted field list out of the schema itself rather than restating it, so a renamed or removed key fails the build instead of failing the reader with an unknown-key error.

- Correct the configuration reference, which advertised a `no_entropy_ml_scoring` key that has never existed. Writing it into `.keyhog.toml` fails closed as an unknown key; the knob is CLI-only.
- Let the configuration module's no-inline-tests gate accept the sanctioned `#[cfg(test)] #[path]` sibling-module hook, which the blanket attribute ban rejected even though the test code lives outside the source tree.

## 0.5.53 - 2026-08-04

- Include both published GitHub Action manifests in the release version transaction, so the minimum version they advertise cannot fall behind the workspace as it did for two releases.
- Track the accumulating batch's route class and chunk identities as chunks arrive instead of rescanning and rehashing the whole batch for every chunk. The coalesced pipeline's 4,096-chunk batches made that quadratic, which is why an explicit GPU backend measured slower than CPU while the accelerator sat idle.

## 0.5.52 - 2026-08-04

- Check every `keyhog` command in the README and the handbook against the compiled command model, so a documented subcommand or long flag that is renamed or removed fails the build instead of failing the reader who types it.

- Correct the system-wide triage example, which showed a `--exclude` flag `scan-system` does not have, and state the bound it actually applies: a total-bytes ceiling plus network filesystems skipped by default.

## 0.5.51 - 2026-08-04

- Assert JSON, JSONL, and SARIF stay completely parseable and ANSI-free across all sixteen hostile environment profiles, including CLICOLOR_FORCE, an unset HOME, an unwritable working directory, a missing TMPDIR, and a rejected backend request.

- Derive the subcommand help matrix from the compiled command model instead of a hand-kept list that had already drifted past `config` and `bloom-diagnostic`, and pin the advertised menu so a removal or rename stays a reviewed change.

- Fall back to the honest legacy identity gaps when a causal profile's detector, configuration, or source enrichment is absent, instead of panicking while rendering the report at the end of a completed scan.
- Run the 1,202-cell product-reliability matrix in CI and drive it on the portable scalar backend, so hostile-environment exit-code, output-format, and installer contracts can no longer rot unexecuted or fail closed on a Hyperscan-free build.
- Check the default-exclusion policy flag at each source factory call rather than at the first mention of a source name anywhere in the file, which reported a missing flag on a call that passes it.

## 0.5.50 - 2026-08-02

- Add low-overhead causal run profiling with fixed scanner stages, state transitions, process resource measurements, and explicit source and backend identity while keeping per-pattern diagnostics behind --perf-trace.
- Add `keyhog explain --compiled-plan` output for resolved companion and cross-detector evidence operations.
- Show detector-owned positive source-admission selectors in `keyhog explain`.
- Add `scan --github-all` as the concise complete-surface form of a GitHub collaboration scan while retaining independent surface selectors.

- Publish patch releases to crates.io through short-lived OIDC trusted publishing and upload a deterministic six-crate commit and lockfile integrity receipt without a long-lived registry token.

- Record scanner accelerator features from dependency-owned compile state so portable autoroute identities no longer claim unavailable GPU or SIMD backends.
- Bound scan-system metadata discovery by the remaining --space budget so small host-scan ceilings stop promptly and report partial coverage instead of traversing the entire filesystem first.
- Preserve valid `.keyhog.toml` detector-disable configurations by transitively removing detectors that require a disabled target and pruning inactive conflict or subsumption relations before scanner compilation.

## 0.5.49 - 2026-07-30

- A single resumable local or SSH command now refreshes benchmark evidence without invalidating candidate freshness, rebinds the exact canonical run-set after scoring, prepares every changelog and version surface, runs pre-tag gates with isolated full and ci-lean binary contracts, preserves exact Git path bytes, verifies the configured OpenPGP fingerprint before any tag push, and watches GitHub Pages, release assets, containers, and the six-crate crates.io publication chain.

- The README star viewer now uses a deterministic accessible SVG generated from repository-owned observations, records only real count transitions, handles same-day corrections and declines truthfully, writes atomically, and retries isolated metrics push races without depending on star-history.com.

## 0.5.48 - 2026-07-28

- Bind the CLI package and composite Action candidate to the exact validated
  release commit, signed SPDX dependency graph, and single post-release crate
  publication path.


## 0.5.47 - 2026-07-26

- Add the POSIX installer `--no-calibrate` override for deterministic
  explicit-backend automation while retaining signature, checksum, binary, and
  doctor verification.

## 0.5.46 - 2026-07-24

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
- Fail closed when autoroute evidence is missing, stale, invalid, incomplete, or
  quarantined. No scalar substitute is selected; affected batches remain
  unscanned and force non-success status with recalibration guidance.
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

## 0.5.45 - 2026-07-22

- Republish the CLI in the release chain whose signed asset publication
  addresses GitHub drafts by immutable release ID.

## 0.5.44 - 2026-07-22

- Republish the CLI in the corrected five-crate release chain after the
  Windows GPU literal artifact generator fix.

## 0.5.43 - 2026-07-22

- Compile the portable CLI on Windows by gating Unix daemon test seams, using
  the platform process-exit path, and importing drive constants from their
  generated windows-sys module.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep CLI orchestration, output modes, baseline filtering, and detector discovery behavior available for the 0.2 line.
