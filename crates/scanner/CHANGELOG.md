# Changelog


## 0.5.80 - 2026-08-17
- perf(scanner): optimize startup memory floor and scanner structure layouts (Row 153). Pack LazyRegexState flags into a single atomic byte, shrink CsrU32 to exact boxed slices, flatten GenericKeywordStemSet byte buckets, dynamically scale LRU thread-local caches, bound DashMap absence cache shards to 16, and box immutable compiled pattern slices.
- feat(scanner): instrument compile surface invocations and prepared artifact loads across 13 compile entrypoints (Row 125).
- feat(parallelism): unify scanner execution width with keyhog_profile host parallelism (Row 110/137).
- refactor(scanner): move rayon to dev-dependencies and replace internal usages with standard iterators (Row 119).
- feat(gpu): resident accelerator execution pool for GPU region dispatch concurrency across CLI and daemon (Row 118).
- perf(scanner): scratch buffer capacity retention under memory budget (Row 117).
- perf(scanner): backend-derived dispatch byte limits for GPU region batching (Row 116).
- perf(scanner): proportional scrub cost bounded to populated content bytes rather than reserved slot capacity (Row 115).
- feat(scanner): single canonical owner of window overlap and size constants shared across reader, stdin, and scanner (Row 111).
- feat(gpu): record positive upload and readback durations across all GPU dispatch modes to populate GpuUploadNs and GpuReadbackNs profile metrics.
- feat(gpu): migrate GPU region dispatch timing from ad-hoc `Instant` stderr `perf-trace` lines into `keyhog_profile` typed metrics and render structured dispatch split during profile dumps.
- fix(safety): enforce written `// SAFETY:` preconditions and release assertions across all `unsafe` blocks with `unsafe_guards.py` workspace gate.
- fix(profile): separate Stage::ScanPipeline container from leaf Stage::BackendDispatch to prevent container-duration distortion in bottleneck and cost tables.
- fix(runtime): enforce panic = "unwind" in release profile to enable catch_unwind GPU isolation boundaries and degradation in shipped release binaries.
- fix(gpu): lazy-scope GPU API initialization to only the selected scan backend route and eliminate redundant WGPU enumeration during CUDA and CPU scans.
- perf(gpu): eliminate intermediate host buffer copies and redundant scrubs on GPU region dispatch, enforcing <= 1 copy per dispatched byte with host data movement instrumentation.
- perf(gpu): short-circuit phase-2 GPU regex-DFA admission and eliminate redundant backend dispatch spans when catalog covers zero patterns.
- fix(router): eliminate inverted batch dominance heuristic in hardware probe backend selection and unify batch routing with measured threshold evaluation.
- feat(cache): implement unified cache eviction engine (`cache_eviction`) and `CacheKind` layout reconciliation across Hyperscan, detector plan, GPU program, and matcher artifact caches with stale lock reclamation.
- feat(cache): add `validate_and_tighten_matcher_artifact_cache_dir` to auto-repair loose default cache directory permissions to 0700 without disabling cache.
- fix(scanner): clamp decode-through window overlap to enforce strictly advancing window progress across UTF-8 scalar boundaries in release builds.
- style: format guard massive diff test and git sources modules.
- fix(detectors): resolve evasion gaps, required literal routing, and Unicode whitespace boundary handling across 8 detector specifications (`apple-push-notification-key`, `google-artifact-registry-key`, `near-api-credentials`, `netrc-password`, `twitter-ads-api-credentials`, `webex-access-token`, `wechat-api-credentials`, `wordpress-api-token`).
- test(scanner): consolidate per-detector regression execution into sequential full-coverage suite to prevent parallel runner memory exhaustion.

## 0.5.79 - 2026-08-16

- ci(release): fallback token and sync floating major tag on release.

## 0.5.78 - 2026-08-16

- fix(scanner): gate expand_triggered_patterns independently of decode feature.

## 0.5.77 - 2026-08-16

- fix(ci): format scan_postprocess, update dogfood hashes for doc fixtures, and bump action version.
- Intermediate decoded byte buffers in URL, Quoted-Printable, and MIME decoders are now wrapped in `Zeroizing` and zeroized on invalid escape and UTF-8 error exits before deallocation.
- Percent and Quoted-Printable escape detection and counting now use SIMD-accelerated `memchr` scanning to bypass intermediate allocations and line-view splitting on ASCII pass-through chunks without `%` or `=` characters.
- Public testing surface in `testing` exposes `url_decode_for_test` for direct URL percent-decode assertions.
- Standalone bounded, zeroizing RFC 4648 and Crockford Base32 byte-stream decoders (`base32_decode` and `crockford_base32_decode`) with const lookup tables are exported from `decode::base32` without modifying the default automated scan pipeline composition.
- Exact literal path and prefix/suffix suppression rules compile to direct string and set comparisons, bypassing regex engine construction on non-metacharacter patterns.
- Phase-two anchor and literal prefilter verification reuses candidate scratch buffers across sequential chunks, coalesces candidate collection under shared evaluation closures, evaluates portable gate prefix evidence lazily on first need per partition, and checks gateable batch prefix evidence before compiling RegexSet matchers.

## 0.5.76 - 2026-08-16

- Hex decoding now zeroizes intermediate decode buffers on malformed trailing characters or invalid hex byte sequences and validates 16-byte and 32-byte hex hashes using a stack buffer, eliminating heap allocations for candidate token validation.
- Decoded reverse-placeholder suppression now uses case-insensitive ASCII byte searching directly on candidate bytes, eliminating transient string reversal and uppercase allocations.
- Short-circuit decoded-match suppression checks in scan post-processing and preserve exact deduplication ordering.
- fix(core): rerun build script on GITHUB_SHA changes to prevent stale git hash in CI cache.
## 0.5.75 - 2026-08-14

- Candidate provenance now derives canonical evidence reasons from producer channel, detector policy, source role, checksum, companion, grammar, and verification proof. Attributed matches carry the verdict into public findings while compatibility insertion remains explicitly `review/unattributed`. Shared execution-pack hydration retains the authenticated compiled detector-plan digest, so equivalent pack routes report one exact corpus identity.
- Emitted candidates in JSON, JSONL, TOML, YAML, dotenv, and INI configuration receive candidate-bounded source-role classification with exact value/candidate spans and borrowed key-path spans. Only candidates admitted for emission or ML scoring initialize parsing; each bounded source is parsed at most once per scan and later candidates reuse the source index. TOML and YAML key paths build in one forward pass, and the index stores path spans in a shared arena. Commented examples, empty INI settings, and commented INI section headers do not invalidate later evidence. The compact role and parser confidence survive adjudication in the 16-byte sidecar. Malformed or truncated syntax and unsupported, over-nested, or over-budget input abstain without suppressing the finding, and public `RawMatch` output is unchanged.
- Emitted candidates in Rust, JavaScript/TypeScript, and Python receive exact lexical source roles for strings, identifiers, regex definitions, test fixtures, command arguments, and option declarations. Parsing is candidate-triggered and capped at 64 KiB; malformed, truncated, unsupported, and over-budget code abstains without changing recall or public `RawMatch` output.
- Emitted candidates in Markdown, roff/man pages, shell scripts, Dockerfiles, and Containerfiles receive bounded source roles for prose, inline code, shell-fenced commands, structured configuration fences, option declarations, environment assignments, and command argument values. JSON, JSONL, TOML, YAML, dotenv, and INI fences reuse their strict structured parser. Structured detector and rule fields derive regex-definition, test-fixture, and prose roles from validated Tier-B markers. Malformed, truncated, unsupported, and over-budget input abstains without changing recall or public `RawMatch` output.
- Detector-owned grammars keep MongoDB Atlas key pairs, command-line password arguments across shell, Dockerfile, PowerShell, CI, and programmatic literal contexts, and quoted Helicone values with token-shape or provider-owned context while rejecting Atlas identifiers, nested password-option names, and OpenAI sibling assignments. JWT detection retains its existing short-signature recall floor; provider-owned Scalr context applies a narrower 20-character floor. Known-prefix candidates used as assignment keys no longer absorb a quoted `=` separator as base64 padding, while quoted provider values retain legitimate padding. These decisions do not use repository or path exclusions.
- Detector TOML schema 5 binds synthetic positives and named hard negatives to exact pattern ordinals and rejects those fields under older manifests. A deterministic regex-HIR generator exercises every shipped pattern. Schema-5 enforcement-capable semantic policies require direct positive, named hard-negative, and generated sibling-prefix evidence; schema-4 policies retain their prior validity. The schema identity change rejects prior detector-corpus caches, execution packs, and autoroute decisions.
- Detector TOML schema 4 accepts typed capture, anchor, allowed-source, and required-evidence roles. Omitted declarations preserve current findings and serialization; declaring them under an older corpus schema fails closed. The schema identity change rejects prior detector-corpus caches and execution packs. Autoroute reports a detector corpus digest mismatch and instructs `keyhog calibrate-autoroute`. Detector-plan schema version 3 persists the resolved policy, rejects stale sections, and `explain` labels omitted scalar roles as compatibility defaults.
- Merge remote-tracking branch 'origin/main'.
- Candidates retain their producer channel and exact canonical pattern ordinal through ML scoring and final adjudication without changing public `RawMatch` output, ordering, deduplication, or caps. Matcher section schema version 6 persists the ordinal and rejects stale or out-of-range provenance during hydration.
- Pattern-conditioned calibration permits model-driven confidence reduction only for exact named-pattern provenance with current detector/model identity and held-out positive/negative support, recall, Brier, and ECE floors. Unsupported channels, stale artifacts, missing required-nullable identity fields, missing keys, and ineligible metrics abstain. Build-time and runtime loading share one strict parser. Runtime and harvested reassembly findings use the canonical detector owner so training and serving share the same pattern identity.
- Credential-anchored entropy now routes dotted source and property identifiers through the common secret-shape rejection gate. JWT and Discord-style structured dotted credentials retain their exact admission rules.
- Model-card and pattern-calibration JSON retain LF checkout bytes on Windows, preserving their exact build-time SHA-256 identity.

## 0.5.74 - 2026-08-14

- fix(release): ignore Marketplace-only tags.

## 0.5.73 - 2026-08-14

- fix(release): preflight registry dependencies.

## 0.5.72 - 2026-08-13

- release: publish the tag the bump job creates.

## 0.5.71 - 2026-08-13

- CPU phase-one admission now reuses the bounded trigger bitmap scratch and stores clean trigger evidence as an allocation-free empty row. Hit rows retain their exact bitmap.
- Large authenticated quantized-confidence CPU batches now score in parallel through the configured Rayon pool with bit-exact ordered output; batches below the established 64-row crossover remain serial.
- Coalesced CPU and SIMD batch topology now stores all small-lane indices in one flat buffer with range descriptors, eliminating one heap allocation per small lane while retaining exact scheduling and byte bounds.
- Sensitive-path keyword-free confidence ownership regression pins that ordinary entropy_very_high cannot demote admitted secrets.env hits.
- Sensitive-path keyword-free entropy keeps ML as lift and scores against the sensitive very-high band so `VALUE=<token>` in secrets.env is not soft-dropped.
- Redis-sentinel evasion contract uses `REDIS_SENTINEL_AUTH=` instead of a commented auth-pass so comment soft-suppression cannot hide the credential.
- Generic RandomByteBlob suppression now requires decoded NUL evidence, matching the entropy path, so strong assignment secrets (JWT_SECRET/API_KEY/TOKEN) remain reportable while SecretBench NUL-bearing pure-alnum decoys stay suppressed. Corrected-primary-role backend parity compiles ExactCpuScanners so SIMD dispatch uses a real simd-regex pack.
- Detector property gates now preserve fixture paths for source-admission checks, compare Caesar prefix admission at exact token boundaries, compile backend-specific CPU and SIMD scanners, and retain minimized parity cases. The WordPress token contract includes its required `wpcom` owner anchor.
- MatcherArtifact cache hits now borrow all persisted matcher sections from the
  capped artifact file buffer through hydration instead of allocating a second
  complete section set.

- Confirmed shared-anchor extraction now reuses bounded worker scratch for its
  sparse active-pattern and literal-id lists instead of allocating both vectors
  for every phase-two pass.
- Runtime tuning snapshots now resolve through `ScannerTuningConfig::effective`
  and use its complete resolved type instead of maintaining a duplicate field
  list and default mapping.

- Expose confirmed_companion_gate on [tuning] and resolved/autoroute config identity (default on), so operators can disable the mid-literal confirmed-pass skip the same way as confirmed_suffix_gate.
- Restore pure structural base64url parsing in jwt_segments, reserve structural payload/header decoding for analyze, replace runtime panic macro paths in BPE token count cache initialization with a compile-time safe TOKEN_CACHE_CAPACITY constant, support legacy var declarations in bounded CryptoJS recovery, and use one containment relation for miss-clustering TP, FP, and FN accounting.
- Cold one-shot and incremental scans now reuse a persisted MatcherArtifact of the eager compiled matcher graph across process invocations (format v4), with CacheId hit/miss/invalidation in profile output, fail-closed identity checks, soft-fail when cache prep fails, and --lockdown disabling the cache.
- Companion-gate derived AC/literal tables use a bounded per-thread LRU keyed by detector digest + active pattern set, and parsed-arm memo is capacity-capped, so heterogeneous trigger mixes do not rebuild from a single-slot thrash or grow unbounded.
- Restore reusable phase-1 absence proofs for small rejected repeated payloads (≤128 KiB), and size-gate markerless bounded-window decode skips so short trailing slices still decode.
- 39 process-safe scanner test files are wired into the all_tests aggregator. Process-global decoder-registry and allocation targets plus the RSS-sensitive execution-pack mapping contract run in isolated CI processes. The recall_locks_wired.py gate is widened from checking only regression_*.rs to checking all top-level test files. CI workflow duplication is eliminated by extracting composite actions for workspace repair and Vectorscan install. All workspace compile warnings are fixed (zero warnings from cargo check --workspace).

- Base64 decode memo retains successful UTF-8 text only after a second sighting of the same candidate, so unique-blob corpora no longer keep a second full-size copy of every decode for the whole chunk. Failures stay memoized immediately.
- Companion-literal presence scratch resizes to the active literal count and fill(false)s every chunk (not only the non-grow branch), with a regression test that seeds stale true bits then grows the literal set.
- Preserve scanner-materialization context on installed execution-pack compile failures, and remove the unused record_matcher_artifact_pack_hit helper that contradicted CLI profile attribution policy.
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

## 0.5.70 - 2026-08-10

- fix(profile): fail-closed overlapping allocation session peaks.

## 0.5.69 - 2026-08-10

- Signed execution packs now reuse whole-pack signature authentication during scanner hydration instead of hashing backend and native shard payloads again; unsigned development packs retain full per-shard validation.
- Explicit CPU and SIMD daemons no longer initialize or retain GPU runtime libraries during startup.
- CPU scans now bypass per-chunk parallel dispatch when authenticated admission evidence proves an entire bounded batch has no direct matches.
- Execution-pack startup now borrows detector-plan prelude strings directly from authenticated framed rows while interning runtime ownership, avoiding transient per-row string copies.
- CPU autoroute now reuses bounded exact payload evidence across source batches while rejecting sampled-fingerprint collisions and stale policy identities.
- SIMD scans now cache bounded exact trigger rows across repeated authenticated batches while requiring full payload equality after sampled lookup.
- CPU scanner startup now hydrates a compact phase-two keyword index and reuses install-compiled repeated-separator metadata; matcher packs require schema version 5.
- Filesystem scans now coalesce tiny files up to the existing 1 MiB payload ceiling and execute them in worker-sized CPU and SIMD lanes, reducing per-file scheduler, channel, and Hyperscan scratch churn.
- CPU and SIMD routing now classify each byte-distinct payload once per batch while preserving exact per-chunk admission evidence.
- Generic assignment scanning now rejects broad keyword-stem lines unless an assignment delimiter follows the stem, while preserving *_PASS= and value-suffix recall.
- GPU routes now execute detection only through VYRE-owned CUDA, Metal, and WGPU programs. KeyHog no longer ships the retired hand-written WGPU MoE shader, the `[tuning].gpu_moe_timeout_ms` key is removed, and GPU health reports expose only VYRE literal-set and production region-presence probes. The separately retired quantized VYRE confidence program is described below.
- GPU region batches now pipeline two VYRE-owned resident IO slots: KeyHog builds and submits the next batch before retiring the previous readback, while immutable matcher tables remain shared and result consumption stays ordered.
- Authenticated execution packs now retain install-validated companion regexes as lazy matchers instead of recompiling every companion during scanner startup.
- Execution packs now persist confirmed, suffix-gate, and phase-two localization plans so installed scans hydrate those indexes without reparsing the detector regex corpus.
- Build only the anchored verifier regex a candidate position actually consults in the phase-two confirmation pass. `extract_anchored` compiled both the `\A(?:src)` verifier and the `\A(?s:.)(?:src)` left-context variant for every eligible pattern, and allocated a capture-slot buffer for each on every call, but a candidate at byte 0 is rare and a pattern with no capture group never reads the slots, so a whole extra regex per pattern was compiled and never read. Non-grouped patterns now resolve through `find` off the lazy DFA without running the capture engine. The same pass replaces a per-chunk hash set of present suffix literals and a binary search run per anchor candidate with reusable per-worker bitsets, skips the per-line homoglyph normalization on chunks preprocessing already proved unchanged, and settles the raw-text comparison by pointer identity rather than a whole-buffer memcmp. Regex construction is one-time per pattern but serialized on whichever worker touches it first, so it costs wall time out of proportion to its instruction share: a frozen 5,554-file copy of crates/ measures 4.10 percent fewer retired instructions and median wall 9.42 s falling to 8.55 s, the 15,000-file mirror corpus measures 1.96 percent fewer instructions, and findings are byte-identical on both corpora under --backend cpu and --backend simd.
- Builds now resolve VYRE 0.7.2 from one reviewed upstream commit instead of requiring a sibling source checkout, while keeping CUDA, native Metal, WGPU, and runtime crates on the same immutable identity.
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
- Concurrent CPU batches now single-flight exact reusable admission evidence misses instead of rebuilding the same representative in parallel.
- Scanner post-processing now skips decode generation for whole chunks and bounded filesystem windows whose decoder admission proof is impossible.

- Delete 235 source-grep shape tests across the five crate test trees. Each read a .rs file at runtime and asserted only substring presence or absence on that text, so they pinned how the source is spelled rather than what the scanner does; the project standard bans them. 107 test files went away entirely, 57 files lost individual tests, and every mod registration plus three Cargo [[test]] entries went with them. Two ambient-env gates (KEYHOG_THREADS, KEYHOG_DETECTORS) became four behavioural tests that drive the binary and read `config --effective` and `detectors --format json`. Each is a negative assertion, so each is paired with a positive case on the same output field, and both oracles were ablated to confirm the comparison discriminates: KEYHOG_THREADS=99 leaves `threads = auto` while --threads 3 moves the same line to 3, and KEYHOG_DETECTORS pointing at a one-detector directory leaves the corpus intact while --detectors on that directory reduces it to one. 23 source pins for network and filesystem security boundaries are kept deliberately: verifier_safety_contracts.rs, the DNS-pin and no-auto-decompression gates, the verifier proxy owner, the git safe-bin and no-follow-symlink gates, and the hosted-Git credential temp-file permission contract. That last pin was repointed at the whole hosted_git module after the module split moved the code it reads out of hosted_git.rs, which had silently made its negative assertions vacuous, and it now asserts an anchor first so it fails loudly rather than passing for free the next time the module is reorganised.

- Named detectors can fire on binary-derived content again. Admission past the binary-strings noise gate required a declared `[detector.credential_shape]`, which 4 of 925 detector TOMLs carry, so 921 named detectors could never report a finding in an ELF, PE, Mach-O, wasm, static archive, shared object, archive member or container layer; the same tar.gz reported `aws-access-key` and silently dropped `slack-bot-token` purely because one TOML had the block. A match is now admitted on per-match structural proof, a declared shape or a span covering a whole lexical token, while generic, weak-anchor and free-form password-slot detectors stay suppressed, and a withheld match is counted as a `binary_strings_named_exclusions` coverage gap instead of vanishing. Expect new findings on compiled artifacts and container images that previously reported clean: a planted Slack token goes from 0 to 14 of 15 binary variants, and 249 MiB of real system ELF goes from 0 to 4 findings. Printable runs are also emitted in file order with every occurrence kept, replacing an alphabetical whole-input dedup that made two runs neighbours because they shared a prefix, and joined by a separator no whitespace, non-whitespace or dot class can cross, so a pattern can no longer bridge runs that were never adjacent.
- Selective anchor construction uses a bounded deterministic frequency sketch instead of retaining every corpus window, reducing scanner startup memory without changing recall.
- Large filesystem windows now decode through bounded overlapping subwindows, recovering encoded credentials beyond the default decode working-set ceiling without raising that ceiling.
- Surface chunks abandoned at their per-chunk deadline as a fail-class coverage gap. When `--per-chunk-timeout-ms` elapsed mid-chunk the scanner returned an empty or short match set for that chunk, and the abort was counted into scanner telemetry that nothing read, so a scan that abandoned every chunk still reported `scan_status: success` with an empty `coverage_gap_summary` and exit 0. Deadline aborts now surface as `scanner chunk abandoned at its per-chunk deadline` and mark the scan partial. Operator-visible change: a scan that hits the deadline exits 13 instead of 0 where it produced no findings, so raise or clear `--per-chunk-timeout-ms` rather than suppressing the exit code. Findings are never discarded; a run that covered some input reports its findings alongside the gap.
- Detector-owned reverse and Caesar prefix gates use compact contiguous automata, reducing packed-scan startup ownership without changing decode selection.
- Report the decode-through coverage that `--decode-size-limit` declines, instead of quietly returning fewer findings. A chunk larger than the limit was denied decode-through with nothing recorded anywhere, while the neighbouring path that truncates decoder OUTPUT has always counted a gap, so the decline that skips the pass entirely was the silent one. Measured on the 2,399-file homefield corpus, `--decode-size-limit 64K` reported 1,623 findings against 2,239 at the 512 KiB default, 616 fewer, with an empty coverage_gap_summary and nothing on stderr. A denied chunk now records a WARN-class `scanner decode-through declined by --decode-size-limit` gap that names the flag in the structured coverage_gap_summary reason rather than only in terminal prose, so a CI wrapper reading the envelope gets the remedy. It stays at zero on an ordinary scan because no chunk reaches the compiled default. WARN rather than FAIL is deliberate: the raw bytes were examined and only a derived layer was skipped, which is the same class as the existing decode-truncation and structured-oversize rows. The counter was initially recorded only on the non-coalesced route, which made the gap backend-dependent (cpu reported one declined chunk where simd reported none, for byte-identical findings); it is now paired with the per-chunk scan event that every route calls, so the warning cannot disappear because autoroute picked a different backend.
- Installed scans stream authenticated detector plans from execution packs without decoding detector schemas, validate canonical matcher envelopes in one typed JSON pass, build prefix propagation through a flat arena trie instead of one hash table per trie node, co-locate each lazy regex's compiled cell and memoized source facts under one shared owner, share compiled signature strings with post-processing, and compile companion regexes and pattern-shape validator sets only when their evidence is first required. The entropy precision gate consumes an exact build-packed cl100k rank table without constructing the tokenizer's duplicate encoder, decoder, sorted-token, and thread-local regex graphs. Report-time remediation validation uses the build-generated detector ID index instead of reparsing the embedded detector corpus after a finding. Compiled detector plans share equal confidence policies across the detector table and keep sparse entropy, shape, and suppression policies in a compact indexed side table. Small detector-owned keyword vocabularies use compact flat byte tables instead of retaining one Aho-Corasick automaton per detector. Phase-two no-candidate gates are scoped to the active residual route, and phase-two anchor lookup tables share literal sources with the lazy runtime rows before the lookup tables are released. The large phase-two, confirmed shared-anchor, and confirmed suffix-gate automata materialize only for a non-empty batch, then their compiler arenas are purged before per-chunk scanning. Sparse files stream only allocated extents and report all-hole files as uncovered regions, stdin validates its byte cap through an anonymous spool before scanning bounded overlapping windows, and bounded stdin windows use a rendezvous-fed fused scan batch instead of accumulating the complete input. Empty stdin remains an explicit zero-byte coverage gap instead of reporting an unearned clean scan. Fused source boundaries default to rendezvous channels, homoglyph prescreening no longer materializes Unicode matchers for unrelated replacement characters, and the one-long-line benchmark now contains one delimited canary on one physical line. Large unbounded filesystem walks retain deterministic path order in one common-root byte slab and compact row/index tables instead of one allocated absolute path per file. The archive-symlink audit streams unbounded directory entries and skips duplicate regular-file metadata checks while no-follow read paths retain link-swap protection. Installed-pack benchmark captures bind detector runtime provenance per workload so catalogs that intentionally use multiple detector corpora remain exact.
- Lazy phase-two anchor construction now warns and keeps affected patterns on recall-preserving whole-chunk or folded RegexSet paths instead of panicking when an Aho-Corasick build fails.
- Authenticated packed scans defer precise hot-pattern validator regexes until their literal prefix is observed; backend parity regressions now compile the exact requested route.
- `--perf-trace` no longer aborts the process it is measuring. Every run died with an index-out-of-bounds panic and exit 134 after the report was written, because the per-pattern timing dump indexed process-global tables sized by whichever scanner initialized them first, and on a GPU build a single-pattern probe scanner warms them before the full corpus compiles. Separately, a phase-2 GPU admission catalog that cannot cover its pattern set is now refused rather than trusted: a GPU miss is only sound as "no covered pattern matched", and completeness was derived from lowering failures alone, so always-active patterns dropped by the candidate filter for any other reason were excluded from the covered set while the catalog still claimed to be complete. That set is empty on the shipped corpus, so the hole was latent and no finding was ever lost. Shard construction is now bounded at 64 shards and stops at the first uncovered pattern, because every shard is a separate dispatch over the same haystack.
- A credential inside a minified or vendored bundle is reachable again, and a dropped one is counted. Every finding whose path ended .min.js, .bundle.js or .min.css, or sat under node_modules/, site-packages/, wp-includes/, dist/assets/ and similar, was discarded before it reached the report. The drop was unconditional, left no trace on any surface, and no flag defeated it, so a live sk_live_ key that a build pipeline had inlined into app.min.js produced an empty report and exit 0. Build tooling inlines API keys into bundles routinely, which made this the one leak class KeyHog could not report at all while saying nothing was detected. Two changes. `--no-default-excludes` now disables this suppression as well as the walker skip, so the flag disables every default exclusion instead of only the one you could see. And a suppressed match is counted and reported as a `matches dropped by the vendored/minified path policy` coverage-gap row naming the count and the flag that recovers it. The row is WARN class, so an ordinary scan of a tree containing vendored code still exits 0. Measured on a wp-includes/config.php holding a live-shaped Stripe key: 88 bytes scanned, 0 findings and an empty coverage_gap_summary before, the same scan plus the counted row after, and exit 1 with the finding under `--no-default-excludes`.

## 0.5.69 - 2026-08-09

- Section-specific schema versions for execution packs: detector-plan sections use schema version 2 and matcher sections use schema version 5. Pack loading validates section schema versions and reports an actionable rebuild recommendation if mismatched.
- Authenticate execution pack content digests and signatures before interpreting section tables or identity headers, protecting the trust boundary against unauthenticated header mutations.
- Verify every changed section schema against independently encoded legacy pack bytes so compatibility checks cannot inherit the current compiler's layout.
- Include retained keyword, generic-position, CPU-trigger, payload, and line-index storage in evidence-cache replacement accounting, reject individually oversized entries, and enforce aggregate residency and entry-count ceilings.
- Use checked page alignment for interior mapping slices while discarding the trailing partial page when releasing whole authenticated execution packs.
- Wire the production-path cache, decoder-admission, and context-window regressions into the aggregate scanner test binary.
- Preserve line indices as `usize` throughout entropy keyword discovery, context checks, and candidate scanning, preventing silent line drops or panics on large inputs.
- Add a validated `chunk_lane_threshold` configuration knob with a supported range of 1 byte through the 1 MiB scan-window ceiling, fail-closed scanner construction, effective-config output, routing identity, and runtime propagation.
- Preserve the infallible `with_tuning_config` builder for source compatibility and add `try_with_tuning_config` for fail-closed dynamic tuning.
- Cap scratch set capacity retention to prevent pathological bucket growth in worker-local scratch pools.
- Ensure deterministic total-ordering tiebreak on decoded candidate match merges.
- Coalesce small chunks through one shared CPU/SIMD topology while keeping every large chunk as an independently scheduled work item.
- Reuse exact SIMD trigger rows across repeated small files in mixed small/large batches without trusting scalar absence evidence for SIMD candidates.
- Fail closed on out-of-bounds lookups in hot-pattern classification.
- Return immediately from windowed processing after an expired deadline, with bounded deadline regressions that tolerate scheduler variance.
- Keep the deterministic CPU library constructor and expose runtime-policy GPU probing through `compile_with_runtime_policy`.
- Bound batch lane memory by the largest chunk, expose `finish_partition` to release cross-partition caches, retain production GPU overlap evidence through dispatch retirement, and verify that linked or packaged GPU kernels remain VYRE-owned.
- Restrict 64-character hexadecimal detection in `generic-api-key` strictly to explicit cryptographic key slots (`signing_key`, `encryption_key`, `master_key`, `session_key`, `hmac_secret`, `hmac_seed`) to prevent false-positive flagging of SHA-256 digests and checksums.
- Add negative false-positive test cases covering content digests, checksums, object IDs, commit hashes, and hash-suffixed fields to `generic_api_key_64_hex`.
- Cover credential-free PostgreSQL connection URLs as negative detector cases.
- Add a versioned integer confidence ABI and a separate asynchronous quantized MoE VYRE score dispatch. Bounded IR loops keep the complete model below finite shader-size limits. Authenticated CPU and GPU routes use the same fixed-point model for accelerator-eligible candidates; selected GPU scoring fails closed while feature extraction, confidence floors, suppression, deduplication, and reporting remain in the shared CPU tail.
- Direct diagnostic GPU routes compiled from a validated live detector corpus now authenticate the build-validated embedded quantized model without requiring an execution pack. Packed GPU routes still require both a valid pack signature and the matching packed GPU artifact.
- Add authenticated ordered GPU device sets with cross-API physical-adapter deduplication, explicit exclusion reasons, all-or-nothing per-ordinal acquisition, measured integer-weight contiguous shard assignment, bounded per-device resident slots, concurrent dispatch, and source-ordered fail-closed retirement.

## 0.5.68 - 2026-08-05

- Add the immutable execution-pack boundary. Packs bind exact binary, feature, detector, config, target, compiler, policy, and backend identities; expose aligned zero-copy sections and exhaustive byte ownership; select before mapping; and carry VYRE receipts instead of KeyHog GPU programs.
- Make scanner construction route-specific. The default library constructor owns only the scalar reference route, `compile_for_backend` owns one explicit route, and cross-route dispatch fails instead of materializing or substituting a backend.
- Store each interned detector metadata string in one lookup-map key instead of a parallel arena and index, and reuse those allocations for resolution and cross-detector relation identities.
- Remove the overlapping scalar phase-one automaton from exact SIMD scanners. Lazy SIMD plans now share the canonical literal table, phase-two keyword catalogs borrow detector-owned strings, and alphabet and GPU plan construction no longer clone temporary literal tables.
- Store SIMD pattern mappings, confirmed-suffix rows, and structural detector partitions as flat `u32` offset tables built from flat row/value pairs instead of allocating one heap vector per row.
- Right-size frozen scanner storage after construction: omit empty detector-relation map rows, release duplicate-heavy interner and generic-ownership map capacity, and discard matcher-vector growth slack before retention.
- Bound caches to live workloads: the shared detector-regex index now weakly deduplicates only concurrently live scanners, while fragment-reassembly shards grow from one row on demand and release that capacity when a workload is cleared.
- Release compiler-only keyword catalogs, warning strings, route-neutral literal tables, and decoded detector schemas before the compiled scanner enters health and scan-state measurement.
- Return freed compiler arenas to the allocator once scanner construction completes. Mimalloc builds collect every Rayon worker heap and the caller heap; Linux glibc builds trim the process heap before runtime health measurement.
- Keep GPU literal rows, regex-bound rows, matcher programs, peers, and dispatch scratch absent from exact CPU and SIMD scanners.
- Make worker scratch lazy and bounded: uppercase, checksum-decode, generic-keyword, and decode-fact pools no longer retain hostile-input or eager per-thread allocations.
- Compile complete phase-two GPU DFA coverage evidence from the detector registry, split oversized compatible programs into bounded deterministic shards, emit compact candidate bitmaps, and reject incomplete or identity-mismatched versioned catalogs.
- Add 128 MiB per-allocation ceilings for CPU and SIMD scratch, return `ScanError::MemoryCeilingExceeded` through the production phase-two scan boundary, and clear active-pattern scratch before any rejected growth so a failed reset cannot reuse the prior chunk's detector set.

- Move two large co-located test suites out of scanner source files and into the tests tree, shrinking `detector_ids.rs` from 414 lines to 127 and the Hyperscan scratch backend from 767 to 341. Both keep running against the crate-private state they exist to check, and both leave the inline-test allowlist, so the allowlist now names two fewer permanent exceptions.
- Remove the unreachable retired VYRE megakernel probe and its testing-only release features, and restore error and adversarial coverage marks for phase-two anchor admission.

## 0.5.67 - 2026-08-05

- Filesystem enumeration-order contract.

## 0.5.66 - 2026-08-04

- Whole-tree GPU guidance in the backends guide.

## 0.5.65 - 2026-08-04

- Tell the operator the truth when a required GPU is unavailable. An explicit `--backend gpu-cuda` also makes GPU mandatory, but the refusal named only `--require-gpu` and advised running without it, sending anyone who used the backend flag looking for a flag they never passed. The message now names the resolved policy, both routes into it, and both ways out.

## 0.5.64 - 2026-08-04

- README evidence panels remeasured against the current detector corpus.

## 0.5.63 - 2026-08-04

- Report Mailchimp keys as Mailchimp keys. The three datacenter patterns declared no routing literal, so the prefilter had nothing to route them on and nine keys on the benchmark corpus were reported as generic secrets instead, one of them a base64 value the generic detector could only show opaquely. Scored against the corpus answer key, declaring the literals moves one finding from false positive to true positive and changes nothing else.

## 0.5.62 - 2026-08-04

- Make the prefixless-pattern gate ask the question that matters. It previously only flagged patterns with extractable inner literals, which let through the exact pattern whose missing declaration suppressed an unrelated detector; it now flags any prefixless pattern that declares no routing literal, with shape-only detectors such as Asana tokens and Telegram bot tokens recorded as a category rather than as debt.

- Stop one detector's pattern from silently costing another detector's recall. A pattern with no literal prefix and no declared routing literal leaves the shared prefilter nothing to route it on, and the loss lands elsewhere: twenty-three patterns across the corpus now declare a literal the compiler proves is required by every match, including the Datadog application key pattern itself.

## 0.5.61 - 2026-08-04

- Extend token-boundary anchoring to every remaining detector whose vendor prefix is three letters or fewer, so `MSG_API_KEY=` is no longer a Singapore GovTech key, `XPBI_CLIENT_ID=` no longer a Power BI credential and `WEBCB_API_KEY=` no longer a Carbon Black key. Fourteen such false positives are now silent, seventeen genuine separator-prefixed forms still report, and findings are unchanged on every corpus.
- Repair a recall regression in the previous two releases. Anchoring short vendor prefixes with a word boundary also stopped them matching after an underscore, because `_` is a word character, so `MY_NR_LICENSE_KEY=`, `MY_GH_WEBHOOK_SECRET=` and every other `PREFIX_TOKEN_...` form went unreported. The anchor now tests the character class before the token instead, which keeps the false positives suppressed and finds the separator forms again.

## 0.5.60 - 2026-08-04

- Anchor four more detectors whose vendor prefix is two or three letters, so they stop matching at the tail of an unrelated identifier. Two were reproducibly wrong on ordinary input: `xapi_key=<uuid>` near the word mexico was reported as a Mexican government key, and `LEIGH_WEBHOOK_SECRET=` was reported as a GitHub webhook secret. Every genuine form still fires and reported findings are unchanged on every corpus.

## 0.5.59 - 2026-08-04

- Stop the Africa's Talking detector matching inside a larger identifier. Its anchor accepted a bare `at`/`AT` with nothing in front of it, and `SNAPCHAT_API_KEY=` contains a literal `AT_API_KEY=`, so every Snapchat token was also matched as an Africa's Talking key. Deduplication kept it out of the report, but the extra match blocked GPU autoroute calibration for the whole workload class.

## 0.5.58 - 2026-08-04

- README evidence panels remeasured against the current binary.

## 0.5.57 - 2026-08-04

- Repeatable autoroute calibration.

## 0.5.56 - 2026-08-04

- Overlapping coalesced batches and autoroute classification for any batch size.

## 0.5.55 - 2026-08-04

- Idempotent source contract-test generator and a warning-free workspace build.

## 0.5.54 - 2026-08-04

- Report how many phase-two prefilter batches the prefix gate ran versus skipped in `--perf-trace`, which answers whether the prefilter is expensive because every chunk reaches it or because every batch runs.

- Skip homoglyph-variant patterns when the chunk provably contains no confusable glyph, instead of only when it is pure ASCII. Ordinary non-ASCII source text carries accented names, CJK, box drawing, arrows and emoji, none of which a homoglyph variant can match, and it was forcing the full residual pattern set.

## 0.5.53 - 2026-08-04

- Make the coalesced batch pipeline eleven times faster and stop starving the accelerator.

## 0.5.52 - 2026-08-04

- Refuse configuration fields the scanner cannot honour and check every documented command against the real CLI.

## 0.5.51 - 2026-08-04

- Prove the bounded accelerator-evidence dedup set refuses and counts every record past capacity, keeps dedup rejection separate from loss, and saturates its loss counter instead of wrapping to zero under sustained overflow.

- Report accelerator evidence dedup overflow on the `keyhog::gpu` tracing target with its exact running loss count, replacing a counter that no caller read.
- Compile each phase-two always-active matcher variant when a chunk selects it instead of building all four for every batch up front, which removed a 1.4 second stall that the first decoded sub-chunk of any scan charged to every scan worker.
- Prove a phase-two batch is empty with the DFA-backed match test before asking which patterns matched, since reporting the matching set has no lazy-DFA path and forced a full PikeVM pass over every batch on every chunk.
- Stop compiling the coalesced phase-two tail, its triggered windowed scan, its batched ML scorer, and the GPU peer timing facets into portable builds, which have no producer that can reach them.

- Resolve a candidate's whole assignment value from the start of its own line rather than from the start of the chunk. Quote and escape state reset at every line break, so the previous walk reread the entire preceding chunk for every candidate and was quadratic in candidates per chunk.

## 0.5.50 - 2026-08-02

- Add low-overhead causal run profiling with fixed scanner stages, state transitions, process resource measurements, and explicit source and backend identity while keeping per-pattern diagnostics behind --perf-trace.
- Compile bounded cross-detector `requires`, `conflicts`, and `subsumes` operations and resolve them to a deterministic fixed point across source findings.
- Enforce detector-owned source path, source type, and file-extension admission before named and phase-two findings survive suppression.
- Restore the documented minimal no-default-features build by keeping decoder admission available when optional decode transforms are absent.

- Publish patch releases to crates.io through short-lived OIDC trusted publishing and bind deterministic six-crate integrity receipts to the exact workspace lockfile and commit.
- Localize plain phase-two patterns by default on portable and explicit CPU scans, avoiding full portable marking-set compilation when the shared anchor index owns candidate extraction.

- Keep complete credentials from native binary strings and executable sections when a strong named detector validates an explicit credential shape, while continuing to suppress weak prefix fragments and generic assignment noise.

## 0.5.49 - 2026-07-30

- A single resumable local or SSH command now refreshes benchmark evidence without invalidating candidate freshness, rebinds the exact canonical run-set after scoring, prepares every changelog and version surface, runs pre-tag gates with isolated full and ci-lean binary contracts, preserves exact Git path bytes, verifies the configured OpenPGP fingerprint before any tag push, and watches GitHub Pages, release assets, containers, and the six-crate crates.io publication chain.
- Keep coalesced triggered windowing and performance-trace support available in portable builds without SIMD or GPU features, with exact oversized-window regression coverage.
- Public certificate and public-key PEM bodies no longer produce entropy or named-detector findings from their base64 data. Private-key blocks and credentials outside a closed public block remain visible.

## 0.5.48 - 2026-07-28

- Bind the scanner package candidate to the exact validated release commit and
  hosted CPU recall, throughput, memory, and signed SPDX dependency evidence.


## 0.5.47 - 2026-07-26

- Bind the crate release identity to the KeyHog installer-recovery patch so
  exact internal dependency pins and the published package graph remain
  coherent.

## 0.5.46 - 2026-07-24

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
- Census CUDA, native Metal, and WGPU identities during scanner compilation
  without creating execution devices or pipelines. Materialize only the
  selected peer, retain exact initialization diagnostics, and leave unrelated peers untouched.
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

## 0.5.45 - 2026-07-22

- Republish the scanner in the release chain whose signed asset publication
  addresses GitHub drafts by immutable release ID.

## 0.5.44 - 2026-07-22

- Compile the GPU literal artifact generator on Windows by passing its UTF-16
  option prefix to `slice::strip_prefix` as a slice.

## 0.5.43 - 2026-07-22

- Keep grown phase-two GPU DFA resident haystack capacities aligned to the
  declared 32-bit element ABI. Forced 8 MiB, 32-shard CUDA evidence now proves
  one haystack upload and exact admission parity against per-shard dispatch.
- Recover balanced Helm template manifests by selecting one complete conditional
  branch and replacing render-time actions with inert YAML values. Recover
  Jupyter notebooks truncated at end of file by closing only open strings and
  containers. Other syntax errors remain counted coverage gaps.
- Batch Base64 and hexadecimal values, JSON strings, quoted-printable text, and
  line-local URL-percent, HTML-entity, Unicode, and octal escapes into bounded
  source and output spans instead of emitting one recursive root per value.
  Physical lines and multiline private-key separators remain intact. Disallowed
  controls become token separators instead of truncation events, preserving
  adjacent printable spans without joining tokens.
- CUDA and WGPU positioned-literal evidence use the same 8 MiB shard ceiling,
  keeping dense corpus match replay exact without backend substitution.
- Single-shard Hyperscan databases compile inline, preventing nested Rayon work
  from re-entering a worker's borrowed phase-two scratch state.
- Chef's generic `api-token` header anchor now requires a token boundary, so it
  cannot replace an exact Snyk UUID finding through overlap resolution.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep scanner compilation, scan execution, entropy, decode, and context scoring APIs available for the 0.2 line.
