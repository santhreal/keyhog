# Changelog

## 0.5.79 - 2026-08-16

- ci(release): fallback token and sync floating major tag on release.

## 0.5.78 - 2026-08-16

- fix(scanner): gate expand_triggered_patterns independently of decode feature.

## 0.5.77 - 2026-08-16

- fix(ci): format scan_postprocess, update dogfood hashes for doc fixtures, and bump action version.

## 0.5.76 - 2026-08-16

- fix(core): rerun build script on GITHUB_SHA changes to prevent stale git hash in CI cache.

## 0.5.75 - 2026-08-14

- Merge remote-tracking branch 'origin/main'.

## 0.5.74 - 2026-08-14

- fix(release): ignore Marketplace-only tags.

## 0.5.73 - 2026-08-14

- fix(release): preflight registry dependencies.

## 0.5.72 - 2026-08-13

- release: publish the tag the bump job creates.

## 0.5.71 - 2026-08-13

- Safe-open now returns the regular-file descriptor metadata it already validates. Filesystem mmap admission, binary, Ghidra, and Docker callers reuse that snapshot instead of issuing a redundant descriptor metadata query; a later windowed buffered fallback refreshes metadata before re-proving its hard cap.
- Whole-file reads up to 16 MiB now reuse the exact-size buffered-read primitive before probing for growth, avoiding generic buffer-growth probes while preserving truncation safety and the one-byte-past-cap refusal.
- Ordinary unbounded filesystem scans now classify archive symlinks during the configured metadata walk instead of traversing every directory once for archive-symlink audit and again for file admission. Byte-budgeted scans retain their path-sorted audit, and long-path fallback retains descriptor-relative symlink classification.
- The default filesystem reader is now one direct producer, so ordinary scans no longer retain a multi-reader crew or intermediate ordered-reassembly thread. Explicit reader counts above one retain deterministic ordered reassembly.
- Git blob scans now index HEAD paths by object ID and borrow decoded raw paths for exact live-versus-historical classification, avoiding one path allocation per membership probe.

- 39 process-safe scanner test files are wired into the all_tests aggregator. Process-global decoder-registry and allocation targets plus the RSS-sensitive execution-pack mapping contract run in isolated CI processes. The recall_locks_wired.py gate is widened from checking only regression_*.rs to checking all top-level test files. CI workflow duplication is eliminated by extracting composite actions for workspace repair and Vectorscan install. All workspace compile warnings are fixed (zero warnings from cargo check --workspace).

## 0.5.70 - 2026-08-10

- fix(profile): fail-closed overlapping allocation session peaks.

## 0.5.69 - 2026-08-10

- Report resettable counters from production filesystem discovery for root inspection, walk entries, metadata admission, errors, and early termination.
- Azure Blob Storage scans now stream blob bodies in deterministic order through the shared bounded cloud fetch window instead of retaining a container-wide result vector.
- Binary and Ghidra analysis now emit gapless 256 KiB text chunks, avoiding whole-output joins and retaining only compact printable-run descriptors before bounded materialization.
- Bitbucket workspace scans now stream ordered repository results through the shared bounded hosted-Git pipeline while preserving listing-error order, instead of retaining every cloned repository result until the workspace finishes.
- Automatic daemon fallback now shares the acquired stdin payload and scans it through bounded overlapping windows, avoiding a second whole-input byte copy and a whole-input decoded retry buffer.
- Docker image scans stream each layer tar through the shared in-memory archive dispatcher with one inflate pass and image-scoped unpack budgets, instead of full decompress plus FilesystemSource re-walk. Large already-UTF-8 plain layer members stream in ~1 MiB windows from the tar entry (peak near one window); formats that need a full member (archives, PDF, images, HAR, lz4/sz) still buffer up to the 100 MiB scan cap. Extensionless members prefix-sniff before full buffer. Layer .har files expand at the Docker boundary with wire:har labels; nested .har inside ordinary zip/tar/7z/RAR keep the historical filesystem/archive leaf identity. UTF-16 archive members keep the whole-member decode path. Top-level layer 7z/RAR extract from bytes when content magic matches.
- Filesystem scans now coalesce ordered tiny-file handoffs into bounded batches and reuse complete extensionless prefix reads instead of reopening the same file.
- Google Cloud Storage scans now stream object bodies in deterministic order through the shared bounded cloud fetch window instead of retaining a bucket-wide result vector.
- Git history scans now yield each bounded decoded-blob batch and annotated-tag message before loading the next payload instead of retaining whole commits or tag sets.
- GitHub collaboration scans now stream issue, pull-request, discussion, wiki, gist, and release chunks through one-row backpressure without retaining a selected surface's full content, and share one token allocation across the worker.
- GitHub organization scans now preserve concurrent shallow cloning while streaming repository chunks in configured repository order with one-row channels, instead of retaining every cloned repository result until the organization finishes.
- GitLab group scans now stream ordered repository results through the shared bounded hosted-Git pipeline instead of retaining every cloned project result until the group finishes.
- Large filesystem scans now retire explicit CPU and SIMD windows in bounded worker waves, share byte-identical source windows, and reuse verified repeated-window findings with rebased locations.
- S3 scans now stream listing-page objects in deterministic order with a 16-result backpressure window, retain prior-page findings when a later listing fails, and avoid accumulating downloaded object bodies across the bucket.
- Slack scans now stream channel histories through an ordered eight-channel backpressure window, share one token allocation across the worker, and stop retaining every workspace message chunk until collection completes.
- Web scans now stream ordered fetch results with eight-response backpressure, emit JavaScript, source-map, and WASM text in gapless 256 KiB chunks, and release parsed source-map ownership before chunk materialization.
- BREAKING: --limit-docker-tar-total-bytes now bounds one whole image rather than one tar. It was enforced with a fresh accumulator per tar, so an image made of an outer tar plus one tar per layer got the full allowance for each; Docker permits 127 layers, so the 8 GiB default admitted roughly 1 TiB of unpacking per image while every individual check passed. A 2-layer image under a declared 5104-byte cap previously unpacked 13361 bytes with no truncation and now refuses at the image total. If you have tuned this flag, raise it to cover the sum across the image tar and every layer tar, or images that previously scanned will be refused with a counted coverage gap.
- Filesystem discovery prunes default-excluded directories during the walk, finishes deep Linux trees via descriptor-relative metadata-only discovery after ENAMETOOLONG, and cheaply sniffs unclassifiable names before full reads.
- `--git-blobs` collects commit blobs by parent-tree diff (added/changed/deleted sides) instead of rewalking every historical tree. Every ref tip under refs/ plus HEAD (detached CI checkouts), root commits, and unreadable parents still get a full tree walk so `--max-commits` keeps untouched tip blobs across custom namespaces. Unsupported non-blob tree-diff entries stay coverage gaps, already-collected parent-diff sides are kept when a later parent falls back to a full walk, default-excluded unsupported entries stay silent (same as the full walk), and blob decode stays on the already-open repository handle.
- Filesystem discovery now walks metadata directly, preserves native path ordering through bounded external sorting, and defers content classification to the no-follow reader instead of reopening every candidate during traversal.
- Nested archive scans stream compressed tarballs member-by-member with a single inflate, instead of retaining each full decompressed image or paying a second inflate for TeX probing. TeX provenance continues to gate on tar header names for buffered uncompressed tar, and on zip central-directory names.
- Directory enumeration now walks in parallel, cutting the serial prefix before the first byte is scanned (mirror source-walk 392-419ms to 155-171ms, wall -14.1% on a 15,000-file tree). Findings are byte-identical: entries are still sorted by path before batching, so batch composition and autoroute workload identity are unchanged. Discovery-budget walks (--limit-discovery-bytes, scan-system) deliberately stay serial, because the budget is charged in arrival order and stops at the first over-budget entry, so a parallel walk would admit a different subset on every run.

- Delete 235 source-grep shape tests across the five crate test trees. Each read a .rs file at runtime and asserted only substring presence or absence on that text, so they pinned how the source is spelled rather than what the scanner does; the project standard bans them. 107 test files went away entirely, 57 files lost individual tests, and every mod registration plus three Cargo [[test]] entries went with them. Two ambient-env gates (KEYHOG_THREADS, KEYHOG_DETECTORS) became four behavioural tests that drive the binary and read `config --effective` and `detectors --format json`. Each is a negative assertion, so each is paired with a positive case on the same output field, and both oracles were ablated to confirm the comparison discriminates: KEYHOG_THREADS=99 leaves `threads = auto` while --threads 3 moves the same line to 3, and KEYHOG_DETECTORS pointing at a one-detector directory leaves the corpus intact while --detectors on that directory reduces it to one. 23 source pins for network and filesystem security boundaries are kept deliberately: verifier_safety_contracts.rs, the DNS-pin and no-auto-decompression gates, the verifier proxy owner, the git safe-bin and no-follow-symlink gates, and the hosted-Git credential temp-file permission contract. That last pin was repointed at the whole hosted_git module after the module split moved the code it reads out of hosted_git.rs, which had silently made its negative assertions vacuous, and it now asserts an anchor first so it fails loudly rather than passing for free the next time the module is reorganised.

- Detect container formats by content signature rather than by filename extension. An archive member or file whose name carried no recognized extension was never opened, so a secret inside it was missed and the scan reported clean with no error row. This is the normal shape of an OCI layer, which is named by digest. Members with no in-memory extractor now emit a counted error row instead of vanishing.
- Named detectors can fire on binary-derived content again. Admission past the binary-strings noise gate required a declared `[detector.credential_shape]`, which 4 of 925 detector TOMLs carry, so 921 named detectors could never report a finding in an ELF, PE, Mach-O, wasm, static archive, shared object, archive member or container layer; the same tar.gz reported `aws-access-key` and silently dropped `slack-bot-token` purely because one TOML had the block. A match is now admitted on per-match structural proof, a declared shape or a span covering a whole lexical token, while generic, weak-anchor and free-form password-slot detectors stay suppressed, and a withheld match is counted as a `binary_strings_named_exclusions` coverage gap instead of vanishing. Expect new findings on compiled artifacts and container images that previously reported clean: a planted Slack token goes from 0 to 14 of 15 binary variants, and 249 MiB of real system ELF goes from 0 to 4 findings. Printable runs are also emitted in file order with every occurrence kept, replacing an alphabetical whole-input dedup that made two runs neighbours because they shared a prefix, and joined by a separator no whitespace, non-whitespace or dot class can cross, so a pattern can no longer bridge runs that were never adjacent.
- Large filesystem windows now decode through bounded overlapping subwindows, recovering encoded credentials beyond the default decode working-set ceiling without raising that ceiling.
- BufferedStdinSource now records the same SourceAcquire and SourceRead profile spans as spooling stdin, so pre-owned stdin payloads no longer appear unprofiled while still charging input totals.
- Container layer path normalization now keeps scanning members whose names begin with `#`, only peeling HAR `#url` suffixes when the member body remains non-empty.
- Installed scans stream authenticated detector plans from execution packs without decoding detector schemas, validate canonical matcher envelopes in one typed JSON pass, build prefix propagation through a flat arena trie instead of one hash table per trie node, co-locate each lazy regex's compiled cell and memoized source facts under one shared owner, share compiled signature strings with post-processing, and compile companion regexes and pattern-shape validator sets only when their evidence is first required. The entropy precision gate consumes an exact build-packed cl100k rank table without constructing the tokenizer's duplicate encoder, decoder, sorted-token, and thread-local regex graphs. Report-time remediation validation uses the build-generated detector ID index instead of reparsing the embedded detector corpus after a finding. Compiled detector plans share equal confidence policies across the detector table and keep sparse entropy, shape, and suppression policies in a compact indexed side table. Small detector-owned keyword vocabularies use compact flat byte tables instead of retaining one Aho-Corasick automaton per detector. Phase-two no-candidate gates are scoped to the active residual route, and phase-two anchor lookup tables share literal sources with the lazy runtime rows before the lookup tables are released. The large phase-two, confirmed shared-anchor, and confirmed suffix-gate automata materialize only for a non-empty batch, then their compiler arenas are purged before per-chunk scanning. Sparse files stream only allocated extents and report all-hole files as uncovered regions, stdin validates its byte cap through an anonymous spool before scanning bounded overlapping windows, and bounded stdin windows use a rendezvous-fed fused scan batch instead of accumulating the complete input. Empty stdin remains an explicit zero-byte coverage gap instead of reporting an unearned clean scan. Fused source boundaries default to rendezvous channels, homoglyph prescreening no longer materializes Unicode matchers for unrelated replacement characters, and the one-long-line benchmark now contains one delimited canary on one physical line. Large unbounded filesystem walks retain deterministic path order in one common-root byte slab and compact row/index tables instead of one allocated absolute path per file. The archive-symlink audit streams unbounded directory entries and skips duplicate regular-file metadata checks while no-follow read paths retain link-swap protection. Installed-pack benchmark captures bind detector runtime provenance per workload so catalogs that intentionally use multiple detector corpora remain exact.
- Linux filesystem scans now traverse and safely open paths beyond the pathname syscall limit with directory descriptors while preserving deterministic ordering and symlink protections.
- Filesystem scans now reconstruct an empty relative walk path as the directly requested file itself instead of appending a directory separator and reporting zero coverage.
- Large unbounded Unix filesystem walks external-merge deterministic native-byte path metadata through bounded temporary runs instead of retaining one row and sort index per file.
- Unbounded Unix filesystem discovery releases its final in-memory sort slabs before mapping the external merge spool, lowering peak RSS without changing enumeration.
- `--github-api-endpoint` is now applied to `--github-org` scans (factory previously ignored it).
- Default GitHub wiki clone URLs now follow the configured API endpoint host (GHES-safe).
- Screen the destination of a self-hosted GitLab or Bitbucket API endpoint before sending the operator's token to it. `--gitlab-endpoint` and `--bitbucket-endpoint` validated the scheme, embedded credentials and the query, and never asked where the request was going, so `https://169.254.169.254`, `https://10.0.0.5` and `http://127.0.0.1` were accepted and the PRIVATE-TOKEN or Basic credential was carried there. Every other remote source already refused this: S3, GCS and Azure screen through the cloud endpoint gate and WebSource refuses loopback outright, so hosted git was the one hole, and a test in the tree asserted the hole was expected behaviour. Both endpoints now use one shared screen that checks the literal host against the canonical SSRF classifier and re-screens every resolved address, so a public hostname whose A record points at a metadata address is refused too; the approved addresses are pinned into the client so the connection cannot re-resolve after the check. BREAKING for on-premises deployments: a self-hosted GitLab or Bitbucket on a private address now exits 13 unless `--allow-private-cloud-endpoint` is passed. That flag already existed and already governed the cloud object stores, and now means what its name says across every remote source. It is deliberately not implied by supplying an endpoint, because the failure being fixed was treating an endpoint as consent to send a credential to it.
- Scanning one large file cost roughly 3.8x its own size in peak memory, so a big enough file ran out of RAM. Three causes, all between read and scan. The filesystem reader collected EVERY window of a file into a Vec and sent nothing until the whole file was read, so a 300 MiB file held all ~343 of its 1 MiB windows live at once and the scan pool sat idle through the read; sampling /proc showed one thread accumulating 617 MB with 31 cores doing nothing. The windowed mmap never released pages it had already walked past. And every queue bound between the source and the scan workers counts chunks rather than bytes, which is ~128 KiB per batch on a small-file corpus and ~32 MiB on one big file, so the large-file regime carried over a gigabyte of queue headroom and split into only ~11 work units for 32 cores. The reader now streams each file's windows in byte-bounded parts (a small file is still exactly one send), the slicer returns each stride with MADV_DONTNEED as it leaves it behind, and the fused batch cut is byte-aware as well as count-aware. Isolating this change alone: one 300 MiB file 1,156,720 -> 772,972 KB peak and 4.79 -> 3.78 s; one 1 GiB file 3,131,944 -> 804,400 KB and 13.89 -> 9.76 s; the 300 x 1 MiB control also improved (862,896 -> 766,216 KB), so the cost was removed rather than moved. Total CPU-seconds are unchanged, so the wall gain is read/scan overlap that was not happening before. Peak memory is now flat in file size instead of proportional to it: +9% across a 3.5x size increase, against +171% before. Findings are byte-identical, and secrets planted at every one of the 21 ways a 20-byte credential can straddle a window cut are each still found exactly once with the correct absolute byte offset and line. NOTE: batches are now cut on bytes as well as chunk count, which changes the workload key autoroute measures against, so the compiled-in fused batch byte ceiling is hashed into the autoroute config digest. Any calibration persisted before this change reads as a config mismatch and is measured again on the next --autoroute-calibrate run. That is intended: replaying a decision timed under different batching would be measuring something else. No flag or output changes, and a scan that has never calibrated is unaffected.
- Stop reporting a stale binary-asset channel as current, and name the real Hyperscan library when an install fails. `keyhog update` compared the running build against the newest GitHub release asset and printed "already on the latest release" whenever nothing newer existed there, so a build newer than that channel, which every release since v0.5.47 is, was told it was up to date forever; it now distinguishes being on the newest asset from being ahead of a channel that stopped publishing, and names `cargo install --locked --force keyhog` in the second case. The installer's missing-library remediation matched the glob `*libhyperscan*`, but the published Linux binary declares `NEEDED libhs.so.5`, so a clean host got the loader error and no fix at all; it now matches the real SONAME plus the `libvectorscan` spelling, and any unrecognized library gets a generic lookup hint instead of dead-ending. The shipped artifact's runtime dependencies are also deterministic again: `lzma-sys` linked the system liblzma whenever `pkg_config` found one and vendored it otherwise, so the same commit produced binaries with or without `NEEDED liblzma.so.5` depending on the build host, and `xz2` is now pinned to a static link for 110,328 bytes.
- Source skip counters (unreadable, binary, over-max-size and the other coverage-gap totals) could be attributed to the wrong scan. The counter-isolation lease was released when a scan's chunk iterator dropped, but the filesystem reader crew records skip events from its own threads and outlives that iterator whenever a consumer stops early, so a finished scan's increments could land in a later scan's window. The lease is now scan-scoped rather than thread-scoped: it is held by every thread doing work for the scan and released only when the last one finishes, and the recording call itself carries the gate. Coverage-gap events are delayed rather than dropped, so a gap is never lost.
- A shallow clone no longer reports its truncated history as a clean scan. `keyhog scan --git-history` and `--git-blobs` against a `git clone --depth N` checkout gave exit 0, scan_status success, and an EMPTY coverage_gap_summary, while a full clone of the same repository reported a credential that had been committed and later removed: the commits holding it were never fetched, so the scan searched history that was not there and said nothing. The parent commits named at the graft boundary but absent from the object database are now counted as unscanned Git objects, so such a scan reports scan_status partial with a `Git object unreadable` coverage-gap row and exits 13, and stderr names `git fetch --unshallow` and `actions/checkout` `fetch-depth: 0` as the remedy. This is a user-visible exit-code change and it fires on the common CI shape, because `actions/checkout` fetches one commit by default, so any job that scans history on an unmodified checkout moves from a green tick to exit 13; fix the checkout depth rather than suppressing the code, since the exit is reporting that the input never contained the history you asked it to search. Findings are never discarded: a shallow clone that does contain credentials still reports every one of them, byte-identical to before, with the gap row added rather than substituted, and a depth-1 clone of a single-commit repository stays a genuine success because its graft boundary is the root commit and hides no parent.
- Source limits are exact at their boundary and honest about which ones a build can reach. A git output line whose content is exactly `--limit-git-line-bytes` is now scanned instead of refused: the cap counted the trailing newline, so an at-cap line produced a coverage gap for input that was inside the limit, and identical content was judged differently depending on whether it ended the stream. `keyhog config --effective` no longer prints a numeric value for a limit whose source backend is not compiled in; those rows now read `unavailable (requires the <feature> feature in this keyhog build)`, matching the flag that is absent from `scan --help` and the `.keyhog.toml` key that was already rejected. All 22 declared limits now have a CLI test proving each admits exactly its cap, refuses one byte or item more, and surfaces the refusal as a coverage gap rather than dropping input silently.

- Cap the number of tar entries KeyHog walks in a docker archive or layer. The existing byte guard sums each entry's payload size, so an archive built entirely from zero-length entries never advanced it and could be walked without bound: a 4.4 MB gzip expands into two million tar headers, each costing a filesystem syscall during unpack. Entries past the cap are refused and counted as a coverage gap rather than silently truncated.
- GitHub collaboration and org API endpoints now fail closed through the shared hosted-git SSRF screen before any bearer token leaves the process.
- GitHub wiki clone URLs now pass the shared clone-origin screen, and api.github.com maps to github.com for HTTPS clones.
- Bind hosted-git askpass credentials to exact URL host boundaries, not origin substrings
- Bound the work the PDF text extractor may spend, not just the bytes it may output. The decoded-output cap limited how much text a PDF could produce but placed no limit on the effort of producing it: the literal-string parser restarted at every open parenthesis and an unbalanced literal made each attempt rescan to end of buffer, so a file of repeated unbalanced nesting was quadratic and got worse with size. A 400 KB file took 34.5 seconds of CPU and a 10 MB one, well inside the default file cap, never finished. Such a file arrives from a repository, an archive member or a docker layer without anyone choosing to parse it. Extraction now stops at a measured work ceiling and reports a counted coverage gap, and strings already recovered before the ceiling are still reported rather than discarded.
- Refuse Slack API HTTP redirects so bearer tokens cannot pivot after the first request

## 0.5.68 - 2026-08-05

- Scanner source files freed of large co-located test suites.
- Verify that oversized TeX archive members remain scannable across every bounded extraction window when provenance analysis reaches its size cap.

## 0.5.67 - 2026-08-05

- Pin that filesystem enumeration yields every file exactly once, in sorted path order, identically across repeated walks. Batch composition follows enumeration order and autoroute keys its persisted decisions by batch shape, so a walk that varied run to run would make a calibrated cache miss on replay. The property was implicit; it is now asserted over twenty walks of the same tree.

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

- Token-boundary anchoring and an actionable autoroute parity rejection.

## 0.5.58 - 2026-08-04

- README evidence panels remeasured against the current binary.

## 0.5.57 - 2026-08-04

- Repeatable autoroute calibration.

## 0.5.56 - 2026-08-04

- Overlapping coalesced batches and autoroute classification for any batch size.

## 0.5.55 - 2026-08-04

- Make the keyhog-sources contract-test generator idempotent by formatting its own output, so re-running it no longer produces a large formatting-only diff, and give the generated rejected-extension cases snake_case names. The workspace now builds all targets without a warning.

## 0.5.54 - 2026-08-04

- Skip homoglyph variants on chunks that provably contain no confusable glyph.

## 0.5.53 - 2026-08-04

- Make the coalesced batch pipeline eleven times faster and stop starving the accelerator.

## 0.5.52 - 2026-08-04

- Refuse configuration fields the scanner cannot honour and check every documented command against the real CLI.

## 0.5.51 - 2026-08-04

- Assert source-instrumentation tests see no coverage errors instead of silently discarding error rows while collecting chunks, so a profiled adapter that starts failing shows up as a failure rather than a smaller chunk count.

- Match source-ownership gates on the arguments and constructs they exist to protect rather than on exact indentation, closure parameter names, or a function name a rename had already changed.
- Fail closed with a source error when the single-flight pinned web client builder is missing, instead of panicking inside the client cache and ending the scan.

## 0.5.50 - 2026-08-02

- Publish a patch release to crates.io after every successful main CI run, with automatic version and changelog updates and no signing or release-asset gates.

- Bound scan-system metadata discovery by the remaining --space budget so small host-scan ceilings stop promptly and report partial coverage instead of traversing the entire filesystem first.

## 0.5.49 - 2026-07-30

- A single resumable local or SSH command now refreshes benchmark evidence without invalidating candidate freshness, rebinds the exact canonical run-set after scoring, prepares every changelog and version surface, runs pre-tag gates with isolated full and ci-lean binary contracts, preserves exact Git path bytes, verifies the configured OpenPGP fingerprint before any tag push, and watches GitHub Pages, release assets, containers, and the six-crate crates.io publication chain.
- Serialize every source scan against counter-asserting test scopes from the first scan onward, preventing in-flight scans from polluting process-global skip counts.
- Docker save scans now prefer `manifest.json` layers over an embedded OCI index, ignore symbolic and hard link layer entries safely, preserve nested archive member labels and binary source provenance, and route large native binaries through printable-string extraction instead of lossy text windows.

## 0.5.48 - 2026-07-28

- Preserve source-backend process-isolation contracts in the split integration
  lanes and bind the package candidate to its signed SPDX dependency graph.


## 0.5.47 - 2026-07-26

- Bind the crate release identity to the KeyHog installer-recovery patch so
  exact internal dependency pins and the published package graph remain
  coherent.

## 0.5.46 - 2026-07-24

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

## 0.5.45 - 2026-07-22

- Republish source backends in the release chain whose signed asset publication
  addresses GitHub drafts by immutable release ID.

## 0.5.44 - 2026-07-22

- Republish source backends in the corrected five-crate release chain after
  the Windows GPU literal artifact generator fix.

## 0.5.43 - 2026-07-22

- Declare the filesystem and git-diff sources' contiguous chunk-identity
  ordering contract for safe provenance-aware autoroute batching.
- Surface oversized Git diff, history, and tag lines as counted source errors
  instead of silently continuing after telemetry.
- Remove shifted UTF-16 LE/BE suffix duplicates by comparing recovered byte
  spans while preserving valid strings in both byte orders.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep filesystem, archive, git, web, Docker, GitHub, Slack, and S3 source APIs available for the 0.2 line.
