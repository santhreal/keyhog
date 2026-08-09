# Changelog

## 0.5.69 - 2026-08-09

- Report resettable counters from production filesystem discovery for root inspection, walk entries, metadata admission, errors, and early termination.

## 0.5.68 - 2026-08-05

- Scanner source files freed of large co-located test suites.

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
