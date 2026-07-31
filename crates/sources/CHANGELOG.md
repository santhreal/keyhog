# Changelog

## 0.5.49 - 2026-07-30

- A single resumable local or SSH command now refreshes benchmark evidence without invalidating candidate freshness, rebinds the exact canonical run-set after scoring, prepares every changelog and version surface, runs pre-tag gates with isolated full and ci-lean binary contracts, preserves exact Git path bytes, verifies the configured OpenPGP fingerprint before any tag push, and watches GitHub Pages, release assets, containers, and the five-crate crates.io publication chain.

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
