# Changelog

## Unreleased

- Declare the filesystem and git-diff sources' contiguous chunk-identity
  ordering contract for safe provenance-aware autoroute batching.

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
- Mark `s3_ambient_credential_forward` with `required-features = ["s3"]` so default `keyhog-sources` tests no longer compile an S3-only integration test without the S3 module.
- Move inline helper tests into registered external source tests via a hidden internal test facade, and clear the no-inline/no-production-unwrap gates for filesystem, binary literals/sections, GitHub org, HTTP, and web sources.
- Move hosted-git git-error redaction into `hosted_git/sanitize.rs`, keeping
  clone stderr sanitization shared across GitHub, GitLab, and Bitbucket sources.
- Move WebSource SSRF/redaction/DNS-pinning helpers into `web/ssrf.rs`, bringing `web.rs` under the 500-line modularity target.
- Move filesystem per-entry extraction into `filesystem/extract.rs` and walker/filter policy into `filesystem/filter.rs`, bringing `filesystem.rs` under the 500-line modularity target and wiring the zip archive skip-list regression into the aggregate source tests.
- Fix HTTP property-test env isolation, split 10k-case policy fuzzing from bounded reqwest builder/client smoke fuzzing, and use direct proptest regression files for HTTP/filesystem property tests so aggregate source gates run without `http_fuzz` skips.
- Run filesystem reading on a dedicated Rayon pool so bounded-channel backpressure cannot starve scanner work on the global Rayon pool during large-tree scans.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep filesystem, archive, git, web, Docker, GitHub, Slack, and S3 source APIs available for the 0.2 line.
