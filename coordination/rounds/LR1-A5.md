# LR1-A5

LOCK: `crates/sources/**`

## Hunt

- finding count: **7** (1 fixed KH-GAP-019, 6 open KH-GAP-013..018)
- **Binary read:** `read_binary_capped` + 64 MiB cap (`MAX_BINARY_READ_BYTES`); KH-GAP-019 fixed; KH-GAP-010 (streaming) still open elsewhere
- **Git:** `resolve_safe_bin("git")`, `--end-of-options`, `validate_repo_path` canonicalize + `.git` check; blob caps 10 MiB / 256 MiB total
- **Archives:** jar/apk unpack with 4× `max_file_size` budget, per-entry cap, symlink refusal; `.zip` in `SKIP_EXTENSIONS` (KH-GAP-018)
- **Timeouts:** `HTTP_REQUEST` 30s, `GIT_CLONE`/`GHIDRA_ANALYSIS` 300s centralized in `timeouts.rs`
- **Symlinks:** walker `follow_symlinks(false)`, Unix `O_NOFOLLOW`, archive symlink skip; Windows TOCTOU (KH-GAP-014)
- **Residual:** `read_file_safe` still `read_to_end` unbounded (KH-GAP-013); inline tests + god files (KH-GAP-015..017)

## Tests added

- count: **56** new one-`#[test]` files (+ `tests/support/git.rs` helper)
- directories:
  - `tests/gap/` — 20 new (binary/git/archive/timeout/mmap/symlink source audits)
  - `tests/adversarial/` — 18 new (bombs, malformed compression, git ref injection, magic-byte reject)
  - `tests/contract/` — 10 new (source names, create_source, metadata, counters)
  - `tests/integration/` — 8 new (git blob/history/diff, windowed offsets, ignore rules, binary fallback)
- wired in `tests/*/mod.rs`, `tests/all_tests.rs`
- fix: `binary_oversized_file_survives.rs` uses `strings_only`, no panic when `binary` feature off

## Commands

```bash
env -u CC cargo test -p keyhog-sources --test all_tests -- --test-threads=8 --skip http_fuzz --skip filesystem_fuzz
```

→ **161 passed; 9 failed** (all pre-existing `unit::gates/*` bar-miss gates from parallel A8 inventory — not A5 slice)

Full suite (includes proptest http_fuzz — slow, network-adjacent):

```bash
env -u CC cargo test -p keyhog-sources --test all_tests
```

→ not run to completion (http_fuzz proptest >10 min); A5 modules all green in targeted run above.

With `binary` feature:

```bash
env -u CC cargo test -p keyhog-sources --test all_tests --features binary -- adversarial::binary
```

## GAP_FINDINGS appended

- KH-GAP-013 — `read_file_safe` unbounded `read_to_end`
- KH-GAP-014 — Windows symlink TOCTOU
- KH-GAP-015 — inline tests in `filesystem/read.rs`
- KH-GAP-016 — `web.rs` >500 LOC
- KH-GAP-017 — `filesystem/read.rs` >500 LOC
- KH-GAP-018 — `.zip` skipped by extension list
- KH-GAP-019 (fixed) — binary capped read via `read_binary_capped`
