//! PERF tripwire: per-file syscall budget on the many-small-files ingestion
//! hot path (`crates/sources/src/filesystem`).
//!
//! HOT PATH
//! --------
//! `keyhog scan <dir>` of a tree of many small text files routes every file
//! through `filesystem::extract::process_entry`, which for a sub-64-KiB text
//! file (the dominant case in any real source tree) does, per file:
//!
//!   1. `file_mtime_ns(&path)` -> `std::fs::metadata(path)`  (extract.rs:111,
//!      extract.rs:673-678) — a path-based, symlink-FOLLOWING `statx`. Its only
//!      consumer is the merkle/incremental cache: the `live_mtime_ns` it
//!      produces is read in `crates/cli/src/orchestrator/dispatch.rs:378/387`
//!      **only** inside `if let (Some(idx), ...) = (merkle.as_ref(), ...)`.
//!      `merkle` is `Some` only when `--incremental` is passed
//!      (`orchestrator/mod.rs:237-248`). On a DEFAULT scan it is `None`, so this
//!      whole `stat` is pure waste — the walker (`codewalk`) already stat'd the
//!      entry to fill `entry.size`/`entry.is_binary`.
//!   2. `read_file_buffered` -> `read_file_safe` (read/raw.rs:72-102):
//!        * `open_file_safe` -> one `openat(O_NOFOLLOW)`,
//!        * one `posix_fadvise` (`fadvise64`),
//!        * `Vec::new(); file.take(..).read_to_end(&mut bytes)` — an
//!          **un-presized** `read_to_end`. `entry.size` is already known
//!          (it sits in the `FileEntry`), but the buffer starts empty and grows
//!          by doubling, so a tiny file costs MANY small `read(2)` syscalls
//!          (32 -> 64 -> 128 ... + a final 0-byte EOF probe) instead of the two
//!          a `Vec::with_capacity(entry.size)` + sized read would cost.
//!
//! MEASURED (release-fast profile, this machine, 2026-06-02; `strace -f -c`,
//! `--threads 1`, N = 2000 tiny `.txt` files, deterministic across runs):
//!
//!   read              ~13_580   => ~6.8  read(2)        per file
//!   statx             ~12_973   => ~6.5  statx          per file
//!   statx+stat+fstat+newfstatat ~16_600 => ~8.3 metadata stats per file
//!   fadvise64           2_000   =>  1.0  per file  (anchor: buffered path ran once/file)
//!   openat(O_NOFOLLOW)  2_000   =>  1.0  per file  (anchor: one content open/file)
//!
//! At 4000 files the per-file constants hold (read ~5.9/file, statx ~6.0/file),
//! confirming the cost is per-file, not fixed startup — i.e. it scales linearly
//! with file count and dominates many-small-files scans.
//!
//! TARGET (what a properly optimized per-file path costs)
//! ------------------------------------------------------
//!   * read(2) per file: ~2  (one sized read into a `with_capacity(entry.size)`
//!     buffer + one 0-byte EOF probe). `read_to_end` on an empty `Vec` is the
//!     defect.
//!   * metadata stats per file: ~3-4 (the walker's own stat + the post-open fd
//!     stat the std read path issues). Dropping the unused `file_mtime_ns`
//!     follow-`stat` on the non-`--incremental` path removes ~1 full path-stat
//!     per file outright.
//!
//! TRIPWIRE
//! --------
//! Robust by construction: the assertion is a per-FILE syscall RATIO from
//! `strace -c`, so it is hardware-, CPU-, and disk-speed-INDEPENDENT (a syscall
//! count does not change with clock speed). We take the MIN over K runs so a
//! scheduler-induced extra short read can only LOWER the observed count, never
//! trip the wire spuriously. The floors are set with comfortable headroom over
//! the optimized target (read <= 3.5/file vs target ~2; metadata <= 5.0/file vs
//! target ~3-4) so ONLY the current blow-up trips them, never a healthy build.
//!
//! This test does NOT modify any source file. It drives the SHIPPED `keyhog`
//! binary (the exact artifact the audit times) so the measurement reflects the
//! real production read path, not a re-implementation.
//!
//! RECALL GUARD (the optimization must not lose findings): the landed fix is a
//! pure I/O-shape change — presize the read buffer to the walker's known
//! `entry.size` (`read/raw.rs` `read_file_safe`), which returns byte-identical
//! content. It must keep the existing filesystem source->scanner recall tests
//! green — in particular `crates/sources/tests/all_tests.rs` (filesystem
//! read/decode coverage) and `crates/sources/tests/property/filesystem_fuzz.rs`.
//!
//! The originally-proposed second half — gating the per-file `file_mtime_ns`
//! stat on `merkle.is_some()` — was NOT applied: `FilesystemSource` populates
//! `Chunk.metadata.mtime_ns` on every scan by contract (see the three
//! `mtime_ns.is_some()` assertions cited on `MAX_META_STATS_PER_FILE`), so that
//! stat is required, not waste. See that constant for why the metadata budget is
//! now a generous gross-regression backstop rather than the refuted ~3-4 target.

use std::path::PathBuf;
use std::process::Command;

const N_FILES: usize = 4000;
const RUNS: usize = 3;

/// Hard ceiling on `read(2)` syscalls per scanned file. Current ~6.8; an
/// optimized presized read is ~2. 3.5 trips on the blow-up only.
const MAX_READS_PER_FILE: f64 = 3.5;

/// GENEROUS gross-regression backstop on path/fd metadata-stat syscalls per
/// scanned file (statx + stat + fstat + newfstatat). Measured ~7-8.5/file
/// across hosts.
///
/// NOTE — the original "drop the unused `file_mtime_ns` follow-stat → ~3-4/file"
/// target was REFUTED. `file_mtime_ns` is NOT waste: `FilesystemSource` populates
/// `Chunk.metadata.mtime_ns` on EVERY scan (not just `--incremental`), a contract
/// asserted by `tests/integration/filesystem.rs` (mtime_ns.is_some() at L378 and
/// L635) and `tests/gaps/filesystem_source.rs:942`. Gating that stat behind
/// `merkle.is_some()` would break those three tests. The stat also can't be
/// deduplicated against the walker's own stat: `codewalk = "=0.2.5"` (pinned
/// crates.io) exposes only `path`/`size`/`is_binary`, not mtime. So one
/// path-stat for mtime is contract-required, and the remaining stats are
/// codewalk's intrinsic per-entry directory walk — neither is a removable
/// keyhog redundancy. This ceiling therefore only catches a GROSS regression
/// (e.g. a SECOND redundant per-file stat creeping in), not the refuted 3-4
/// target. The controllable, landed win is the `read(2)` budget below.
const MAX_META_STATS_PER_FILE: f64 = 12.0;

/// Locate the shipped `keyhog` binary the audit times. Documented profile:
/// `release-fast`. We accept several discovery routes so the tripwire runs in
/// CI and locally without a hardcoded single path; all of them point at the
/// same source read path, so the syscall ratio is identical regardless of which
/// optimization profile built it.
fn locate_keyhog() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("KEYHOG_PERF_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(t) = std::env::var("CARGO_TARGET_DIR") {
        roots.push(PathBuf::from(t));
    }
    roots.push(PathBuf::from(
        "/mnt/FlareTraining/santh-archive/cargo-target",
    ));
    // Fallback: walk up from the test binary's own dir to a `target`-like root.
    if let Ok(exe) = std::env::current_exe() {
        // .../<root>/release-fast/deps/perf_io_path-<hash>
        let mut cur = exe.as_path();
        while let Some(parent) = cur.parent() {
            roots.push(parent.to_path_buf());
            cur = parent;
        }
    }
    // Prefer release-fast (the documented audit artifact), then release, then
    // debug — all share the same syscall shape.
    for root in &roots {
        for profile in ["release-fast", "release", "debug"] {
            let cand = root.join(profile).join("keyhog");
            if cand.is_file() {
                return Some(cand);
            }
        }
        let direct = root.join("keyhog");
        if direct.is_file() {
            return Some(direct);
        }
    }
    None
}

fn have_strace() -> bool {
    Command::new("strace")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build a corpus of `N_FILES` tiny, clean (no-secret) text files with a
/// `.txt` extension so every file takes the buffered sub-`MMAP_THRESHOLD`
/// (64 KiB) read path in `process_entry`. Clean content keeps the scan exit
/// code at 0 and isolates the *ingestion* cost from match reporting.
fn build_corpus(dir: &std::path::Path) {
    for i in 0..N_FILES {
        let body = format!(
            "config entry number {i}\nplain text value line {i}\nnothing secret here at all {i}\n"
        );
        std::fs::write(dir.join(format!("file_{i}.txt")), body).expect("write corpus file");
    }
}

/// Run the binary under `strace -f -c` and return per-syscall call counts
/// parsed from the summary table. The `calls` column is field index 3
/// (0-based) and the syscall name is the LAST field.
fn strace_syscall_counts(
    bin: &std::path::Path,
    scan_dir: &std::path::Path,
) -> std::collections::HashMap<String, u64> {
    let summary = tempfile::NamedTempFile::new().expect("strace summary temp");
    let summary_path = summary.path().to_path_buf();

    let status = Command::new("strace")
        .arg("-f")
        .arg("-c")
        .arg("-e")
        .arg("trace=read,statx,stat,fstat,newfstatat,lstat,openat,fadvise64")
        .arg("-o")
        .arg(&summary_path)
        .arg(bin)
        .arg("scan")
        .arg(scan_dir)
        .arg("--threads")
        .arg("1")
        // findings-or-not is irrelevant; we only measure ingestion syscalls.
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawn strace");
    // exit 0 (clean) or 2 (findings) are both fine; a crash is not.
    assert!(
        status.code().map(|c| c == 0 || c == 2).unwrap_or(false),
        "keyhog under strace exited unexpectedly: {status:?}"
    );

    let text = std::fs::read_to_string(&summary_path).expect("read strace summary");
    let mut counts = std::collections::HashMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // A data row looks like: "% time seconds usecs/call calls [errors] name"
        // -> at least 5 fields, field[3] numeric (calls), field[last] = name.
        if fields.len() < 5 {
            continue;
        }
        let name = *fields.last().unwrap();
        if let Ok(calls) = fields[3].parse::<u64>() {
            // Skip the "total" footer row (its last field is "total").
            if name != "total" {
                *counts.entry(name.to_string()).or_insert(0) += calls;
            }
        }
    }
    counts
}

#[test]
fn io_path_per_file_syscall_budget_is_not_blown() {
    let bin = locate_keyhog().unwrap_or_else(|| {
        panic!(
            "PERF-io_path tripwire could not locate a `keyhog` binary. Build it \
             (CARGO_TARGET_DIR=/mnt/FlareTraining/santh-archive/cargo-target \
             cargo build -p keyhog --profile release-fast) or set KEYHOG_PERF_BIN. \
             A perf tripwire must MEASURE, not silently pass — refusing to no-op."
        )
    });
    assert!(
        have_strace(),
        "PERF-io_path tripwire requires `strace` to count per-file syscalls \
         (the metric is hardware-independent only as a syscall RATIO). Install \
         strace; refusing to silently pass."
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    build_corpus(tmp.path());

    // Best-of-K: keep the MINIMUM observed per-file count. Extra short reads
    // from scheduler jitter can only raise a single run's count, so the min is
    // the tightest, least-flaky estimate of the structural per-file cost.
    let mut min_reads_per_file = f64::INFINITY;
    let mut min_meta_per_file = f64::INFINITY;
    let mut anchor_ok = false;
    let n = N_FILES as f64;

    for _ in 0..RUNS {
        let c = strace_syscall_counts(&bin, tmp.path());
        let get = |k: &str| *c.get(k).unwrap_or(&0) as f64;

        let reads = get("read");
        let meta = get("statx") + get("stat") + get("fstat") + get("newfstatat") + get("lstat");
        let fadvise = get("fadvise64");
        let opens_nofollow = get("openat"); // includes a per-file content open

        // Anchor sanity: the buffered read path must have run ~once per file.
        // `fadvise64` is emitted exactly once per `read_file_safe`. If this
        // anchor is wildly off, the corpus didn't take the path we think and
        // the ratio would be meaningless — surface that instead of asserting on
        // garbage.
        if fadvise >= n * 0.9 && opens_nofollow >= n * 0.9 {
            anchor_ok = true;
        }

        min_reads_per_file = min_reads_per_file.min(reads / n);
        min_meta_per_file = min_meta_per_file.min(meta / n);
    }

    assert!(
        anchor_ok,
        "PERF-io_path anchor failed: expected ~1 fadvise64 and ~1 openat per \
         file across {N_FILES} files (the buffered read path). The corpus did \
         not take the expected sub-64KiB buffered path; measurement invalid."
    );

    // ---- PERF-io_path-2: un-presized read_to_end blows up read(2) count ----
    assert!(
        min_reads_per_file <= MAX_READS_PER_FILE,
        "PERF-io_path-2 TRIPWIRE FAILED (un-presized read_to_end on the buffered \
         small-file path).\n  measured: {min_reads_per_file:.2} read(2) syscalls/file \
         (best of {RUNS}, N={N_FILES})\n  target:   <= {MAX_READS_PER_FILE:.1} read/file \
         (optimized ~2: one sized read into Vec::with_capacity(entry.size) + one \
         EOF probe)\n  defect:   crates/sources/src/filesystem/read/raw.rs:99-100 \
         `let mut bytes = Vec::new(); file.take(..).read_to_end(&mut bytes)` grows \
         the buffer by doubling, costing many small reads per tiny file even \
         though entry.size is already known.\n  fix: thread the known size into \
         read_file_buffered and pre-allocate the buffer."
    );

    // ---- PERF-io_path metadata-stat GROSS-REGRESSION backstop --------------
    // (Generous ceiling: the per-file mtime stat is contract-required and the
    // rest are codewalk's intrinsic walk — see MAX_META_STATS_PER_FILE. This
    // only fires if a SECOND redundant per-file stat creeps in.)
    assert!(
        min_meta_per_file <= MAX_META_STATS_PER_FILE,
        "PERF-io_path metadata-stat GROSS-REGRESSION backstop tripped.\n  \
         measured: {min_meta_per_file:.2} metadata-stat syscalls/file \
         (statx+stat+fstat+newfstatat, best of {RUNS}, N={N_FILES})\n  ceiling:  \
         <= {MAX_META_STATS_PER_FILE:.1}/file (a GROSS-regression backstop, not a tight \
         target)\n  expected floor: ~7-8.5/file = codewalk's intrinsic per-entry \
         walk + the ONE contract-required `file_mtime_ns` stat that populates \
         Chunk.metadata.mtime_ns (asserted is_some() by tests/integration/\
         filesystem.rs and tests/gaps/filesystem_source.rs). A value above the \
         ceiling means a NEW redundant per-file stat was added (e.g. a second \
         path-stat, or an fd-stat the small-file buffered path does not need). \
         Find and remove the added stat; do NOT drop file_mtime_ns (it is the \
         mtime_ns contract and codewalk \"=0.2.5\" does not surface mtime)."
    );
}
