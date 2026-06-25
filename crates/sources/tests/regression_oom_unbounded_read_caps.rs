//! LANE 5 (sources-safety) OOM regression: mmap-failure fallback reads must be
//! BOUNDED, never an unbounded slurp of a TOCTOU-grown file. Locked files are
//! not fallback-readable at all: lock contention is a counted unreadable skip,
//! not permission to reopen the path unlocked.
//!
//! Two holes existed:
//!   * `read/raw.rs::read_file_mmap` fell back to a bare `read_to_end(&mut file)`
//!     (no `.take`) when mmap failed — unbounded, so a file grown past the
//!     walker's stat between the walk and this read could OOM the process,
//!     defeating the very `MMAP_TOCTOU_SANITY_CAP_BYTES` ceiling the mmap path
//!     enforces.
//!   * `read/bytes.rs::read_file_for_compressed_input` fell back to a bare
//!     `std::fs::read(path)` — both UNBOUNDED (same OOM) and symlink-FOLLOWING
//!     (re-opening the path with libc defaults, undoing the `O_NOFOLLOW` guard
//!     the mmap open just applied).
//!
//! These are structural pins: the unbounded/symlink-following idioms must be
//! absent and the bounded no-follow helper present. A behavioural OOM test would
//! require allocating multi-GiB to trip the cap; the source pin is the durable,
//! cheap regression guard, paired with the behavioural decompression-bomb tests
//! (`regression_decompression_bomb_and_oom_caps.rs`) that prove the decode-side
//! cap actually bounds memory.

fn read_src(rel: &str) -> String {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn mmap_fallback_buffered_reads_are_capped() {
    let raw = read_src("src/filesystem/read/raw.rs");
    // The bare unbounded slurp must be gone.
    assert!(
        !raw.contains("read_to_end(&mut file, &mut bytes)"),
        "read_file_mmap must NOT fall back to an unbounded `read_to_end(&mut file, ...)`: \
         a TOCTOU-grown file would OOM the process. Bound it with `capped_read::read_to_cap`."
    );
    let mmap_fn_start = raw
        .find("pub(in crate::filesystem) fn read_file_mmap")
        .expect("read_file_mmap function");
    let lock_start = raw[mmap_fn_start..]
        .find("if unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } != 0")
        .map(|offset| mmap_fn_start + offset)
        .expect("raw read mmap lock branch");
    let mmap_start = raw[lock_start..]
        .find("// SAFETY: the mapping is read-only")
        .map(|offset| lock_start + offset)
        .expect("mmap section after lock branch");
    let lock_branch = &raw[lock_start..mmap_start];
    assert!(
        lock_branch.contains("SourceSkipEvent::Unreadable")
            && lock_branch.contains("scanning a torn write"),
        "locked-file contention must skip visibly as unreadable"
    );
    assert!(
        !lock_branch.contains("read_to_end")
            && !lock_branch.contains("crate::capped_read::read_to_cap"),
        "locked-file contention must not have a buffered fallback; it must skip visibly"
    );
    assert!(
        raw.contains("crate::capped_read::read_to_cap")
            && raw.contains("MMAP_TOCTOU_SANITY_CAP_BYTES")
            && raw.contains("read.truncated")
            && raw.contains("SourceSkipEvent::OverMaxSize"),
        "the mmap-failure buffered fallback must use the shared capped-read owner and count over-cap growth"
    );

    let extract = read_src("src/filesystem/extract.rs");
    assert!(
        extract.contains("refusing large-file buffered fallback: live size exceeds mmap sanity cap")
            && extract.contains("cannot stat large file for buffered fallback sanity cap; skipping")
            && extract.contains("read::MMAP_TOCTOU_SANITY_CAP_BYTES")
            && extract.contains("SourceSkipEvent::OverMaxSize")
            && extract.contains("SourceSkipEvent::Unreadable"),
        "large-file buffered fallback after windowed-mmap refusal must re-prove the hard mmap sanity cap and fail closed when it cannot"
    );
}

#[test]
fn compressed_fallback_read_is_bounded_and_no_follow() {
    let bytes = read_src("src/filesystem/read/bytes.rs");
    // The symlink-following, unbounded `std::fs::read(path)` fallbacks must be gone.
    assert!(
        !bytes.contains("std::fs::read(path)"),
        "read_file_for_compressed_input must NOT fall back to `std::fs::read(path)`: it \
         FOLLOWS symlinks (undoing the O_NOFOLLOW guard) and is UNBOUNDED (OOM on a \
         TOCTOU-grown compressed file). Use the bounded no-follow helper instead."
    );
    // The bounded, no-follow helper must exist and remain used for the
    // mmap-failure fallback.
    assert!(
        bytes.contains("fn read_capped_no_follow"),
        "the bounded no-follow read helper must exist"
    );
    assert!(
        bytes.contains("open_file_safe(path)")
            && bytes.contains("crate::capped_read::read_to_cap")
            && bytes.contains("read.truncated")
            && bytes.contains("SourceSkipEvent::OverMaxSize"),
        "read_capped_no_follow must open via open_file_safe, use the shared capped-read owner, and count over-cap growth"
    );
    let used = bytes.matches("read_capped_no_follow(path,").count();
    assert!(
        used >= 1,
        "the mmap-failure fallback must route through \
         read_capped_no_follow (found {used} use(s), expected >= 1)"
    );
    assert!(
        !bytes.contains("compressed file is locked; falling back to buffered read"),
        "compressed locked-file contention must not reopen and buffered-read the path unlocked"
    );
}

#[test]
fn seven_zip_entry_reads_are_capped() {
    let seven_zip = read_src("src/filesystem/extract/seven_zip.rs");
    assert!(
        !seven_zip.contains("entry_reader.read_to_end(&mut content)"),
        "7z entries must not use bare read_to_end: a forged or expanding entry would allocate beyond the per-entry/archive bomb budget"
    );
    assert!(
        seven_zip.contains("let read_cap = per_entry_cap.min(remaining_budget)")
            && seven_zip.contains("crate::capped_read::read_to_cap(")
            && seven_zip.contains("read.truncated && read_cap == per_entry_cap"),
        "7z entry reads must use the shared capped-read owner with the smaller of per-entry cap and remaining archive budget"
    );
    let per_entry_branch = seven_zip
        .find("if read.truncated && read_cap == per_entry_cap")
        .expect("7z per-entry overflow branch");
    let aggregate_branch = seven_zip[per_entry_branch + 1..]
        .find("if read.truncated")
        .map(|offset| per_entry_branch + 1 + offset)
        .expect("7z aggregate-budget overflow branch");
    assert!(
        per_entry_branch < aggregate_branch
            && seven_zip[per_entry_branch..aggregate_branch].contains("SourceSkipEvent::OverMaxSize"),
        "7z decoded-entry overflow must be classified as over-max-size before falling through to aggregate archive truncation"
    );
}

#[test]
fn rar_entry_sink_uses_remaining_archive_budget() {
    let rar = read_src("src/filesystem/extract/rar.rs");
    assert!(
        !rar.contains("RarEntrySink::new(entry_name.clone(), entry_size, state.per_entry_cap)"),
        "RAR entry sinks must not use the static per-entry cap: uncapped mode or late entries can allocate beyond the aggregate archive budget"
    );
    assert!(
        rar.matches("RarEntrySink::new(entry_name.clone(), entry_size, state.sink_cap())")
            .count()
            == 3
            && rar.contains("fn sink_cap(&self) -> u64")
            && rar.contains("self.per_entry_cap")
            && rar.contains("self.total_budget.saturating_sub(self.total_uncompressed)"),
        "RAR entry sinks must cap decoded output to min(per-entry cap, remaining aggregate archive budget)"
    );
}
