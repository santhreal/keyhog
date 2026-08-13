//! LANE 5 (sources-safety) OOM regression: mmap-failure fallback reads must be
//! BOUNDED, never an unbounded slurp of a TOCTOU-grown file. Locked files are
//! not fallback-readable at all: lock contention is a counted unreadable skip,
//! not permission to reopen the path unlocked.
//!
//! Two holes existed:
//!   * `read/raw.rs::read_file_mmap` fell back to a bare `read_to_end(&mut file)`
//!     (no `.take`) when mmap failed, unbounded, so a file grown past the
//!     walker's stat between the walk and this read could OOM the process,
//!     defeating the very `MMAP_TOCTOU_SANITY_CAP_BYTES` ceiling the mmap path
//!     enforces.
//!   * `read/bytes.rs::read_file_for_compressed_input` fell back to a bare
//!     `std::fs::read(path)`: both UNBOUNDED (same OOM) and symlink-FOLLOWING
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
fn whole_file_read_is_capped_and_never_maps() {
    let raw = read_src("src/filesystem/read/raw.rs");
    // The bare unbounded slurp must be gone.
    assert!(
        !raw.contains("read_to_end(&mut file, &mut bytes)"),
        "read_file_whole_capped must NOT slurp with an unbounded \
         `read_to_end(&mut file, ...)`: a TOCTOU-grown file would OOM the \
         process. Bound the read with `.take(cap)`."
    );
    // Nothing in this module may map a file. A file-backed mapping cannot be
    // read race-free: another process truncating the file invalidates the
    // page-cache pages past the new EOF, and the next touch raises SIGBUS,
    // which kills the whole scan with no report written at all. Measured on a
    // plain `keyhog scan <file>` against a concurrently truncated file: 1 of 6
    // trials at 128 KiB and 4 of 6 at 800 KiB died by signal 7. `read(2)`
    // cannot fault, so this path reads instead of mapping.
    assert!(
        !raw.contains("MmapOptions") && !raw.contains("memmap2"),
        "read/raw.rs must not map files: a concurrent truncation of a mapped \
         file raises SIGBUS and kills the scan with no report. Read the fd."
    );
    // Locked-file contention is refused at the SHARED open helper, not inside
    // the whole-file read. The 2026-07 refactor hoisted the advisory flock into
    // `open_file_safe` (documented in raw.rs as "ONE owner of the flock guard"),
    // so EVERY read path, prefix, buffered, and whole-file, inherits the
    // torn-write refusal. Pin that structure: the shared opener must take a
    // NON-BLOCKING shared lock and turn contention into an ERROR (fail closed,
    // never a fallback read), and the whole-file read must treat any open
    // failure as a visible unreadable SKIP with no unlocked reopen or second
    // read. (The `scanning a torn write` message + its no-fallback contract
    // live on the large-file windowed path in extract.rs, pinned by the second
    // half of this test and by `unit/file_gate.rs`.)
    let open_fn_start = raw
        .find("pub(crate) fn open_file_safe")
        .expect("open_file_safe (the shared no-follow + advisory-lock owner)");
    let open_fn = &raw[open_fn_start..];
    assert!(
        open_fn.contains("libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB)")
            && open_fn.contains("file is locked by another process"),
        "open_file_safe must take a non-blocking advisory shared lock and turn \
         lock contention into an error, so no read path can reopen a locked / \
         torn-write file through an unlocked fallback"
    );
    let read_fn_start = raw
        .find("pub(in crate::filesystem) fn read_file_whole_capped")
        .expect("read_file_whole_capped function");
    let open_arm = raw[read_fn_start..]
        .find("match open_file_safe_with_metadata(path)")
        .map(|offset| read_fn_start + offset)
        .expect("read_file_whole_capped must reuse metadata from the shared safe-open helper");
    let read_start = raw[open_arm..]
        .find(".take(read_limit)")
        .map(|offset| open_arm + offset)
        .expect("bounded read after the open arm");
    // Everything between the open call and the bounded read is pre-read failure
    // handling (open error incl. lock contention and oversize): each arm must be
    // a visible skip that returns None, with no second/unlocked read.
    let pre_read_failure = &raw[open_arm..read_start];
    assert!(
        pre_read_failure.contains("SourceSkipEvent::Unreadable")
            && pre_read_failure.contains("return None"),
        "a failed open (incl. locked-file contention) must be a visible unreadable skip"
    );
    assert!(
        !pre_read_failure.contains("read_to_end"),
        "the open-failure path must NOT read or reopen; it must skip visibly"
    );
    let read_fn = &raw[read_fn_start..];
    assert!(
        read_fn.contains("MMAP_TOCTOU_SANITY_CAP_BYTES")
            && read_fn.contains(".take(read_limit)")
            && read_fn.contains("SourceSkipEvent::OverMaxSize"),
        "the whole-file read must bound itself with the hard sanity cap and count \
         over-cap growth as a visible skip"
    );

    let extract = read_src("src/filesystem/extract.rs");
    assert!(
        extract.contains("refusing large-file buffered fallback: live size exceeds mmap sanity cap")
            && extract.contains("WindowedMmapOutcome::Fallback(mut file)")
            && extract.contains("let meta = match file.metadata()")
            && !extract.contains("match read::open_file_safe(&path)")
            && extract.contains("read::MMAP_TOCTOU_SANITY_CAP_BYTES")
            && extract.contains("SourceSkipEvent::OverMaxSize")
            && extract.contains("SourceSkipEvent::Unreadable"),
        "large-file buffered fallback must keep the validated descriptor, refresh its metadata at fallback time, and fail closed when the hard sanity cap cannot be re-proved"
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
