//! LANE 5 (sources-safety) OOM regression: the mmap-failure / locked-file
//! fallback reads must be BOUNDED, never an unbounded slurp of a TOCTOU-grown
//! file.
//!
//! Two holes existed:
//!   * `read/raw.rs::read_file_mmap` fell back to a bare `read_to_end(&mut file)`
//!     (no `.take`) when mmap or the shared flock failed — unbounded, so a file
//!     grown past the walker's stat between the walk and this read could OOM the
//!     process, defeating the very `MMAP_TOCTOU_SANITY_CAP_BYTES` ceiling the
//!     mmap path enforces.
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
         a TOCTOU-grown file would OOM the process. Bound it with `.take(MMAP_TOCTOU_SANITY_CAP_BYTES)`."
    );
    // Both fallback arms (locked-file + mmap-failure) must bound via the cap.
    let bounded = raw
        .matches("(&mut file).take(MMAP_TOCTOU_SANITY_CAP_BYTES)")
        .count();
    assert!(
        bounded >= 2,
        "both the locked-file and mmap-failure buffered fallbacks must cap the read at \
         MMAP_TOCTOU_SANITY_CAP_BYTES (found {bounded} bounded fallback(s), expected >= 2)"
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
    // The bounded, no-follow helper must exist and be used for BOTH fallbacks
    // (the locked-file arm and the mmap-failure arm).
    assert!(
        bytes.contains("fn read_capped_no_follow"),
        "the bounded no-follow read helper must exist"
    );
    assert!(
        bytes.contains("open_file_safe(path)") && bytes.contains(".take(cap)"),
        "read_capped_no_follow must open via open_file_safe (no-follow) and `.take(cap)` the read"
    );
    let used = bytes.matches("read_capped_no_follow(path,").count();
    assert!(
        used >= 2,
        "both the locked-file and mmap-failure fallbacks must route through \
         read_capped_no_follow (found {used} use(s), expected >= 2)"
    );
}
