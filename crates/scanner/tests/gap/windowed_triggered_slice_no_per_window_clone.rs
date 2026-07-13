//! Regression: the parallel windowed scan must pass the triggered-pattern
//! bitmap to `scan_prepared_with_triggered` BY SLICE, never re-clone it per
//! window.
//!
//! `scan_prepared_with_triggered` only borrows `triggered_patterns`: its sole
//! use is `expand_triggered_patterns(triggered_patterns)`, and that helper
//! takes `&[u64]`. The signature used to take `Vec<u64>` by value, which forced
//! `scan_windowed_with_triggered` to call `triggered_patterns.to_vec()` INSIDE
//! its `rayon` `.par_iter().map()`: one owned `Vec<u64>` allocation per window,
//! i.e. N redundant copies of the same bitmap on a multi-MiB chunk (Law 7).
//!
//! The fix changed the signature to `&[u64]` and threads the borrow straight
//! through. This pins both halves so a future edit can't reintroduce the clone:
//!   (1) the receiver takes the slice, not an owned `Vec`;
//!   (2) the windowed map passes the slice, with no `.to_vec()` in sight.

fn read_src(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(rel)).expect("source file readable")
}

#[test]
fn windowed_triggered_passes_slice_not_per_window_clone() {
    let backend = read_src("src/engine/backend_triggered.rs");
    // The receiver borrows the bitmap, owned `Vec<u64>` would force callers to
    // allocate to satisfy it.
    assert!(
        backend.contains("triggered_patterns: &[u64],"),
        "scan_prepared_with_triggered must take triggered_patterns by &[u64] slice"
    );
    assert!(
        !backend.contains("triggered_patterns: Vec<u64>"),
        "scan_prepared_with_triggered must not take an owned Vec<u64> (forces per-caller clone)"
    );
    // It only borrows: the sole use threads the slice straight into expansion.
    assert!(
        backend.contains("self.expand_triggered_patterns(triggered_patterns)"),
        "the borrow is threaded directly into expand_triggered_patterns (no owned copy needed)"
    );

    let windowed = read_src("src/engine/windowed.rs");
    // No per-window clone inside the rayon map.
    assert!(
        !windowed.contains("triggered_patterns.to_vec()"),
        "scan_windowed_with_triggered must not clone the triggered bitmap per window"
    );
    // The parallel window scan still takes (and forwards) the borrowed slice.
    assert!(
        windowed.contains("triggered_patterns: &[u64],"),
        "scan_windowed_with_triggered must accept the triggered bitmap by slice"
    );
}
