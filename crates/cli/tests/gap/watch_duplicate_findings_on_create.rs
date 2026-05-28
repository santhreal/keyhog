//! KH-GAP-109: `keyhog watch` prints duplicate findings for a single new file
//! when notify delivers both Create and Modify (or duplicate Create) events.
//!
//! R4-D dogfood (release binary): one `brandnew.txt` create → 4 stdout lines
//! (2 detectors × 2 notify events). Until fixed, watch.rs has no per-path dedupe.

use std::path::Path;

#[test]
fn watch_event_loop_dedupes_repeated_path_scans() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/subcommands/watch.rs"),
    )
    .expect("watch.rs");
    assert!(
        src.contains("recently_scanned")
            || src.contains("dedup")
            || src.contains("seen_paths")
            || src.contains("last_scan"),
        "watch must dedupe repeated notify events for the same path (Create+Modify burst)"
    );
}
