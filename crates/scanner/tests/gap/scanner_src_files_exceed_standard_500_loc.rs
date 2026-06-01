//! KH-GAP-123: scanner `src/` files that historically exceeded the Santh
//! STANDARD 500 LOC cap. The oracle guards them from regressing past the cap.
//!
//! `hw_probe.rs` was the sixth offender; it was resolved by splitting it into
//! the `src/hw_probe/` module (every file there is now under the cap), so it is
//! no longer a single file to measure and has dropped off the watch list.

use std::path::{Path, PathBuf};

fn line_count(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()))
        .lines()
        .count()
}

#[test]
fn no_scanner_src_file_exceeds_standard_500_loc_cap() {
    const CAP: usize = 500;
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let offenders = [
        ("engine/scan.rs", manifest.join("src/engine/scan.rs")),
        (
            "suppression/mod.rs",
            manifest.join("src/suppression/mod.rs"),
        ),
        ("engine/backend.rs", manifest.join("src/engine/backend.rs")),
        ("gpu.rs", manifest.join("src/gpu.rs")),
        ("compiler.rs", manifest.join("src/compiler.rs")),
    ];

    let mut over: Vec<String> = Vec::new();
    for (label, path) in offenders {
        let lines = line_count(&path);
        if lines > CAP {
            over.push(format!("{label}: {lines} lines (cap {CAP})"));
        }
    }

    assert!(
        over.is_empty(),
        "KH-GAP-123: scanner src files exceed STANDARD 500 LOC:\n  - {}",
        over.join("\n  - ")
    );
}
