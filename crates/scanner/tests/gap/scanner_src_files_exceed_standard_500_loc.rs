//! KH-GAP-123: Six scanner `src/` files exceed the Santh STANDARD 500 LOC cap.
//!
//! Unit gates under `tests/unit/gates/` already fail RED; this gap oracle consolidates
//! the bar-miss for GAP_FINDINGS tracking.

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
        ("hw_probe.rs", manifest.join("src/hw_probe.rs")),
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
