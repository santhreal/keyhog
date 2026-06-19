//! KH-GAP-011: A3 slice src files still contain inline #[cfg(test)] modules.

use std::path::{Path, PathBuf};

fn scan_rust_sources(dir: &Path, offenders: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir({}) failed: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_rust_sources(&path, offenders);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
        if super::inline_gate::contains_inline_test_module_or_function(&content) {
            offenders.push(path);
        }
    }
}

#[test]
fn no_inline_tests_in_a3_slice() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    scan_rust_sources(&manifest.join("src/pipeline"), &mut offenders);
    scan_rust_sources(&manifest.join("src/decode"), &mut offenders);
    scan_rust_sources(&manifest.join("src/multiline"), &mut offenders);
    offenders.sort();

    assert!(
        offenders.is_empty(),
        "{} A3-slice src files still contain #[cfg(test)] - migrate to tests/unit/:\n  - {}",
        offenders.len(),
        offenders
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join("\n  - ")
    );
}
