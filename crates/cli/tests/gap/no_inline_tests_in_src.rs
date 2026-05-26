//! KH-GAP-004 (cli slice): `src/` must not host `#[cfg(test)]` modules.

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
        if content
            .lines()
            .any(|line| line.trim().starts_with("#[cfg(test)]"))
        {
            offenders.push(path);
        }
    }
}

#[test]
fn no_inline_tests_in_src() {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    scan_rust_sources(&src_dir, &mut offenders);
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "{} cli/src files still contain #[cfg(test)] — migrate to tests/unit/:\n  - {}",
        offenders.len(),
        offenders
            .iter()
            .map(|p| p
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(p)
                .display()
                .to_string())
            .collect::<Vec<_>>()
            .join("\n  - ")
    );
}
