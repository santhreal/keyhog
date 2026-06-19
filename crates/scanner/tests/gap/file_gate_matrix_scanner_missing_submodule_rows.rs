//! KH-GAP-176: every scanner src module must appear in FILE_GATE_MATRIX.
//! Regression: previously missing rows (added as part of the gap fix):
//!   crates/scanner/src/api.rs
//!   crates/scanner/src/context/placeholder.rs
//!   crates/scanner/src/engine/phase2_entropy/gates.rs
//!   crates/scanner/src/engine/phase2_entropy/helpers.rs
//!   crates/scanner/src/engine/phase2_generic/keywords.rs
//!   crates/scanner/src/engine/phase2_generic/shape_helpers.rs
//!   crates/scanner/src/engine/generic_keyword_owner.rs
//!   crates/scanner/src/engine/gpu_stack.rs
//!   crates/scanner/src/engine/gpu_region_dispatch.rs
//!   crates/scanner/src/engine/windowed_support.rs
//!   crates/scanner/src/multiline/string_extract.rs
//!   crates/scanner/src/placeholder_words.rs
//!   crates/scanner/src/simd/backend.rs
//!   crates/scanner/src/simd/backend/scan.rs
//!   crates/scanner/src/tuning.rs

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn matrix_paths(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| {
            line.strip_prefix("path = \"")
                .and_then(|p| p.strip_suffix('"'))
                .map(str::to_string)
        })
        .collect()
}

/// These are the concrete module paths that were absent from FILE_GATE_MATRIX
/// before the KH-GAP-176 fix.  Each entry in this list must be present in the
/// matrix — if any is missing the test fails with the specific path.
const PREVIOUSLY_MISSING: &[&str] = &[
    "crates/scanner/src/api.rs",
    "crates/scanner/src/context/placeholder.rs",
    "crates/scanner/src/engine/phase2_entropy/gates.rs",
    "crates/scanner/src/engine/phase2_entropy/helpers.rs",
    "crates/scanner/src/engine/phase2_generic/keywords.rs",
    "crates/scanner/src/engine/phase2_generic/shape_helpers.rs",
    "crates/scanner/src/engine/generic_keyword_owner.rs",
    "crates/scanner/src/engine/gpu_stack.rs",
    "crates/scanner/src/engine/gpu_region_dispatch.rs",
    "crates/scanner/src/engine/windowed_support.rs",
    "crates/scanner/src/multiline/string_extract.rs",
    "crates/scanner/src/placeholder_words.rs",
    "crates/scanner/src/simd/backend.rs",
    "crates/scanner/src/simd/backend/scan.rs",
    "crates/scanner/src/tuning.rs",
];

#[test]
fn file_gate_matrix_lists_every_scanner_src_module() {
    let raw = std::fs::read_to_string(repo_root().join("tests/FILE_GATE_MATRIX.toml"))
        .expect("FILE_GATE_MATRIX.toml");
    let listed = matrix_paths(&raw);
    let root = repo_root().join("crates/scanner/src");
    let mut paths = Vec::new();
    collect_rs_files(&root, &mut paths).expect("walk scanner src");
    let required: Vec<String> = paths
        .iter()
        .map(|path| {
            path.strip_prefix(repo_root())
                .expect("under repo root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    let missing: Vec<_> = required
        .iter()
        .filter(|p| !listed.contains(p))
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "FILE_GATE_MATRIX missing scanner src rows: {missing:?}"
    );
    assert!(
        !listed
            .iter()
            .any(|p| p == "crates/scanner/src/engine/scan_gpu.rs"),
        "stale scan_gpu.rs row must be removed from matrix"
    );
}

/// Regression test for KH-GAP-176: each concrete path that was previously
/// absent from FILE_GATE_MATRIX must now appear in it.
/// This test would have FAILED before the fix was applied.
#[test]
fn previously_missing_modules_are_now_listed_in_matrix() {
    let raw = std::fs::read_to_string(repo_root().join("tests/FILE_GATE_MATRIX.toml"))
        .expect("FILE_GATE_MATRIX.toml");
    let listed = matrix_paths(&raw);
    for path in PREVIOUSLY_MISSING {
        assert!(
            listed.iter().any(|p| p == path),
            "FILE_GATE_MATRIX is still missing the row for {path:?} \
             (KH-GAP-176 regression: this path was added as part of the fix)"
        );
    }
}
