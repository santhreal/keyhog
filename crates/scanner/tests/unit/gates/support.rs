//! Shared helpers for the source-shape gate tests under `tests/unit/gates/`.
//!
//! The named-detector suppression gate uses the same source-tree traversal and
//! comment filtering in several assertions. Keeping those operations here gives
//! that gate one implementation and leaves the test body focused on its policy
//! contract.

use std::path::{Path, PathBuf};

/// The scanner crate's `src/` directory (gates read production source to pin
/// its shape). Resolved from `CARGO_MANIFEST_DIR` so it is CWD-independent.
pub(crate) fn scanner_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Read a source file to a `String`, failing loudly with the path on error (a
/// missing gate target is a harness/checkout bug, never a silent skip).
pub(crate) fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{} not readable: {e}", path.display()))
}

/// Recursively collect every `.rs` file under `dir` into `out`.
pub(crate) fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{} not readable: {e}", dir.display()))
    {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Drop whole-line `//` comments so a gate's `contains(...)` check matches only
/// real code, never a symbol mentioned in a comment. (Does not strip trailing
/// or block comments — gates that need those handle them explicitly.)
pub(crate) fn uncommented_code(src: &str) -> String {
    src.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}
