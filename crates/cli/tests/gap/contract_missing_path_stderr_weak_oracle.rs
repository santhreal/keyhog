//! KH-GAP-139: `scan_missing_path_stderr_nonempty` must assert path/error contract, not stderr-nonempty-only.

use std::path::PathBuf;

#[test]
fn missing_path_contract_asserts_actionable_error_not_nonempty_only() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/contract/scan_missing_path_stderr_nonempty.rs");
    let src = std::fs::read_to_string(path).expect("contract test");
    assert!(
        src.contains("does not exist")
            || src.contains("not found")
            || src.contains("nonexistent"),
        "missing-path contract must assert actionable error text (see scan_missing_path_stderr_mentions_nonexistent)"
    );
    assert!(
        !src.contains("trim().is_empty()") || src.contains("mentions_nonexistent"),
        "stderr-nonempty-only oracle is assertion theater per STANDARD §378"
    );
}
