//! KH-GAP-012: Santh STANDARD requires tests/contract/ on in-policy crates.

use std::path::PathBuf;

#[test]
fn contract_directory_exists() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contract");
    assert!(
        dir.is_dir(),
        "KH-GAP-012: missing tests/contract/ — external surface tests belong here per STANDARD.md"
    );
}
