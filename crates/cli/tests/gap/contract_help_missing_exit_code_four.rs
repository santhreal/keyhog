//! KH-GAP-137: Documented exit 4 must have a contract test, not only a src-contains gap gate.

use std::path::PathBuf;

#[test]
fn contract_dir_documents_exit_code_four_in_help() {
    let contract_mod = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contract/mod.rs");
    let src = std::fs::read_to_string(contract_mod).expect("contract/mod.rs");
    assert!(
        src.contains("help_documents_exit_code_four"),
        "contract/ must include help_documents_exit_code_four for backend --self-test exit 4"
    );
}
