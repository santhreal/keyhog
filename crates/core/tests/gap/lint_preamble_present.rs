//! Santh STANDARD.md lint preamble must be present at the top of `lib.rs`.

const REQUIRED_SNIPPETS: &[&str] = &[
    "#![warn(missing_docs)]",
    "#![cfg_attr(",
    "not(test),",
    "deny(",
    "clippy::unwrap_used,",
    "clippy::expect_used,",
    "clippy::todo,",
    "clippy::unimplemented,",
    "clippy::panic",
];

/// `lib.rs` must deny unwrap/expect/todo/panic outside tests and warn on missing docs.
#[test]
fn lint_preamble_present() {
    let lib_rs = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("read crates/core/src/lib.rs");

    let missing: Vec<&str> = REQUIRED_SNIPPETS
        .iter()
        .copied()
        .filter(|snippet| !lib_rs.contains(snippet))
        .collect();

    assert!(
        missing.is_empty(),
        "lib.rs is missing Santh lint preamble fragments: {missing:?}"
    );
}
