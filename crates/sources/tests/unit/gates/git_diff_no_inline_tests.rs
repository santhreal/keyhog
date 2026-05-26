//! Gate `git::diff`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn git_diff_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/diff.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "git::diff: move inline tests to crates/sources/tests/"
    );
}
