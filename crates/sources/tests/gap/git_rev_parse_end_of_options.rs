//! Git ref resolution must use --end-of-options before user refs.

#[test]
fn git_rev_parse_end_of_options() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/git/mod.rs"
    ))
    .expect("git/mod.rs");
    assert!(
        src.contains("--end-of-options"),
        "git ref commands must terminate option parsing before refs"
    );
}
