//! Gate `git::source`: modularity file cap (500 LOC).

#[test]
fn git_source_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/source.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "git::source: {lines} lines exceeds 500-line cap — split module"
    );
}
