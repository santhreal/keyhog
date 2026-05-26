//! Gate `multiline::fragment_cache`: modularity file cap (500 LOC).

#[test]
fn multiline_fragment_cache_file_size_cap() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/multiline/fragment_cache.rs"
    );
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "multiline::fragment_cache: {lines} lines exceeds 500-line cap — split module"
    );
}
