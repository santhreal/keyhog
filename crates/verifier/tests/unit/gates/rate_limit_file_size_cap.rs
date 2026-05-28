//! Gate `rate_limit`: modularity file cap (500 LOC).

#[test]
fn rate_limit_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/rate_limit.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "rate_limit: {lines} lines exceeds 500-line cap - split module"
    );
}
