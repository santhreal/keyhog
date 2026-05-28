//! Gate `engine::hot_patterns`: modularity file cap (500 LOC).

#[test]
fn engine_hot_patterns_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/hot_patterns.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "engine::hot_patterns: {lines} lines exceeds 500-line cap - split module"
    );
}
