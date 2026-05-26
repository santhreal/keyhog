//! Gate `engine::fallback_entropy`: modularity file cap (500 LOC).

#[test]
fn engine_fallback_entropy_file_size_cap() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/fallback_entropy.rs"
    );
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "engine::fallback_entropy: {lines} lines exceeds 500-line cap — split module"
    );
}
