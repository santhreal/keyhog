//! Gate `entropy_avx512`: modularity file cap (500 LOC).

#[test]
fn entropy_avx512_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/entropy_avx512.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "entropy_avx512: {lines} lines exceeds 500-line cap - split module"
    );
}
