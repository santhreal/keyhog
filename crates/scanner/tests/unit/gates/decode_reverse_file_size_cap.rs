//! Gate `decode::reverse`: modularity file cap (500 LOC).

#[test]
fn decode_reverse_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/reverse.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "decode::reverse: {lines} lines exceeds 500-line cap — split module"
    );
}
