//! Gate `decode::base64`: modularity file cap (500 LOC).

#[test]
fn decode_base64_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/base64.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "decode::base64: {lines} lines exceeds 500-line cap — split module"
    );
}
