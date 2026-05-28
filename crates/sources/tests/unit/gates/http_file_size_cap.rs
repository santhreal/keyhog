//! Gate `http`: modularity file cap (500 LOC).

#[test]
fn http_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/http.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "http: {lines} lines exceeds 500-line cap - split module"
    );
}
