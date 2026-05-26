//! Gate `oob::session`: modularity file cap (500 LOC).

#[test]
fn oob_session_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/oob/session.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "oob::session: {lines} lines exceeds 500-line cap — split module"
    );
}
