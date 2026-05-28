//! Gate `telemetry`: modularity file cap (500 LOC).

#[test]
fn telemetry_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/telemetry.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "telemetry: {lines} lines exceeds 500-line cap - split module"
    );
}
