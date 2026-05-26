//! Gate `simdsieve_prefilter`: modularity file cap (500 LOC).

#[test]
fn simdsieve_prefilter_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/simdsieve_prefilter.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "simdsieve_prefilter: {lines} lines exceeds 500-line cap — split module"
    );
}
