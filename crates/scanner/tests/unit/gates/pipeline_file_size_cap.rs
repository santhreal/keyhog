//! Gate `pipeline`: modularity file cap (500 LOC).

#[test]
fn pipeline_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/pipeline/mod.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
    if lines > 500 {
        eprintln!("pipeline: {lines} lines exceeds 500-line cap - split module");
    }
}
