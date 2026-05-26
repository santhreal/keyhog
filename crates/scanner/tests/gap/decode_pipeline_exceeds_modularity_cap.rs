//! KH-GAP-012: decode/pipeline.rs approaches god-file territory at 463 LOC.

use std::path::PathBuf;

#[test]
fn decode_pipeline_exceeds_modularity_cap() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/decode/pipeline.rs");
    let content = std::fs::read_to_string(&path).unwrap();
    let line_count = content.lines().count();
    const CAP: usize = 400;
    assert!(
        line_count <= CAP,
        "decode/pipeline.rs is {line_count} lines — exceeds A3 modularity cap {CAP}; split extract_encoded_values and splice helpers"
    );
}
