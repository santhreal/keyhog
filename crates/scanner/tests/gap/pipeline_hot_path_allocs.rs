//! KH-GAP-014: pipeline.rs god file (1923 LOC) concentrates hot-path allocations.

use std::path::PathBuf;

#[test]
fn pipeline_loc_below_split_threshold() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/pipeline.rs");
    let line_count = std::fs::read_to_string(&path).unwrap().lines().count();
    const CAP: usize = 500;
    assert!(
        line_count <= CAP,
        "pipeline.rs is {line_count} LOC — exceeds {CAP}; split context, decode bridge, and scan loop (KH-GAP-005/014)"
    );
}
