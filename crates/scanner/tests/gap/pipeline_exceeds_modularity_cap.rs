//! KH-GAP-005 (pipeline slice): `pipeline.rs` must stay ≤500 LOC until
//! split into context / decode-bridge / scan-loop modules.

use std::path::PathBuf;

#[test]
fn pipeline_exceeds_modularity_cap() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/pipeline.rs");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
    let line_count = content.lines().count();
    const CAP: usize = 500;

    assert!(
        line_count <= CAP,
        "pipeline.rs is {line_count} lines — exceeds modularity cap {CAP}; \
         split into context, decode bridge, and scan loop modules"
    );
}
