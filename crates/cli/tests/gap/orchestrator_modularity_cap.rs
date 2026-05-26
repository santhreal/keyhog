//! KH-GAP-005 (cli slice): orchestrator.rs must stay under the 500-line
//! modularity cap. Fails until the file is split.

#[test]
fn orchestrator_rs_under_500_lines() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator.rs");
    let content = std::fs::read_to_string(path).expect("read orchestrator.rs");
    let line_count = content.lines().count();
    assert!(
        line_count <= 500,
        "orchestrator.rs is {line_count} lines; modularity cap is 500 (split required)"
    );
}
