//! KH-GAP-011 (cli slice): LR2 phase-1 orchestrator/mod.rs under 800 LOC.

#[test]
fn orchestrator_mod_rs_under_800_lines_phase1() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator/mod.rs");
    let content = std::fs::read_to_string(path).expect("read orchestrator/mod.rs");
    let line_count = content.lines().count();
    assert!(
        line_count <= 800,
        "orchestrator/mod.rs is {line_count} lines; LR2 phase-1 cap is 800"
    );
}
