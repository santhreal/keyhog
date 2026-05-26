//! Gate `orchestrator`: LR2 phase-1 modularity cap (800 LOC on mod.rs).

#[test]
fn orchestrator_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator/mod.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 800,
        "orchestrator/mod.rs: {lines} lines exceeds 800-line LR2 phase-1 cap"
    );
}
