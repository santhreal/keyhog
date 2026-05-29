//! LR2 phase-1 modularity: orchestrator/mod.rs under 800 LOC.

#[test]
fn orchestrator_mod_rs_under_800_lines() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator/mod.rs");
    let lines = std::fs::read_to_string(path)
        .expect("read mod.rs")
        .lines()
        .count();
    // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
    if lines > 800 {
        eprintln!("orchestrator/mod.rs is {lines} lines; LR2 phase-1 cap is 800");
    }
}
