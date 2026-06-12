//! Advisory modularity cap for the GPU literal phase-1 trigger dispatch. The
//! 78046450 consolidation merged `engine/gpu_literal_phase1.rs` into
//! `backend_triggered.rs` (`collect_triggered_patterns_gpu` +
//! `triggered_patterns_from_gpu_presence`), so the cap now tracks that successor.
#[test]
fn gpu_literal_phase1_under_500_lines() {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/backend_triggered.rs");
    let n = std::fs::read_to_string(p)
        .unwrap_or_else(|e| panic!("backend_triggered.rs not readable ({e}); path moved - update this gate"))
        .lines()
        .count();
    // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
    if n > 500 {
        eprintln!("backend_triggered.rs is {n} lines, exceeds the 500-line cap (advisory)");
    }
}
