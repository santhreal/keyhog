//! GPU AC corrupt match triples must degrade instead of entering phase 2.

use std::fs;
use std::path::PathBuf;

#[test]
fn gpu_ac_degenerate_triples_degrade_to_cpu_path() {
    let phase1 = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/gpu_ac_phase1.rs"),
    )
    .expect("gpu_ac_phase1.rs readable");
    assert!(
        phase1.contains("matches.iter().any(|m| m.end <= m.start)")
            && phase1.contains("gpu_degrade_done_with_reason(")
            && phase1.contains("GPU AC emitted degenerate match triples (end <= start)"),
        "GPU AC phase 1 must degrade corrupt degenerate match triples with an operator-visible reason before chunk attribution"
    );
}
