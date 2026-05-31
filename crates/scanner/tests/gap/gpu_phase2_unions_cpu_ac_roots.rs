//! GPU phase 2 must fail closed against literal-set trigger drift.

use std::fs;
use std::path::PathBuf;

#[test]
fn gpu_phase2_unions_cpu_ac_roots_before_extraction() {
    let phase2 = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/backend_pattern_hits.rs"),
    )
    .expect("backend_pattern_hits.rs readable");
    assert!(
        phase2.contains("collect_triggered_patterns_cpu(text)")
            && phase2.contains("Fail closed against GPU literal-set drift"),
        "GPU phase 2 must union canonical CPU AC roots so GPU literal-set drift cannot drop raw detector matches"
    );
}
