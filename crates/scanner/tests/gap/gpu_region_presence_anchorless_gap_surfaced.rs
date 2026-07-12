//! LAW10 contract: prefixless/anchorless phase-2 admission is accelerated by a
//! GPU regex-DFA, but CPU admission remains authoritative whenever its catalog
//! is incomplete or dispatch fails. A stale unconditional divergence warning
//! is incorrect now that this recall-preserving union exists.

use std::fs;
use std::path::PathBuf;

#[test]
fn gpu_region_presence_anchorless_gap_notice_is_wired_unconditionally() {
    let dispatch = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/gpu_region_dispatch.rs"),
    )
    .expect("gpu_region_dispatch.rs readable");
    let dfa = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/phase2_gpu_dfa.rs"),
    )
    .expect("phase2_gpu_dfa.rs readable");
    assert!(
        dispatch.contains("build_phase2_gpu_admission_workload_filtered")
            && dispatch.contains("phase2_gpu_dfa_catalog")
            && dfa.contains("uncovered patterns")
            && dfa.contains("CPU admission remains authoritative")
            && dfa.contains("PHASE2_GPU_CATALOG_LOSS_WARNED")
            && !dispatch.contains("note_gpu_region_presence_anchorless_gap_once"),
        "GPU prefixless admission must preserve CPU authority for uncovered patterns and report catalog loss once"
    );
}
