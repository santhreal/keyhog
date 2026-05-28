//! KH-GAP-125: Engine backend parity lacks worst-case full-corpus CPU/SIMD/GPU gate.
//!
//! `backend_parity_matrix.rs` uses 6 synthetic fixtures; `gpu_parity.rs` uses one
//! boundary corpus; megakernel full parity is waived (KH-GAP-043). No oracle runs
//! all 891 detectors × all backends on adversarial worst-case fixtures.

use std::path::PathBuf;

#[test]
fn full_corpus_multi_backend_worst_case_parity_test_exists() {
    let tests_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let candidates = [
        "full_corpus_backend_parity.rs",
        "worst_case_backend_parity.rs",
        "all_detectors_backend_parity.rs",
    ];
    let exists = candidates.iter().any(|name| tests_dir.join(name).is_file());
    assert!(
        exists,
        "KH-GAP-125: no worst-case full-corpus CPU/SIMD/GPU parity harness — \
         only sample parity (3 detectors) + 6 synthetic fixtures + waived megakernel (043)"
    );
}
