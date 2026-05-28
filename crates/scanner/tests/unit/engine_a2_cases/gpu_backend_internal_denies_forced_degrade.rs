//! KH-GAP-002: GPU batch fallback in `backend.rs` must call `deny_silent_gpu_degrade`
//! before routing to CPU when literals/backend handles are missing.

#[test]
fn gpu_backend_internal_denies_forced_degrade() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/backend.rs");
    let src = std::fs::read_to_string(path).expect("backend.rs readable");
    assert!(
        src.contains("gpu_forced::deny_silent_gpu_degrade"),
        "backend::scan_chunks_with_backend_internal must forbid silent CPU fallback when KEYHOG_BACKEND forces GPU"
    );
}
