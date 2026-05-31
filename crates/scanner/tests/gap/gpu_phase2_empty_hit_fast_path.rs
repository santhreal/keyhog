//! GPU phase2 must keep the SIMD coalesced no-hit fast path.

fn scanner_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn gpu_phase2_empty_hits_skip_uninteresting_chunks_before_prepare() {
    let src = std::fs::read_to_string(scanner_root().join("src/engine/gpu_phase2.rs"))
        .expect("gpu_phase2 source readable");
    let empty_hit_gate = src
        .find("hits.is_empty() && !gpu_phase2_should_scan_no_hit_chunk(chunk)")
        .expect("gpu phase2 must gate empty-hit chunks");
    let prepare = src
        .find("let prepared = self.prepare_chunk(chunk);")
        .expect("gpu phase2 prepares chunks");

    assert!(
        empty_hit_gate < prepare,
        "empty-hit GPU phase2 chunks must skip before prepare_chunk/post_process work"
    );
    assert!(
        src.contains("return Vec::new();"),
        "empty-hit GPU phase2 fast path must return without post-processing"
    );
    assert!(
        src.contains("has_generic_assignment_keyword(data)")
            && src.contains("has_secret_keyword_fast(data)")
            && src.contains("has_high_entropy_run_fast(data)"),
        "GPU no-hit fallback gate must match SIMD's keyword/entropy admission policy"
    );
}
