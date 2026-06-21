//! Static fail-closed guard: the coalesced phase-2 tail must keep the no-hit fast
//! path that drops an unadmitted no-trigger chunk to `Vec::new()` BEFORE any
//! `prepare_chunk` / post-process work, and its admission policy must match the
//! keyword/entropy gate. Both the CPU Hyperscan prefilter and the GPU
//! region-presence producer feed this single tail, so the old per-backend
//! `gpu_phase2.rs` fast path was unified into `scan_coalesced_phase2`; this
//! guard tracks it at its new home.

fn scanner_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn coalesced_phase2_empty_hits_skip_uninteresting_chunks_before_prepare() {
    let src = std::fs::read_to_string(scanner_root().join("src/engine/scan_coalesced.rs"))
        .expect("engine/scan_coalesced.rs source readable");

    let empty_hit_gate = src.find("&& !self.should_scan_no_hit_chunk(chunk)").expect(
        "coalesced phase2 must gate unadmitted no-trigger chunks on should_scan_no_hit_chunk",
    );
    let return_empty = src[empty_hit_gate..]
        .find("return Vec::new();")
        .map(|off| empty_hit_gate + off)
        .expect("unadmitted no-hit chunk must return without post-processing");
    // The no-hit branch's prepare_chunk: the first prepare_chunk AFTER the gate.
    let prepare = src[empty_hit_gate..]
        .find("let prepared = self.prepare_chunk(chunk);")
        .map(|off| empty_hit_gate + off)
        .expect("admitted no-hit chunk prepares the chunk");

    assert!(
        empty_hit_gate < return_empty && return_empty < prepare,
        "unadmitted no-hit chunks must short-circuit to Vec::new() BEFORE prepare_chunk \
         (gate@{empty_hit_gate} < return@{return_empty} < prepare@{prepare})"
    );

    // The no-hit admission policy must match the keyword/entropy gate exactly,
    // shared by every trigger-production backend.
    assert!(
        src.contains("has_generic_assignment_keyword(data)")
            && src.contains("has_secret_keyword_fast(data)")
            && src.contains("has_high_entropy_run_fast(data)")
            && src.contains("crate::entropy::is_entropy_appropriate"),
        "no-hit phase-2 gate must match the keyword/entropy admission policy"
    );
}
