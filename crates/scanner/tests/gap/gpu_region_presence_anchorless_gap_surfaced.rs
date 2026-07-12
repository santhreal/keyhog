//! LAW10 contract: the GPU region-presence backend structurally DIVERGES from
//! `--backend simd` on anchorless (generic/entropy + Hyperscan-only vendor)
//! detectors — empirically gpu 4435 vs simd 5155 on a 3054-file CredData subset
//! (entropy-api-key 878 vs 1625), and INDEPENDENT of `gpu_recall_floor`
//! (floor-on == floor-off == 4435 measured; the floor recovers only AC-literal
//! region under-fires, `det < ac_map.len()`, never the anchorless set).
//! Dogfood-verified on a real RTX 5090: the notice fires EXACTLY ONCE on stderr
//! on BOTH gpu floor states and NOT on `--backend simd`.
//!
//! There is no clean per-scanner predicate for the divergence — the phase-2
//! structures are polluted by per-detector homoglyph variants (`phase2_patterns`
//! is never empty, and `phase2_always_active_indices` counts any phase-2 pattern
//! with no >=4-char keyword, including those homoglyphs). So the notice fires
//! UNCONDITIONALLY whenever the region-presence dispatch runs — an opt-in
//! `--backend gpu` path. This source-contract locks that Law-10 surface: the
//! notice must exist, state the divergence, carry the `--backend simd` remedy,
//! DISCLAIM the floor (so operators are not sent to a remedy that does not work),
//! be process-once guarded, and be invoked UNCONDITIONALLY (never re-gated on the
//! floor, which would silently under-scan floor-on `--backend gpu` users). It
//! reads source only, so it also guards the surface on the GPU-less ci-lean lane.

use std::fs;
use std::path::PathBuf;

#[test]
fn gpu_region_presence_anchorless_gap_notice_is_wired_unconditionally() {
    let src = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/gpu_region_dispatch.rs"),
    )
    .expect("gpu_region_dispatch.rs readable");

    // The notice exists and carries the CORRECT remediation (`--backend simd`),
    // not the refuted one (`gpu_recall_floor`, which does NOT recover the gap).
    assert!(
        src.contains("fn note_gpu_region_presence_anchorless_gap_once"),
        "the Law-10 anchorless-gap notice function must exist"
    );
    assert!(
        src.contains("DIVERGES from --backend simd")
            && src.contains("Use --backend simd for complete anchorless-detector recall"),
        "the notice must state the divergence and the --backend simd remediation"
    );
    assert!(
        src.contains("gpu_recall_floor does NOT recover this"),
        "the notice must DISCLAIM gpu_recall_floor (empirically floor-on == floor-off), so \
operators are not sent to a remedy that does not work"
    );

    // The notice must be invoked UNCONDITIONALLY on the region-presence path — the
    // earlier floor-gated forms (a `gpu_region_presence_undercovers_anchorless`
    // predicate / a `note_gpu_recall_floor_off_once` fired only on the floor-off
    // branch) were REMOVED because the divergence is floor-INDEPENDENT; re-gating
    // on the floor would silently under-scan floor-on `--backend gpu` users.
    assert!(
        src.contains("note_gpu_region_presence_anchorless_gap_once();"),
        "the notice must be invoked on the region-presence path"
    );
    assert!(
        !src.contains("gpu_region_presence_undercovers_anchorless")
            && !src.contains("note_gpu_recall_floor_off_once"),
        "the earlier floor-gated notice forms must be gone — the anchorless divergence is \
floor-INDEPENDENT (measured floor-on == floor-off), so the notice must fire regardless of floor"
    );

    // Process-once guarded so the loud notice never spams per sub-batch.
    assert!(
        src.contains("GPU_ANCHORLESS_GAP_WARNED") && src.contains("OnceLock"),
        "the notice must be process-once guarded (no per-sub-batch spam)"
    );
}
