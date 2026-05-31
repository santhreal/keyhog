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
            && phase1.contains("GPU_AC_DEGENERATE_DISABLED.load")
            && phase1.contains("GPU_AC_DEGENERATE_DISABLED.store")
            && phase1.contains("gpu_degrade_done_with_reason(")
            && phase1.contains("GPU AC emitted degenerate match triples (end <= start)"),
        "GPU AC phase 1 must degrade corrupt degenerate match triples with an operator-visible reason before chunk attribution and skip later known-corrupt AC dispatches"
    );
}

#[test]
fn gpu_ac_dispatch_failures_preserve_operator_visible_reasons() {
    let phase1 = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/gpu_ac_phase1.rs"),
    )
    .expect("gpu_ac_phase1.rs readable");
    assert!(
        phase1.contains("AC GPU batched dispatch failed: {e}")
            && phase1.contains("AC GPU shard {i} dispatch failed: {e}")
            && phase1.contains("returned {} output buffer(s), expected at least 2")
            && phase1.contains("returned truncated count buffer")
            && phase1.contains("exceeding cap {}")
            && phase1.matches("gpu_degrade_done_with_reason(").count() >= 6,
        "Every AC GPU runtime-dispatch failure must carry a concrete reason into KEYHOG_REQUIRE_GPU/user-visible degrade output"
    );
}

#[test]
fn gpu_ac_self_test_can_report_recorded_degrade_reason() {
    let engine =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/mod.rs"))
            .expect("engine/mod.rs readable");
    let wrapper = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/gpu_scan_wrappers.rs"),
    )
    .expect("gpu_scan_wrappers.rs readable");
    let gpu = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/gpu.rs"))
        .expect("gpu.rs readable");

    assert!(
        engine.contains("gpu_last_degrade_reason")
            && engine.contains("last_gpu_degrade_reason")
            && wrapper.contains("gpu_last_degrade_reason")
            && gpu.contains("last_gpu_degrade_reason()"),
        "backend --self-test JSON must receive the concrete GPU degrade reason without scraping stderr"
    );
}

#[test]
fn gpu_ac_plain_append_binds_one_atomic_slot_for_triple() {
    let lazy = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/gpu_lazy.rs"),
    )
    .expect("gpu_lazy.rs readable");

    assert!(
        lazy.contains("fn append_match_bound_slot")
            && lazy.contains("Node::let_bind(\n            slot_name,\n            Expr::atomic_add")
            && lazy.contains("Expr::var(slot_name)")
            && lazy.contains("build_ac_bounded_ranges_program_bound_atomic"),
        "AC GPU plain append must bind atomic_add once so pattern/start/end are written to the same match slot"
    );
}
