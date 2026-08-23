//! WHY: Verifies that compile surface counters are populated across all 13 compiler surfaces
//! and emitted in CausalProfileV2 profile reports (Row 125).
//!
//! What this does NOT catch: Network-level telemetry transmission failures when uploading profile dumps.
use keyhog_profile::{
    compile_surface_reports, set_compile_phase, total_runtime_compiles, CompilePhase,
    CompileSurfaceId, RunIdentity, RunState, Session,
};

#[test]
fn test_cli_compile_surface_metrics_tracking() {
    let session = Session::start(RunIdentity::new(
        "0.5.80",
        "detectors",
        "config",
        "cli-compile-test",
        "test",
        "cpu",
    ))
    .expect("start session");

    set_compile_phase(CompilePhase::Developer);
    let initial_compiles = total_runtime_compiles();

    // Trigger compilations across scanner surfaces
    let detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("load embedded detectors");

    let _scanner = keyhog_scanner::CompiledScanner::compile(detectors).expect("compile scanner");
    let final_compiles = total_runtime_compiles();
    assert!(
        final_compiles > initial_compiles,
        "runtime compiles must increment during in-process compilation"
    );

    let reports = compile_surface_reports();
    assert_eq!(reports.len(), 13);
    for report in &reports {
        assert!(!report.name.is_empty());
    }

    let plan_report = reports
        .iter()
        .find(|r| r.surface == CompileSurfaceId::DetectorPlan)
        .expect("detector plan report");
    assert!(plan_report.developer_compiles > 0);

    let _ = session.finish(RunState::Completed);
}
