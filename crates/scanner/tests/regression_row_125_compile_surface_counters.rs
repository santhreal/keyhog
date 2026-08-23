//! WHY: Verifies that compiling detector plans, entropy policies, assignment matchers,
//! etc. records compile surface invocations with the active compile phase (Row 125).
//!
//! What this does NOT catch: Hardware CPU microarchitectural counter fluctuations during compilation.
use keyhog_profile::{
    compile_surface_reports, set_compile_phase, total_runtime_compiles, CompilePhase,
    CompileSurfaceId, RunIdentity, RunState, Session,
};
use keyhog_scanner::CompiledScanner;

#[test]
fn test_scanner_compile_surface_counters() {
    let session = Session::start(RunIdentity::new(
        "0.5.80",
        "detectors",
        "config",
        "scanner-compile-test",
        "test",
        "cpu",
    ))
    .expect("start session");

    set_compile_phase(CompilePhase::Developer);
    let detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("load embedded detectors");

    let initial_compiles = total_runtime_compiles();

    let _scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let final_compiles = total_runtime_compiles();
    assert!(
        final_compiles > initial_compiles,
        "compilation must increment runtime compile counters"
    );

    let reports = compile_surface_reports();
    let detector_plan_report = reports
        .iter()
        .find(|r| r.surface == CompileSurfaceId::DetectorPlan)
        .expect("detector plan report");
    assert!(
        detector_plan_report.developer_compiles > 0,
        "detector plan compile must be recorded under Developer phase"
    );

    let _ = session.finish(RunState::Completed);
}
