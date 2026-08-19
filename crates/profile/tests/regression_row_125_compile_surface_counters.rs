//! WHY: Closes the defect class where runtime compilation vs prepared artifact loads
//! were uninstrumented across compiler entrypoints and compile phases (Row 125).
//!
//! What this does NOT catch: In-process memory corruption or external process binary mutation outside the profile runtime.

use keyhog_profile::{
    active_compile_phase, compile_surface_reports, record_compile_surface_invocation,
    record_compile_surface_invocation_with_phase, record_compile_surface_load, set_compile_phase,
    total_runtime_compiles, CausalProfileV2, CompilePhase, CompileSurfaceId, RunIdentity,
    RunInsightV2, RunState, Session,
};

#[test]
fn test_compile_surface_id_properties() {
    assert_eq!(CompileSurfaceId::ALL.len(), 13);
    for (index, &surface) in CompileSurfaceId::ALL.iter().enumerate() {
        assert_eq!(surface.index(), index);
        assert!(!surface.as_str().is_empty());
        assert!(!surface.entry_points().is_empty());
    }
}

#[test]
fn test_compile_phase_properties() {
    assert_eq!(CompilePhase::ALL.len(), 4);
    assert_eq!(CompilePhase::Install.as_str(), "install");
    assert_eq!(CompilePhase::Update.as_str(), "update");
    assert_eq!(CompilePhase::Scan.as_str(), "scan");
    assert_eq!(CompilePhase::Developer.as_str(), "developer");
}

#[test]
fn test_compile_surface_recording_and_profile_integration() {
    let session = Session::start(RunIdentity::new(
        "0.5.50",
        "detectors-test",
        "config-test",
        "source-test",
        "workload-test",
        "cpu",
    ))
    .expect("start session");

    set_compile_phase(CompilePhase::Developer);
    assert_eq!(active_compile_phase(), CompilePhase::Developer);

    record_compile_surface_invocation(CompileSurfaceId::DetectorPlan);
    record_compile_surface_invocation(CompileSurfaceId::DetectorPlan);
    record_compile_surface_invocation_with_phase(
        CompileSurfaceId::EntropyPolicy,
        CompilePhase::Scan,
    );
    record_compile_surface_load(CompileSurfaceId::ValidatorCatalog);
    record_compile_surface_load(CompileSurfaceId::ValidatorCatalog);
    record_compile_surface_load(CompileSurfaceId::ValidatorCatalog);

    assert!(total_runtime_compiles() >= 3);

    let reports = compile_surface_reports();
    let plan_report = reports
        .iter()
        .find(|r| r.surface == CompileSurfaceId::DetectorPlan)
        .expect("plan report");
    assert!(plan_report.developer_compiles >= 2);
    assert!(plan_report.runtime_compiles >= 2);

    let profile = session.finish(RunState::Completed);
    let causal = CausalProfileV2::from_v1(profile);
    assert_eq!(causal.compile_surfaces.len(), 13);

    let json = serde_json::to_string(&causal).expect("serialize profile");
    let deserialized: CausalProfileV2 = serde_json::from_str(&json).expect("deserialize profile");
    assert_eq!(deserialized.compile_surfaces.len(), 13);

    let insight = RunInsightV2::derive(&causal);
    let rendered = insight.render_summary();
    assert!(!rendered.is_empty());
}
