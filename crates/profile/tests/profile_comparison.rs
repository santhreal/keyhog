use keyhog_profile::{
    compare_profiles, RunIdentity, RunState, Session, Stage, StageMeasurement,
    STAGE_MEASUREMENT_VERSION,
};

fn profile(label: &str) -> keyhog_profile::RunProfile {
    Session::start(RunIdentity::new(
        "0.5.49",
        "detectors-a",
        "config-a",
        label,
        "small-text",
        "auto",
    ))
    .expect("start comparison profile")
    .finish(RunState::Completed)
}

fn measured_profile(label: &str, wall_ns: u64, stage_ns: u64) -> keyhog_profile::RunProfile {
    let mut profile = profile(label);
    profile.wall_time_ns = wall_ns;
    profile.stages = vec![StageMeasurement {
        version: STAGE_MEASUREMENT_VERSION,
        stage: Stage::SourceRead,
        elapsed_ns: stage_ns,
        calls: 4,
        attributed_ns: 0,
    }];
    profile
}

/// Comparable records must produce exact signed wall and stage deltas in stable stage order.
#[test]
fn comparable_profiles_report_exact_wall_and_stage_deltas() {
    let baseline = measured_profile("filesystem", 1_000, 800);
    let mut candidate = baseline.clone();
    candidate.identity.run_id = "candidate-run".to_owned();
    candidate.wall_time_ns = 750;
    candidate.stages[0].elapsed_ns = 600;
    candidate.stages[0].calls = 3;

    let comparison = compare_profiles(&baseline, &candidate);
    assert!(comparison.comparable);
    assert!(comparison.incompatibilities.is_empty());
    assert_eq!(comparison.wall_time_delta_ns, -250);
    assert_eq!(comparison.wall_time_change_percent, Some(-25.0));
    assert_eq!(comparison.stages.len(), 1);
    assert_eq!(comparison.stages[0].stage, Stage::SourceRead);
    assert_eq!(comparison.stages[0].elapsed_delta_ns, -200);
    assert_eq!(comparison.stages[0].elapsed_change_percent, Some(-25.0));
    assert_eq!(comparison.stages[0].calls_delta, -1);
}

/// Workload, configuration, and input drift must make the comparison invalid instead of reporting a false speedup.
#[test]
fn incompatible_profiles_name_every_changed_comparability_field() {
    let baseline = measured_profile("filesystem", 1_000, 800);
    let mut candidate = baseline.clone();
    candidate.identity.run_id = "candidate-run".to_owned();
    candidate.identity.config_digest = "config-b".to_owned();
    candidate.identity.backend_selected = Some("simd".to_owned());
    candidate.input_bytes = 99;

    let comparison = compare_profiles(&baseline, &candidate);
    assert!(!comparison.comparable);
    assert_eq!(
        comparison
            .incompatibilities
            .iter()
            .map(|difference| difference.field.as_str())
            .collect::<Vec<_>>(),
        vec![
            "identity.config_digest",
            "identity.backend_selected",
            "input_bytes"
        ]
    );
    assert!(comparison
        .render_text()
        .starts_with("KeyHog profile comparison comparable=false"));
}

/// A zero baseline must report an undefined percentage for new work rather than infinity or NaN.
#[test]
fn zero_baseline_uses_defined_zero_or_explicitly_undefined_percentages() {
    let baseline = measured_profile("filesystem", 0, 0);
    let mut unchanged = baseline.clone();
    unchanged.identity.run_id = "unchanged".to_owned();
    let unchanged_comparison = compare_profiles(&baseline, &unchanged);
    assert_eq!(unchanged_comparison.wall_time_change_percent, Some(0.0));
    assert_eq!(
        unchanged_comparison.stages[0].elapsed_change_percent,
        Some(0.0)
    );

    let mut candidate = unchanged;
    candidate.wall_time_ns = 1;
    candidate.stages[0].elapsed_ns = 1;
    let increased = compare_profiles(&baseline, &candidate);
    assert_eq!(increased.wall_time_change_percent, None);
    assert_eq!(increased.stages[0].elapsed_change_percent, None);
    assert!(increased.render_text().contains("change_percent=undefined"));
}

/// Untrusted identity labels must remain escaped on one incompatibility line in the text report.
#[test]
fn text_comparison_escapes_control_characters_in_identity_values() {
    let baseline = profile("filesystem");
    let mut candidate = baseline.clone();
    candidate.identity.run_id = "candidate-run".to_owned();
    candidate.identity.source_kind = "stdin\nforged-stage".to_owned();

    let report = compare_profiles(&baseline, &candidate).render_text();
    let incompatibilities = report
        .lines()
        .filter(|line| line.starts_with("incompatible "))
        .collect::<Vec<_>>();
    assert_eq!(incompatibilities.len(), 1);
    assert!(incompatibilities[0].contains("stdin\\nforged-stage"));
    assert!(!report.lines().any(|line| line == "forged-stage"));
}

/// Comparison JSON must preserve exact signed deltas and compatibility evidence through a round trip.
#[test]
fn comparison_json_round_trip_preserves_evidence() {
    let baseline = measured_profile("filesystem", 200, 100);
    let mut candidate = baseline.clone();
    candidate.identity.run_id = "candidate-run".to_owned();
    candidate.wall_time_ns = 300;
    candidate.stages[0].elapsed_ns = 175;
    let comparison = compare_profiles(&baseline, &candidate);

    let json = serde_json::to_string(&comparison).expect("serialize comparison");
    let decoded: keyhog_profile::ProfileComparison =
        serde_json::from_str(&json).expect("deserialize comparison");
    assert_eq!(decoded, comparison);
}
