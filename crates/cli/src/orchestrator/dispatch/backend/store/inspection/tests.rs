use super::*;

#[test]
fn disabled_cache_is_valid_when_no_backend_choice_exists() {
    let inspection = inspect_autoroute_cache_for_build(None, false);

    assert!(!inspection.calibration_required);
    assert_eq!(inspection.direct_backend, Some("cpu-fallback"));
    assert!(!inspection.present);
    assert_eq!(inspection.error, None);
    assert!(inspection.configs.is_empty());
    assert_eq!(inspection.readiness(), AutorouteReadiness::Direct);
    assert_eq!(inspection.readiness().repair_command(), None);
}

#[test]
fn absent_cache_is_valid_when_no_backend_choice_exists() {
    let directory = tempfile::tempdir().expect("create isolated cache directory");
    let path = directory.path().join("missing-autoroute.json");

    let inspection = inspect_autoroute_cache_for_build(Some(&path), false);

    assert_eq!(inspection.path.as_deref(), path.to_str());
    assert!(!inspection.calibration_required);
    assert_eq!(inspection.direct_backend, Some("cpu-fallback"));
    assert!(!inspection.present);
    assert_eq!(inspection.error, None);
    assert_eq!(inspection.readiness(), AutorouteReadiness::Direct);
}

#[test]
fn disabled_cache_is_invalid_when_build_has_backend_choice() {
    let inspection = inspect_autoroute_cache_for_build(None, true);

    assert!(inspection.calibration_required);
    assert_eq!(inspection.direct_backend, None);
    assert!(!inspection.present);
    assert!(inspection.error.as_deref().is_some_and(|error| {
        error.contains("cache is disabled") && error.contains("explicit --backend")
    }));
    assert!(inspection.configs.is_empty());
    assert_eq!(inspection.readiness(), AutorouteReadiness::Disabled);
    assert_eq!(
        inspection.readiness().repair_command(),
        Some("keyhog calibrate-autoroute --autoroute-cache <PATH>")
    );
}

#[test]
fn readiness_distinguishes_absent_invalid_stale_and_ready_cache_states() {
    let mut inspection = AutorouteCacheInspection {
        path: Some("/cache/autoroute.json".to_string()),
        calibration_required: true,
        ..AutorouteCacheInspection::default()
    };
    assert_eq!(
        inspection.readiness(),
        AutorouteReadiness::CalibrationRequired
    );

    inspection.present = true;
    inspection.error = Some("unreadable".to_string());
    assert_eq!(inspection.readiness(), AutorouteReadiness::Invalid);

    inspection.error = None;
    inspection.identity_matches_build = Some(false);
    assert_eq!(inspection.readiness(), AutorouteReadiness::Stale);

    inspection.identity_matches_build = Some(true);
    assert_eq!(inspection.readiness(), AutorouteReadiness::Ready);
}
