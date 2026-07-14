use super::*;

#[test]
fn disabled_cache_is_valid_when_no_backend_choice_exists() {
    let inspection = inspect_autoroute_cache_for_build(None, false);

    assert!(!inspection.calibration_required);
    assert_eq!(inspection.direct_backend, Some("cpu-fallback"));
    assert!(!inspection.present);
    assert_eq!(inspection.error, None);
    assert!(inspection.configs.is_empty());
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
}
