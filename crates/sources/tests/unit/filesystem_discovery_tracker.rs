use super::*;

#[test]
fn tracked_walk_counts_production_events_and_early_termination() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sub_dir = temp_dir.path().join("sub");
    std::fs::create_dir(&sub_dir).unwrap();
    std::fs::write(temp_dir.path().join("sample1.txt"), "hello world").unwrap();
    std::fs::write(sub_dir.join("sample2.txt"), "nested hello").unwrap();

    let tracker = DiscoveryTracker::default();
    let config = super::super::filter::walker_config(0, &[], true);
    walk_metadata_tracked(temp_dir.path(), &config, &tracker, |_| false);

    let counts = tracker.snapshot();
    assert!(counts.root_components_inspected > 0);
    assert!(counts.walk_entries_seen >= 2);
    assert!(counts.directories_seen >= 1);
    assert_eq!(counts.file_metadata_requests, 1);
    assert_eq!(counts.files_admitted, 1);
    assert_eq!(counts.errors, 0);
    assert_eq!(counts.early_stops, 1);
}

#[test]
fn tracked_walk_records_root_validation_failure_without_walker_events() {
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing");
    let tracker = DiscoveryTracker::default();
    let config = super::super::filter::walker_config(0, &[], true);
    let mut errors = Vec::new();
    walk_metadata_tracked(&missing, &config, &tracker, |result| {
        errors.push(result.unwrap_err());
        true
    });

    let counts = tracker.snapshot();
    assert_eq!(errors.len(), 1);
    assert_eq!(counts.errors, 1);
    assert_eq!(counts.walk_entries_seen, 0);
    assert_eq!(counts.files_admitted, 0);
}
