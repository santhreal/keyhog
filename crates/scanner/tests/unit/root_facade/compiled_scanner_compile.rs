use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::testing::{
    exact_scanner_storage_snapshot_for_test, named_detector_fixture_defaults,
};

fn detector() -> DetectorSpec {
    DetectorSpec {
        id: "selected-simd-index-owner".into(),
        name: "Selected SIMD Index Owner".into(),
        service: "test".into(),
        severity: Severity::Medium,
        patterns: vec![PatternSpec {
            regex: r"STATIC_SECRET_[0-9]+".into(),
            ..Default::default()
        }],
        ..named_detector_fixture_defaults()
    }
}

/// WHY: retaining the complete scalar automaton beside exact SIMD shards
/// doubles phase-one matcher ownership and makes every single-chunk SIMD scan
/// repeat the same trigger pass.
#[test]
fn exact_simd_scanner_omits_overlapping_scalar_literal_index() {
    let snapshot = exact_scanner_storage_snapshot_for_test(detector(), true)
        .expect("compile exact SIMD scanner");
    assert!(
        snapshot.omits_scalar_literal_index,
        "exact SIMD ownership is native shards plus unsupported-pattern recovery"
    );
}

/// WHY: GPU-only matcher rows and lazy matcher cells must not be populated when
/// autoroute has already selected a host backend, or inactive buffers multiply
/// across concurrent scans.
#[cfg(feature = "gpu")]
#[test]
fn exact_host_scanners_omit_gpu_matcher_buffers() {
    use keyhog_scanner::testing::exact_host_gpu_storage_snapshot_for_test;

    for simd in [false, true] {
        let snapshot = exact_host_gpu_storage_snapshot_for_test(detector(), simd)
            .expect("compile exact host scanner");
        assert!(snapshot.omits_gpu_literals);
        assert!(snapshot.omits_gpu_matcher);
        assert!(snapshot.omits_match_upper_bounds);
        assert_eq!(snapshot.gpu_max_literal_len, 0);
        assert!(!snapshot.gpu_available);
    }
}

/// WHY: detector and pattern partitions previously retained one inner vector
/// per row even when almost every row was empty; scanner relations must retain
/// only flat values and one offset per logical row boundary.
#[test]
fn scanner_relations_retain_only_flat_offset_tables() {
    let mut spec = detector();
    spec.keywords = vec!["credential".into()];
    spec.patterns[0].structural_password_slot = true;
    spec.patterns.push(PatternSpec {
        regex: r"[A-Za-z_]+[:=]([A-Z0-9]{16})".into(),
        group: Some(1),
        structural_password_slot: true,
        ..Default::default()
    });
    let snapshot = exact_scanner_storage_snapshot_for_test(spec, false)
        .expect("compile compact relation fixture");

    let expected_confirmed = snapshot
        .confirmed_structural_flags
        .iter()
        .enumerate()
        .filter_map(|(index, &structural)| structural.then_some(index as u32))
        .collect::<Vec<_>>();
    let expected_phase2 = snapshot
        .phase2_structural_flags
        .iter()
        .enumerate()
        .filter_map(|(index, &structural)| structural.then_some(index as u32))
        .collect::<Vec<_>>();

    assert_eq!(snapshot.confirmed_structural_row, expected_confirmed);
    assert_eq!(snapshot.phase2_structural_row, expected_phase2);
    assert_eq!(
        snapshot.confirmed_structural_storage,
        (expected_confirmed.len(), 2)
    );
    assert_eq!(
        snapshot.phase2_structural_storage,
        (expected_phase2.len(), 2)
    );
    assert_eq!(
        snapshot.confirmed_suffix_gate_rows,
        snapshot.confirmed_structural_flags.len()
    );
    assert_eq!(
        snapshot.confirmed_suffix_gate_storage.1,
        snapshot.confirmed_structural_flags.len() + 1
    );
}
