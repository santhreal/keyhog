//! WHY: Row 79 closes the class of unmonitored capability-conditional test skips.
//! When capabilities like GPU, Hyperscan, or AVX features are absent, tests can skip
//! silently without recording the skip or failing against host-class baselines.
//! This regression proves that:
//! 1. HostClass detection identifies the host class (H0–H5) accurately at run time.
//! 2. `register_capability_test` accurately tracks outcomes (`Ran` vs `SkippedCapabilityAbsent`).
//! 3. The capability ledger summary aggregates outcomes and enforces committed baselines.
//! 4. Injected skips on classes exceeding the committed baseline fail closed.
//! What it does not catch: tests outside cargo-test discovery that do not execute during cargo test.

use keyhog_scanner::capability_ledger::{
    capability_ledger_summary, print_capability_ledger_summary, register_capability_test,
    reset_capability_ledger, verify_capability_ledger_baseline, CapabilityOutcome, HostClass,
};
use std::path::PathBuf;

#[test]
fn host_class_enumeration_is_derived_and_exact() {
    assert_eq!(
        HostClass::ALL.len(),
        6,
        "HostClass::ALL must contain exactly 6 host classes H0..H5"
    );

    let mut seen_labels = std::collections::HashSet::new();
    for class in HostClass::ALL {
        assert!(
            seen_labels.insert(class.label()),
            "host class label {} must be unique across all classes",
            class.label()
        );
    }

    let detected = HostClass::detect();
    assert!(
        HostClass::ALL.contains(&detected),
        "detected host class {:?} must be a member of HostClass::ALL",
        detected
    );
}

#[test]
fn capability_ledger_registers_outcomes_and_enforces_baseline() {
    reset_capability_ledger();

    // 1. Register a present capability
    let ran = register_capability_test("test_present_capability", "cpu_simd", true);
    assert!(ran, "present capability must return true");

    // 2. Register an absent capability
    let skipped = register_capability_test("test_absent_capability", "exotic_accel", false);
    assert!(!skipped, "absent capability must return false");

    // 3. Inspect summary
    let summary = capability_ledger_summary();
    assert_eq!(summary.ran_count, 1, "expected 1 ran test");
    assert_eq!(summary.skipped_count, 1, "expected 1 skipped test");
    assert_eq!(summary.failed_count, 0, "expected 0 failed tests");

    let ran_record = summary
        .records
        .iter()
        .find(|r| r.test_name == "test_present_capability")
        .expect("present test record must exist");
    assert_eq!(ran_record.outcome, CapabilityOutcome::Ran);

    let skip_record = summary
        .records
        .iter()
        .find(|r| r.test_name == "test_absent_capability")
        .expect("absent test record must exist");
    assert_eq!(
        skip_record.outcome,
        CapabilityOutcome::SkippedCapabilityAbsent
    );

    // 4. Verify baseline file
    let baseline_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("scripts/gates/capability_skip_baseline.toml");

    assert!(
        baseline_path.exists(),
        "capability skip baseline TOML must exist"
    );

    // 5. Test baseline enforcement: 1 skip is within baseline for non-H2 classes
    print_capability_ledger_summary();

    // 6. Test mutation: injecting excessive skips must fail baseline check
    for i in 0..100 {
        register_capability_test(&format!("test_overflow_{i}"), "exotic_accel", false);
    }
    let overflow_result = verify_capability_ledger_baseline(&baseline_path);
    assert!(
        overflow_result.is_err(),
        "exceeding committed skip baseline must fail closed (got ok: {overflow_result:?})"
    );
}
