//! Migrated from engine/recovery.rs inline tests (KH-1308).

use keyhog_scanner::hw_probe::ScanBackend;
use keyhog_scanner::{BackendRecoveryReceipt, RecoveredInputRange};

#[test]
fn recovery_reason_is_printable_nonempty_and_bounded() {
    let receipt = BackendRecoveryReceipt::new(
        ScanBackend::GpuCuda,
        ScanBackend::SimdCpu,
        Vec::new(),
        format!("device\\nreset{}", "x".repeat(8192)),
    );
    assert!(!receipt.reason.is_empty());
    assert!(receipt.reason.len() <= 4096);
    assert!(!receipt.reason.chars().any(char::is_control));

    let missing = BackendRecoveryReceipt::new(
        ScanBackend::GpuCuda,
        ScanBackend::SimdCpu,
        Vec::new(),
        String::new(),
    );
    assert_eq!(missing.reason, "backend fault without diagnostic");
}

#[test]
fn recovered_ranges_are_sorted_and_coalesced_per_chunk() {
    let receipt = BackendRecoveryReceipt::new(
        ScanBackend::GpuCuda,
        ScanBackend::SimdCpu,
        vec![
            RecoveredInputRange::new(1, 8, 12),
            RecoveredInputRange::new(0, 4, 9),
            RecoveredInputRange::new(0, 0, 4),
            RecoveredInputRange::new(1, 3, 10),
            RecoveredInputRange::new(2, 7, 7),
        ],
        "ok".into(),
    );
    assert_eq!(
        receipt.ranges,
        vec![
            RecoveredInputRange::new(0, 0, 9),
            RecoveredInputRange::new(1, 3, 12),
        ]
    );
}
