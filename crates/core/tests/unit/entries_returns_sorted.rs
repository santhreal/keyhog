//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::Calibration;
#[test]
fn entries_returns_sorted() {
    let c = Calibration::default();
    c.record_outcome("zzz", true);
    c.record_outcome("aaa", true);
    c.record_outcome("mmm", true);
    let e = c.entries();
    assert_eq!(e.len(), 3);
    assert_eq!(e[0].0, "aaa");
    assert_eq!(e[1].0, "mmm");
    assert_eq!(e[2].0, "zzz");
}
