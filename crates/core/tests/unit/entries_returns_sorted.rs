//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::calibration::Calibration;
#[test]
    fn entries_returns_sorted() {
        let c = Calibration::empty();
        c.record_true_positive("zzz");
        c.record_true_positive("aaa");
        c.record_true_positive("mmm");
        let e = c.entries();
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].0, "aaa");
        assert_eq!(e[1].0, "mmm");
        assert_eq!(e[2].0, "zzz");
    }
