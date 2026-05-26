//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::Calibration;
#[test]
    fn corrupted_cache_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("calibration.json");
        std::fs::write(&path, b"this is not json").unwrap();
        let loaded = Calibration::load(&path);
        assert_eq!(loaded.entries().len(), 0);
    }
