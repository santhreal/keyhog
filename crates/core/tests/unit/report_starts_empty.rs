//! Migrated from `src/hardening.rs` inline tests.
use keyhog_core::{apply_default_protections, HardeningReport};
#[test]
    fn report_starts_empty() {
        let r = HardeningReport::default();
        assert!(!r.no_core_dumps);
        assert!(!r.no_ptrace);
        assert!(!r.mlocked);
        assert!(r.failures.is_empty());
    }
