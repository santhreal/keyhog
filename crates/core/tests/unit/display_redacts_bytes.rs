//! Migrated from `src/credential.rs` inline tests.
use keyhog_core::Credential;
#[test]
    fn display_redacts_bytes() {
        let c = Credential::from_text("ghp_abcdef1234567890");
        let s = format!("{c}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("ghp_"));
    }
