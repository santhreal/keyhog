//! W9 keyhog-core proptest
use keyhog_core::dedup_matches;
use keyhog_core::{Credential, DedupScope, Severity};
use keyhog_core::{MatchLocation, RawMatch};
use proptest::prelude::*;
fn loc() -> MatchLocation {
    MatchLocation {
        source: "fs".into(),
        file_path: Some("f".into()),
        line: Some(1),
        offset: 0,
        commit: None,
        author: None,
        date: None,
    }
}
fn raw(cred: &str) -> RawMatch {
    RawMatch {
        detector_id: "d".into(),
        detector_name: "n".into(),
        service: "s".into(),
        severity: Severity::High,
        credential: cred.into(),
        credential_hash: format!("hash-{cred}"),
        companions: Default::default(),
        location: loc(),
        entropy: None,
        confidence: Some(0.5),
    }
}
proptest! {
#[test] fn prop_credential_len_matches(cred in "[A-Za-z0-9]{0,200}") { let c=Credential::from_text(&cred); prop_assert_eq!(c.len(), cred.len()); }
#[test] fn prop_credential_no_panic(cred in ".*") { let _=Credential::from_text(&cred); }
#[test] fn prop_dedup_none_preserves_count(n in 0usize..20) { let ms: Vec<_>=(0..n).map(|i| raw(&format!("c{}",i))).collect(); prop_assert_eq!(dedup_matches(ms, &DedupScope::None).len(), n); }
#[test] fn prop_dedup_credential_merges_dup(cred in "[a-z]{1,40}") { let ms=vec![raw(&cred), raw(&cred)]; prop_assert_eq!(dedup_matches(ms, &DedupScope::Credential).len(), 1); }
#[test] fn prop_debug_redacts(cred in "[A-Za-z0-9]{8,40}") {
        let dbg = format!("{:?}", Credential::from_text(&cred));
        prop_assert!(dbg.contains("redacted"));
        prop_assert!(!dbg.contains(&cred));
    }
#[test] fn prop_hash_nonempty(cred in "[a-z]{1,20}") { let d=dedup_matches(vec![raw(&cred)], &DedupScope::Credential); prop_assert!(!d[0].credential_hash.is_empty()); }
#[test] fn prop_empty_credential(cred in "") { let c=Credential::from_text(&cred); prop_assert!(c.is_empty()); }
#[test] fn prop_clone_eq(cred in "[A-Za-z0-9]{1,50}") { let a=Credential::from_text(&cred); let b=a.clone(); prop_assert_eq!(a, b); }
#[test] fn prop_dedup_file_scope_same_file(cred in "secret") { let ms=vec![raw(&cred), raw(&cred)]; prop_assert_eq!(dedup_matches(ms, &DedupScope::File).len(), 1); }
#[test] fn prop_expose_secret_roundtrip(cred in "[A-Za-z0-9]{1,80}") { let c=Credential::from_text(&cred); prop_assert_eq!(c.expose_secret(), cred.as_bytes()); }
#[test] fn prop_dedup_empty_input(_ in 0u8..5) { prop_assert!(dedup_matches(vec![], &DedupScope::Credential).is_empty()); }
#[test] fn prop_credential_from_bytes_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..64)) { let _=Credential::from_bytes(&bytes); }
#[test] fn prop_dedup_additional_locs(n in 2usize..10) { let cred="x"; let ms: Vec<_>=(0..n).map(|_| raw(cred)).collect(); let d=dedup_matches(ms, &DedupScope::Credential); prop_assert_eq!(d.len(), 1); prop_assert_eq!(d[0].additional_locations.len(), n-1); }
#[test] fn prop_severity_eq_reflexive(s in prop_oneof![Just(Severity::High), Just(Severity::Low)]) { prop_assert_eq!(s, s); }
#[test] fn prop_display_redacts(cred in "[^\0]{1,30}") { let d=format!("{}", Credential::from_text(&cred)); prop_assert!(d.contains("redacted")); }
}
