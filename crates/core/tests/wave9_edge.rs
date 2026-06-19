//! W9 keyhog-core edge
use keyhog_core::dedup_matches;
use keyhog_core::{Credential, DedupScope, Severity};
use keyhog_core::{MatchLocation, RawMatch};
macro_rules! w9_edge {
    ($n:ident, $b:block) => {
        #[test]
        fn $n() {
            $b
        }
    };
}
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

fn loc() -> MatchLocation {
    // Each helper call gets a distinct (line, offset) so that two
    // `raw()` invocations for the same credential look like two REAL
    // occurrences (one primary + one additional), not two
    // synthetic-preprocessor aliases at the same (file, line) which
    // dedup_matches deliberately collapses to a single finding.
    static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
    let n = CALL_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
    MatchLocation {
        source: "fs".into(),
        file_path: Some("a.txt".into()),
        line: Some(1 + n),
        offset: n * 16,
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
        credential_hash: [0; 32],
        companions: Default::default(),
        location: loc(),
        entropy: None,
        confidence: Some(0.9),
    }
}
w9_edge!(w9_kh_01, {
    let c = Credential::from("secret");
    assert_eq!(c.expose_secret().len(), 6);
});

w9_edge!(w9_kh_02, {
    let c = Credential::from("");
    assert!(c.expose_secret().is_empty());
});

w9_edge!(w9_kh_03, {
    assert_eq!(dedup_matches(vec![], &DedupScope::None).len(), 0);
});

w9_edge!(w9_kh_04, {
    let d = dedup_matches(vec![raw("a"), raw("a")], &DedupScope::Credential);
    assert_eq!(d.len(), 1);
});

w9_edge!(w9_kh_05, {
    let d = dedup_matches(vec![raw("a"), raw("b")], &DedupScope::Credential);
    assert_eq!(d.len(), 2);
});

w9_edge!(w9_kh_06, {
    let d = dedup_matches(vec![raw("x"), raw("x")], &DedupScope::None);
    assert_eq!(d.len(), 2);
});

w9_edge!(w9_kh_07, {
    let c = Credential::from(vec![0xff, 0xfe]);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::credential_expose_str(
            &keyhog_core::testing::TestApi,
            &c
        ),
        None
    );
});

w9_edge!(w9_kh_08, {
    let dbg = format!("{:?}", Credential::from("x"));
    assert!(dbg.contains("redacted"));
});

w9_edge!(w9_kh_09, {
    let c1 = Credential::from("same");
    let c2 = Credential::from("same");
    assert_eq!(c1, c2);
});

w9_edge!(w9_kh_10, {
    let d = dedup_matches(vec![raw("z")], &DedupScope::File);
    assert_eq!(d.len(), 1);
});

w9_edge!(w9_kh_11, {
    assert_ne!(Severity::High, Severity::Low);
});

w9_edge!(w9_kh_12, {
    let c = Credential::from("tok");
    assert_eq!(c.expose_secret(), b"tok");
});

w9_edge!(w9_kh_13, {
    let d = dedup_matches(vec![raw("a")], &DedupScope::Credential);
    assert!(!d[0].credential_hash.is_empty());
});

w9_edge!(w9_kh_14, {
    let c: Credential = "hello".into();
    assert_eq!(
        keyhog_core::testing::CoreTestApi::credential_expose_str(
            &keyhog_core::testing::TestApi,
            &c
        ),
        Some("hello")
    );
});

w9_edge!(w9_kh_15, {
    assert_eq!(DedupScope::None, DedupScope::None);
});

w9_edge!(w9_kh_16, {
    let d = dedup_matches(vec![raw("a"), raw("a")], &DedupScope::File);
    assert_eq!(d.len(), 1);
});

w9_edge!(w9_kh_17, {
    let c = Credential::from("x");
    let _ = c.clone();
});

w9_edge!(w9_kh_18, {
    let d = dedup_matches(vec![raw("a")], &DedupScope::Credential);
    assert_eq!(d[0].additional_locations.len(), 0);
});

w9_edge!(w9_kh_19, {
    let d = dedup_matches(vec![raw("a"), raw("a")], &DedupScope::Credential);
    assert_eq!(d[0].additional_locations.len(), 1);
});

w9_edge!(w9_kh_20, {
    assert_ne!(DedupScope::File, DedupScope::Credential);
});

w9_edge!(w9_kh_21, {
    let c = Credential::from("abc");
    assert!(!c.expose_secret().is_empty());
});

w9_edge!(w9_kh_22, {
    let d = dedup_matches(vec![raw("1"), raw("2"), raw("1")], &DedupScope::Credential);
    assert_eq!(d.len(), 2);
});

w9_edge!(w9_kh_23, {
    let c = Credential::from("z");
    assert_eq!(format!("{}", c), "<redacted 1 bytes>");
});

w9_edge!(w9_kh_24, {
    let d = dedup_matches(vec![raw("t")], &DedupScope::None);
    assert_eq!(d[0].credential.as_ref(), "t");
});

w9_edge!(w9_kh_25, {
    assert_eq!(Severity::Critical, Severity::Critical);
});
