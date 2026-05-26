//! LR1-A8 replacement gate: `verify/credential.rs` empty credential shape.

use keyhog_core::{MatchLocation, RawMatch, Severity};
use std::sync::Arc;

#[test]
fn empty_credential_match_has_zero_len_secret() {
    let m = RawMatch {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("Demo"),
        service: Arc::from("demo"),
        severity: Severity::High,
        credential: Arc::from(""),
        credential_hash: "hash".into(),
        companions: Default::default(),
        location: MatchLocation {
            source: Arc::from("fs"),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    };
    assert!(m.credential.is_empty());
}
