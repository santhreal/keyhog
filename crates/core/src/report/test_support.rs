//! Shared test fixtures for the reporter unit tests.
//!
//! The whole module is `#![cfg(test)]`, so it compiles to nothing in a
//! release build and never trips dead-code lints. Reporter test modules in
//! `csv.rs`, `junit.rs`, and `html.rs` build their writer over a
//! `&mut Vec<u8>` and drive the reporter against a finding produced here, so
//! the emitted bytes are inspectable and asserted concretely.
//!
//! This lives in its own file (declared as a plain `mod test_support;` from
//! `report.rs`) rather than inline in `report.rs` because the
//! `report_no_inline_tests` gate forbids any `#[cfg(test)]` token in
//! `report.rs` itself.
#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use crate::{MatchLocation, Severity, VerificationResult, VerifiedFinding};

/// A representative high-severity AWS finding with every reporter-visible
/// field populated, including a value that forces CSV/XML/HTML escaping
/// (`detector_name` carries a comma + quote + `<` + `&`). Reporter tests
/// assert concrete bytes against the output produced from this finding.
pub(crate) fn sample_finding() -> VerifiedFinding {
    let mut metadata = HashMap::new();
    metadata.insert("account_id".to_string(), "123456789012".to_string());

    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        // Embeds a comma, a double quote, a `<`, and an `&` so every
        // reporter's escaping path is exercised by a single fixture.
        detector_name: Arc::from("AWS Key, \"prod\" <a&b>"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential_redacted: std::borrow::Cow::Borrowed("AKIA...7XYA"),
        credential_hash: "deadbeef".into(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("config/app.env")),
            line: Some(12),
            offset: 5,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Live,
        metadata,
        additional_locations: vec![],
        confidence: Some(0.875),
    }
}
