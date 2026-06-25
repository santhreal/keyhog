//! Regression: SARIF `tool.driver.informationUri` points at the canonical
//! keyhog repository, not a wrong/placeholder org.
//!
//! Root cause of the bug: `SarifReporter::finish` hardcoded
//! `Some("https://github.com/keyhog/keyhog".to_string())`. The real project
//! lives at `github.com/santhsecurity/keyhog` (see `repository` in
//! `crates/core/Cargo.toml`). GitHub Code Scanning, Azure DevOps, and IDE
//! integrations render `informationUri` as the "open tool homepage" link, so
//! the wrong org sent every consumer to a non-existent repo.
//!
//! Fix: source the value from `env!("CARGO_PKG_REPOSITORY")` so the SARIF link
//! can never drift from the published manifest.
//!
//! These tests assert the CONCRETE correct string. They FAIL against the old
//! `keyhog/keyhog` value and PASS once the URI tracks the manifest.

use keyhog_core::{
    write_report, MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

/// The canonical repository URL as declared in `crates/core/Cargo.toml`'s
/// `repository` field. Cargo surfaces this to the compiled crate AND to this
/// integration-test target (same package) via `CARGO_PKG_REPOSITORY`.
const EXPECTED_INFORMATION_URI: &str = "https://github.com/santhsecurity/keyhog";

/// The exact wrong value the bug shipped. The fix must not reintroduce it.
const BUGGY_INFORMATION_URI: &str = "https://github.com/keyhog/keyhog";

fn sample_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "aws-access-key".into(),
        detector_name: "AWS Access Key".into(),
        service: "aws".into(),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA****"),
        credential_hash: [0; 32].into(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("config.env".into()),
            line: Some(12),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: Some(0.9),
    }
}

fn render_sarif(with_finding: bool) -> serde_json::Value {
    let mut buf = Vec::new();
    let findings = if with_finding {
        vec![sample_finding()]
    } else {
        Vec::new()
    };
    write_report(
        &mut buf,
        ReportFormat::Sarif {
            skip_summary: Vec::new(),
        },
        &findings,
    )
    .expect("finish SARIF document");
    serde_json::from_slice(&buf).expect("SARIF output must parse as JSON")
}

fn information_uri(json: &serde_json::Value) -> &str {
    json["runs"][0]["tool"]["driver"]["informationUri"]
        .as_str()
        .expect("runs[0].tool.driver.informationUri must be a present JSON string")
}

/// Positive: with at least one finding the driver's `informationUri` is the
/// canonical santhsecurity repo, byte-for-byte.
#[test]
fn information_uri_is_canonical_repo_with_findings() {
    let json = render_sarif(true);
    let uri = information_uri(&json);
    assert_eq!(
        uri, EXPECTED_INFORMATION_URI,
        "SARIF tool.driver.informationUri must be exactly {EXPECTED_INFORMATION_URI:?}, got {uri:?}"
    );
}

/// Boundary: an empty run (no findings, only `finish()`) still emits the
/// tool.driver block, and its `informationUri` must be correct too — the
/// streaming reporter builds the driver in `finish()` regardless of count.
#[test]
fn information_uri_is_canonical_repo_on_empty_run() {
    let json = render_sarif(false);
    let uri = information_uri(&json);
    assert_eq!(
        uri, EXPECTED_INFORMATION_URI,
        "empty-run SARIF tool.driver.informationUri must be exactly {EXPECTED_INFORMATION_URI:?}, got {uri:?}"
    );
}

/// Negative twin: the wrong `keyhog/keyhog` org that the bug shipped must not
/// appear anywhere in the document, not just in the driver field. A substring
/// scan catches it even if a future refactor moves the value.
#[test]
fn buggy_information_uri_never_appears() {
    for with_finding in [false, true] {
        let mut buf = Vec::new();
        let findings = if with_finding {
            vec![sample_finding()]
        } else {
            Vec::new()
        };
        write_report(
            &mut buf,
            ReportFormat::Sarif {
                skip_summary: Vec::new(),
            },
            &findings,
        )
        .expect("finish SARIF document");
        let text = String::from_utf8(buf).expect("SARIF output must be valid UTF-8");
        assert!(
            !text.contains(BUGGY_INFORMATION_URI),
            "SARIF output must not contain the buggy URI {BUGGY_INFORMATION_URI:?} (with_finding={with_finding})"
        );
        // And the correct one must be present.
        assert!(
            text.contains(EXPECTED_INFORMATION_URI),
            "SARIF output must contain the canonical URI {EXPECTED_INFORMATION_URI:?} (with_finding={with_finding})"
        );
    }
}

/// Source-of-truth: the emitted `informationUri` must equal the crate's
/// `CARGO_PKG_REPOSITORY` (the `repository` field in Cargo.toml). This pins
/// the value to the manifest so it can never silently drift from a hardcoded
/// literal again, and asserts our `EXPECTED_INFORMATION_URI` constant matches
/// the manifest the crate was built with.
#[test]
fn information_uri_tracks_cargo_pkg_repository() {
    let manifest_repo = env!("CARGO_PKG_REPOSITORY");
    assert_eq!(
        manifest_repo, EXPECTED_INFORMATION_URI,
        "test expectation drifted from Cargo.toml `repository`"
    );

    let json = render_sarif(true);
    let uri = information_uri(&json);
    assert_eq!(
        uri, manifest_repo,
        "SARIF informationUri must mirror CARGO_PKG_REPOSITORY, got {uri:?}"
    );
}

/// Adversarial / shape: `informationUri` must be an absolute https URL on the
/// real org, not stdin, not a relative path, not empty. Guards against a fix
/// that swaps the wrong literal for another wrong-but-nonempty value.
#[test]
fn information_uri_is_well_formed_https_url() {
    let json = render_sarif(true);
    let uri = information_uri(&json);
    assert!(
        uri.starts_with("https://github.com/"),
        "informationUri must be an https GitHub URL, got {uri:?}"
    );
    assert!(
        uri.contains("/santhsecurity/"),
        "informationUri must reference the santhsecurity org, got {uri:?}"
    );
    assert!(
        !uri.ends_with('/') && !uri.is_empty(),
        "informationUri must be a concrete repo URL, got {uri:?}"
    );
}
