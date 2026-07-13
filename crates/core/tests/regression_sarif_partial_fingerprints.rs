//! Regression: SARIF `results[].partialFingerprints` carries the stable
//! per-credential identity GitHub code-scanning uses to dedup alerts across
//! runs.
//!
//! Contract under test (see `report/sarif_uri.rs::credential_fingerprints` and
//! `report/sarif.rs::build_sarif_result`):
//!   1. Every finding with a real (non-zero) credential hash emits a
//!      `partialFingerprints` object with the SINGLE key
//!      `"keyhog/credentialHash/v1"`.
//!   2. Its value is the lower-case hex of the finding's SHA-256 credential
//!      hash (i.e. `hex(sha256(credential_value))`).
//!   3. Two findings sharing a credential VALUE share the fingerprint byte-for-
//!      byte (so the platform collapses them to one alert), regardless of file,
//!      line, severity, or redaction text.
//!   4. Two findings with DIFFERENT values get DIFFERENT fingerprints.
//!   5. The fingerprint is stable across independent render runs.
//!   6. The all-zero compatibility sentinel hash emits NO `partialFingerprints`
//!      block (there is no credential identity to dedup on).
//!
//! Every assertion below pins a concrete value: the exact key string, the exact
//! 64-char lower-case SHA-256 hex, exact equality/inequality between findings,
//! and presence/absence of the JSON object.

use keyhog_core::{
    hex_encode, sha256_hash, write_report, CredentialHash, MatchLocation, ReportFormat, Severity,
    VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

/// The single, versioned partialFingerprints key keyhog emits. Owned in
/// `report/sarif_uri.rs::credential_fingerprints`; pinned here so a rename is a
/// visible, reviewed break (code-scanning keys the dedup on this exact string).
const FP_KEY: &str = "keyhog/credentialHash/v1";

/// SHA-256 hex of `"AKIAIOSFODNN7EXAMPLE"`, computed out-of-band with
/// `printf '%s' 'AKIAIOSFODNN7EXAMPLE' | sha256sum`. This is the exact string
/// the fingerprint value must equal for a finding hashed from that credential.
const AWS_VALUE: &str = "AKIAIOSFODNN7EXAMPLE";
const AWS_VALUE_SHA256_HEX: &str =
    "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3";

/// SHA-256 hex of `"glpat-XXXXXXXXXXXXXXXXXXXX"` (independent out-of-band value).
const GITLAB_VALUE: &str = "glpat-XXXXXXXXXXXXXXXXXXXX";
const GITLAB_VALUE_SHA256_HEX: &str =
    "156b2cdd8ff1617f07c96a3642465c3f5d0d784fc6fa089ceda2de2dca01cf6e";

/// SHA-256 hex of the EMPTY string, proves the empty credential is NOT the
/// all-zero sentinel and therefore is still fingerprinted.
const EMPTY_VALUE_SHA256_HEX: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Build a finding whose credential identity is `sha256(value)`, at a caller-
/// chosen file/line/severity so we can prove the fingerprint ignores those.
fn finding_for(
    value: &str,
    file: &str,
    line: usize,
    severity: Severity,
    redacted: &'static str,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "aws-access-key".into(),
        detector_name: "AWS Access Key".into(),
        service: "aws".into(),
        severity,
        credential_redacted: Cow::Borrowed(redacted),
        credential_hash: sha256_hash(value),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some(file.into()),
            line: Some(line),
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

/// A finding carrying the all-zero compatibility sentinel hash (no identity).
fn finding_zero_hash() -> VerifiedFinding {
    let mut f = finding_for("ignored", "z.env", 1, Severity::High, "****");
    f.credential_hash = CredentialHash::ZERO;
    f
}

fn render_sarif(findings: &[VerifiedFinding]) -> serde_json::Value {
    let mut buf = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::Sarif {
            skip_summary: Vec::new(),
        },
        findings,
    )
    .expect("finish SARIF document");
    serde_json::from_slice(&buf).expect("SARIF output must parse as JSON")
}

/// `runs[0].results[idx].partialFingerprints` as a JSON value (may be absent).
fn partial_fingerprints(json: &serde_json::Value, idx: usize) -> serde_json::Value {
    json["runs"][0]["results"][idx]["partialFingerprints"].clone()
}

/// Positive: the fingerprint object exists and carries the exact versioned key.
#[test]
fn partial_fingerprints_has_exact_key() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "config.env",
        12,
        Severity::High,
        "AKIA****",
    )]);
    let fp = partial_fingerprints(&json, 0);
    let obj = fp
        .as_object()
        .expect("results[0].partialFingerprints must be a JSON object");
    assert!(
        obj.contains_key(FP_KEY),
        "partialFingerprints must contain key {FP_KEY:?}, got keys {:?}",
        obj.keys().collect::<Vec<_>>()
    );
}

/// Positive: the fingerprint VALUE is the exact SHA-256 hex of the credential
/// value (the load-bearing identity assertion).
#[test]
fn fingerprint_value_is_exact_sha256_hex_of_credential() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "config.env",
        12,
        Severity::High,
        "AKIA****",
    )]);
    let value = partial_fingerprints(&json, 0)[FP_KEY]
        .as_str()
        .expect("fingerprint value must be a JSON string")
        .to_string();
    assert_eq!(
        value, AWS_VALUE_SHA256_HEX,
        "fingerprint must be sha256({AWS_VALUE:?}) hex"
    );
}

/// Cross-check: the emitted fingerprint equals the crate's own
/// `hex_encode(sha256_hash(value))`, pinning the reporter to the public hashing
/// API (guards a future hash/encoding swap from silently drifting the identity).
#[test]
fn fingerprint_matches_public_hash_api() {
    let expected = hex_encode(sha256_hash(GITLAB_VALUE));
    // Sanity: the public API agrees with the out-of-band constant.
    assert_eq!(
        expected, GITLAB_VALUE_SHA256_HEX,
        "sha256_hash/hex_encode must match the out-of-band sha256sum"
    );

    let json = render_sarif(&[finding_for(
        GITLAB_VALUE,
        "src/token.rs",
        3,
        Severity::Critical,
        "glpat-****",
    )]);
    let fps = partial_fingerprints(&json, 0);
    let value = fps[FP_KEY]
        .as_str()
        .expect("fingerprint value must be a JSON string");
    assert_eq!(
        value, expected,
        "reporter must use hex_encode(sha256_hash(..))"
    );
}

/// Boundary/shape: the fingerprint is exactly 64 lower-case hex characters
/// (a full SHA-256 digest, never truncated, never upper-cased).
#[test]
fn fingerprint_is_64_lowercase_hex_chars() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "config.env",
        7,
        Severity::Medium,
        "AKIA****",
    )]);
    let value = partial_fingerprints(&json, 0)[FP_KEY]
        .as_str()
        .expect("fingerprint value must be a JSON string")
        .to_string();
    assert_eq!(
        value.len(),
        64,
        "SHA-256 hex is 64 chars, got {}",
        value.len()
    );
    assert!(
        value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "fingerprint must be lower-case hex, got {value:?}"
    );
}

/// The fingerprint object contains EXACTLY one key, the versioned identity 
/// and nothing else. Guards against accidental extra fingerprints that would
/// change code-scanning's dedup grouping.
#[test]
fn partial_fingerprints_has_exactly_one_key() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "config.env",
        12,
        Severity::High,
        "AKIA****",
    )]);
    let obj = partial_fingerprints(&json, 0)
        .as_object()
        .expect("partialFingerprints must be an object")
        .clone();
    assert_eq!(
        obj.len(),
        1,
        "partialFingerprints must hold exactly one key, got {:?}",
        obj.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        obj.keys().next().map(String::as_str),
        Some(FP_KEY),
        "the one key must be {FP_KEY:?}"
    );
}

/// Dedup contract (positive): two findings with the SAME credential value at
/// DIFFERENT files/lines produce byte-identical fingerprints, so code-scanning
/// collapses them into one alert.
#[test]
fn same_value_two_findings_share_fingerprint() {
    let json = render_sarif(&[
        finding_for(AWS_VALUE, "a/one.env", 1, Severity::High, "AKIA****"),
        finding_for(AWS_VALUE, "b/two.env", 99, Severity::High, "AKIA****"),
    ]);
    let fp0 = partial_fingerprints(&json, 0)[FP_KEY]
        .as_str()
        .expect("finding 0 fingerprint")
        .to_string();
    let fp1 = partial_fingerprints(&json, 1)[FP_KEY]
        .as_str()
        .expect("finding 1 fingerprint")
        .to_string();
    assert_eq!(
        fp0, fp1,
        "same credential value must yield the same fingerprint across locations"
    );
    assert_eq!(fp0, AWS_VALUE_SHA256_HEX, "and it is sha256(value)");
}

/// Dedup identity ignores severity AND redaction text: same value, different
/// severity and different redacted display still share the fingerprint. The
/// identity is the VALUE, nothing else.
#[test]
fn fingerprint_ignores_severity_and_redaction() {
    let json = render_sarif(&[
        finding_for(AWS_VALUE, "a/one.env", 1, Severity::Critical, "AKIAA***"),
        finding_for(AWS_VALUE, "b/two.env", 2, Severity::Low, "AK********"),
    ]);
    let fp0 = partial_fingerprints(&json, 0)[FP_KEY]
        .as_str()
        .expect("fp0")
        .to_string();
    let fp1 = partial_fingerprints(&json, 1)[FP_KEY]
        .as_str()
        .expect("fp1")
        .to_string();
    assert_eq!(
        fp0, fp1,
        "fingerprint must not depend on severity or redaction text"
    );
}

/// Dedup contract (negative twin): two findings with DIFFERENT credential
/// values produce DIFFERENT fingerprints (distinct leaks stay distinct alerts).
#[test]
fn different_values_differ_fingerprints() {
    let json = render_sarif(&[
        finding_for(AWS_VALUE, "a.env", 1, Severity::High, "AKIA****"),
        finding_for(GITLAB_VALUE, "b.env", 2, Severity::High, "glpat-****"),
    ]);
    let fp0 = partial_fingerprints(&json, 0)[FP_KEY]
        .as_str()
        .expect("fp0")
        .to_string();
    let fp1 = partial_fingerprints(&json, 1)[FP_KEY]
        .as_str()
        .expect("fp1")
        .to_string();
    assert_ne!(fp0, fp1, "distinct credential values must not collide");
    assert_eq!(fp0, AWS_VALUE_SHA256_HEX);
    assert_eq!(fp1, GITLAB_VALUE_SHA256_HEX);
}

/// Stability: rendering the SAME finding twice yields the SAME fingerprint.
/// Code-scanning re-opens an alert if the fingerprint drifts between runs, so
/// this must be deterministic across independent invocations.
#[test]
fn fingerprint_stable_across_runs() {
    let make = || finding_for(AWS_VALUE, "config.env", 12, Severity::High, "AKIA****");
    let a = render_sarif(&[make()]);
    let b = render_sarif(&[make()]);
    let fa = partial_fingerprints(&a, 0)[FP_KEY]
        .as_str()
        .expect("run a fp")
        .to_string();
    let fb = partial_fingerprints(&b, 0)[FP_KEY]
        .as_str()
        .expect("run b fp")
        .to_string();
    assert_eq!(fa, fb, "fingerprint must be stable across runs");
    assert_eq!(fa, AWS_VALUE_SHA256_HEX);
}

/// Sentinel: the all-zero compatibility hash carries NO credential identity, so
/// the `partialFingerprints` object must be absent entirely (serde skips it).
#[test]
fn zero_hash_omits_partial_fingerprints() {
    let json = render_sarif(&[finding_zero_hash()]);
    let fp = partial_fingerprints(&json, 0);
    assert!(
        fp.is_null(),
        "all-zero sentinel hash must emit NO partialFingerprints block, got {fp}"
    );
    // The result itself must still be present (the finding is not dropped).
    assert_eq!(
        json["runs"][0]["results"][0]["ruleId"].as_str(),
        Some("aws-access-key"),
        "the zero-hash finding must still be reported, just without a fingerprint"
    );
}

/// Adversarial: an EMPTY credential value is NOT the zero sentinel, sha256("")
/// is a concrete non-zero digest (so it IS fingerprinted with that exact hex).
#[test]
fn empty_credential_value_is_fingerprinted_not_sentinel() {
    let json = render_sarif(&[finding_for("", "empty.env", 4, Severity::High, "****")]);
    let value = partial_fingerprints(&json, 0)[FP_KEY]
        .as_str()
        .expect("empty-value finding must still have a fingerprint")
        .to_string();
    assert_eq!(
        value, EMPTY_VALUE_SHA256_HEX,
        "empty credential must hash to sha256(\"\"), not the zero sentinel"
    );
}

/// Mixed run: a real-hash finding and a zero-hash finding in the SAME document
/// keep their independent behavior, one fingerprinted, one not, proving the
/// per-result streaming logic does not leak state between results.
#[test]
fn mixed_zero_and_real_hash_in_one_run() {
    let json = render_sarif(&[
        finding_for(AWS_VALUE, "real.env", 1, Severity::High, "AKIA****"),
        finding_zero_hash(),
        finding_for(GITLAB_VALUE, "real2.env", 2, Severity::High, "glpat-****"),
    ]);
    assert_eq!(
        partial_fingerprints(&json, 0)[FP_KEY].as_str(),
        Some(AWS_VALUE_SHA256_HEX),
        "result 0 (real hash) must carry the aws fingerprint"
    );
    assert!(
        partial_fingerprints(&json, 1).is_null(),
        "result 1 (zero hash) must carry no fingerprint block"
    );
    assert_eq!(
        partial_fingerprints(&json, 2)[FP_KEY].as_str(),
        Some(GITLAB_VALUE_SHA256_HEX),
        "result 2 (real hash) must carry the gitlab fingerprint"
    );
}

/// The fingerprint is independent of the additional/related locations attached
/// to a finding: two findings with the same value but different additional
/// locations still share the fingerprint (identity = value, not geometry).
#[test]
fn fingerprint_independent_of_additional_locations() {
    let mut with_extra = finding_for(AWS_VALUE, "a.env", 1, Severity::High, "AKIA****");
    with_extra.additional_locations = vec![MatchLocation {
        source: "filesystem".into(),
        file_path: Some("other.env".into()),
        line: Some(42),
        offset: 0,
        commit: None,
        author: None,
        date: None,
    }];
    let plain = finding_for(AWS_VALUE, "b.env", 1, Severity::High, "AKIA****");
    let json = render_sarif(&[with_extra, plain]);
    let fps0 = partial_fingerprints(&json, 0);
    let fp0 = fps0[FP_KEY].as_str().expect("fp0");
    let fps1 = partial_fingerprints(&json, 1);
    let fp1 = fps1[FP_KEY].as_str().expect("fp1");
    assert_eq!(
        fp0, fp1,
        "additional locations must not change the credential fingerprint"
    );
    assert_eq!(fp0, AWS_VALUE_SHA256_HEX);
}
