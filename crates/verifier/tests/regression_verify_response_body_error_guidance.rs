//! #131 UX lock (batch 3): the three response-body verification failures
//! (`body read failed`, `response body exceeds 1MB limit`, `body is not utf-8`)
//! were bare tokens with no remedy. They now carry context + an actionable
//! `Fix:` while keeping their legacy short phrase as the leading substring
//! (Law 3: downstream `.contains` checks keep matching). A family-wide gate
//! covers ALL NINE actionable verification reasons so a future edit can't
//! reintroduce a bare token.

use keyhog_verifier::testing::{
    BODY_NOT_UTF8_ERROR, BODY_READ_FAILED_ERROR, CONNECTION_FAILED_ERROR, INVALID_AWS_REGION_ERROR,
    MAX_RETRIES_ERROR, REDIRECT_LIMIT_ERROR, REQUEST_FAILED_ERROR, RESPONSE_TOO_LARGE_ERROR,
    TIMEOUT_ERROR,
};

/// The remedy substring after the `Fix:` marker.
fn fix_portion(msg: &str) -> &str {
    let idx = msg
        .find("Fix:")
        .expect("message must contain a Fix: marker");
    &msg[idx + "Fix:".len()..]
}

// ── BODY_READ_FAILED_ERROR ────────────────────────────────────────────────────

#[test]
fn body_read_failed_leads_with_legacy_phrase() {
    assert!(
        BODY_READ_FAILED_ERROR.starts_with("body read failed"),
        "must lead with `body read failed`: {BODY_READ_FAILED_ERROR:?}"
    );
}

#[test]
fn body_read_failed_has_fix_section() {
    assert!(
        BODY_READ_FAILED_ERROR.contains("Fix:"),
        "must state the fix"
    );
}

#[test]
fn body_read_failed_names_transient_cause() {
    assert!(
        BODY_READ_FAILED_ERROR.contains("connection dropped"),
        "must explain the connection dropped mid-body: {BODY_READ_FAILED_ERROR:?}"
    );
}

#[test]
fn body_read_failed_suggests_retry_or_egress_check() {
    let fix = fix_portion(BODY_READ_FAILED_ERROR);
    assert!(
        fix.contains("retry") && fix.contains("egress"),
        "the fix should suggest retrying / checking egress: {fix:?}"
    );
}

// ── RESPONSE_TOO_LARGE_ERROR ──────────────────────────────────────────────────

#[test]
fn response_too_large_leads_with_legacy_phrase() {
    assert!(
        RESPONSE_TOO_LARGE_ERROR.starts_with("response body exceeds 1MB limit"),
        "must lead with the legacy phrase: {RESPONSE_TOO_LARGE_ERROR:?}"
    );
}

#[test]
fn response_too_large_has_fix_section() {
    assert!(
        RESPONSE_TOO_LARGE_ERROR.contains("Fix:"),
        "must state the fix"
    );
}

#[test]
fn response_too_large_explains_unparseable_signal() {
    assert!(
        RESPONSE_TOO_LARGE_ERROR.contains("cannot be parsed"),
        "must explain the success signal can't be parsed: {RESPONSE_TOO_LARGE_ERROR:?}"
    );
}

#[test]
fn response_too_large_points_at_verify_url() {
    assert!(
        fix_portion(RESPONSE_TOO_LARGE_ERROR).contains("verify URL"),
        "the fix should point at the detector's verify URL: {RESPONSE_TOO_LARGE_ERROR:?}"
    );
}

// ── BODY_NOT_UTF8_ERROR ───────────────────────────────────────────────────────

#[test]
fn body_not_utf8_leads_with_legacy_phrase() {
    assert!(
        BODY_NOT_UTF8_ERROR.starts_with("body is not utf-8"),
        "must lead with `body is not utf-8`: {BODY_NOT_UTF8_ERROR:?}"
    );
}

#[test]
fn body_not_utf8_has_fix_section() {
    assert!(BODY_NOT_UTF8_ERROR.contains("Fix:"), "must state the fix");
}

#[test]
fn body_not_utf8_names_binary_cause() {
    assert!(
        BODY_NOT_UTF8_ERROR.contains("binary"),
        "must explain the body was binary: {BODY_NOT_UTF8_ERROR:?}"
    );
}

#[test]
fn body_not_utf8_points_at_json_api_endpoint() {
    assert!(
        fix_portion(BODY_NOT_UTF8_ERROR).contains("JSON API"),
        "the fix should point at the JSON API endpoint: {BODY_NOT_UTF8_ERROR:?}"
    );
}

// ── family-wide gate over ALL nine actionable reasons ─────────────────────────

const ALL_ACTIONABLE: &[&str] = &[
    TIMEOUT_ERROR,
    CONNECTION_FAILED_ERROR,
    REDIRECT_LIMIT_ERROR,
    REQUEST_FAILED_ERROR,
    MAX_RETRIES_ERROR,
    INVALID_AWS_REGION_ERROR,
    BODY_READ_FAILED_ERROR,
    RESPONSE_TOO_LARGE_ERROR,
    BODY_NOT_UTF8_ERROR,
];

#[test]
fn every_actionable_reason_has_a_fix_marker() {
    for msg in ALL_ACTIONABLE {
        assert!(
            msg.contains("Fix:"),
            "actionable reason lacks a Fix: marker: {msg:?}"
        );
    }
}

#[test]
fn every_actionable_reason_fix_is_nonempty() {
    for msg in ALL_ACTIONABLE {
        assert!(
            !fix_portion(msg).trim().is_empty(),
            "Fix: section is empty: {msg:?}"
        );
    }
}

#[test]
fn every_actionable_reason_has_exactly_one_fix_marker() {
    // A second `Fix:` would mean a doubled / second-order interpolated message.
    for msg in ALL_ACTIONABLE {
        assert_eq!(
            msg.matches("Fix:").count(),
            1,
            "exactly one Fix: expected: {msg:?}"
        );
    }
}

#[test]
fn no_actionable_reason_is_a_security_refusal() {
    // Security refusals (`blocked: private URL`) are deliberately terse and are
    // NOT in this actionable family — guard against mixing the categories.
    for msg in ALL_ACTIONABLE {
        assert!(
            !msg.starts_with("blocked:"),
            "actionable reason must not be a refusal: {msg:?}"
        );
    }
}

#[test]
fn all_actionable_reasons_are_distinct() {
    for (i, a) in ALL_ACTIONABLE.iter().enumerate() {
        for b in &ALL_ACTIONABLE[i + 1..] {
            assert_ne!(a, b, "duplicate actionable reason text");
        }
    }
}

#[test]
fn response_body_trio_are_mutually_distinct() {
    let trio = [
        BODY_READ_FAILED_ERROR,
        RESPONSE_TOO_LARGE_ERROR,
        BODY_NOT_UTF8_ERROR,
    ];
    for (i, a) in trio.iter().enumerate() {
        for b in &trio[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn response_body_trio_each_leads_with_its_legacy_phrase() {
    assert!(BODY_READ_FAILED_ERROR.starts_with("body read failed"));
    assert!(RESPONSE_TOO_LARGE_ERROR.starts_with("response body exceeds 1MB limit"));
    assert!(BODY_NOT_UTF8_ERROR.starts_with("body is not utf-8"));
}
