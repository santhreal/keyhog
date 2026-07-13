//! #131 UX lock (batch 4): the verifier's `VerificationResult::Error` messages
//! split into two deliberate taxonomies, and this gate keeps them clean:
//!   * ACTIONABLE failures (timeout, connection, redirect, request, max-retries,
//!     invalid AWS region, the three response-body errors, and now `invalid URL`)
//!     each carry a concrete `Fix:` the operator can act on.
//!   * REFUSALS (`blocked: private URL`, `blocked: HTTPS only`, `blocked: DNS
//!     returned no addresses`) are security/policy fail-closed outcomes: terse,
//!     uniformly `blocked:`-prefixed, and intentionally WITHOUT a `Fix:` (the
//!     refusal is the correct result, not an operator error).
//! The two families must stay disjoint. `invalid URL` was the last actionable
//! message still emitted as a bare `format!("invalid URL: {e}")`; it is now built
//! by `invalid_url_error`, which preserves the parse error and appends the fix.

use keyhog_verifier::testing::{
    invalid_url_error, BODY_NOT_UTF8_ERROR, BODY_READ_FAILED_ERROR, CONNECTION_FAILED_ERROR,
    DNS_NO_ADDRESSES_ERROR, HTTPS_ONLY_ERROR, INVALID_AWS_REGION_ERROR, MAX_RETRIES_ERROR,
    PRIVATE_URL_ERROR, REDIRECT_LIMIT_ERROR, REQUEST_FAILED_ERROR, RESPONSE_TOO_LARGE_ERROR,
    TIMEOUT_ERROR,
};

fn fix_portion(msg: &str) -> &str {
    let idx = msg
        .find("Fix:")
        .expect("message must contain a Fix: marker");
    &msg[idx + "Fix:".len()..]
}

/// Every actionable verifier failure, including the freshly-fixed `invalid URL`.
fn actionable_family() -> Vec<String> {
    vec![
        TIMEOUT_ERROR.to_string(),
        CONNECTION_FAILED_ERROR.to_string(),
        REDIRECT_LIMIT_ERROR.to_string(),
        REQUEST_FAILED_ERROR.to_string(),
        MAX_RETRIES_ERROR.to_string(),
        INVALID_AWS_REGION_ERROR.to_string(),
        BODY_READ_FAILED_ERROR.to_string(),
        RESPONSE_TOO_LARGE_ERROR.to_string(),
        BODY_NOT_UTF8_ERROR.to_string(),
        invalid_url_error("relative URL without a base"),
    ]
}

/// Every security/policy refusal.
const REFUSALS: &[&str] = &[PRIVATE_URL_ERROR, HTTPS_ONLY_ERROR, DNS_NO_ADDRESSES_ERROR];

// ── invalid_url_error specifics ───────────────────────────────────────────────

#[test]
fn invalid_url_error_leads_with_legacy_phrase() {
    assert!(
        invalid_url_error("oops").starts_with("invalid URL:"),
        "must lead with the legacy `invalid URL:` phrase"
    );
}

#[test]
fn invalid_url_error_preserves_the_parse_error_text() {
    let msg = invalid_url_error("empty host");
    assert!(
        msg.contains("empty host"),
        "underlying parse error must be preserved: {msg:?}"
    );
}

#[test]
fn invalid_url_error_has_a_fix() {
    assert!(
        invalid_url_error("x").contains("Fix:"),
        "must state the fix"
    );
}

#[test]
fn invalid_url_error_points_at_the_detector_verify_url() {
    let msg = invalid_url_error("x");
    assert!(
        fix_portion(&msg).contains("verify") && fix_portion(&msg).contains("url"),
        "the fix should point at the detector's verify url: {msg:?}"
    );
}

#[test]
fn invalid_url_error_is_not_a_refusal() {
    assert!(
        !invalid_url_error("x").starts_with("blocked:"),
        "invalid URL is actionable, not a refusal"
    );
}

#[test]
fn invalid_url_error_handles_varied_parse_errors() {
    for raw in [
        "",
        "no scheme here",
        "invalid port number",
        "spaces in host",
    ] {
        let msg = invalid_url_error(raw);
        assert!(
            msg.starts_with("invalid URL:"),
            "leads with phrase for {raw:?}: {msg:?}"
        );
        assert!(msg.contains("Fix:"), "has fix for {raw:?}: {msg:?}");
        if !raw.is_empty() {
            assert!(msg.contains(raw), "preserves {raw:?}: {msg:?}");
        }
    }
}

// ── refusal family ────────────────────────────────────────────────────────────

#[test]
fn private_url_is_a_blocked_refusal() {
    assert!(PRIVATE_URL_ERROR.starts_with("blocked:"));
}

#[test]
fn https_only_is_a_blocked_refusal() {
    assert!(HTTPS_ONLY_ERROR.starts_with("blocked:"));
}

#[test]
fn dns_no_addresses_is_a_blocked_refusal() {
    assert!(DNS_NO_ADDRESSES_ERROR.starts_with("blocked:"));
}

#[test]
fn dns_no_addresses_value_is_unchanged() {
    // verifier_safety_contracts.rs asserts this exact substring via `.contains`.
    assert_eq!(DNS_NO_ADDRESSES_ERROR, "blocked: DNS returned no addresses");
}

#[test]
fn every_refusal_is_blocked_prefixed() {
    for r in REFUSALS {
        assert!(
            r.starts_with("blocked:"),
            "refusal must be blocked:-prefixed: {r:?}"
        );
    }
}

#[test]
fn refusals_carry_no_fix_marker() {
    // Refusals are terse by design, a `Fix:` would wrongly imply the operator
    // can make the blocked host safe to contact.
    for r in REFUSALS {
        assert!(
            !r.contains("Fix:"),
            "a refusal must stay terse (no Fix:): {r:?}"
        );
    }
}

#[test]
fn refusals_are_distinct() {
    for (i, a) in REFUSALS.iter().enumerate() {
        for b in &REFUSALS[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

// ── actionable family ─────────────────────────────────────────────────────────

#[test]
fn every_actionable_message_has_a_fix() {
    for m in actionable_family() {
        assert!(m.contains("Fix:"), "actionable message lacks a Fix:: {m:?}");
    }
}

#[test]
fn every_actionable_fix_is_nonempty() {
    for m in actionable_family() {
        assert!(!fix_portion(&m).trim().is_empty(), "Fix: is empty: {m:?}");
    }
}

#[test]
fn every_actionable_message_has_exactly_one_fix_marker() {
    for m in actionable_family() {
        assert_eq!(
            m.matches("Fix:").count(),
            1,
            "exactly one Fix: expected: {m:?}"
        );
    }
}

#[test]
fn no_actionable_message_is_blocked_prefixed() {
    for m in actionable_family() {
        assert!(
            !m.starts_with("blocked:"),
            "an actionable message must not look like a refusal: {m:?}"
        );
    }
}

// ── disjointness between the two families ─────────────────────────────────────

#[test]
fn actionable_and_refusal_families_share_no_message() {
    for a in actionable_family() {
        for r in REFUSALS {
            assert_ne!(&a, r, "a message cannot be both actionable and a refusal");
        }
    }
}

#[test]
fn all_verifier_error_messages_are_distinct() {
    let mut all: Vec<String> = actionable_family();
    all.extend(REFUSALS.iter().map(|r| r.to_string()));
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b, "duplicate verifier error message");
        }
    }
}

#[test]
fn families_partition_by_blocked_prefix() {
    // The `blocked:` prefix is the exact discriminator between the families.
    for m in actionable_family() {
        assert!(!m.starts_with("blocked:"));
    }
    for r in REFUSALS {
        assert!(r.starts_with("blocked:"));
    }
}
