//! #131 UX lock: the four operator-facing transport-failure verification reasons
//! must carry context + an actionable fix, not a bare token. These reasons
//! surface directly as a finding's verification status, so "timeout" alone leaves
//! the operator with no next step. The enriched messages additionally KEEP each
//! legacy short phrase as a leading substring so existing downstream `.contains`
//! checks (verifier_safety_contracts, mock_verify) keep matching (Law 3: no
//! contract break). This locks both halves: back-compat substring + fix guidance.

use keyhog_verifier::testing::{
    CONNECTION_FAILED_ERROR, REDIRECT_LIMIT_ERROR, REQUEST_FAILED_ERROR, TIMEOUT_ERROR,
};

/// (message, legacy short phrase that downstream string checks rely on).
const TRANSPORT_REASONS: &[(&str, &str)] = &[
    (TIMEOUT_ERROR, "timeout"),
    (CONNECTION_FAILED_ERROR, "connection failed"),
    (REDIRECT_LIMIT_ERROR, "too many redirects"),
    (REQUEST_FAILED_ERROR, "request failed"),
];

// ── TIMEOUT_ERROR ─────────────────────────────────────────────────────────────

#[test]
fn timeout_error_leads_with_legacy_token() {
    assert!(
        TIMEOUT_ERROR.starts_with("timeout"),
        "must lead with the legacy `timeout` token for back-compat: {TIMEOUT_ERROR:?}"
    );
}

#[test]
fn timeout_error_has_fix_section() {
    assert!(TIMEOUT_ERROR.contains("Fix:"), "timeout reason must state the fix");
}

#[test]
fn timeout_error_cites_the_timeout_flag() {
    assert!(
        TIMEOUT_ERROR.contains("--timeout"),
        "the actionable knob is the --timeout flag: {TIMEOUT_ERROR:?}"
    );
}

#[test]
fn timeout_error_mentions_egress_or_proxy() {
    assert!(
        TIMEOUT_ERROR.contains("egress") || TIMEOUT_ERROR.contains("proxy"),
        "must point at the network cause (egress/proxy)"
    );
}

// ── CONNECTION_FAILED_ERROR ───────────────────────────────────────────────────

#[test]
fn connection_failed_leads_with_legacy_phrase() {
    assert!(
        CONNECTION_FAILED_ERROR.starts_with("connection failed"),
        "must lead with `connection failed`: {CONNECTION_FAILED_ERROR:?}"
    );
}

#[test]
fn connection_failed_has_fix_section() {
    assert!(CONNECTION_FAILED_ERROR.contains("Fix:"), "must state the fix");
}

#[test]
fn connection_failed_cites_dns_and_firewall() {
    assert!(
        CONNECTION_FAILED_ERROR.contains("DNS") && CONNECTION_FAILED_ERROR.contains("firewall"),
        "the actionable causes are DNS + firewall/egress: {CONNECTION_FAILED_ERROR:?}"
    );
}

#[test]
fn connection_failed_mentions_proxy() {
    assert!(
        CONNECTION_FAILED_ERROR.contains("proxy"),
        "proxy misconfiguration is a common cause and must be named"
    );
}

// ── REDIRECT_LIMIT_ERROR ──────────────────────────────────────────────────────

#[test]
fn redirect_leads_with_legacy_phrase() {
    assert!(
        REDIRECT_LIMIT_ERROR.starts_with("too many redirects"),
        "must lead with `too many redirects`: {REDIRECT_LIMIT_ERROR:?}"
    );
}

#[test]
fn redirect_has_fix_section() {
    assert!(REDIRECT_LIMIT_ERROR.contains("Fix:"), "must state the fix");
}

#[test]
fn redirect_explains_ssrf_rationale() {
    assert!(
        REDIRECT_LIMIT_ERROR.contains("SSRF"),
        "redirects are refused for SSRF safety — the message must say so, not look like a bug"
    );
}

#[test]
fn redirect_suggests_canonical_host() {
    assert!(
        REDIRECT_LIMIT_ERROR.contains("canonical"),
        "the fix is to target the canonical API host: {REDIRECT_LIMIT_ERROR:?}"
    );
}

// ── REQUEST_FAILED_ERROR ──────────────────────────────────────────────────────

#[test]
fn request_failed_leads_with_legacy_phrase() {
    assert!(
        REQUEST_FAILED_ERROR.starts_with("request failed"),
        "must lead with `request failed`: {REQUEST_FAILED_ERROR:?}"
    );
}

#[test]
fn request_failed_has_fix_section() {
    assert!(REQUEST_FAILED_ERROR.contains("Fix:"), "must state the fix");
}

#[test]
fn request_failed_cites_tls() {
    assert!(
        REQUEST_FAILED_ERROR.contains("TLS"),
        "TLS handshake is a common request-failure cause and must be named"
    );
}

#[test]
fn request_failed_mentions_proxy() {
    assert!(
        REQUEST_FAILED_ERROR.contains("proxy"),
        "proxy configuration must be named as a cause"
    );
}

// ── cross-cutting invariants over all four reasons ────────────────────────────

#[test]
fn every_reason_leads_with_its_legacy_phrase() {
    for (msg, legacy) in TRANSPORT_REASONS {
        assert!(
            msg.starts_with(legacy),
            "{legacy:?} must remain the leading substring of {msg:?} (back-compat)"
        );
    }
}

#[test]
fn every_reason_has_a_fix_section() {
    for (msg, _) in TRANSPORT_REASONS {
        assert!(msg.contains("Fix:"), "every transport reason must include `Fix:`: {msg:?}");
    }
}

#[test]
fn every_reason_is_meaningfully_longer_than_its_legacy_token() {
    // The whole point is that the bare phrase grew into context+fix; require a
    // substantial expansion so a future edit can't silently revert to the token.
    for (msg, legacy) in TRANSPORT_REASONS {
        assert!(
            msg.len() >= legacy.len() + 40,
            "{msg:?} is barely longer than {legacy:?} — it lost its fix guidance"
        );
    }
}

#[test]
fn all_reasons_are_distinct() {
    let msgs: Vec<&str> = TRANSPORT_REASONS.iter().map(|(m, _)| *m).collect();
    for i in 0..msgs.len() {
        for j in (i + 1)..msgs.len() {
            assert_ne!(msgs[i], msgs[j], "two transport reasons collided; each must be specific");
        }
    }
}

#[test]
fn no_reason_is_multiline() {
    // Verification status renders on one line in reports/SARIF; an embedded newline
    // would break that layout. The `\` line-continuations in source must collapse.
    for (msg, _) in TRANSPORT_REASONS {
        assert!(!msg.contains('\n'), "transport reason must be single-line: {msg:?}");
    }
}

#[test]
fn no_reason_leaks_a_template_placeholder() {
    // These are static operator messages — they must never carry an un-substituted
    // interpolation placeholder that could imply a leaked credential/companion.
    for (msg, _) in TRANSPORT_REASONS {
        assert!(
            !msg.contains("{credential}") && !msg.contains("companion."),
            "transport reason must not contain an interpolation placeholder: {msg:?}"
        );
    }
}

#[test]
fn no_reason_has_double_spaces_from_line_continuation() {
    // A `\` continuation with stray leading whitespace on the next line would inject
    // a double space; assert the messages read cleanly.
    for (msg, _) in TRANSPORT_REASONS {
        assert!(!msg.contains("  "), "transport reason has a double space (bad continuation): {msg:?}");
    }
}
