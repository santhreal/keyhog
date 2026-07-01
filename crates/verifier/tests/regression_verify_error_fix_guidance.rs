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
use keyhog_verifier::VerifyError;

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
    assert!(
        TIMEOUT_ERROR.contains("Fix:"),
        "timeout reason must state the fix"
    );
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
    assert!(
        CONNECTION_FAILED_ERROR.contains("Fix:"),
        "must state the fix"
    );
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
        assert!(
            msg.contains("Fix:"),
            "every transport reason must include `Fix:`: {msg:?}"
        );
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
            assert_ne!(
                msgs[i], msgs[j],
                "two transport reasons collided; each must be specific"
            );
        }
    }
}

#[test]
fn no_reason_is_multiline() {
    // Verification status renders on one line in reports/SARIF; an embedded newline
    // would break that layout. The `\` line-continuations in source must collapse.
    for (msg, _) in TRANSPORT_REASONS {
        assert!(
            !msg.contains('\n'),
            "transport reason must be single-line: {msg:?}"
        );
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
        assert!(
            !msg.contains("  "),
            "transport reason has a double space (bad continuation): {msg:?}"
        );
    }
}

// ── VerifyError enum contract ─────────────────────────────────────────────────
//
// The transport *reasons* above are the operator-facing verdict strings. The
// `VerifyError` *enum* is the sibling error surface returned while constructing or
// executing verification (bad proxy URL, missing detector field, transport/client
// build failure). #131 requires every one of its variants to carry actionable
// `Fix:` guidance too. The two String-detail variants are checked at runtime; the
// two `ReqwestError`-wrapping variants have no public constructor, so their
// templates are pinned at the source level — plus a whole-enum guard that counts
// `#[error(...)]` templates against `Fix:` clauses so a NEW variant added without
// fix guidance fails this gate (the same contract the scanner's `ScanError`
// `scan_error_display_messages` gate enforces).

/// The `pub enum VerifyError { ... }` block, sliced out of the verifier lib.rs so
/// the whole-enum guard counts templates only within the enum (lib.rs holds other
/// code). Ends at the first column-0 `}` after the enum header.
fn verify_error_enum_block() -> String {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("verifier lib.rs readable");
    let start = src
        .find("pub enum VerifyError {")
        .expect("VerifyError enum present in lib.rs");
    let tail = &src[start..];
    let end = tail.find("\n}\n").expect("VerifyError enum close present");
    tail[..end].to_string()
}

#[test]
fn proxy_config_display_carries_fix_and_preserves_detail() {
    let msg = VerifyError::ProxyConfig("weird://scheme".to_string()).to_string();
    assert!(
        msg.contains("weird://scheme"),
        "must preserve the detail: {msg:?}"
    );
    assert!(msg.contains(". Fix: "), "must carry Fix guidance: {msg:?}");
    assert!(
        msg.find("weird://scheme") < msg.find(". Fix:"),
        "detail must precede the Fix: {msg:?}"
    );
}

#[test]
fn proxy_config_fix_names_every_supported_scheme_and_the_off_switch() {
    // A proxy-config error is only actionable if it tells the operator what a VALID
    // value looks like — all three supported schemes plus the disable switch.
    let msg = VerifyError::ProxyConfig("x".to_string()).to_string();
    assert!(msg.contains("http://"), "must name http:// : {msg:?}");
    assert!(msg.contains("https://"), "must name https:// : {msg:?}");
    assert!(msg.contains("socks5://"), "must name socks5:// : {msg:?}");
    assert!(
        msg.contains("'off'"),
        "must name the 'off' disable switch: {msg:?}"
    );
}

#[test]
fn field_resolution_display_carries_fix_and_preserves_detail() {
    let msg = VerifyError::FieldResolution("companion.missing".to_string()).to_string();
    assert!(
        msg.contains("companion.missing"),
        "must preserve the detail: {msg:?}"
    );
    assert!(msg.contains(". Fix: "), "must carry Fix guidance: {msg:?}");
    assert!(
        msg.find("companion.missing") < msg.find(". Fix:"),
        "detail must precede the Fix: {msg:?}"
    );
}

#[test]
fn field_resolution_fix_names_the_valid_field_forms() {
    let msg = VerifyError::FieldResolution("x".to_string()).to_string();
    assert!(
        msg.contains("`match`") && msg.contains("companion."),
        "the fix must name the valid field forms (`match` / `companion.<name>`): {msg:?}"
    );
}

#[test]
fn constructible_verify_errors_all_carry_fix_after_their_detail() {
    // Loop guard over the two runtime-constructible String variants: each must
    // render `. Fix: ` AFTER a preserved `SENTINEL` detail.
    let cases = [
        VerifyError::ProxyConfig("SENTINEL".to_string()),
        VerifyError::FieldResolution("SENTINEL".to_string()),
    ];
    for err in cases {
        let msg = err.to_string();
        let detail = msg.find("SENTINEL").expect("detail present");
        let fix = msg.find(". Fix: ").expect("fix present");
        assert!(detail < fix, "detail must precede Fix: {msg:?}");
    }
}

#[test]
fn proxy_and_field_fixes_are_distinct() {
    let proxy = VerifyError::ProxyConfig("x".to_string()).to_string();
    let field = VerifyError::FieldResolution("x".to_string()).to_string();
    assert_ne!(
        proxy.rsplit(". Fix: ").next(),
        field.rsplit(". Fix: ").next(),
        "proxy-config and field-resolution errors must give distinct fixes"
    );
}

#[test]
fn http_variant_template_declares_the_fix() {
    // Source-level pin (ReqwestError has no public constructor): the Http variant's
    // `#[error]` template must carry Fix guidance pointing at the network causes.
    let block = verify_error_enum_block();
    assert!(
        block.contains("failed to send HTTP request: {0}. Fix: check network access, proxy settings, and the verification endpoint"),
        "Http variant must declare its Fix template"
    );
}

#[test]
fn client_build_variant_template_declares_the_fix() {
    let block = verify_error_enum_block();
    assert!(
        block.contains("failed to build configured HTTP client: {0}. Fix: use a valid timeout and supported TLS/network configuration"),
        "ClientBuild variant must declare its Fix template"
    );
}

#[test]
fn http_and_client_build_fixes_are_distinct() {
    // Two transport-adjacent failures with the same {0} type must still give
    // different remedies (endpoint/proxy vs timeout/TLS config).
    let block = verify_error_enum_block();
    assert!(block.contains("proxy settings, and the verification endpoint"));
    assert!(block.contains("supported TLS/network configuration"));
}

#[test]
fn every_verify_error_variant_template_declares_a_fix() {
    // Whole-enum guard: no VerifyError `#[error(...)]` template may ship without a
    // `Fix:` clause. Counts templates against Fix clauses inside the enum block, so
    // a NEW variant added without fix guidance fails loudly (mirrors the scanner
    // ScanError contract). Each variant carries exactly one Fix clause.
    let block = verify_error_enum_block();
    let templates = block.matches("#[error(").count();
    let fixes = block.matches("Fix:").count();
    assert!(
        templates >= 4,
        "expected all four VerifyError variants present; got {templates}"
    );
    assert_eq!(
        templates, fixes,
        "every VerifyError #[error(...)] template must carry exactly one `Fix:` clause \
         ({templates} templates, {fixes} Fix clauses)"
    );
}

#[test]
fn verify_error_enum_block_is_bounded_to_the_enum() {
    // The whole-enum guard's template/Fix count is only correct if the sliced block
    // is exactly the enum — it must include the last variant and stop before the
    // following item (VerificationEngine), or the count could drift.
    let block = verify_error_enum_block();
    assert!(
        block.contains("FieldResolution"),
        "must include the last variant"
    );
    assert!(
        !block.contains("pub struct VerificationEngine"),
        "the slice over-ran past the enum close: {}",
        &block[block.len().saturating_sub(80)..]
    );
}

#[test]
fn proxy_config_preserves_the_detail_verbatim() {
    let inner = "socks4://legacy:1080";
    let msg = VerifyError::ProxyConfig(inner.to_string()).to_string();
    assert!(
        msg.contains(inner),
        "the exact operator-supplied value must round-trip: {msg:?}"
    );
}

#[test]
fn field_resolution_preserves_the_detail_verbatim() {
    let inner = "companion.totp_seed";
    let msg = VerifyError::FieldResolution(inner.to_string()).to_string();
    assert!(
        msg.contains(inner),
        "the field name must round-trip: {msg:?}"
    );
}

#[test]
fn constructible_variants_do_not_leak_a_template_placeholder() {
    // A rendered message must never carry an un-substituted `{0}` (format bug) nor an
    // interpolation placeholder that could imply a leaked credential/companion value.
    for err in [
        VerifyError::ProxyConfig("x".to_string()),
        VerifyError::FieldResolution("x".to_string()),
    ] {
        let msg = err.to_string();
        assert!(!msg.contains("{0}"), "un-substituted placeholder: {msg:?}");
        assert!(
            !msg.contains("{credential}"),
            "credential placeholder: {msg:?}"
        );
    }
}

#[test]
fn constructible_variants_render_single_line() {
    // VerifyError surfaces in CLI stderr / logs; an embedded newline from a `\`
    // continuation would fragment the line. The templates must collapse cleanly.
    for err in [
        VerifyError::ProxyConfig("x".to_string()),
        VerifyError::FieldResolution("x".to_string()),
    ] {
        assert!(
            !err.to_string().contains('\n'),
            "must be single-line: {err}"
        );
    }
}

#[test]
fn constructible_variants_have_no_double_space() {
    for err in [
        VerifyError::ProxyConfig("x".to_string()),
        VerifyError::FieldResolution("x".to_string()),
    ] {
        assert!(
            !err.to_string().contains("  "),
            "double space from a bad line continuation: {err}"
        );
    }
}

#[test]
fn constructible_variants_lead_with_context_not_the_fix() {
    // Operators read WHAT failed before HOW to fix it: the message must not open
    // with the `Fix:` clause, and must carry context before it.
    for err in [
        VerifyError::ProxyConfig("x".to_string()),
        VerifyError::FieldResolution("x".to_string()),
    ] {
        let msg = err.to_string();
        assert!(!msg.starts_with("Fix:"), "must lead with context: {msg:?}");
        let fix = msg.find(". Fix:").expect("fix present");
        assert!(fix > 0, "context must precede the Fix: {msg:?}");
    }
}

#[test]
fn proxy_config_fix_offers_a_disable_switch() {
    let msg = VerifyError::ProxyConfig("x".to_string()).to_string();
    assert!(
        msg.contains("disable proxying"),
        "the fix must offer the disable path, not only valid schemes: {msg:?}"
    );
}

#[test]
fn verify_error_implements_std_error_for_question_mark_propagation() {
    // VerifyError is returned via `?` throughout the engine; it must satisfy the
    // std::error::Error bound (source chain + Display) so callers can box it.
    let err = VerifyError::FieldResolution("x".to_string());
    let as_std: &dyn std::error::Error = &err;
    assert!(!as_std.to_string().is_empty());
}

#[test]
fn field_resolution_fix_scopes_to_the_detector_spec() {
    // The actionable location is the detector spec, not an arbitrary field — the fix
    // must say so, or the operator doesn't know where to look.
    let msg = VerifyError::FieldResolution("x".to_string()).to_string();
    assert!(
        msg.contains("detector spec"),
        "fix must point at the detector spec: {msg:?}"
    );
}
