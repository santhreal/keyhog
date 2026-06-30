//! The doc-marker EXAMPLE suppression carves out RFC 2606 reserved-domain
//! mentions (`example.com` / `example.org`) so a value that merely references
//! the reserved domain is not suppressed as a documentation specimen. The marker
//! DETECTION runs case-insensitively (on the uppercased credential), but the
//! carve-out used to match `credential` case-SENSITIVELY — so a title-case
//! `Example.com` or upper `EXAMPLE.COM` slipped past the carve-out and the
//! adjacent value was over-suppressed (recall loss). These tests pin that the
//! carve-out is case-insensitive at every domain case, while the EXAMPLE marker
//! still suppresses real documentation specimens that lack the reserved domain.

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

fn suppressed(value: &str) -> bool {
    known_example_suppressed(value, None, CodeContext::Unknown)
}

// ── EXAMPLE marker still suppresses specimens with NO reserved domain ────────

#[test]
fn example_token_underscore_boundary_suppressed() {
    assert!(suppressed("alpha_EXAMPLE_beta"));
}

#[test]
fn example_token_dash_boundary_suppressed() {
    assert!(suppressed("alpha-EXAMPLE-beta"));
}

#[test]
fn example_token_dot_boundary_suppressed() {
    // A `.example` that is NOT the reserved `.com`/`.org` domain still suppresses.
    assert!(suppressed("alpha.EXAMPLE.beta"));
}

#[test]
fn example_token_slash_boundary_suppressed() {
    assert!(suppressed("path/EXAMPLE/key"));
}

#[test]
fn example_token_ends_with_suppressed() {
    assert!(suppressed("alpha_EXAMPLE"));
}

#[test]
fn examplekey_token_suppressed() {
    assert!(suppressed("alpha_EXAMPLEKEY_beta"));
}

#[test]
fn example_token_detected_case_insensitively_lowercase() {
    assert!(suppressed("alpha_example_beta"));
}

#[test]
fn example_token_detected_case_insensitively_titlecase() {
    assert!(suppressed("alpha_Example_beta"));
}

// ── reserved-domain carve-out: lowercase (works before and after the fix) ───

#[test]
fn lowercase_example_com_domain_not_suppressed() {
    assert!(!suppressed("https://example.com"));
}

#[test]
fn lowercase_example_org_domain_not_suppressed() {
    assert!(!suppressed("https://example.org"));
}

// ── the fix: carve-out is now case-insensitive across every domain case ─────

#[test]
fn titlecase_example_com_domain_not_suppressed() {
    assert!(!suppressed("https://Example.com"));
}

#[test]
fn uppercase_example_com_domain_not_suppressed() {
    assert!(!suppressed("https://EXAMPLE.COM"));
}

#[test]
fn mixedcase_example_com_domain_not_suppressed() {
    assert!(!suppressed("https://eXaMpLe.cOm"));
}

#[test]
fn titlecase_example_org_domain_not_suppressed() {
    assert!(!suppressed("https://Example.org"));
}

#[test]
fn uppercase_example_org_domain_not_suppressed() {
    assert!(!suppressed("https://EXAMPLE.ORG"));
}

#[test]
fn titlecase_domain_with_path_not_suppressed() {
    assert!(!suppressed("https://Example.com/api/v1/users"));
}

#[test]
fn titlecase_subdomain_not_suppressed() {
    assert!(!suppressed("api.Example.com"));
}

// ── recall: a real-looking value beside a title-case reserved domain survives ─

#[test]
fn value_beside_titlecase_example_com_survives() {
    // The EXAMPLE token comes only from the reserved domain; pre-fix this was
    // suppressed, hiding the adjacent token. It must now survive.
    assert!(!suppressed("tok_a9Xq2Z_Example.com"));
}

#[test]
fn connection_string_with_titlecase_domain_survives() {
    assert!(!suppressed("db://svc@Example.com:5432/app"));
}

#[test]
fn value_with_uppercase_domain_and_query_survives() {
    assert!(!suppressed("https://EXAMPLE.COM/callback?token=zQ81mK"));
}
