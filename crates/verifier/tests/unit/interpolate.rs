use keyhog_verifier::testing::{
    missing_companion_refs, TestApi, VerifierTestApi, MAX_TEMPLATE_TOKENS,
};
use std::collections::HashMap;

#[test]
fn resolve_field_match() {
    assert_eq!(
        TestApi.resolve_field("match", "cred123", &HashMap::new()),
        "cred123"
    );
}

#[test]
fn resolve_field_companion() {
    let mut companions = HashMap::new();
    companions.insert("secret".to_string(), "sec123".to_string());
    assert_eq!(
        TestApi.resolve_field("companion.secret", "key", &companions),
        "sec123"
    );
}

#[test]
fn resolve_field_literal() {
    assert_eq!(
        TestApi.resolve_field("Bearer", "cred", &HashMap::new()),
        "Bearer"
    );
}

#[test]
fn interpolate_match_in_url() {
    let result = TestApi.interpolate(
        "https://api.example.com/check?key={{match}}",
        "abc123",
        &HashMap::new(),
    );
    // Assert the exact substituted URL, not just substring containment.
    // The contains() assertion would still pass if the interpolator
    // produced `https://api.example.com/check?key={{match}}abc123` or
    // `abc123foo` - both shapes are broken HTTP requests that would
    // hit unexpected endpoints in production.
    assert_eq!(result, "https://api.example.com/check?key=abc123");
}

#[test]
fn interpolate_companion() {
    let mut companions = HashMap::new();
    companions.insert("secret".to_string(), "mysecret".to_string());
    let result = TestApi.interpolate("{{companion.secret}}", "key", &companions);
    assert_eq!(result, "mysecret");
}

#[test]
fn interpolate_strips_crlf_from_raw_match() {
    let result = TestApi.interpolate(
        "{{match}}",
        "value\r\nInjected-Header: evil",
        &HashMap::new(),
    );

    assert_eq!(result, "valueInjected-Header: evil");
    assert!(!result.contains('\r'));
    assert!(!result.contains('\n'));
}

/// Positive twin for the missing-companion scan: refs whose names ARE present in
/// the companion map are not reported; only the genuinely-absent names come back,
/// in first-seen order.
#[test]
fn missing_companion_refs_reports_only_absent_names_in_order() {
    let mut companions = HashMap::new();
    companions.insert("present".to_string(), "v".to_string());
    let template = "{{companion.present}} {{companion.absent_a}} {{companion.absent_b}}";
    assert_eq!(
        missing_companion_refs(template, &companions),
        vec!["absent_a".to_string(), "absent_b".to_string()],
    );
}

/// A missing ref repeated many times is reported exactly once, the dedup guard
/// (`!missing.iter().any(|m| m == name)`) holds, so the returned vec is a set.
#[test]
fn missing_companion_refs_dedups_a_repeated_missing_ref() {
    let template = "{{companion.x}}{{companion.x}}{{companion.x}}{{companion.x}}";
    assert_eq!(
        missing_companion_refs(template, &HashMap::new()),
        vec!["x".to_string()],
        "a repeated missing ref must be reported once, not per occurrence"
    );
}

/// DoS BOUND (Law 7 / Testing-Contract adversarial): a hostile template with far
/// more than `MAX_TEMPLATE_TOKENS` distinct `{{companion.*}}` refs must not be
/// scanned unboundedly: `missing_companion_refs` stops after exactly
/// `MAX_TEMPLATE_TOKENS` tokens. We plant `MAX+76` DISTINCT missing names (so no
/// dedup collision masks the count) and assert: (a) exactly `MAX` names come back
///: proving the loop halted at the bound rather than walking all of them; (b)
/// the FIRST ref (`m0`) is present but (c) a ref PAST the bound (`m{MAX+75}`) is
/// absent, the definitive proof the scan stopped early instead of processing the
/// whole template. Asserts against the single `MAX_TEMPLATE_TOKENS` owner, never a
/// hardcoded `1024`, so a retune of the bound moves the test with it.
#[test]
fn missing_companion_refs_stops_scanning_at_max_template_tokens() {
    let n = MAX_TEMPLATE_TOKENS + 76;
    let mut template = String::new();
    for i in 0..n {
        template.push_str("{{companion.m");
        template.push_str(&i.to_string());
        template.push_str("}}");
    }
    let missing = missing_companion_refs(&template, &HashMap::new());
    assert_eq!(
        missing.len(),
        MAX_TEMPLATE_TOKENS,
        "the scan must halt at the bound ({MAX_TEMPLATE_TOKENS}), not process all {n} refs"
    );
    assert!(
        missing.iter().any(|m| m == "m0"),
        "the earliest ref must be scanned"
    );
    let past_bound = format!("m{}", n - 1);
    assert!(
        !missing.iter().any(|m| *m == past_bound),
        "a ref past the {MAX_TEMPLATE_TOKENS}-token bound must NOT be scanned (proves the loop stopped early)"
    );
}

/// DoS BOUND on the replacement pass (5017, companion of the scan bound above):
/// `interpolate` walks the template once and resolves at most
/// `MAX_TEMPLATE_TOKENS` `{{…}}` tokens; everything past the cap is copied
/// verbatim (interpolate.rs:311). A hostile template with `MAX+50` `{{match}}`
/// tokens must therefore yield exactly `MAX` substituted credentials followed by
/// the 50 un-expanded `{{match}}` tokens, proving the loop halted at the bound
/// rather than substituting all `MAX+50`. This goes through the PUBLIC
/// `TestApi.interpolate` (no facade needed) and asserts exact occurrence counts,
/// not `contains`, so a regression that lifted or removed the cap (unbounded
/// substitution = the DoS this bound exists to stop) fails loudly.
#[test]
fn interpolate_replacement_pass_stops_at_max_template_tokens() {
    let extra = 50usize;
    let template = "{{match}}".repeat(MAX_TEMPLATE_TOKENS + extra);
    // `CRED` is pure-alnum, so URL-encoding leaves it byte-identical and it can
    // never collide with the literal `{{match}}` text left in the verbatim tail.
    let result = TestApi.interpolate(&template, "CRED", &HashMap::new());
    assert_eq!(
        result.matches("CRED").count(),
        MAX_TEMPLATE_TOKENS,
        "exactly {MAX_TEMPLATE_TOKENS} tokens must be substituted, not all {}",
        MAX_TEMPLATE_TOKENS + extra
    );
    assert_eq!(
        result.matches("{{match}}").count(),
        extra,
        "the {extra} tokens past the cap must survive verbatim (loop halted at the bound)"
    );
}
