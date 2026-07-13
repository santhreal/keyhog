//! Verification-verdict contract: `body_indicates_error` and `evaluate_success`
//! decide whether a credential is reported LIVE or DEAD, so their precision is
//! recall-load-bearing. `body_indicates_error` is a deliberately CONSERVATIVE
//! backstop, an error token only counts when it is paired with a *populated*
//! value, so the overwhelmingly common benign shapes (`"error":null`,
//! `"errors":[]`, `"error":0/false/""/{}`) never flip a live credential to Dead.
//! These tests pin the entire truthy-error truth table, the exact-key contract,
//! the recursion, the non-JSON whole-word fallback, and every `evaluate_success`
//! branch.

use keyhog_core::SuccessSpec;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

fn err(body: &str) -> bool {
    TestApi.body_indicates_error_for_test(body)
}

// ── json truthy-error matrix: an error KEY with an EMPTY value is NOT an error ─

#[test]
fn error_key_null_value_is_no_error() {
    assert!(!err(r#"{"error":null}"#));
}

#[test]
fn error_key_false_value_is_no_error() {
    assert!(!err(r#"{"error":false}"#));
}

#[test]
fn error_key_zero_number_is_no_error() {
    assert!(!err(r#"{"error":0}"#));
}

#[test]
fn error_key_negative_zero_is_no_error() {
    // -0.0 == 0.0 in IEEE, so a negative-zero error count is still "no error".
    assert!(!err(r#"{"error":-0.0}"#));
}

#[test]
fn error_key_empty_string_is_no_error() {
    assert!(!err(r#"{"error":""}"#));
}

#[test]
fn error_key_empty_array_is_no_error() {
    assert!(!err(r#"{"error":[]}"#));
}

#[test]
fn error_key_empty_object_is_no_error() {
    assert!(!err(r#"{"error":{}}"#));
}

// ── json truthy-error matrix: an error KEY with a POPULATED value IS an error ──

#[test]
fn error_key_nonempty_string_is_error() {
    assert!(err(r#"{"error":"bad token"}"#));
}

#[test]
fn error_key_true_value_is_error() {
    assert!(err(r#"{"error":true}"#));
}

#[test]
fn error_key_nonzero_number_is_error() {
    assert!(err(r#"{"error":5}"#));
}

#[test]
fn error_key_fractional_number_is_error() {
    assert!(err(r#"{"error":0.5}"#));
}

#[test]
fn error_key_nonempty_array_is_error() {
    assert!(err(r#"{"errors":["rate limit exceeded"]}"#));
}

#[test]
fn error_key_nonempty_object_is_error() {
    assert!(err(r#"{"error":{"code":401}}"#));
}

// ── exact-key contract: the five error keys match; lookalikes do not ─────────

#[test]
fn all_five_error_keys_match_when_populated() {
    assert!(err(r#"{"error":"x"}"#), "error");
    assert!(err(r#"{"errors":["x"]}"#), "errors");
    assert!(err(r#"{"invalid":true}"#), "invalid");
    assert!(err(r#"{"expired":true}"#), "expired");
    assert!(err(r#"{"revoked":true}"#), "revoked");
}

#[test]
fn error_lookalike_keys_do_not_match() {
    // Substring / suffix / prefix variants must NOT match the exact contract.
    assert!(!err(r#"{"error_url":"https://x"}"#), "error_url");
    assert!(!err(r#"{"errors_count":3}"#), "errors_count");
    assert!(!err(r#"{"myerror":true}"#), "myerror");
    assert!(!err(r#"{"erro":true}"#), "erro");
    assert!(!err(r#"{"validated":true}"#), "validated (not 'invalid')");
}

// ── recursion: error is found at any depth, benign siblings don't mask it ────

#[test]
fn deeply_nested_error_is_detected() {
    assert!(err(r#"{"a":{"b":{"c":{"error":true}}}}"#));
}

#[test]
fn error_inside_array_of_objects_is_detected() {
    assert!(err(r#"{"results":[{"ok":1},{"invalid":true}]}"#));
}

#[test]
fn populated_error_among_benign_siblings_is_detected() {
    assert!(err(r#"{"data":"fine","status":"ok","error":"bad"}"#));
}

#[test]
fn all_empty_error_signals_across_tree_is_no_error() {
    assert!(!err(
        r#"{"a":{"error":null},"b":{"errors":[]},"c":{"valid":true,"count":0}}"#
    ));
}

#[test]
fn error_word_only_in_string_value_is_not_an_error_in_json() {
    // A non-error key whose string VALUE merely mentions an error word must not
    // trip the JSON contract (only error KEYS with populated values count).
    assert!(!err(
        r#"{"message":"see docs about errors and invalid input"}"#
    ));
}

// ── non-JSON whole-word fallback ─────────────────────────────────────────────

#[test]
fn plaintext_error_words_with_separators_match() {
    assert!(err("token: invalid"));
    assert!(err("401 error"));
    assert!(err("this key was revoked"));
    assert!(err("session expired"));
}

#[test]
fn plaintext_without_error_words_is_no_error() {
    assert!(!err("all systems operational"));
    assert!(!err("user octocat authenticated"));
}

#[test]
fn plaintext_embedded_substrings_do_not_match() {
    // Whole-word contract: a longer token that merely contains an error word
    // is not a standalone error signal.
    assert!(!err("errorless mode"));
    assert!(!err("invalidated_at field present"));
}

// ── evaluate_success: each filter branch in isolation ───────────────────────

fn ok(spec: &SuccessSpec, status: u16, body: &str) -> bool {
    TestApi.evaluate_success_for_test(spec, status, body)
}

#[test]
fn success_requires_matching_status() {
    let spec = SuccessSpec {
        status: Some(200),
        ..Default::default()
    };
    assert!(ok(&spec, 200, ""));
    assert!(!ok(&spec, 401, ""));
}

#[test]
fn success_rejects_forbidden_status() {
    let spec = SuccessSpec {
        status_not: Some(403),
        ..Default::default()
    };
    assert!(!ok(&spec, 403, ""));
    assert!(ok(&spec, 200, ""));
}

#[test]
fn success_requires_body_contains_substring() {
    let spec = SuccessSpec {
        body_contains: Some("authenticated".to_string()),
        ..Default::default()
    };
    assert!(ok(&spec, 200, "user authenticated ok"));
    assert!(!ok(&spec, 200, "access denied"));
}

#[test]
fn success_rejects_body_not_contains_substring() {
    let spec = SuccessSpec {
        body_not_contains: Some("error".to_string()),
        ..Default::default()
    };
    assert!(!ok(&spec, 200, "an error occurred"));
    assert!(ok(&spec, 200, "clean response"));
}

#[test]
fn success_with_no_criteria_defaults_true() {
    let spec = SuccessSpec::default();
    assert!(ok(&spec, 200, "anything"));
    assert!(ok(&spec, 500, ""));
}

#[test]
fn success_combines_status_and_body_not_contains() {
    let spec = SuccessSpec {
        status: Some(200),
        body_not_contains: Some("fail".to_string()),
        ..Default::default()
    };
    // Status passes but the forbidden substring is present → not success.
    assert!(!ok(&spec, 200, "fail: bad creds"));
    // Status passes and the body is clean → success.
    assert!(ok(&spec, 200, "all good"));
    // Forbidden substring absent but status wrong → not success.
    assert!(!ok(&spec, 401, "all good"));
}

#[test]
fn success_combines_status_and_body_contains() {
    let spec = SuccessSpec {
        status: Some(200),
        body_contains: Some("success".to_string()),
        ..Default::default()
    };
    assert!(ok(&spec, 200, "operation success!"));
    assert!(!ok(&spec, 200, "operation pending"));
}
