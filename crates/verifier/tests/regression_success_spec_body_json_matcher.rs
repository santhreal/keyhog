//! Truth table for the `SuccessSpec` BODY and JSON-PATH success gates
//! (`verify::response::evaluate_success`).
//!
//! `evaluate_success` is the pure precursor that decides whether a 2xx response
//! actually confirms a credential Live. The `status`/`status_not` gates are
//! pinned by `regression_status_verdict_map`; this file closes the gap on the
//! REMAINING gates: `body_contains`, `body_not_contains`, and
//! `json_path` (+`equals`), which are IMPLEMENTED and live in the verify path
//! but currently populated by zero shipped detectors (see backlog 6245), so a
//! silent drift there would ship unnoticed. Every gate is AND-combined: a
//! response is a success only when EVERY set constraint holds. A false verdict
//! here = a real credential reported Dead (recall bug) or a dead one reported
//! Live (precision bug), so each branch is pinned to its exact bool.

use keyhog_core::SuccessSpec;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

fn eval(spec: &SuccessSpec, status: u16, body: &str) -> bool {
    TestApi.evaluate_success_for_test(spec, status, body)
}

// ── body_contains ────────────────────────────────────────────────────────────

#[test]
fn body_contains_requires_the_substring_present() {
    let spec = SuccessSpec {
        body_contains: Some("active".into()),
        ..Default::default()
    };
    assert!(
        eval(&spec, 200, r#"{"state":"active"}"#),
        "substring present => success"
    );
    assert!(
        !eval(&spec, 200, r#"{"state":"revoked"}"#),
        "substring absent => not success"
    );
    assert!(!eval(&spec, 200, ""), "empty body can't contain the needle");
    // Substring (not word/JSON) semantics: an embedded match still counts
    // "inactive" contains the substring "active" (in‑active), so it passes;
    // note "deactivated" does NOT (…activ-A-ted), a genuine substring subtlety.
    assert!(eval(&spec, 200, "inactive"));
    assert!(
        !eval(&spec, 200, "deactivated"),
        "'deactivated' lacks the exact substring 'active'"
    );
}

// ── body_not_contains ────────────────────────────────────────────────────────

#[test]
fn body_not_contains_rejects_when_the_substring_present() {
    let spec = SuccessSpec {
        body_not_contains: Some("error".into()),
        ..Default::default()
    };
    assert!(
        eval(&spec, 200, r#"{"ok":true}"#),
        "needle absent => success"
    );
    assert!(
        !eval(&spec, 200, r#"{"error":"bad key"}"#),
        "needle present => not success"
    );
    assert!(
        eval(&spec, 200, ""),
        "empty body trivially lacks the needle"
    );
}

// ── json_path without `equals`: presence + non-null ──────────────────────────

#[test]
fn json_path_without_equals_requires_a_present_non_null_value() {
    let spec = SuccessSpec {
        json_path: Some("$.valid".into()),
        ..Default::default()
    };
    assert!(
        eval(&spec, 200, r#"{"valid":true}"#),
        "present non-null (bool true) => success"
    );
    assert!(
        eval(&spec, 200, r#"{"valid":"yes"}"#),
        "present non-null (string) => success"
    );
    assert!(
        eval(&spec, 200, r#"{"valid":0}"#),
        "present non-null (number 0 is NOT null) => success"
    );
    assert!(
        !eval(&spec, 200, r#"{"valid":null}"#),
        "explicit null => not success"
    );
    assert!(!eval(&spec, 200, r#"{"other":1}"#));
}

#[test]
fn json_path_selector_resolves_nested_paths() {
    let spec = SuccessSpec {
        json_path: Some("$.data.account.active".into()),
        ..Default::default()
    };
    assert!(eval(&spec, 200, r#"{"data":{"account":{"active":true}}}"#));
    assert!(!eval(&spec, 200, r#"{"data":{"account":{}}}"#));
}

// ── json_path WITH `equals`: exact contract-string compare ───────────────────

#[test]
fn json_path_equals_compares_the_contract_string_exactly() {
    // String value -> raw string.
    let s = SuccessSpec {
        json_path: Some("$.status".into()),
        equals: Some("active".into()),
        ..Default::default()
    };
    assert!(
        eval(&s, 200, r#"{"status":"active"}"#),
        "string equals match => success"
    );
    assert!(
        !eval(&s, 200, r#"{"status":"suspended"}"#),
        "string equals mismatch => not success"
    );

    // Bool value -> "true"/"false".
    let b = SuccessSpec {
        json_path: Some("$.enabled".into()),
        equals: Some("true".into()),
        ..Default::default()
    };
    assert!(
        eval(&b, 200, r#"{"enabled":true}"#),
        "bool true stringifies to \"true\""
    );
    assert!(
        !eval(&b, 200, r#"{"enabled":false}"#),
        "bool false != \"true\""
    );

    // Number value -> decimal string.
    let n = SuccessSpec {
        json_path: Some("$.quota".into()),
        equals: Some("42".into()),
        ..Default::default()
    };
    assert!(
        eval(&n, 200, r#"{"quota":42}"#),
        "number 42 stringifies to \"42\""
    );
    assert!(!eval(&n, 200, r#"{"quota":7}"#));
}

// ── invalid JSON with a json_path is a hard contract error ───────────────────

#[test]
fn json_path_on_non_json_body_is_a_contract_error() {
    let spec = SuccessSpec {
        json_path: Some("$.valid".into()),
        ..Default::default()
    };
    let result = TestApi.evaluate_success_result_for_test(&spec, 200, "this is not json");
    assert!(
        result.is_err(),
        "a json_path spec against a non-JSON body must error, not silently pass"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("$.valid") && msg.to_ascii_lowercase().contains("json"),
        "error must name the json_path and the JSON-parse failure, got: {msg}"
    );
}

// ── AND semantics: every set gate must hold ──────────────────────────────────

#[test]
fn all_set_gates_are_anded_together() {
    let spec = SuccessSpec {
        status: Some(200),
        body_contains: Some("ok".into()),
        body_not_contains: Some("err".into()),
        ..Default::default()
    };
    // All three satisfied.
    assert!(eval(&spec, 200, "status:ok payload"));
    // Each single violation flips the whole verdict to false.
    assert!(
        !eval(&spec, 201, "status:ok payload"),
        "wrong status fails the AND"
    );
    assert!(
        !eval(&spec, 200, "status:done payload"),
        "missing body_contains fails the AND"
    );
    assert!(
        !eval(&spec, 200, "status:ok but err inside"),
        "present body_not_contains fails the AND"
    );
}

#[test]
fn empty_spec_is_unconditional_success() {
    // No constraints set -> any response is a success (the status/verdict layer
    // above still gates on the 2xx family).
    let spec = SuccessSpec::default();
    assert!(eval(&spec, 200, ""));
    assert!(eval(&spec, 500, "anything at all"));
}

// ── differential loop: body gates exactly mirror `str::contains` ─────────────
// (No proptest dev-dep in this crate, so a deterministic case sweep stands in
// for a property tier.)

#[test]
fn body_contains_is_exactly_str_contains_across_a_case_sweep() {
    let bodies = [
        "",
        "active",
        "ACTIVE",
        "the key is active now",
        "deactivated",
        "revoked",
        "act ive",
        "{\"state\":\"active\",\"error\":null}",
    ];
    let needles = ["active", "error", "revoked", "act", "xyz", ""];
    for needle in needles {
        let contains_spec = SuccessSpec {
            body_contains: Some(needle.to_string()),
            ..Default::default()
        };
        let not_contains_spec = SuccessSpec {
            body_not_contains: Some(needle.to_string()),
            ..Default::default()
        };
        for body in bodies {
            let present = body.contains(needle);
            assert_eq!(
                eval(&contains_spec, 200, body),
                present,
                "body_contains({needle:?}) on {body:?} must equal str::contains"
            );
            assert_eq!(
                eval(&not_contains_spec, 200, body),
                !present,
                "body_not_contains({needle:?}) on {body:?} must equal !str::contains"
            );
        }
    }
}
