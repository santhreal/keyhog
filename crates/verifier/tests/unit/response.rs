use keyhog_core::{AuthSpec, DetectorSpec, SuccessSpec, VerifySpec};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use keyhog_verifier::{VerificationEngine, VerifyConfig};

fn json_success(path: &str, equals: Option<&str>) -> SuccessSpec {
    SuccessSpec {
        status: Some(200),
        json_path: Some(path.to_string()),
        equals: equals.map(str::to_string),
        ..Default::default()
    }
}

#[test]
fn success_json_equals_accepts_boolean_scalar_values() {
    let spec = json_success("$.valid", Some("true"));

    assert!(TestApi.evaluate_success_for_test(&spec, 200, r#"{"valid":true}"#));
    assert!(
        !TestApi.evaluate_success_for_test(&spec, 200, r#"{"valid":false}"#),
        "boolean false must not satisfy equals=true"
    );
}

#[test]
fn shipped_rooted_success_selector_matches_cloudflare_shape() {
    let spec = json_success("$.success", Some("true"));
    assert!(TestApi.evaluate_success_for_test(
        &spec,
        200,
        r#"{"success":true,"result":{"status":"active"}}"#
    ));
    assert!(!TestApi.evaluate_success_for_test(&spec, 200, r#"{"success":false,"result":null}"#));
}

#[test]
fn verification_engine_rejects_programmatic_invalid_selectors() {
    let detector = DetectorSpec {
        id: "invalid-selector-contract".into(),
        verify: Some(VerifySpec {
            auth: Some(AuthSpec::None {}),
            success: Some(SuccessSpec {
                json_path: Some("/legacy-pointer".into()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let error = VerificationEngine::new(&[detector], VerifyConfig::default())
        .err()
        .expect("invalid programmatic selector must fail construction");
    let message = error.to_string();
    assert!(message.contains("invalid-selector-contract"), "{message}");
    assert!(message.contains("verify.success.json_path"), "{message}");
}

#[test]
fn success_json_equals_accepts_numeric_scalar_values() {
    let spec = json_success("$.remaining", Some("0"));

    assert!(TestApi.evaluate_success_for_test(&spec, 200, r#"{"remaining":0}"#));
    assert!(
        !TestApi.evaluate_success_for_test(&spec, 200, r#"{"remaining":1}"#),
        "numeric value 1 must not satisfy equals=0"
    );
}

#[test]
fn success_json_path_presence_treats_false_and_zero_as_present() {
    let bool_spec = json_success("$.enabled", None);
    let number_spec = json_success("$.remaining", None);

    assert!(TestApi.evaluate_success_for_test(&bool_spec, 200, r#"{"enabled":false}"#));
    assert!(TestApi.evaluate_success_for_test(&number_spec, 200, r#"{"remaining":0}"#));
}

#[test]
fn success_json_path_null_never_satisfies_equals() {
    let spec = json_success("$.value", Some("null"));

    assert!(
        !TestApi.evaluate_success_for_test(&spec, 200, r#"{"value":null}"#),
        "JSON null is absence and must not satisfy an equals contract"
    );
}

#[test]
fn success_json_path_malformed_body_is_error_not_dead() {
    let spec = json_success("$.valid", Some("true"));

    let error = TestApi
        .evaluate_success_result_for_test(&spec, 200, r#"{"valid":true"#)
        .expect_err("malformed JSON must not collapse to a false/dead success result");

    assert!(
        error.contains("response body is not valid JSON for success selector `$.valid`"),
        "error must name the broken success contract and path, got {error:?}"
    );
}

#[test]
fn success_json_path_missing_key_remains_non_match() {
    let spec = json_success("$.missing", Some("true"));

    assert_eq!(
        TestApi.evaluate_success_result_for_test(&spec, 200, r#"{"valid":true}"#),
        Ok(false)
    );
}

#[test]
fn success_json_equals_keeps_string_exact_match_contract() {
    let spec = json_success("$.status", Some("true"));

    assert!(TestApi.evaluate_success_for_test(&spec, 200, r#"{"status":"true"}"#));
    assert!(
        !TestApi.evaluate_success_for_test(&spec, 200, r#"{"status":"True"}"#),
        "string comparisons stay exact and case-sensitive"
    );
}

#[test]
fn body_error_detection_is_ascii_case_insensitive_for_plaintext_words() {
    assert!(TestApi.body_indicates_error_for_test("ERROR: INVALID token"));
    assert!(TestApi.body_indicates_error_for_test("credential Expired"));
    assert!(
        !TestApi.body_indicates_error_for_test("error_rate is zero"),
        "underscore-separated metric names are not standalone error words"
    );
    assert!(
        !TestApi.body_indicates_error_for_test("myinvalidatedname"),
        "embedded substrings must not classify a live response as dead"
    );
}

#[test]
fn json_error_key_detection_is_ascii_case_insensitive_without_substring_keys() {
    assert!(TestApi.body_indicates_error_for_test(r#"{"ERROR":"bad"}"#));
    assert!(TestApi.body_indicates_error_for_test(r#"{"meta":{"Expired":true}}"#));
    assert!(
        !TestApi.body_indicates_error_for_test(r#"{"Errors":[]}"#),
        "empty JSON error arrays mean no populated error"
    );
    assert!(
        !TestApi.body_indicates_error_for_test(r#"{"error_rate":1}"#),
        "JSON keys must match the error contract exactly"
    );
}
