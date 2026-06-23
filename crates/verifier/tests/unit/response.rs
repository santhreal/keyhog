use keyhog_core::SuccessSpec;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

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
    let spec = json_success("/valid", Some("true"));

    assert!(TestApi.evaluate_success_for_test(&spec, 200, r#"{"valid":true}"#));
    assert!(
        !TestApi.evaluate_success_for_test(&spec, 200, r#"{"valid":false}"#),
        "boolean false must not satisfy equals=true"
    );
}

#[test]
fn success_json_equals_accepts_numeric_scalar_values() {
    let spec = json_success("/remaining", Some("0"));

    assert!(TestApi.evaluate_success_for_test(&spec, 200, r#"{"remaining":0}"#));
    assert!(
        !TestApi.evaluate_success_for_test(&spec, 200, r#"{"remaining":1}"#),
        "numeric value 1 must not satisfy equals=0"
    );
}

#[test]
fn success_json_path_presence_treats_false_and_zero_as_present() {
    let bool_spec = json_success("/enabled", None);
    let number_spec = json_success("/remaining", None);

    assert!(TestApi.evaluate_success_for_test(&bool_spec, 200, r#"{"enabled":false}"#));
    assert!(TestApi.evaluate_success_for_test(&number_spec, 200, r#"{"remaining":0}"#));
}

#[test]
fn success_json_equals_keeps_string_exact_match_contract() {
    let spec = json_success("/status", Some("true"));

    assert!(TestApi.evaluate_success_for_test(&spec, 200, r#"{"status":"true"}"#));
    assert!(
        !TestApi.evaluate_success_for_test(&spec, 200, r#"{"status":"True"}"#),
        "string comparisons stay exact and case-sensitive"
    );
}
