use std::path::PathBuf;

use keyhog_core::{load_detectors, DetectorSpec, SuccessPolicy, SuccessSpec};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

fn detector_corpus() -> Vec<DetectorSpec> {
    let detector_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("detectors");
    load_detectors(&detector_dir).expect("shipped detector success contracts must validate")
}

fn success_spec(detectors: &[DetectorSpec], id: &str) -> SuccessSpec {
    detectors
        .iter()
        .find(|detector| detector.id == id)
        .unwrap_or_else(|| panic!("missing detector {id}"))
        .verify
        .as_ref()
        .and_then(|verify| verify.success.clone())
        .unwrap_or_else(|| panic!("detector {id} has no success contract"))
}

fn replay(spec: &SuccessSpec, status: u16, body: &str) -> Result<bool, String> {
    TestApi.evaluate_success_result_for_test(spec, status, body)
}

fn resolved_replay(spec: &SuccessSpec, status: u16, body: &str) -> Result<bool, String> {
    let matched = replay(spec, status, body)?;
    Ok(TestApi.resolve_live_verdict_for_test(
        matched,
        TestApi.success_spec_is_explicit_for_test(spec),
        body,
    ))
}

/// Regression: an unclassified status gate could silently inherit ambiguous
/// semantics, so every shipped success contract must choose exactly one policy;
/// exact accounting makes additions require an intentional classification.
#[test]
fn every_shipped_success_contract_is_classified() {
    let detectors = detector_corpus();
    let mut status_with_error_backstop = 0usize;
    let mut status_authoritative = 0usize;
    let mut body_positive = 0usize;
    let mut unclassified = Vec::new();

    for detector in &detectors {
        let Some(verify) = &detector.verify else {
            continue;
        };
        let mut contracts = Vec::with_capacity(1 + verify.steps.len());
        if let Some(success) = &verify.success {
            contracts.push(("verify.success".to_string(), success));
        }
        for (index, step) in verify.steps.iter().enumerate() {
            contracts.push((format!("verify.steps[{index}].success"), &step.success));
        }

        for (scope, success) in contracts {
            match success.policy {
                Some(SuccessPolicy::BodyPositive) => body_positive += 1,
                Some(SuccessPolicy::StatusWithErrorBackstop) => {
                    status_with_error_backstop += 1;
                }
                Some(SuccessPolicy::StatusAuthoritative) => status_authoritative += 1,
                None => unclassified.push(format!("{}:{scope}", detector.id)),
            }
        }
    }

    assert!(
        unclassified.is_empty(),
        "success contracts without an explicit policy: {unclassified:?}"
    );
    assert_eq!(
        status_with_error_backstop, 328,
        "conservative status contract accounting drifted"
    );
    assert_eq!(
        status_authoritative, 1,
        "provider-authoritative status accounting drifted"
    );
    assert_eq!(
        body_positive, 18,
        "body-positive contract accounting drifted"
    );
}

/// Regression: New Relic log ingestion intentionally returns an empty 202, so
/// requiring a fabricated body marker would turn a legitimate license key Dead;
/// its reviewed authoritative policy accepts 202 and still rejects other status.
#[test]
fn newrelic_ingestion_uses_justified_authoritative_status() {
    let detectors = detector_corpus();
    let spec = success_spec(&detectors, "newrelic-license-key");

    assert_eq!(spec.policy, Some(SuccessPolicy::StatusAuthoritative));
    assert_eq!(resolved_replay(&spec, 202, ""), Ok(true));
    assert_eq!(
        resolved_replay(&spec, 202, r#"{"error":"non-verdict diagnostic"}"#),
        Ok(true),
        "an authoritative accepted status is not overridden by an unstable body"
    );
    assert_eq!(
        resolved_replay(&spec, 401, r#"{"error":"invalid license key"}"#),
        Ok(false)
    );
}

/// Regression: unaudited status-only endpoints previously risked becoming false
/// Live when marked authoritative; their explicit conservative policy must keep
/// the generic populated-error backstop active even after an HTTP 200 match.
#[test]
fn conservative_status_policy_rejects_200_error_body() {
    let detectors = detector_corpus();
    let spec = success_spec(&detectors, "github-refresh-token");
    let error_body = r#"{"error":"bad credentials"}"#;

    assert_eq!(spec.policy, Some(SuccessPolicy::StatusWithErrorBackstop));
    assert_eq!(replay(&spec, 200, error_body), Ok(true));
    assert_eq!(resolved_replay(&spec, 200, error_body), Ok(false));
    assert_eq!(
        resolved_replay(&spec, 200, r#"{"login":"octocat"}"#),
        Ok(true)
    );
}

/// Regression: the two status policies must make opposite final decisions for
/// the same matched HTTP 200 carrying a populated provider error: conservative
/// status rejects it, while reviewed authoritative status accepts it.
#[test]
fn http_200_error_body_distinguishes_both_status_policies() {
    let error_body = r#"{"error":"provider diagnostic"}"#;
    let conservative = SuccessSpec {
        status: Some(200),
        policy: Some(SuccessPolicy::StatusWithErrorBackstop),
        ..Default::default()
    };
    let authoritative = SuccessSpec {
        status: Some(200),
        policy: Some(SuccessPolicy::StatusAuthoritative),
        ..Default::default()
    };

    assert_eq!(replay(&conservative, 200, error_body), Ok(true));
    assert_eq!(replay(&authoritative, 200, error_body), Ok(true));
    assert_eq!(resolved_replay(&conservative, 200, error_body), Ok(false));
    assert_eq!(resolved_replay(&authoritative, 200, error_body), Ok(true));
}

/// Regression: Etherscan returns HTTP 200 for both valid and invalid API keys,
/// so status alone produced false Live verdicts; the stable JSON status field
/// now distinguishes provider success from its real sanitized error body.
#[test]
fn etherscan_requires_body_positive_evidence() {
    let detectors = detector_corpus();
    let spec = success_spec(&detectors, "etherscan-api-key");

    assert_eq!(spec.policy, Some(SuccessPolicy::BodyPositive));
    assert_eq!(
        resolved_replay(
            &spec,
            200,
            r#"{"status":"1","message":"OK","result":{"ethusd":"3500.00"}}"#,
        ),
        Ok(true)
    );
    assert_eq!(
        resolved_replay(
            &spec,
            200,
            r#"{"status":"0","message":"NOTOK","result":"Invalid API Key"}"#,
        ),
        Ok(false)
    );
    assert_eq!(resolved_replay(&spec, 403, r#"{"status":"1"}"#), Ok(false));
}

/// Regression: a successful identity response may legitimately contain a
/// populated `errors` field; once GitHub's stable `login` evidence matches, the
/// generic error-name backstop must not flip that confirmed success to Dead.
#[test]
fn github_success_with_error_named_field_stays_live() {
    let detectors = detector_corpus();
    let spec = success_spec(&detectors, "github-oauth-access-token");
    let body = r#"{"login":"octocat","errors":["scope warning"]}"#;

    assert_eq!(spec.policy, Some(SuccessPolicy::BodyPositive));
    assert_eq!(resolved_replay(&spec, 200, body), Ok(true));
}

/// Regression: malformed or drifted JSON must not collapse to a boolean Dead
/// verdict, because a provider response-shape change is unverifiable rather than
/// proof that the credential is revoked; selector evaluation therefore fails visibly.
#[test]
fn body_contract_response_drift_fails_closed() {
    let detectors = detector_corpus();
    let spec = success_spec(&detectors, "cloudflare-d1-credentials");

    let malformed = replay(&spec, 200, r#"{"success":true"#)
        .expect_err("malformed provider JSON must remain unverifiable");
    assert!(malformed.contains("response body is not valid JSON for success selector `$.success`"));
    assert_eq!(
        replay(&spec, 200, r#"{"result":{"status":"active"}}"#),
        Ok(false),
        "well-formed response drift without the stable success field is not success"
    );
    assert_eq!(
        replay(&spec, 200, r#"{"success":false,"errors":[{"code":9109}]}"#),
        Ok(false),
        "the provider's actual error body must not verify"
    );
}
