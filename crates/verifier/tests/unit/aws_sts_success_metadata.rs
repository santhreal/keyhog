use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn aws_sts_xml_success_metadata_preserves_identity_fields() {
    let xml = r#"
        <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
          <GetCallerIdentityResult>
            <Arn>arn:aws:iam::123456789012:user/alice</Arn>
            <UserId>AIDAEXAMPLEUSERID</UserId>
            <Account>123456789012</Account>
          </GetCallerIdentityResult>
          <ResponseMetadata>
            <RequestId>request-id</RequestId>
          </ResponseMetadata>
        </GetCallerIdentityResponse>
    "#;

    let metadata = TestApi
        .parse_aws_sts_success_metadata(xml)
        .expect("AWS STS XML success response parses");
    assert_eq!(
        metadata.get("arn").map(String::as_str),
        Some("arn:aws:iam::123456789012:user/alice")
    );
    assert_eq!(
        metadata.get("account_id").map(String::as_str),
        Some("123456789012")
    );
    assert_eq!(
        metadata.get("user_id").map(String::as_str),
        Some("AIDAEXAMPLEUSERID")
    );
}

#[test]
fn aws_sts_json_success_metadata_remains_supported() {
    let json = r#"{
      "GetCallerIdentityResponse": {
        "GetCallerIdentityResult": {
          "Arn": "arn:aws:sts::123456789012:assumed-role/demo/session",
          "Account": "123456789012",
          "UserId": "AROATEST:session"
        }
      }
    }"#;

    let metadata = TestApi
        .parse_aws_sts_success_metadata(json)
        .expect("AWS STS JSON success response parses");
    assert_eq!(
        metadata.get("arn").map(String::as_str),
        Some("arn:aws:sts::123456789012:assumed-role/demo/session")
    );
    assert_eq!(
        metadata.get("account_id").map(String::as_str),
        Some("123456789012")
    );
    assert_eq!(
        metadata.get("user_id").map(String::as_str),
        Some("AROATEST:session")
    );
}

#[test]
fn aws_sts_success_metadata_rejects_non_identity_xml() {
    let xml = r#"<GetCallerIdentityResponse><ResponseMetadata /></GetCallerIdentityResponse>"#;
    let error = TestApi
        .parse_aws_sts_success_metadata(xml)
        .expect_err("missing Arn/Account is not a successful identity parse");
    assert!(
        error.contains("missing Arn or Account"),
        "error must name the missing identity fields: {error}"
    );
}

#[test]
fn aws_sts_request_time_too_skewed_is_transient_error_not_dead() {
    let body = r#"
        <ErrorResponse>
          <Error>
            <Code>RequestTimeTooSkewed</Code>
            <Message>The difference between the request time and the current time is too large.</Message>
          </Error>
        </ErrorResponse>
    "#;
    let (result, transient) = TestApi.classify_aws_sts_failure(403, body);
    assert!(transient, "clock skew is retryable after fixing host time");
    match result {
        keyhog_core::VerificationResult::Error(message) => {
            assert!(
                message.contains("system time") && message.contains("retry"),
                "clock-skew error must tell the operator what to fix: {message}"
            );
        }
        other => panic!("RequestTimeTooSkewed must not classify as {other:?}"),
    }
}

#[test]
fn aws_sts_plain_403_still_means_dead() {
    let (result, transient) =
        TestApi.classify_aws_sts_failure(403, "<Error><Code>InvalidClientTokenId</Code></Error>");
    assert!(!transient, "ordinary STS 403 remains conclusive");
    assert!(matches!(result, keyhog_core::VerificationResult::Dead));
}

#[test]
fn aws_sts_non_403_failure_remains_transient_rate_limited() {
    let (result, transient) = TestApi.classify_aws_sts_failure(500, "server error");
    assert!(transient);
    assert!(matches!(
        result,
        keyhog_core::VerificationResult::RateLimited
    ));
}

#[test]
fn aws_request_errors_do_not_use_debug_verification_text() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/aws.rs"))
        .expect("AWS verifier source must be readable");

    assert!(
        !source.contains("format!(\"{:?}\", e.result)"),
        "AWS request/body errors must surface canonical operator text, not Debug-derived Error(\"...\") strings"
    );
    assert!(
        source.contains("verification_result_text(&e.result)"),
        "AWS request/body errors must route through the explicit verification-result text adapter"
    );
}
