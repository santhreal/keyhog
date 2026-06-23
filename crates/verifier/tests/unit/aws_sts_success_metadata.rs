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
