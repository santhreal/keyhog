#[test]
fn sigv4_owner_signs_sts_session_token_headers() {
    let (authorization, amz_date, signed_headers) =
        keyhog_verifier::sigv4::sign_request_authorization(
            "ASIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            Some("FwoGZXIvYXdzEXAMPLEtoken=="),
            "us-east-1",
            "sts",
            "POST",
            "/",
            &[],
            "sts.us-east-1.amazonaws.com",
            "ab821ae955788b0e33ebd34c208442ccfc2d406e2edc5e7a39bd6458fbb4f843",
            1_704_067_200,
            &[],
        )
        .expect("sign STS request");

    assert_eq!(amz_date, "20240101T000000Z");
    assert_eq!(signed_headers, "host;x-amz-date;x-amz-security-token");
    assert!(authorization.starts_with(
        "AWS4-HMAC-SHA256 Credential=ASIAIOSFODNN7EXAMPLE/20240101/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature="
    ));
    assert!(
        !authorization.contains("FwoGZXIvYXdzEXAMPLEtoken"),
        "session token is signed as a header but must not be embedded in Authorization"
    );
    let signature = authorization
        .rsplit_once("Signature=")
        .expect("authorization carries signature")
        .1;
    assert_eq!(signature.len(), 64);
    assert!(signature.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn sigv4_owner_sorts_s3_content_hash_and_query_pairs() {
    let query_pairs = vec![
        ("z".to_string(), "last".to_string()),
        ("space".to_string(), "a b".to_string()),
        ("slash".to_string(), "a/b".to_string()),
    ];
    let (authorization, amz_date, signed_headers) =
        keyhog_verifier::sigv4::sign_request_authorization(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            None,
            "us-west-2",
            "s3",
            "GET",
            "/bucket/object",
            &query_pairs,
            "example-bucket.s3.us-west-2.amazonaws.com",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            1_704_067_200,
            &[(
                "x-amz-content-sha256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )],
        )
        .expect("sign S3 request");

    assert_eq!(amz_date, "20240101T000000Z");
    assert_eq!(signed_headers, "host;x-amz-content-sha256;x-amz-date");
    assert!(authorization
        .contains("Credential=AKIAIOSFODNN7EXAMPLE/20240101/us-west-2/s3/aws4_request"));
    assert!(authorization.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
}
