//! AWS SigV4 **known-answer tests** (KAT): lock the real public signer
//! `keyhog_verifier::sigv4::sign_request_authorization` byte-for-byte against
//! AWS's own published reference vectors.
//!
//! Why this file exists
//! --------------------
//! `crates/verifier/src/verify/aws.rs::build_sigv4_request` is the production
//! path that decides whether an AWS credential is `Live` or `Dead`: it signs an
//! STS `GetCallerIdentity` probe and reads the HTTP status. The entire verdict
//! rests on the signature being **bit-exact**: AWS replies `403
//! SignatureDoesNotMatch` to a signature that is wrong by a single byte, and
//! `classify_aws_sts_failure` maps that 403 to `VerificationResult::Dead`. So a
//! latent defect anywhere in canonical-request assembly (header sort/merge/trim,
//! canonical-query percent-encoding + ordering, the `\n` joins, the SHA-256
//! payload-hash placement, the credential scope, the HMAC signing-key
//! derivation, or the final hex) would silently misverify a **live** credential
//! as Dead. That is a Law-10 silent failure: a real secret reported safe.
//!
//! The pre-existing `regression_sigv4_asia_security_token.rs` only re-mirrors the
//! pure string builders and drives `format_sigv4_timestamps`; it never runs the
//! real HMAC pipeline, so it cannot catch a signing-math regression. These tests
//! close that gap by asserting the actual produced `Authorization` header (which
//! embeds the signature) against values AWS publishes.
//!
//! Reference vectors
//! -----------------
//! Both vectors below share AWS's documented example identity, instant, and
//! region (`AKIDEXAMPLE` / `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY` /
//! `2015-08-30T12:36:00Z` / `us-east-1`); they differ only by service, host,
//! query, and signed headers, which is exactly what isolates each moving part:
//!
//! * **IAM `GET ListUsers`**: the worked example from the AWS "Signature
//!   Version 4" documentation. Exercises a multi-pair canonical query
//!   (`Action`/`Version`), an extra signed header (`content-type`), and the
//!   three-header lexicographic sort. Published signature:
//!   `5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7`.
//! * **`get-vanilla`**: the canonical case from the AWS SigV4 test suite
//!   (`service`/`example.amazonaws.com`, no query, no extra headers). Published
//!   signature: `5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31`.
//!
//! Everything is driven through the single `pub` entrypoint
//! `sign_request_authorization`: these are end-to-end locks, not unit pokes at
//! internals, so they also prove the public surface is the one the production
//! caller uses.

use keyhog_verifier::sigv4::sign_request_authorization;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

// ---------------------------------------------------------------------------
// Shared reference constants (verbatim from AWS's published examples).
// ---------------------------------------------------------------------------

/// `hex(SHA256(b""))`: the empty-body payload hash AWS uses in its GET
/// reference vectors.
const EMPTY_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// AWS documented example access key id.
const AWS_EXAMPLE_ACCESS: &str = "AKIDEXAMPLE";
/// AWS documented example secret access key (shared by every published vector).
const AWS_EXAMPLE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
/// AWS documented reference instant `2015-08-30T12:36:00Z` as a Unix second.
const AWS_EXAMPLE_UNIX: u64 = 1_440_938_160;

// ---------------------------------------------------------------------------
// Small helpers (kept in the test target; the signer carries its own deps).
// ---------------------------------------------------------------------------

/// Extract the value of the `Signature=` field from an `Authorization` header.
fn signature_of(authorization: &str) -> &str {
    authorization
        .rsplit_once("Signature=")
        .expect("authorization header must contain a Signature= field")
        .1
}

/// Sign a vanilla GET (no token, no extra headers, empty body) over `query`,
/// returning just the lowercase-hex signature. Used by the query-encoding
/// differential tests, which only care that two inputs sign *differently*.
fn vanilla_query_signature(query: &[(String, String)]) -> String {
    let (authorization, _amz_date, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "GET",
        "/",
        query,
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed for a well-formed request");
    signature_of(&authorization).to_string()
}

/// Convenience: build an owned `(String, String)` query pair.
fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_string(), value.to_string())
}

// ===========================================================================
// GROUP A: AWS official known-answer vectors (the headline locks).
// ===========================================================================

#[test]
fn iam_get_listusers_matches_aws_documented_authorization() {
    let query = vec![pair("Action", "ListUsers"), pair("Version", "2010-05-08")];
    let extra = [(
        "content-type",
        "application/x-www-form-urlencoded; charset=utf-8",
    )];
    let (authorization, amz_date, signed_headers) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "iam",
        "GET",
        "/",
        &query,
        "iam.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &extra,
    )
    .expect("signing must succeed");

    assert_eq!(amz_date, "20150830T123600Z");
    assert_eq!(signed_headers, "content-type;host;x-amz-date");
    assert_eq!(
        authorization,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
         SignedHeaders=content-type;host;x-amz-date, \
         Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    );
}

#[test]
fn iam_get_listusers_signature_field_matches_published_hex() {
    let query = vec![pair("Action", "ListUsers"), pair("Version", "2010-05-08")];
    let extra = [(
        "content-type",
        "application/x-www-form-urlencoded; charset=utf-8",
    )];
    let (authorization, _amz, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "iam",
        "GET",
        "/",
        &query,
        "iam.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &extra,
    )
    .expect("signing must succeed");

    assert_eq!(
        signature_of(&authorization),
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    );
}

#[test]
fn get_vanilla_matches_aws_test_suite_authorization() {
    let (authorization, amz_date, signed_headers) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "GET",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert_eq!(amz_date, "20150830T123600Z");
    assert_eq!(signed_headers, "host;x-amz-date");
    assert_eq!(
        authorization,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
}

#[test]
fn get_vanilla_signature_field_matches_published_hex() {
    let (authorization, _amz, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "GET",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert_eq!(
        signature_of(&authorization),
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
}

#[test]
fn two_reference_vectors_share_scope_prefix_and_differ_by_service() {
    // Both AWS example vectors share date+region; only the service differs.
    // This proves the credential scope is assembled from the right parts and
    // that the two KATs above are not accidentally the same request.
    let iam_query = vec![pair("Action", "ListUsers"), pair("Version", "2010-05-08")];
    let (iam_auth, _a, _s) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "iam",
        "GET",
        "/",
        &iam_query,
        "iam.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[(
            "content-type",
            "application/x-www-form-urlencoded; charset=utf-8",
        )],
    )
    .expect("signing must succeed");
    let (svc_auth, _a2, _s2) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "GET",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert!(iam_auth.contains("/20150830/us-east-1/iam/aws4_request"));
    assert!(svc_auth.contains("/20150830/us-east-1/service/aws4_request"));
    assert_ne!(
        signature_of(&iam_auth),
        signature_of(&svc_auth),
        "different service+query+headers must yield different signatures"
    );
}

// ===========================================================================
// GROUP B: Authorization grammar / structural contract.
// ===========================================================================

#[test]
fn authorization_header_has_algorithm_credential_signed_headers_signature() {
    let (authorization, _amz, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "GET",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential="));
    let sections: Vec<&str> = authorization.splitn(3, ", ").collect();
    assert_eq!(sections.len(), 3, "exactly three comma-space sections");
    assert!(sections[0].starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
    assert!(sections[1].starts_with("SignedHeaders="));
    assert!(sections[2].starts_with("Signature="));
}

#[test]
fn credential_scope_segments_are_date_region_service_aws4_request() {
    let (authorization, _amz, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "eu-west-1",
        "s3",
        "GET",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert!(authorization.contains("Credential=AKIDEXAMPLE/20150830/eu-west-1/s3/aws4_request,"));
}

#[test]
fn signature_is_exactly_sixty_four_lowercase_hex_chars() {
    let (authorization, _amz, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "GET",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    let signature = signature_of(&authorization);
    assert_eq!(signature.len(), 64, "SHA-256 HMAC hex is 64 chars");
    assert!(
        signature
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "signature must be lowercase hex"
    );
}

#[test]
fn algorithm_token_is_aws4_hmac_sha256() {
    let (authorization, _amz, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "GET",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert!(authorization.starts_with("AWS4-HMAC-SHA256 "));
}

// ===========================================================================
// GROUP C (determinism & purity (no hidden clock / randomness in the signer)).
// ===========================================================================

#[test]
fn signing_is_deterministic_for_identical_inputs() {
    let sign = || {
        sign_request_authorization(
            AWS_EXAMPLE_ACCESS,
            AWS_EXAMPLE_SECRET,
            None,
            "us-east-1",
            "service",
            "GET",
            "/",
            &[],
            "example.amazonaws.com",
            EMPTY_BODY_SHA256,
            AWS_EXAMPLE_UNIX,
            &[],
        )
        .expect("signing must succeed")
    };
    assert_eq!(sign(), sign(), "identical inputs produce identical output");
}

#[test]
fn returned_amz_date_prefix_equals_credential_scope_date() {
    let (authorization, amz_date, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "GET",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    // The scope date is the 8-char prefix of the returned amz_date.
    assert_eq!(&amz_date[0..8], "20150830");
    assert!(authorization.contains("/20150830/us-east-1/service/aws4_request"));
}

#[test]
fn changing_only_the_secret_changes_only_the_signature() {
    let base = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "GET",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");
    let other = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYDIFFERENTKEY",
        None,
        "us-east-1",
        "service",
        "GET",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    // SignedHeaders + amz_date identical; only the signature differs.
    assert_eq!(base.1, other.1, "amz_date unchanged");
    assert_eq!(base.2, other.2, "signed headers unchanged");
    assert_ne!(
        signature_of(&base.0),
        signature_of(&other.0),
        "a different secret must produce a different signature"
    );
}

// ===========================================================================
// GROUP D (session token (ASIA temp creds) folded into the real signature).
// ===========================================================================

#[test]
fn session_token_appends_security_token_signed_header_sorted_last() {
    let (_auth, _amz, signed_headers) = sign_request_authorization(
        "ASIAIOSFODNN7EXAMPLE",
        AWS_EXAMPLE_SECRET,
        Some("FwoGZXIvYXdzEXAMPLEtoken=="),
        "us-east-1",
        "sts",
        "POST",
        "/",
        &[],
        "sts.us-east-1.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert_eq!(signed_headers, "host;x-amz-date;x-amz-security-token");
}

#[test]
fn session_token_is_signed_not_cosmetic() {
    // The same request with vs. without a session token must produce different
    // signatures, proving the token is folded into the canonical request, not
    // merely sent as an unsigned header (the C5 regression's root cause).
    let without = sign_request_authorization(
        "ASIAIOSFODNN7EXAMPLE",
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "sts",
        "POST",
        "/",
        &[],
        "sts.us-east-1.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");
    let with = sign_request_authorization(
        "ASIAIOSFODNN7EXAMPLE",
        AWS_EXAMPLE_SECRET,
        Some("FwoGZXIvYXdzEXAMPLEtoken=="),
        "us-east-1",
        "sts",
        "POST",
        "/",
        &[],
        "sts.us-east-1.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert_eq!(without.2, "host;x-amz-date");
    assert_eq!(with.2, "host;x-amz-date;x-amz-security-token");
    assert_ne!(
        signature_of(&without.0),
        signature_of(&with.0),
        "the session token must change the signature"
    );
}

#[test]
fn distinct_session_tokens_produce_distinct_signatures() {
    let sign_token = |token: &str| {
        let (auth, _a, _s) = sign_request_authorization(
            "ASIAIOSFODNN7EXAMPLE",
            AWS_EXAMPLE_SECRET,
            Some(token),
            "us-east-1",
            "sts",
            "POST",
            "/",
            &[],
            "sts.us-east-1.amazonaws.com",
            EMPTY_BODY_SHA256,
            AWS_EXAMPLE_UNIX,
            &[],
        )
        .expect("signing must succeed");
        signature_of(&auth).to_string()
    };
    assert_ne!(sign_token("token-alpha=="), sign_token("token-beta=="));
}

// ===========================================================================
// GROUP E (canonical-query encoding + ordering (exercised end-to-end)).
// ===========================================================================

#[test]
fn query_pair_input_order_does_not_change_signature() {
    // SigV4 sorts the canonical query by encoded key; feeding the IAM pairs in
    // reverse must therefore sign identically.
    let forward = vanilla_query_signature(&[pair("Action", "ListUsers"), pair("Version", "2")]);
    let reverse = vanilla_query_signature(&[pair("Version", "2"), pair("Action", "ListUsers")]);
    assert_eq!(forward, reverse, "canonical query is order-independent");
}

#[test]
fn space_plus_and_bare_query_values_encode_to_distinct_signatures() {
    // A space encodes to %20, a literal '+' to %2B, and neither equals the bare
    // value (so all three sign differently. Proves percent-encoding happens).
    let spaced = vanilla_query_signature(&[pair("k", "a b")]);
    let plussed = vanilla_query_signature(&[pair("k", "a+b")]);
    let bare = vanilla_query_signature(&[pair("k", "ab")]);
    assert_ne!(spaced, plussed, "space (%20) != plus (%2B)");
    assert_ne!(spaced, bare, "space changes the canonical query");
    assert_ne!(plussed, bare, "plus changes the canonical query");
}

#[test]
fn reserved_equals_in_query_value_changes_signature() {
    // '=' is reserved and must be encoded (%3D), so a value with '=' signs
    // differently from the same value without it.
    let with_eq = vanilla_query_signature(&[pair("k", "a=b")]);
    let without_eq = vanilla_query_signature(&[pair("k", "ab")]);
    assert_ne!(with_eq, without_eq);
}

#[test]
fn adding_a_query_pair_changes_the_signature() {
    let one = vanilla_query_signature(&[pair("a", "1")]);
    let two = vanilla_query_signature(&[pair("a", "1"), pair("b", "2")]);
    assert_ne!(one, two, "an extra query parameter changes the signature");
}

// ===========================================================================
// GROUP F (production caller shape (real aws.rs A -> sigv4 B coverage)).
// ===========================================================================

#[test]
fn sts_get_caller_identity_post_shape_signs_cleanly() {
    // Mirror the exact argument shape build_sigv4_request uses for the live STS
    // probe: POST, "/", empty query, no extra headers, the GetCallerIdentity
    // body hash. Locks that the production call path yields a well-formed result.
    use sha2::{Digest, Sha256};
    let body_hash = hex::encode(Sha256::digest(
        b"Action=GetCallerIdentity&Version=2011-06-15",
    ));
    let (authorization, amz_date, signed_headers) = sign_request_authorization(
        "AKIAIOSFODNN7EXAMPLE",
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "sts",
        "POST",
        "/",
        &[],
        "sts.us-east-1.amazonaws.com",
        &body_hash,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert_eq!(signed_headers, "host;x-amz-date");
    assert_eq!(amz_date.len(), 16, "amz_date is the fixed 16-char form");
    assert!(authorization.contains("/20150830/us-east-1/sts/aws4_request"));
    assert_eq!(signature_of(&authorization).len(), 64);
}

#[test]
fn sts_body_hash_is_load_bearing_in_the_signature() {
    // The payload hash is the last canonical-request line; a different body must
    // change the signature (guards against the hash being dropped on the floor).
    use sha2::{Digest, Sha256};
    let real_hash = hex::encode(Sha256::digest(
        b"Action=GetCallerIdentity&Version=2011-06-15",
    ));
    let sign_with = |hash: &str| {
        let (auth, _a, _s) = sign_request_authorization(
            "AKIAIOSFODNN7EXAMPLE",
            AWS_EXAMPLE_SECRET,
            None,
            "us-east-1",
            "sts",
            "POST",
            "/",
            &[],
            "sts.us-east-1.amazonaws.com",
            hash,
            AWS_EXAMPLE_UNIX,
            &[],
        )
        .expect("signing must succeed");
        signature_of(&auth).to_string()
    };
    assert_ne!(sign_with(&real_hash), sign_with(EMPTY_BODY_SHA256));
}

// ===========================================================================
// GROUP G (date routine boundaries reachable via the testing facade).
//           NEW boundaries not covered by regression_sigv4_asia_security_token:
//           epoch zero, end-of-day, the 400-year leap rule, and the non-leap
//           century rule (2100). These pin the Howard-Hinnant civil-from-days
//           math the credential scope + amz_date depend on.
// ===========================================================================

#[test]
fn epoch_zero_is_unix_new_year() {
    let (date_stamp, amz_date) = TestApi.format_sigv4_timestamps(0);
    assert_eq!(date_stamp, "19700101");
    assert_eq!(amz_date, "19700101T000000Z");
}

#[test]
fn last_second_of_first_day_is_235959() {
    let (date_stamp, amz_date) = TestApi.format_sigv4_timestamps(86_399);
    assert_eq!(date_stamp, "19700101");
    assert_eq!(amz_date, "19700101T235959Z");
}

#[test]
fn year_2000_is_leap_under_the_400_rule() {
    // 2000-02-29T12:00:00Z exists (divisible by 400). Epoch 951_825_600.
    let (date_stamp, amz_date) = TestApi.format_sigv4_timestamps(951_825_600);
    assert_eq!(date_stamp, "20000229");
    assert_eq!(amz_date, "20000229T120000Z");
}

#[test]
fn year_2100_is_not_leap_under_the_century_rule() {
    // 2100 is divisible by 100 but not 400, so there is no 2100-02-29: the
    // second after 2100-02-28T23:59:59Z must roll straight to 2100-03-01.
    let (last_feb_date, last_feb) = TestApi.format_sigv4_timestamps(4_107_542_399);
    assert_eq!(last_feb_date, "21000228");
    assert_eq!(last_feb, "21000228T235959Z");

    let (first_mar_date, first_mar) = TestApi.format_sigv4_timestamps(4_107_542_400);
    assert_eq!(first_mar_date, "21000301");
    assert_eq!(first_mar, "21000301T000000Z");
}
