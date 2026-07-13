//! AWS SigV4 signing, known-answer regression locks on the public signer
//! `keyhog_verifier::sigv4::sign_request_authorization`.
//!
//! Why this file exists
//! --------------------
//! `crates/verifier/src/verify/aws.rs` decides `Live` vs `Dead` for an AWS
//! credential by signing a real STS `GetCallerIdentity` probe and reading the
//! HTTP status. AWS answers `403 SignatureDoesNotMatch` to a signature wrong by
//! a single byte, and that 403 maps to `VerificationResult::Dead`. So any latent
//! drift in canonical-request assembly, credential scope, the HMAC signing-key
//! derivation chain, or the final hex would silently misverify a *live*
//! credential as Dead (a Law-10 silent failure (a real secret reported safe)).
//!
//! What this file locks that the sibling files do not
//! --------------------------------------------------
//! `regression_sigv4_known_answer.rs` locks the IAM `ListUsers` and `get-vanilla`
//! vectors; `regression_sigv4_asia_security_token.rs` mirrors the pure string
//! builders. This file adds NON-overlapping AWS-published and production-shape
//! vectors, each asserted as a CONCRETE lowercase-hex signature embedded in the
//! full `Authorization` header:
//!
//!   * `post-vanilla`: the AWS `aws-sig-v4-test-suite` canonical POST vector,
//!     published signature
//!     `5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b`.
//!   * The exact STS `GetCallerIdentity` POST probe the production `aws.rs`
//!     caller signs, permanent (`AKIA…`) and temporary (`ASIA…` + session
//!     token), with their concrete signatures, so a signing-math regression on
//!     the real probe body is caught here.
//!   * Header-value whitespace collapse, query percent-encoding, and
//!     region/service → credential-scope wiring, each with a concrete hex lock.
//!
//! Independence note (host-agnostic by construction)
//! -------------------------------------------------
//! `sign_request_authorization` is a pure CPU function: HMAC-SHA256 + SHA-256 +
//! string assembly, no accelerator branch, no clock, no RNG. Every expected hex
//! below was produced by an independent Python HMAC oracle that reproduces AWS's
//! own published `get-vanilla`, `iam ListUsers`, and `post-vanilla` signatures
//! byte-for-byte, so these locks hold identically on any host.

use keyhog_verifier::sigv4::sign_request_authorization;

// ---------------------------------------------------------------------------
// Shared reference constants (verbatim from AWS's published examples).
// ---------------------------------------------------------------------------

/// `hex(SHA256(b""))`: the empty-body payload hash AWS uses in GET vectors.
const EMPTY_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// AWS documented example access key id (long-lived form).
const AWS_EXAMPLE_ACCESS: &str = "AKIDEXAMPLE";
/// AWS documented example secret access key (shared by every published vector).
const AWS_EXAMPLE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
/// AWS documented reference instant `2015-08-30T12:36:00Z` as a Unix second.
const AWS_EXAMPLE_UNIX: u64 = 1_440_938_160;
/// `hex(SHA256(b"Action=GetCallerIdentity&Version=2011-06-15"))`: the payload
/// hash the production STS probe puts on the last canonical-request line.
const STS_BODY_SHA256: &str = "ab821ae955788b0e33ebd34c208442ccfc2d406e2edc5e7a39bd6458fbb4f843";

// ---------------------------------------------------------------------------
// Small helpers (the signer carries its own hmac/sha2/hex deps).
// ---------------------------------------------------------------------------

/// Extract the value of the `Signature=` field from an `Authorization` header.
fn signature_of(authorization: &str) -> &str {
    authorization
        .rsplit_once("Signature=")
        .expect("authorization header must contain a Signature= field")
        .1
}

/// Build an owned `(String, String)` query pair.
fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_string(), value.to_string())
}

// ===========================================================================
// GROUP A: AWS `aws-sig-v4-test-suite` published vector (headline lock).
// ===========================================================================

#[test]
fn post_vanilla_matches_aws_test_suite_authorization() {
    // POST "/" with no query, no extra headers, empty body, the canonical
    // `post-vanilla` case from AWS's SigV4 conformance suite.
    let (authorization, amz_date, signed_headers) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "POST",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed for a well-formed request");

    assert_eq!(amz_date, "20150830T123600Z");
    assert_eq!(signed_headers, "host;x-amz-date");
    assert_eq!(
        authorization,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
    );
}

#[test]
fn post_vanilla_signature_field_matches_published_hex() {
    let (authorization, _amz, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "POST",
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
        "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
    );
}

#[test]
fn post_vanilla_differs_from_get_vanilla_only_by_http_method() {
    // Same identity/instant/region/service/host/body, only the HTTP method
    // changes (GET vs POST), which flips the first canonical-request line and so
    // must yield a different signature. Guards the method being dropped.
    let common = |method: &str| {
        let (auth, _a, _s) = sign_request_authorization(
            AWS_EXAMPLE_ACCESS,
            AWS_EXAMPLE_SECRET,
            None,
            "us-east-1",
            "service",
            method,
            "/",
            &[],
            "example.amazonaws.com",
            EMPTY_BODY_SHA256,
            AWS_EXAMPLE_UNIX,
            &[],
        )
        .expect("signing must succeed");
        signature_of(&auth).to_string()
    };
    // GET is the sibling file's published vector; POST is this file's.
    assert_eq!(
        common("GET"),
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
    assert_eq!(
        common("POST"),
        "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
    );
    assert_ne!(common("GET"), common("POST"), "method is signed");
}

// ===========================================================================
// GROUP B (the exact STS GetCallerIdentity probe the production caller signs).
// ===========================================================================

#[test]
fn sts_body_hash_constant_is_sha256_of_getcalleridentity_body() {
    // Prove the STS body-hash constant used below is really SHA-256 of the probe
    // body, so the STS locks are anchored to the real payload, not a magic hex.
    use sha2::{Digest, Sha256};
    let computed = hex::encode(Sha256::digest(
        b"Action=GetCallerIdentity&Version=2011-06-15",
    ));
    assert_eq!(computed, STS_BODY_SHA256);
}

#[test]
fn sts_getcalleridentity_akia_full_authorization() {
    // The production `build_sigv4_request` shape for a permanent credential:
    // POST "/", empty query, no extra headers, the GetCallerIdentity body hash.
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
        STS_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert_eq!(amz_date, "20150830T123600Z");
    assert_eq!(signed_headers, "host;x-amz-date");
    assert_eq!(
        authorization,
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/sts/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=6f5b24efd725b4b1346d20ecef0d9907d33fb68d3ee5cc640fd6eb2da4505d57"
    );
}

#[test]
fn sts_getcalleridentity_asia_session_token_full_authorization() {
    // Temporary credential (ASIA…) with a session token: the token MUST be a
    // signed header (`x-amz-security-token`, sorted last) and fold into the hex.
    let (authorization, amz_date, signed_headers) = sign_request_authorization(
        "ASIAIOSFODNN7EXAMPLE",
        AWS_EXAMPLE_SECRET,
        Some("AQoDYXdzEXAMPLEtokenEXAMPLEEXAMPLE=="),
        "us-east-1",
        "sts",
        "POST",
        "/",
        &[],
        "sts.us-east-1.amazonaws.com",
        STS_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert_eq!(amz_date, "20150830T123600Z");
    assert_eq!(signed_headers, "host;x-amz-date;x-amz-security-token");
    assert_eq!(
        authorization,
        "AWS4-HMAC-SHA256 Credential=ASIAIOSFODNN7EXAMPLE/20150830/us-east-1/sts/aws4_request, \
         SignedHeaders=host;x-amz-date;x-amz-security-token, \
         Signature=02cbf4bb64ddefa07024ac2d4502b8efba6ba53b0a1e691f21f04d15a9248f18"
    );
}

#[test]
fn session_token_changes_the_sts_signature_versus_permanent_creds() {
    // Same probe, differing only by presence of the session token: the signed
    // hex must differ (the token is folded into the canonical request, not sent
    // as a cosmetic unsigned header (the C5 regression's root cause)).
    let akia = sign_request_authorization(
        "AKIAIOSFODNN7EXAMPLE",
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "sts",
        "POST",
        "/",
        &[],
        "sts.us-east-1.amazonaws.com",
        STS_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");
    let asia = sign_request_authorization(
        "ASIAIOSFODNN7EXAMPLE",
        AWS_EXAMPLE_SECRET,
        Some("AQoDYXdzEXAMPLEtokenEXAMPLEEXAMPLE=="),
        "us-east-1",
        "sts",
        "POST",
        "/",
        &[],
        "sts.us-east-1.amazonaws.com",
        STS_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert_eq!(akia.1, asia.1, "amz_date unchanged");
    assert_eq!(
        signature_of(&akia.0),
        "6f5b24efd725b4b1346d20ecef0d9907d33fb68d3ee5cc640fd6eb2da4505d57"
    );
    assert_eq!(
        signature_of(&asia.0),
        "02cbf4bb64ddefa07024ac2d4502b8efba6ba53b0a1e691f21f04d15a9248f18"
    );
    assert_ne!(
        signature_of(&akia.0),
        signature_of(&asia.0),
        "the session token must change the signature"
    );
}

#[test]
fn session_token_value_is_not_placed_in_the_authorization_header() {
    // The Authorization grammar carries only Credential / SignedHeaders /
    // Signature. The raw token must NOT leak into it; only the header name is
    // named inside the SignedHeaders list.
    let token = "AQoDYXdzEXAMPLEtokenEXAMPLEEXAMPLE==";
    let (authorization, _amz, signed_headers) = sign_request_authorization(
        "ASIAIOSFODNN7EXAMPLE",
        AWS_EXAMPLE_SECRET,
        Some(token),
        "us-east-1",
        "sts",
        "POST",
        "/",
        &[],
        "sts.us-east-1.amazonaws.com",
        STS_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert!(
        !authorization.contains(token),
        "raw session token must not appear in the Authorization header"
    );
    assert!(authorization.contains("SignedHeaders=host;x-amz-date;x-amz-security-token"));
    assert_eq!(signed_headers, "host;x-amz-date;x-amz-security-token");
}

// ===========================================================================
// GROUP C (region/service → credential scope → signature wiring).
// ===========================================================================

#[test]
fn region_and_service_feed_credential_scope_and_signature() {
    // A different region+service (eu-west-1 / s3) must appear verbatim in the
    // credential scope AND produce the matching concrete signature, proving the
    // scope is not cosmetic but derived into the signing-key chain.
    let (authorization, _amz, signed_headers) = sign_request_authorization(
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

    assert_eq!(signed_headers, "host;x-amz-date");
    assert_eq!(
        authorization,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/eu-west-1/s3/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=27e6322861895549537920ae29ecd4b7885ad660aa8d2e326a96e8261681f2d0"
    );
}

#[test]
fn changing_only_the_region_changes_the_signature() {
    // us-east-1 vs eu-west-1 (same service `s3`), the region is baked into the
    // k_region step of the signing-key derivation, so the hex must differ.
    let sign_region = |region: &str| {
        let (auth, _a, _s) = sign_request_authorization(
            AWS_EXAMPLE_ACCESS,
            AWS_EXAMPLE_SECRET,
            None,
            region,
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
        signature_of(&auth).to_string()
    };
    assert_eq!(
        sign_region("eu-west-1"),
        "27e6322861895549537920ae29ecd4b7885ad660aa8d2e326a96e8261681f2d0"
    );
    assert_ne!(
        sign_region("us-east-1"),
        sign_region("eu-west-1"),
        "region is part of the signing-key derivation"
    );
}

// ===========================================================================
// GROUP D (canonical-query percent-encoding & header-value normalization).
// ===========================================================================

#[test]
fn space_in_query_value_percent_encodes_to_expected_signature() {
    // A space in a query value must encode as %20 in the canonical query; the
    // whole request then signs to this concrete hex. Guards the encoder.
    let (authorization, _amz, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "GET",
        "/",
        &[pair("k", "a b")],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    assert_eq!(
        signature_of(&authorization),
        "6a438f2ae7f564af65a73967814b05b466b4279881b9b4099b8881cfd3b4a6fd"
    );
}

#[test]
fn header_value_internal_whitespace_is_collapsed_before_signing() {
    // SigV4 trims and collapses internal runs of whitespace in header values, so
    // "  a   b   c  " signs identically to "a b c", and both to this concrete
    // hex. Also proves the extra header is inserted in sorted position
    // (host < my-header1 < x-amz-date).
    let padded = sign_request_authorization(
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
        &[("my-header1", "  a   b   c  ")],
    )
    .expect("signing must succeed");
    let clean = sign_request_authorization(
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
        &[("my-header1", "a b c")],
    )
    .expect("signing must succeed");

    assert_eq!(padded.2, "host;my-header1;x-amz-date", "sorted insertion");
    assert_eq!(
        padded.0, clean.0,
        "internal whitespace collapse is canonical"
    );
    assert_eq!(
        signature_of(&padded.0),
        "6ff6bc3cebca8811504dc903f3a072c310d9f48f8ee5c0b08115052209439e1b"
    );
}

#[test]
fn extra_signed_header_is_sorted_and_named_in_signed_headers() {
    // An extra header sorting between `host` and `x-amz-date` must land in the
    // middle of the semicolon-joined SignedHeaders list.
    let (authorization, _amz, signed_headers) = sign_request_authorization(
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
        &[("my-header1", "a b c")],
    )
    .expect("signing must succeed");

    assert_eq!(signed_headers, "host;my-header1;x-amz-date");
    assert!(authorization.contains("SignedHeaders=host;my-header1;x-amz-date"));
}

// ===========================================================================
// GROUP E: Authorization grammar & host-independence (purity) contract.
// ===========================================================================

#[test]
fn authorization_grammar_is_exactly_three_comma_space_sections() {
    let (authorization, _amz, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "POST",
        "/",
        &[],
        "example.amazonaws.com",
        EMPTY_BODY_SHA256,
        AWS_EXAMPLE_UNIX,
        &[],
    )
    .expect("signing must succeed");

    let sections: Vec<&str> = authorization.splitn(3, ", ").collect();
    assert_eq!(sections.len(), 3, "exactly three comma-space sections");
    assert_eq!(
        sections[0],
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request"
    );
    assert_eq!(sections[1], "SignedHeaders=host;x-amz-date");
    assert_eq!(
        sections[2],
        "Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
    );
}

#[test]
fn signature_is_exactly_sixty_four_lowercase_hex_chars() {
    let (authorization, _amz, _signed) = sign_request_authorization(
        AWS_EXAMPLE_ACCESS,
        AWS_EXAMPLE_SECRET,
        None,
        "us-east-1",
        "service",
        "POST",
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
fn signing_is_pure_and_host_independent() {
    // No accelerator branch, no clock, no RNG: two calls on ANY host must yield
    // the byte-identical documented result (this is why the KATs above are
    // portable). A silent nondeterministic path would break this equality.
    let sign = || {
        sign_request_authorization(
            AWS_EXAMPLE_ACCESS,
            AWS_EXAMPLE_SECRET,
            None,
            "us-east-1",
            "service",
            "POST",
            "/",
            &[],
            "example.amazonaws.com",
            EMPTY_BODY_SHA256,
            AWS_EXAMPLE_UNIX,
            &[],
        )
        .expect("signing must succeed")
    };
    let first = sign();
    let second = sign();
    assert_eq!(first, second, "pure signer is deterministic across calls");
    assert_eq!(
        first.0,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
    );
}
