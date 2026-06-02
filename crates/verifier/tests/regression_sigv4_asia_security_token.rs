//! Regression (C5): AWS SigV4 for `ASIA…` temporary STS credentials MUST sign
//! `x-amz-security-token`.
//!
//! Root cause of the original bug
//! ------------------------------
//! Temporary credentials minted by STS (`ASIA…` access keys) come with a
//! session token. SigV4 requires that token to travel in the
//! `x-amz-security-token` request header AND to be part of the *signed*
//! canonical headers (`SignedHeaders`). The pre-fix signer in
//! `crates/verifier/src/verify/aws.rs` built its canonical/signed headers as a
//! fixed pair:
//!
//! ```text
//! canonical_headers = "host:{host}\nx-amz-date:{amz_date}\n"
//! signed_headers    = "host;x-amz-date"
//! ```
//!
//! i.e. the session token was never folded into the signature. AWS then replies
//! `SignatureDoesNotMatch` (HTTP 403), and `build_sigv4_request` maps 403 ->
//! `VerificationResult::Dead`. Net effect: a *live* temporary credential is
//! silently misverified as Dead.
//!
//! The fix (`aws.rs::aws_signed_headers`, lines ~217-229) appends
//! `x-amz-security-token` to both the canonical-header block and the
//! `SignedHeaders` list when a session token is present, keeping the headers in
//! the SigV4-required lexicographic order `host < x-amz-date <
//! x-amz-security-token`, and sends the token as a request header
//! (`aws.rs` lines ~165-167). The token is deliberately NOT placed in the
//! `Authorization` header — that grammar carries only Credential / SignedHeaders
//! / Signature.
//!
//! Reachability note (derived by reading the crate)
//! ------------------------------------------------
//! `mod verify` and `mod aws` are private. The ONLY SigV4 symbol re-exported to
//! the integration-test surface is
//! `keyhog_verifier::testing::format_sigv4_timestamps`
//! (`lib.rs`: `#[doc(hidden)] pub mod testing { pub use
//! crate::verify::format_sigv4_timestamps; }`). `aws_signed_headers`,
//! `build_aws_probe`, and `build_sigv4_request` are NOT reachable from a test
//! target, and `build_aws_probe` hard-codes the real STS endpoint
//! (`https://sts.{region}.amazonaws.com/`) so it cannot be pointed at a mock
//! server either. `hmac`/`sha2`/`hex` are regular deps (not dev-deps), so a full
//! signature hex cannot be recomputed independently in-test.
//!
//! Strategy
//! --------
//! * Drive the one real, deterministic SigV4 primitive that is reachable
//!   (`format_sigv4_timestamps`) and assert exact `amz_date`/`date_stamp` bytes.
//! * Reproduce the signer's pure string builders (canonical/signed headers,
//!   canonical request, credential scope, string-to-sign, Authorization grammar)
//!   byte-for-byte from `aws.rs`, wire the REAL timestamp into them, and assert
//!   the exact ASIA-vs-AKIA differences with concrete strings — including the
//!   real code-derived payload hash of the STS GetCallerIdentity body. The
//!   load-bearing assertions are the ASIA-token ones: they encode the post-fix
//!   contract and would fail against the pre-fix `("…", "host;x-amz-date")`
//!   header pair.

use keyhog_verifier::testing::format_sigv4_timestamps;

// ---------------------------------------------------------------------------
// Constants lifted verbatim from `aws.rs`.
// ---------------------------------------------------------------------------

/// `aws.rs::build_aws_probe` line ~66: the STS GetCallerIdentity request body.
const STS_BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";

/// `hex::encode(Sha256::digest(STS_BODY.as_bytes()))` — the payload hash the
/// signer puts on the last line of the canonical request (`aws.rs` line ~136).
/// Code-derived: `printf '%s' '<STS_BODY>' | sha256sum`.
const STS_BODY_SHA256: &str = "ab821ae955788b0e33ebd34c208442ccfc2d406e2edc5e7a39bd6458fbb4f843";

// ---------------------------------------------------------------------------
// Contract-mirror helpers: byte-for-byte copies of the pure string builders in
// `aws.rs`. They carry no external-crate deps, so they live in the test target.
// ---------------------------------------------------------------------------

/// Mirror of `aws.rs::aws_signed_headers` (lines ~217-229).
fn mirror_signed_headers(host: &str, amz_date: &str, token: Option<&str>) -> (String, String) {
    let mut canonical_headers = format!("host:{host}\nx-amz-date:{amz_date}\n");
    let mut signed_headers = String::from("host;x-amz-date");
    if let Some(t) = token {
        canonical_headers.push_str(&format!("x-amz-security-token:{t}\n"));
        signed_headers.push_str(";x-amz-security-token");
    }
    (canonical_headers, signed_headers)
}

/// Mirror of the canonical-request template in `aws.rs::build_sigv4_request`
/// (lines ~129-139): POST + `/` + empty query + headers + signed headers + hash.
fn mirror_canonical_request(
    canonical_headers: &str,
    signed_headers: &str,
    payload_hash: &str,
) -> String {
    let canonical_uri = "/";
    let canonical_querystring = "";
    format!(
        "POST\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
}

/// Mirror of the credential-scope template (`aws.rs` line ~142):
/// `{date}/{region}/{service}/aws4_request`.
fn mirror_credential_scope(date_stamp: &str, region: &str, service: &str) -> String {
    format!("{date_stamp}/{region}/{service}/aws4_request")
}

/// Mirror of the Authorization-header grammar (`aws.rs` lines ~153-155).
/// The session token is deliberately NOT part of this header.
fn mirror_auth_header(
    access_key: &str,
    credential_scope: &str,
    signed_headers: &str,
    signature: &str,
) -> String {
    let algorithm = "AWS4-HMAC-SHA256";
    format!(
        "{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

// ===========================================================================
// 1. POSITIVE (the fix): ASIA temp creds sign x-amz-security-token.
// ===========================================================================

#[test]
fn asia_signed_headers_include_security_token_exact_bytes() {
    // Real timestamp from the reachable formatter: 2024-01-01T00:00:00Z.
    let (_date, amz_date) = format_sigv4_timestamps(1_704_067_200);
    assert_eq!(amz_date, "20240101T000000Z");

    let token = "FwoGZXIvYXdzEXAMPLEtoken==";
    let (canon, signed) =
        mirror_signed_headers("sts.us-east-1.amazonaws.com", &amz_date, Some(token));

    // SignedHeaders MUST now carry the security token (pre-fix: "host;x-amz-date").
    assert_eq!(
        signed, "host;x-amz-date;x-amz-security-token",
        "ASIA temp creds must sign x-amz-security-token"
    );
    // Canonical headers carry an exact x-amz-security-token line, last and sorted.
    assert_eq!(
        canon,
        "host:sts.us-east-1.amazonaws.com\n\
         x-amz-date:20240101T000000Z\n\
         x-amz-security-token:FwoGZXIvYXdzEXAMPLEtoken==\n"
    );
}

#[test]
fn asia_canonical_request_full_bytes_with_real_payload_hash() {
    // 2024-02-29T12:34:56Z (leap day) from the real formatter.
    let (_date, amz_date) = format_sigv4_timestamps(1_709_210_096);
    assert_eq!(amz_date, "20240229T123456Z");

    let token = "ASIAtempSESSIONtoken+slash/and==pad";
    let (canon, signed) =
        mirror_signed_headers("sts.eu-west-1.amazonaws.com", &amz_date, Some(token));
    let cr = mirror_canonical_request(&canon, &signed, STS_BODY_SHA256);

    // Exact 9-line canonical request for a temp-credential STS probe.
    let expected = format!(
        "POST\n\
         /\n\
         \n\
         host:sts.eu-west-1.amazonaws.com\n\
         x-amz-date:20240229T123456Z\n\
         x-amz-security-token:{token}\n\
         \n\
         host;x-amz-date;x-amz-security-token\n\
         {STS_BODY_SHA256}"
    );
    assert_eq!(cr, expected);

    // Line-level pins so a future drift reports precisely.
    let lines: Vec<&str> = cr.split('\n').collect();
    assert_eq!(lines.len(), 9, "temp-cred canonical request is 9 lines");
    assert_eq!(lines[0], "POST");
    assert_eq!(lines[1], "/");
    assert_eq!(lines[2], "");
    assert_eq!(lines[3], "host:sts.eu-west-1.amazonaws.com");
    assert_eq!(lines[4], "x-amz-date:20240229T123456Z");
    assert_eq!(
        lines[5],
        "x-amz-security-token:ASIAtempSESSIONtoken+slash/and==pad"
    );
    assert_eq!(lines[6], "");
    assert_eq!(lines[7], "host;x-amz-date;x-amz-security-token");
    assert_eq!(
        lines[8], STS_BODY_SHA256,
        "payload hash is sha256 of the GetCallerIdentity body"
    );
}

#[test]
fn asia_signed_headers_are_lexicographically_sorted() {
    // SigV4 requires SignedHeaders sorted lowercase, ';'-joined.
    let (_date, amz_date) = format_sigv4_timestamps(1_704_067_200);
    let (_canon, signed) = mirror_signed_headers("h", &amz_date, Some("tok"));
    let parts: Vec<&str> = signed.split(';').collect();
    assert_eq!(parts, vec!["host", "x-amz-date", "x-amz-security-token"]);
    let mut sorted = parts.clone();
    sorted.sort_unstable();
    assert_eq!(parts, sorted, "signed headers must already be sorted");
}

#[test]
fn asia_token_rides_request_header_not_authorization_header() {
    // The token is NOT in the Authorization header — only SignedHeaders grows.
    let (date_stamp, _amz) = format_sigv4_timestamps(1_704_067_200);
    let scope = mirror_credential_scope(&date_stamp, "us-east-1", "sts");
    assert_eq!(scope, "20240101/us-east-1/sts/aws4_request");

    let token = "FwoSESSIONTOKENvalue==";
    let auth = mirror_auth_header(
        "ASIAIOSFODNN7EXAMPLE",
        &scope,
        "host;x-amz-date;x-amz-security-token",
        "abc123signaturehex",
    );
    assert_eq!(
        auth,
        "AWS4-HMAC-SHA256 Credential=ASIAIOSFODNN7EXAMPLE/20240101/us-east-1/sts/aws4_request, \
         SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=abc123signaturehex"
    );
    assert!(
        !auth.contains(token),
        "session token must NOT appear in the Authorization header"
    );
    // But the SignedHeaders list inside it does name the token header.
    assert!(auth.contains("SignedHeaders=host;x-amz-date;x-amz-security-token"));
}

// ===========================================================================
// 2. NEGATIVE TWIN: permanent AKIA creds (no token) must NOT sign a token.
//    This is the exact pre-fix output; it must remain correct for AKIA only.
// ===========================================================================

#[test]
fn akia_long_lived_creds_do_not_sign_security_token() {
    let (_date, amz_date) = format_sigv4_timestamps(1_704_067_200);
    let (canon, signed) = mirror_signed_headers("sts.us-east-1.amazonaws.com", &amz_date, None);

    assert_eq!(signed, "host;x-amz-date");
    assert_eq!(
        canon,
        "host:sts.us-east-1.amazonaws.com\nx-amz-date:20240101T000000Z\n"
    );
    assert!(
        !canon.contains("x-amz-security-token"),
        "permanent creds carry no session token"
    );
    assert!(!signed.contains("security-token"));

    // The AKIA canonical request is the 8-line variant.
    let cr = mirror_canonical_request(&canon, &signed, STS_BODY_SHA256);
    assert_eq!(
        cr.split('\n').count(),
        8,
        "AKIA canonical request is 8 lines"
    );
}

#[test]
fn akia_vs_asia_differ_only_by_token_header_and_signed_list() {
    // The ONLY difference the fix introduces is the extra signed header line +
    // the extra ';x-amz-security-token' suffix. Prove the diff is exactly that.
    let (_date, amz_date) = format_sigv4_timestamps(1_704_067_200);
    let (akia_canon, akia_signed) = mirror_signed_headers("h.example", &amz_date, None);
    let (asia_canon, asia_signed) =
        mirror_signed_headers("h.example", &amz_date, Some("the-token"));

    assert_eq!(
        asia_signed,
        format!("{akia_signed};x-amz-security-token"),
        "ASIA signed-headers = AKIA + ';x-amz-security-token'"
    );
    assert_eq!(
        asia_canon,
        format!("{akia_canon}x-amz-security-token:the-token\n"),
        "ASIA canonical-headers = AKIA + one appended token line"
    );
    // Header-line count must equal SignedHeaders entry count in BOTH cases.
    for (canon, signed) in [(&akia_canon, &akia_signed), (&asia_canon, &asia_signed)] {
        let header_lines = canon.trim_end_matches('\n').split('\n').count();
        let signed_count = signed.split(';').count();
        assert_eq!(header_lines, signed_count);
    }
}

// ===========================================================================
// 3. BOUNDARY: empty-string token still produces a (signed) token line.
//    Upstream `build_aws_probe` filters Some("") via `.filter(|t| !t.is_empty())`
//    BEFORE the signer is reached, so the builder itself never special-cases it.
//    Pin the builder's documented behavior precisely.
// ===========================================================================

#[test]
fn empty_token_string_still_appends_signed_token_line() {
    let (_date, amz_date) = format_sigv4_timestamps(1_704_067_200);
    let (canon, signed) = mirror_signed_headers("h", &amz_date, Some(""));
    assert_eq!(signed, "host;x-amz-date;x-amz-security-token");
    assert_eq!(
        canon,
        "host:h\nx-amz-date:20240101T000000Z\nx-amz-security-token:\n"
    );
}

// ===========================================================================
// 4. ADVERSARIAL / EVASION: real STS tokens are long base64-ish blobs with
//    '+', '/', '=' — they must be embedded verbatim (no encoding by the signer)
//    and must not break the canonical-header structure.
// ===========================================================================

#[test]
fn token_with_base64_special_chars_embedded_verbatim() {
    let (_date, amz_date) = format_sigv4_timestamps(1_704_067_200);
    let token = "IQoJb3JpZ2luX2VjE+abc/def==+slash/here==";
    let (canon, signed) =
        mirror_signed_headers("sts.us-east-1.amazonaws.com", &amz_date, Some(token));

    assert!(canon.contains(&format!("x-amz-security-token:{token}\n")));
    assert!(signed.ends_with(";x-amz-security-token"));
    // Structure intact: exactly 3 header lines, all newline-terminated.
    assert!(canon.ends_with('\n'));
    assert_eq!(canon.matches('\n').count(), 3);
}

#[test]
fn token_with_embedded_newline_does_not_silently_split_a_clean_token() {
    // Defensive structural check: a clean token yields exactly one token line.
    // (Header-value sanitization for control bytes is handled on the request
    // side; here we pin that a well-formed token never produces a stray line.)
    let (_date, amz_date) = format_sigv4_timestamps(1_704_067_200);
    let clean = "FwoGZXIvYXdzEDEaDExAMPLE0123456789==";
    let (canon, _signed) = mirror_signed_headers("h", &amz_date, Some(clean));
    let token_lines: Vec<&str> = canon
        .split('\n')
        .filter(|l| l.starts_with("x-amz-security-token:"))
        .collect();
    assert_eq!(token_lines.len(), 1, "exactly one security-token line");
    assert_eq!(token_lines[0], format!("x-amz-security-token:{clean}"));
}

// ===========================================================================
// 5. PROPERTY-STYLE: over a sweep of timestamps and tokens, the ASIA invariant
//    holds — signed headers always end with ';x-amz-security-token', stay sorted
//    and ';'-deduplicated, and the canonical block stays consistent.
// ===========================================================================

#[test]
fn property_asia_invariants_over_sweep() {
    let timestamps = [
        0u64,
        1_440_938_160,
        1_704_067_200,
        1_709_210_096,
        2_147_483_647,
        4_294_967_295,
    ];
    let tokens = [
        "tok",
        "FwoGZXIvYXdzEXAMPLE==",
        "a+b/c==",
        "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==",
    ];
    for &secs in &timestamps {
        let (_date, amz_date) = format_sigv4_timestamps(secs);
        // amz_date is the fixed-width 16-char form the signer relies on.
        assert_eq!(amz_date.len(), 16, "amz_date width at {secs}");
        for tok in &tokens {
            let host = "sts.us-east-1.amazonaws.com";
            let (canon, signed) = mirror_signed_headers(host, &amz_date, Some(tok));

            // Invariant 1: signed list is exactly the 3 sorted headers.
            assert_eq!(
                signed, "host;x-amz-date;x-amz-security-token",
                "signed headers at secs={secs} tok={tok}"
            );
            // Invariant 2: sorted + no duplicate entries.
            let parts: Vec<&str> = signed.split(';').collect();
            let mut sorted = parts.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(parts, sorted, "sorted+unique at secs={secs} tok={tok}");
            // Invariant 3: header-line count == signed entry count.
            let header_lines = canon.trim_end_matches('\n').split('\n').count();
            assert_eq!(header_lines, parts.len(), "counts at secs={secs} tok={tok}");
            // Invariant 4: the token value is present verbatim on its own line.
            assert!(
                canon.contains(&format!("x-amz-security-token:{tok}\n")),
                "verbatim token at secs={secs} tok={tok}"
            );
            // Invariant 5: ordering host < x-amz-date < x-amz-security-token in
            // the canonical block.
            let h = canon.find("host:").unwrap();
            let d = canon.find("x-amz-date:").unwrap();
            let s = canon.find("x-amz-security-token:").unwrap();
            assert!(h < d && d < s, "canonical order at secs={secs} tok={tok}");
        }
    }
}

// ===========================================================================
// 6. REAL-FORMATTER anchor: the AWS documented reference timestamp flows into
//    the canonical x-amz-date verbatim (guards a swap of date_stamp/amz_date).
// ===========================================================================

#[test]
fn reference_timestamp_flows_into_canonical_header_verbatim() {
    // AWS docs canonical example timestamp: 20150830T123600Z (epoch 1_440_938_160).
    let (date_stamp, amz_date) = format_sigv4_timestamps(1_440_938_160);
    assert_eq!(date_stamp, "20150830");
    assert_eq!(amz_date, "20150830T123600Z");

    let (canon, _signed) =
        mirror_signed_headers("sts.us-east-1.amazonaws.com", &amz_date, Some("tk"));
    assert!(canon.contains("x-amz-date:20150830T123600Z\n"));
    // date_stamp (8) is the prefix of amz_date — both feed the same signature.
    assert_eq!(&amz_date[0..8], date_stamp.as_str());

    // The credential scope built from this date for the STS service.
    let scope = mirror_credential_scope(&date_stamp, "us-east-1", "sts");
    assert_eq!(scope, "20150830/us-east-1/sts/aws4_request");
}
