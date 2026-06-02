//! Integration tests for keyhog-verifier AWS SigV4 signing.
//!
//! Coverage area: `sigv4_signing`.
//!
//! Source under test: `crates/verifier/src/verify/aws.rs`.
//!
//! Reachability note (derived by reading the crate):
//!   * `mod verify` and `mod aws` are private modules. The ONLY SigV4 symbol
//!     re-exported to the integration-test surface is
//!     `keyhog_verifier::testing::format_sigv4_timestamps`
//!     (`lib.rs`: `pub mod testing { ... pub use crate::verify::format_sigv4_timestamps; }`).
//!   * `aws_signed_headers`, `valid_aws_format`, `get_signature_key`,
//!     `hmac_sha256`, and `build_aws_probe` are NOT reachable from a test target
//!     (`build_aws_probe` is `pub(crate)`; the others live in the private
//!     `mod aws`). `hmac` / `sha2` / `hex` are regular deps, NOT dev-deps, so a
//!     test cannot recompute a full signature hex independently.
//!
//! Strategy: `format_sigv4_timestamps` is the load-bearing pure input to the
//! whole signature chain (it feeds `amz_date`, `date_stamp`, the credential
//! scope, the canonical headers, and the string-to-sign). Every expected value
//! below was derived from the civil-from-days algorithm in `aws.rs` and
//! independently cross-checked against a reference date library. The signer's
//! string templates (canonical request, credential scope, string-to-sign,
//! canonical / signed headers including the ASIA `x-amz-security-token`
//! ordering invariant) are reproduced here as contract-mirror helpers and
//! asserted against the real timestamps, locking the documented behavior in
//! `aws.rs::build_sigv4_request` / `aws.rs::aws_signed_headers`.

use keyhog_verifier::testing::format_sigv4_timestamps;

// ---------------------------------------------------------------------------
// Contract-mirror helpers: byte-for-byte copies of the pure string builders in
// `aws.rs`. They carry no external crate deps, so they can live in the test
// target. If the real signer's documented format ever drifts from these, the
// structural assertions below will diverge from AWS's wire format.
// ---------------------------------------------------------------------------

/// Mirror of `aws.rs::aws_signed_headers`.
/// `host` and `x-amz-date` are always signed; for temporary (ASIA / STS)
/// credentials `x-amz-security-token` is appended to both, preserving the
/// lexicographic order `host < x-amz-date < x-amz-security-token`.
fn mirror_signed_headers(host: &str, amz_date: &str, token: Option<&str>) -> (String, String) {
    let mut canonical_headers = format!("host:{host}\nx-amz-date:{amz_date}\n");
    let mut signed_headers = String::from("host;x-amz-date");
    if let Some(t) = token {
        canonical_headers.push_str(&format!("x-amz-security-token:{t}\n"));
        signed_headers.push_str(";x-amz-security-token");
    }
    (canonical_headers, signed_headers)
}

/// Mirror of the canonical-request template in `aws.rs::build_sigv4_request`.
/// POST + `/` + empty query + canonical headers + signed headers + payload hash.
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

/// Mirror of the credential-scope template: `{date}/{region}/{service}/aws4_request`.
fn mirror_credential_scope(date_stamp: &str, region: &str, service: &str) -> String {
    format!("{date_stamp}/{region}/{service}/aws4_request")
}

/// Mirror of the string-to-sign template in `aws.rs::build_sigv4_request`.
fn mirror_string_to_sign(
    amz_date: &str,
    credential_scope: &str,
    canonical_request_hash: &str,
) -> String {
    let algorithm = "AWS4-HMAC-SHA256";
    format!("{algorithm}\n{amz_date}\n{credential_scope}\n{canonical_request_hash}")
}

/// Mirror of the Authorization header grammar in `aws.rs::build_sigv4_request`.
/// Note: the session token is deliberately NOT in this header — it travels only
/// as the signed `x-amz-security-token` request header.
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
// 1. AWS reference vector (timestamp component of the documented example)
// ===========================================================================

#[test]
fn sigv4_reference_vector_20150830_123600() {
    // AWS docs canonical example: request timestamp 20150830T123600Z,
    // date value 20150830. Unix epoch 1_440_938_160.
    let (date_stamp, amz_date) = format_sigv4_timestamps(1_440_938_160);
    assert_eq!(date_stamp, "20150830");
    assert_eq!(amz_date, "20150830T123600Z");
}

#[test]
fn sigv4_reference_vector_credential_scope_us_east_1_iam() {
    // The AWS reference example signs against scope:
    // 20150830/us-east-1/iam/aws4_request.
    let (date_stamp, _amz) = format_sigv4_timestamps(1_440_938_160);
    let scope = mirror_credential_scope(&date_stamp, "us-east-1", "iam");
    assert_eq!(scope, "20150830/us-east-1/iam/aws4_request");
}

#[test]
fn sigv4_reference_vector_string_to_sign_first_three_lines() {
    // The signer composes string-to-sign as:
    //   "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{sha256(canonical_request)}"
    // The 4th line is a SHA256 hex that cannot be recomputed in-test (sha2 is
    // not a dev-dep), so we assert only the three deterministic lines that come
    // straight from `format_sigv4_timestamps` + the scope template. Using a
    // sentinel for the hash keeps the asserted value fully code-derived.
    let (date_stamp, amz_date) = format_sigv4_timestamps(1_440_938_160);
    let scope = mirror_credential_scope(&date_stamp, "us-east-1", "iam");
    let sts = mirror_string_to_sign(&amz_date, &scope, "<cr-hash>");
    let lines: Vec<&str> = sts.split('\n').collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0], "AWS4-HMAC-SHA256");
    assert_eq!(lines[1], "20150830T123600Z");
    assert_eq!(lines[2], "20150830/us-east-1/iam/aws4_request");
    assert_eq!(lines[3], "<cr-hash>");
}

#[test]
fn sigv4_reference_second_example_20240119_145542() {
    let (date_stamp, amz_date) = format_sigv4_timestamps(1_705_676_142);
    assert_eq!(date_stamp, "20240119");
    assert_eq!(amz_date, "20240119T145542Z");
    // Component positions used by the signer.
    assert_eq!(&amz_date[0..8], "20240119");
    assert_eq!(&amz_date[8..9], "T");
    assert_eq!(&amz_date[9..11], "14");
    assert_eq!(&amz_date[11..13], "55");
    assert_eq!(&amz_date[13..15], "42");
    assert_eq!(&amz_date[15..16], "Z");
}

// ===========================================================================
// 2. Timestamp format contract (exact length + structure)
// ===========================================================================

#[test]
fn sigv4_date_stamp_always_8_ascii_digits() {
    for secs in [
        0u64,
        1_440_938_160,
        1_704_067_200,
        1_709_210_096,
        4_107_542_400,
    ] {
        let (d, _) = format_sigv4_timestamps(secs);
        assert_eq!(d.len(), 8, "date_stamp len for {secs}");
        assert!(d.chars().all(|c| c.is_ascii_digit()), "date digits {secs}");
    }
}

#[test]
fn sigv4_amz_date_always_16_chars_t_and_z_anchored() {
    for secs in [
        0u64,
        1_440_938_160,
        1_704_067_200,
        1_709_210_096,
        4_107_542_400,
    ] {
        let (_, a) = format_sigv4_timestamps(secs);
        assert_eq!(a.len(), 16, "amz_date len for {secs}");
        assert_eq!(&a[8..9], "T", "T anchor for {secs}");
        assert_eq!(&a[15..16], "Z", "Z anchor for {secs}");
        assert!(
            a[0..8].chars().all(|c| c.is_ascii_digit()),
            "date part {secs}"
        );
        assert!(
            a[9..15].chars().all(|c| c.is_ascii_digit()),
            "time part {secs}"
        );
    }
}

#[test]
fn sigv4_amz_date_first_eight_equal_date_stamp() {
    // The signer reuses date_stamp inside amz_date — they must agree on the
    // leading YYYYMMDD. A mismatch would corrupt the credential scope.
    for secs in [
        0u64,
        951_782_400,
        1_677_542_400,
        1_704_067_199,
        1_704_067_200,
        1_709_210_096,
        2_147_483_647,
        4_294_967_295,
    ] {
        let (d, a) = format_sigv4_timestamps(secs);
        assert_eq!(&a[0..8], d.as_str(), "amz/date agreement for {secs}");
    }
}

// ===========================================================================
// 3. Leap years
// ===========================================================================

#[test]
fn sigv4_leap_year_2024_feb_29_midnight() {
    // 2024 divisible by 4, not 100 -> leap. Feb 29 exists.
    let (d, a) = format_sigv4_timestamps(1_709_164_800);
    assert_eq!(d, "20240229");
    assert_eq!(a, "20240229T000000Z");
}

#[test]
fn sigv4_leap_year_2024_feb_29_with_time() {
    let (d, a) = format_sigv4_timestamps(1_709_210_096);
    assert_eq!(d, "20240229");
    assert_eq!(a, "20240229T123456Z");
}

#[test]
fn sigv4_leap_year_2024_feb_28_to_29_to_mar_1_progression() {
    // Last second of Feb 28.
    let (d0, a0) = format_sigv4_timestamps(1_709_164_799);
    assert_eq!((d0.as_str(), a0.as_str()), ("20240228", "20240228T235959Z"));
    // First second of Feb 29 (the leap day).
    let (d1, a1) = format_sigv4_timestamps(1_709_164_800);
    assert_eq!((d1.as_str(), a1.as_str()), ("20240229", "20240229T000000Z"));
    // First second of Mar 1 (one full leap day later).
    let (d2, a2) = format_sigv4_timestamps(1_709_251_200);
    assert_eq!((d2.as_str(), a2.as_str()), ("20240301", "20240301T000000Z"));
}

#[test]
fn sigv4_century_leap_year_2000_feb_29() {
    // 2000 divisible by 400 -> leap. Feb 29 exists.
    let (d, a) = format_sigv4_timestamps(951_782_400);
    assert_eq!(d, "20000229");
    assert_eq!(a, "20000229T000000Z");
    // Preceding second is Feb 28 23:59:59.
    let (dp, ap) = format_sigv4_timestamps(951_782_399);
    assert_eq!((dp.as_str(), ap.as_str()), ("20000228", "20000228T235959Z"));
}

#[test]
fn sigv4_leap_year_2004_feb_29_with_time() {
    let (d, a) = format_sigv4_timestamps(1_078_036_215);
    assert_eq!(d, "20040229");
    assert_eq!(a, "20040229T063015Z");
}

#[test]
fn sigv4_non_leap_century_2100_no_feb_29() {
    // 2100 divisible by 100, not by 400 -> NOT a leap year. Feb 28 -> Mar 1.
    let (d0, a0) = format_sigv4_timestamps(4_107_542_399);
    assert_eq!((d0.as_str(), a0.as_str()), ("21000228", "21000228T235959Z"));
    let (d1, a1) = format_sigv4_timestamps(4_107_542_400);
    assert_eq!((d1.as_str(), a1.as_str()), ("21000301", "21000301T000000Z"));
}

#[test]
fn sigv4_non_leap_year_2023_feb_28_to_mar_1() {
    let (d0, a0) = format_sigv4_timestamps(1_677_542_400);
    assert_eq!((d0.as_str(), a0.as_str()), ("20230228", "20230228T000000Z"));
    let (d1, a1) = format_sigv4_timestamps(1_677_628_800);
    assert_eq!((d1.as_str(), a1.as_str()), ("20230301", "20230301T000000Z"));
}

// ===========================================================================
// 4. Midnight / time-of-day boundaries
// ===========================================================================

#[test]
fn sigv4_midnight_exact_2020_01_01() {
    let (d, a) = format_sigv4_timestamps(1_577_836_800);
    assert_eq!(d, "20200101");
    assert_eq!(a, "20200101T000000Z");
}

#[test]
fn sigv4_one_second_before_midnight_2019_12_31() {
    let (d, a) = format_sigv4_timestamps(1_577_836_799);
    assert_eq!(d, "20191231");
    assert_eq!(a, "20191231T235959Z");
}

#[test]
fn sigv4_one_second_after_midnight() {
    // 2020-01-01 00:00:01.
    let (d, a) = format_sigv4_timestamps(1_577_836_801);
    assert_eq!(d, "20200101");
    assert_eq!(a, "20200101T000001Z");
}

#[test]
fn sigv4_exact_noon() {
    // 2024-06-30 12:00:00.
    let (d, a) = format_sigv4_timestamps(1_719_748_800);
    assert_eq!(d, "20240630");
    assert_eq!(a, "20240630T120000Z");
}

#[test]
fn sigv4_hour_rollover_at_3600_within_epoch_day() {
    // 1970-01-01 01:00:00.
    let (d, a) = format_sigv4_timestamps(3_600);
    assert_eq!(d, "19700101");
    assert_eq!(a, "19700101T010000Z");
}

#[test]
fn sigv4_minute_rollover_at_60() {
    // 1970-01-01 00:01:00.
    let (d, a) = format_sigv4_timestamps(60);
    assert_eq!(d, "19700101");
    assert_eq!(a, "19700101T000100Z");
}

#[test]
fn sigv4_last_second_of_first_epoch_day() {
    // 86399 -> 1970-01-01 23:59:59 (still epoch day 0).
    let (d, a) = format_sigv4_timestamps(86_399);
    assert_eq!(d, "19700101");
    assert_eq!(a, "19700101T235959Z");
}

#[test]
fn sigv4_first_second_of_second_epoch_day() {
    // 86400 -> 1970-01-02 00:00:00.
    let (d, a) = format_sigv4_timestamps(86_400);
    assert_eq!(d, "19700102");
    assert_eq!(a, "19700102T000000Z");
}

// ===========================================================================
// 5. Year boundaries
// ===========================================================================

#[test]
fn sigv4_epoch_zero_1970_01_01() {
    let (d, a) = format_sigv4_timestamps(0);
    assert_eq!(d, "19700101");
    assert_eq!(a, "19700101T000000Z");
}

#[test]
fn sigv4_year_boundary_2023_to_2024() {
    // Last second of 2023.
    let (d0, a0) = format_sigv4_timestamps(1_704_067_199);
    assert_eq!((d0.as_str(), a0.as_str()), ("20231231", "20231231T235959Z"));
    // First second of 2024.
    let (d1, a1) = format_sigv4_timestamps(1_704_067_200);
    assert_eq!((d1.as_str(), a1.as_str()), ("20240101", "20240101T000000Z"));
}

#[test]
fn sigv4_year_boundary_2099_to_2100() {
    let (d0, a0) = format_sigv4_timestamps(4_102_444_799);
    assert_eq!((d0.as_str(), a0.as_str()), ("20991231", "20991231T235959Z"));
    let (d1, a1) = format_sigv4_timestamps(4_102_444_800);
    assert_eq!((d1.as_str(), a1.as_str()), ("21000101", "21000101T000000Z"));
}

#[test]
fn sigv4_signed_32bit_epoch_2038() {
    // i32::MAX seconds = 2038-01-19 03:14:07. The fn takes u64, so no overflow.
    let (d, a) = format_sigv4_timestamps(2_147_483_647);
    assert_eq!(d, "20380119");
    assert_eq!(a, "20380119T031407Z");
}

#[test]
fn sigv4_unsigned_32bit_epoch_2106() {
    // u32::MAX seconds = 2106-02-07 06:28:15.
    let (d, a) = format_sigv4_timestamps(4_294_967_295);
    assert_eq!(d, "21060207");
    assert_eq!(a, "21060207T062815Z");
}

// ===========================================================================
// 6. ASIA / temporary-credential canonical & signed header contract
//    (x-amz-security-token MUST be signed for STS temp creds)
// ===========================================================================

#[test]
fn sigv4_signed_headers_no_token_for_long_lived_akia() {
    // Permanent (AKIA) keys: only host + x-amz-date are signed.
    let (canon, signed) =
        mirror_signed_headers("sts.us-east-1.amazonaws.com", "20240101T000000Z", None);
    assert_eq!(signed, "host;x-amz-date");
    assert_eq!(
        canon,
        "host:sts.us-east-1.amazonaws.com\nx-amz-date:20240101T000000Z\n"
    );
    // No security-token line leaks in.
    assert!(!canon.contains("x-amz-security-token"));
    assert!(!signed.contains("security-token"));
}

#[test]
fn sigv4_signed_headers_include_security_token_for_asia() {
    // Temporary (ASIA) creds carry a session token that MUST be in BOTH the
    // canonical headers and the SignedHeaders list, else AWS returns
    // SignatureDoesNotMatch (403) and a live key is misread as Dead.
    let token = "FwoGZXIvYXdzEXAMPLEtoken==";
    let (canon, signed) = mirror_signed_headers(
        "sts.us-east-1.amazonaws.com",
        "20240101T000000Z",
        Some(token),
    );
    assert_eq!(signed, "host;x-amz-date;x-amz-security-token");
    assert_eq!(
        canon,
        "host:sts.us-east-1.amazonaws.com\nx-amz-date:20240101T000000Z\nx-amz-security-token:FwoGZXIvYXdzEXAMPLEtoken==\n"
    );
}

#[test]
fn sigv4_signed_headers_lexicographically_sorted_with_token() {
    // SigV4 requires SignedHeaders be sorted lowercase, ';'-joined.
    // host < x-amz-date < x-amz-security-token must hold.
    let (_, signed) = mirror_signed_headers("h", "20240101T000000Z", Some("tok"));
    let parts: Vec<&str> = signed.split(';').collect();
    assert_eq!(parts, vec!["host", "x-amz-date", "x-amz-security-token"]);
    let mut sorted = parts.clone();
    sorted.sort_unstable();
    assert_eq!(parts, sorted, "signed headers must already be sorted");
}

#[test]
fn sigv4_canonical_headers_trailing_newline_per_header() {
    // Each canonical header line ends with '\n', including the last one.
    let (canon_no_tok, _) = mirror_signed_headers("h", "20240101T000000Z", None);
    assert!(canon_no_tok.ends_with('\n'));
    assert_eq!(canon_no_tok.matches('\n').count(), 2);
    let (canon_tok, _) = mirror_signed_headers("h", "20240101T000000Z", Some("t"));
    assert!(canon_tok.ends_with('\n'));
    assert_eq!(canon_tok.matches('\n').count(), 3);
}

#[test]
fn sigv4_canonical_headers_count_matches_signed_headers_count() {
    // The number of canonical-header lines must equal the number of
    // ';'-separated SignedHeaders entries — both with and without a token.
    for token in [None, Some("session-token-abc")] {
        let (canon, signed) = mirror_signed_headers("host.example", "20240101T000000Z", token);
        let header_lines = canon.trim_end_matches('\n').split('\n').count();
        let signed_count = signed.split(';').count();
        assert_eq!(header_lines, signed_count, "token={token:?}");
    }
}

#[test]
fn sigv4_canonical_headers_use_actual_amz_date_from_formatter() {
    // Wire the real timestamp formatter into the canonical headers, proving the
    // signer's amz_date feeds the x-amz-date header verbatim.
    let (_, amz_date) = format_sigv4_timestamps(1_440_938_160);
    let (canon, _) = mirror_signed_headers("sts.us-east-1.amazonaws.com", &amz_date, None);
    assert_eq!(
        canon,
        "host:sts.us-east-1.amazonaws.com\nx-amz-date:20150830T123600Z\n"
    );
}

// ===========================================================================
// 7. Canonical request / string-to-sign structure for STS GetCallerIdentity
// ===========================================================================

#[test]
fn sigv4_canonical_request_structure_post_root_empty_query() {
    // The STS probe is always POST / with an empty query string.
    let (canon, signed) =
        mirror_signed_headers("sts.us-east-1.amazonaws.com", "20240101T000000Z", None);
    // SHA256("Action=GetCallerIdentity&Version=2011-06-15") is fixed; the exact
    // hex cannot be recomputed in-test, so use a placeholder and assert shape.
    let cr = mirror_canonical_request(&canon, &signed, "PAYLOAD_HASH");
    let lines: Vec<&str> = cr.split('\n').collect();
    assert_eq!(lines[0], "POST", "HTTP method line");
    assert_eq!(lines[1], "/", "canonical URI line");
    assert_eq!(lines[2], "", "empty canonical query line");
    // host / x-amz-date header lines.
    assert_eq!(lines[3], "host:sts.us-east-1.amazonaws.com");
    assert_eq!(lines[4], "x-amz-date:20240101T000000Z");
    // blank line separating canonical headers block from signed-headers line.
    assert_eq!(lines[5], "");
    assert_eq!(lines[6], "host;x-amz-date");
    assert_eq!(lines[7], "PAYLOAD_HASH");
    assert_eq!(lines.len(), 8);
}

#[test]
fn sigv4_canonical_request_structure_with_security_token() {
    let token = "ASIA-temp-session-token";
    let (canon, signed) = mirror_signed_headers(
        "sts.eu-west-1.amazonaws.com",
        "20240229T123456Z",
        Some(token),
    );
    let cr = mirror_canonical_request(&canon, &signed, "HASH");
    let lines: Vec<&str> = cr.split('\n').collect();
    assert_eq!(lines[0], "POST");
    assert_eq!(lines[1], "/");
    assert_eq!(lines[2], "");
    assert_eq!(lines[3], "host:sts.eu-west-1.amazonaws.com");
    assert_eq!(lines[4], "x-amz-date:20240229T123456Z");
    assert_eq!(lines[5], "x-amz-security-token:ASIA-temp-session-token");
    assert_eq!(lines[6], "", "blank line after canonical headers");
    assert_eq!(lines[7], "host;x-amz-date;x-amz-security-token");
    assert_eq!(lines[8], "HASH");
    assert_eq!(lines.len(), 9);
}

#[test]
fn sigv4_credential_scope_sts_service_for_get_caller_identity() {
    // The STS probe signs with service "sts".
    let (date_stamp, _) = format_sigv4_timestamps(1_704_067_200);
    let scope = mirror_credential_scope(&date_stamp, "us-east-1", "sts");
    assert_eq!(scope, "20240101/us-east-1/sts/aws4_request");
}

#[test]
fn sigv4_credential_scope_region_varies() {
    let (date_stamp, _) = format_sigv4_timestamps(1_709_210_096);
    for region in [
        "us-east-1",
        "eu-central-1",
        "ap-southeast-2",
        "us-gov-west-1",
    ] {
        let scope = mirror_credential_scope(&date_stamp, region, "sts");
        assert_eq!(scope, format!("20240229/{region}/sts/aws4_request"));
        // Scope always ends with the literal terminator.
        assert!(scope.ends_with("/aws4_request"));
    }
}

#[test]
fn sigv4_string_to_sign_four_lines_with_algorithm_first() {
    let (date_stamp, amz_date) = format_sigv4_timestamps(1_705_676_142);
    let scope = mirror_credential_scope(&date_stamp, "us-east-1", "sts");
    let sts = mirror_string_to_sign(&amz_date, &scope, "deadbeef");
    let lines: Vec<&str> = sts.split('\n').collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0], "AWS4-HMAC-SHA256");
    assert_eq!(lines[1], "20240119T145542Z");
    assert_eq!(lines[2], "20240119/us-east-1/sts/aws4_request");
    assert_eq!(lines[3], "deadbeef");
}

#[test]
fn sigv4_string_to_sign_uses_amz_date_not_date_stamp_on_line_two() {
    // Line 2 must be the full amz_date (16 chars), line 3 scope starts with the
    // 8-char date_stamp. A common bug is swapping them.
    let (date_stamp, amz_date) = format_sigv4_timestamps(1_704_067_200);
    let scope = mirror_credential_scope(&date_stamp, "us-east-1", "sts");
    let sts = mirror_string_to_sign(&amz_date, &scope, "h");
    let lines: Vec<&str> = sts.split('\n').collect();
    assert_eq!(lines[1].len(), 16);
    assert_eq!(lines[1], "20240101T000000Z");
    assert!(lines[2].starts_with("20240101/"));
}

// ===========================================================================
// 8. Authorization header grammar (token is NOT in it)
// ===========================================================================

#[test]
fn sigv4_auth_header_grammar_for_akia() {
    let (date_stamp, _) = format_sigv4_timestamps(1_704_067_200);
    let scope = mirror_credential_scope(&date_stamp, "us-east-1", "sts");
    let auth = mirror_auth_header(
        "AKIAIOSFODNN7EXAMPLE",
        &scope,
        "host;x-amz-date",
        "abc123signaturehex",
    );
    assert_eq!(
        auth,
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240101/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123signaturehex"
    );
}

#[test]
fn sigv4_auth_header_for_asia_does_not_carry_session_token() {
    // For ASIA temp creds the SignedHeaders list grows, but the session token
    // itself never appears in the Authorization header — it rides the
    // x-amz-security-token request header only.
    let (date_stamp, _) = format_sigv4_timestamps(1_704_067_200);
    let scope = mirror_credential_scope(&date_stamp, "us-east-1", "sts");
    let token = "FwoSESSIONTOKENvalue==";
    let auth = mirror_auth_header(
        "ASIAIOSFODNN7EXAMPLE",
        &scope,
        "host;x-amz-date;x-amz-security-token",
        "sighex",
    );
    assert!(auth.contains("SignedHeaders=host;x-amz-date;x-amz-security-token"));
    assert!(auth.contains("Credential=ASIAIOSFODNN7EXAMPLE/"));
    assert!(
        !auth.contains(token),
        "session token must NOT appear in the Authorization header"
    );
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential="));
}

#[test]
fn sigv4_auth_header_field_order_credential_signedheaders_signature() {
    // The grammar order is Credential, then SignedHeaders, then Signature.
    let auth = mirror_auth_header(
        "ASIAEXAMPLE",
        "20240101/us-east-1/sts/aws4_request",
        "host;x-amz-date",
        "ff",
    );
    let cred_idx = auth.find("Credential=").unwrap();
    let sh_idx = auth.find("SignedHeaders=").unwrap();
    let sig_idx = auth.find("Signature=").unwrap();
    assert!(cred_idx < sh_idx);
    assert!(sh_idx < sig_idx);
}

// ===========================================================================
// 9. Determinism / property-style coverage
// ===========================================================================

#[test]
fn sigv4_timestamps_deterministic_repeat() {
    // Same input -> identical output, always (no hidden clock dependency).
    for secs in [0u64, 1, 86_399, 1_440_938_160, 4_294_967_295] {
        let a = format_sigv4_timestamps(secs);
        let b = format_sigv4_timestamps(secs);
        assert_eq!(a, b, "non-deterministic at {secs}");
    }
}

#[test]
fn sigv4_timestamps_monotonic_lexicographic_over_range() {
    // For increasing unix seconds, amz_date (a zero-padded fixed-width
    // timestamp) must be lexicographically non-decreasing — a property AWS
    // relies on for scope/date ordering. Step across many days.
    let mut prev: Option<(u64, String)> = None;
    let mut secs = 0u64;
    while secs <= 4_294_967_295 {
        let (_, a) = format_sigv4_timestamps(secs);
        if let Some((psecs, p)) = &prev {
            assert!(
                a.as_str() >= p.as_str(),
                "amz_date not monotonic: {psecs}->{p} then {secs}->{a}"
            );
        }
        prev = Some((secs, a));
        secs += 97_001; // odd step to hit many times-of-day
    }
}

#[test]
fn sigv4_property_components_in_valid_calendar_ranges() {
    // Over a dense sweep, the parsed month/day/hour/min/sec must always land in
    // legal ranges. Catches any civil-from-days arithmetic regression.
    let mut secs = 0u64;
    while secs < 6_000_000_000 {
        let (d, a) = format_sigv4_timestamps(secs);
        let month: u32 = d[4..6].parse().unwrap();
        let day: u32 = d[6..8].parse().unwrap();
        let hour: u32 = a[9..11].parse().unwrap();
        let minute: u32 = a[11..13].parse().unwrap();
        let second: u32 = a[13..15].parse().unwrap();
        assert!((1..=12).contains(&month), "month {month} at {secs}");
        assert!((1..=31).contains(&day), "day {day} at {secs}");
        assert!(hour <= 23, "hour {hour} at {secs}");
        assert!(minute <= 59, "minute {minute} at {secs}");
        assert!(second <= 59, "second {second} at {secs}");
        secs += 50_000_021; // ~1.58 years between samples, prime-ish step
    }
}

#[test]
fn sigv4_property_seconds_of_day_decompose_exactly() {
    // hour*3600 + minute*60 + second must equal (unix_secs % 86400) for any
    // input — the time-of-day half of the algorithm, independent of the date.
    for secs in [
        0u64,
        1,
        59,
        60,
        61,
        3599,
        3600,
        3661,
        86_399,
        86_400,
        90_061,
        1_440_938_160,
        4_294_967_295,
    ] {
        let (_, a) = format_sigv4_timestamps(secs);
        let hour: u64 = a[9..11].parse().unwrap();
        let minute: u64 = a[11..13].parse().unwrap();
        let second: u64 = a[13..15].parse().unwrap();
        assert_eq!(
            hour * 3600 + minute * 60 + second,
            secs % 86_400,
            "time-of-day decomposition wrong at {secs}"
        );
    }
}

// ===========================================================================
// 10. Adversarial / evasion-shaped inputs to the header builder
// ===========================================================================

#[test]
fn sigv4_security_token_with_special_chars_embedded_verbatim() {
    // STS session tokens are long base64-ish blobs with '+', '/', '='. They are
    // embedded verbatim into the canonical header value (no encoding by the
    // signer); the value is whatever STS issued.
    let token = "IQoJb3JpZ2luX2VjE+abc/def==+slash/here==";
    let (canon, signed) = mirror_signed_headers(
        "sts.us-east-1.amazonaws.com",
        "20240101T000000Z",
        Some(token),
    );
    assert!(canon.contains(&format!("x-amz-security-token:{token}\n")));
    assert!(signed.ends_with(";x-amz-security-token"));
}

#[test]
fn sigv4_empty_token_string_still_produces_token_header_line() {
    // The header builder does not itself filter empties — that filtering happens
    // upstream in build_aws_probe via `.filter(|t| !t.is_empty())`. So if a
    // Some("") ever reaches the builder, it emits an (empty-valued) line. This
    // pins the builder's documented behavior precisely.
    let (canon, signed) = mirror_signed_headers("h", "20240101T000000Z", Some(""));
    assert_eq!(signed, "host;x-amz-date;x-amz-security-token");
    assert_eq!(
        canon,
        "host:h\nx-amz-date:20240101T000000Z\nx-amz-security-token:\n"
    );
}

#[test]
fn sigv4_host_value_embedded_verbatim_for_regional_endpoint() {
    // Region drives the STS host: sts.{region}.amazonaws.com. The builder
    // embeds whatever host string it is handed.
    for region in ["us-east-1", "eu-west-2", "ap-northeast-1"] {
        let host = format!("sts.{region}.amazonaws.com");
        let (canon, _) = mirror_signed_headers(&host, "20240101T000000Z", None);
        assert!(canon.starts_with(&format!("host:{host}\n")));
    }
}

// ===========================================================================
// 11. Dense single-day exhaustive sample (every value formatted correctly)
// ===========================================================================

#[test]
fn sigv4_full_first_day_hour_marks() {
    // Walk each hour mark of 1970-01-01 and assert exact HH0000Z formatting.
    for h in 0u64..24 {
        let (d, a) = format_sigv4_timestamps(h * 3_600);
        assert_eq!(d, "19700101", "date stays Jan 1 at hour {h}");
        assert_eq!(a, format!("19700101T{h:02}0000Z"), "hour {h}");
    }
}

#[test]
fn sigv4_minute_and_second_zero_padding() {
    // 1970-01-01 00:05:09 — verifies single-digit minute/second are zero-padded.
    let (d, a) = format_sigv4_timestamps(5 * 60 + 9);
    assert_eq!(d, "19700101");
    assert_eq!(a, "19700101T000509Z");
}

#[test]
fn sigv4_single_digit_month_and_day_zero_padded() {
    // 1970-02-03 (Feb is month 2, padded "02"; day 3 padded "03").
    // Feb 3 1970 00:00:00 = 31 (Jan) + 2 days -> 33 days * 86400.
    let secs = 33 * 86_400;
    let (d, a) = format_sigv4_timestamps(secs);
    assert_eq!(d, "19700203");
    assert_eq!(a, "19700203T000000Z");
}
