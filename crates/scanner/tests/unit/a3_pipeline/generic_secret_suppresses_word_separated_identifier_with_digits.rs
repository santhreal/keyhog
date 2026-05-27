use keyhog_scanner::context::CodeContext;
use keyhog_scanner::pipeline::should_suppress_named_detector_finding;

#[test]
fn snake_case_identifier_with_digits_suppressed() {
    // Dogfood: alist internal/conf/const.go:113 has
    //   `S3SecretAccessKey = "s3_secret_access_key"`
    // The generic-secret fallback captured `s3_secret_access_key`
    // (20 chars, 3 underscores, digit `3`) which slipped past
    // `looks_like_pure_identifier` (rejects on `has_digit`).
    // v0.5.22 wires `looks_like_word_separated_identifier`, which
    // permits digits but enforces max-word-length ≤ 10.
    assert!(should_suppress_named_detector_finding(
        "s3_secret_access_key",
        Some("alist/internal/conf/const.go"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // openssl apps/ts.c:683 — `token = d2i_PKCS7_bio(in_bio, NULL)`
    assert!(should_suppress_named_detector_finding(
        "d2i_PKCS7_bio",
        Some("openssl/apps/ts.c"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // sqlite ext/fts5/fts5_test_tok.c — `sqlite3_malloc64`
    assert!(should_suppress_named_detector_finding(
        "sqlite3_malloc64",
        Some("sqlite/ext/fts5/fts5_test_tok.c"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // curl lib/vauth/ntlm_sspi.c:204 — `input_token = curlx_memdup0(...)`
    assert!(should_suppress_named_detector_finding(
        "curlx_memdup0",
        Some("curl/lib/vauth/ntlm_sspi.c"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
}
