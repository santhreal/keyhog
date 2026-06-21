use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::named_detector_suppressed;

#[test]
fn single_underscore_c_function_name_suppressed_for_generic_password() {
    // Dogfood: curl/lib/netrc.c:280 has `ns->password = curlx_strdup(tok);`
    // and generic-password captures `curlx_strdup` (single-underscore,
    // 12 alpha chars, no digit - a C function name). The earlier
    // looks_like_pure_identifier required ≥ 2 underscores so this
    // slipped; bumped the alpha-cluster path to ≤ 1 separator
    // (underscore or hyphen).
    assert!(named_detector_suppressed(
        "curlx_strdup",
        Some("curl/lib/netrc.c"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
}
