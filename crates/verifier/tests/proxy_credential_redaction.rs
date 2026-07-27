use std::error::Error as _;

use keyhog_verifier::{VerificationEngine, VerifyConfig, VerifyError};

const FIX: &str = "Fix: use a valid http://, https://, or socks5:// URL, or set 'off' to disable proxying entirely";

fn proxy_error(raw: &str) -> VerifyError {
    match VerificationEngine::new(
        &[],
        VerifyConfig {
            proxy: Some(raw.to_owned()),
            ..VerifyConfig::default()
        },
    ) {
        Err(error) => error,
        Ok(_) => panic!("malformed proxy unexpectedly built a verifier client"),
    }
}

fn all_error_text(error: &VerifyError) -> Vec<String> {
    let mut rendered = vec![error.to_string(), format!("{error:?}")];
    let mut source = error.source();
    while let Some(error) = source {
        rendered.push(error.to_string());
        rendered.push(format!("{error:?}"));
        source = error.source();
    }
    rendered
}

fn assert_no_bytes(rendered: &[String], forbidden: &[&[u8]]) {
    for text in rendered {
        for needle in forbidden {
            assert!(
                !text
                    .as_bytes()
                    .windows(needle.len())
                    .any(|window| window == *needle),
                "error output contained forbidden bytes {needle:?}: {text:?}"
            );
        }
    }
}

fn assert_actionable(error: &VerifyError) {
    let display = error.to_string();
    assert!(display.contains("verifier proxy URL"), "{display:?}");
    assert!(display.contains(FIX), "{display:?}");
}

#[test]
fn malformed_userinfo_is_not_echoed() {
    let raw = "http://proxy-user:MALFORMED_USERINFO_SECRET@";
    let error = proxy_error(raw);
    let rendered = all_error_text(&error);

    // The missing host makes the URL invalid, but the complete userinfo remains secret.
    assert_no_bytes(
        &rendered,
        &[raw.as_bytes(), b"proxy-user", b"MALFORMED_USERINFO_SECRET"],
    );
    assert_actionable(&error);
}

#[test]
fn percent_encoded_password_is_not_echoed_raw_or_decoded() {
    let raw = "http://proxy-user:PERCENT%2DENCODED%2DSECRET@";
    let error = proxy_error(raw);
    let rendered = all_error_text(&error);

    // Consumers may percent-decode an error later, so neither representation is safe.
    assert_no_bytes(
        &rendered,
        &[
            raw.as_bytes(),
            b"PERCENT%2DENCODED%2DSECRET",
            b"PERCENT-ENCODED-SECRET",
        ],
    );
    assert_actionable(&error);
}

#[test]
fn query_token_is_not_echoed() {
    let raw = "http://?access_token=QUERY_TOKEN_SECRET";
    let error = proxy_error(raw);
    let rendered = all_error_text(&error);

    // Query parameters frequently carry bearer material and are never diagnostic context.
    assert_no_bytes(
        &rendered,
        &[raw.as_bytes(), b"access_token", b"QUERY_TOKEN_SECRET"],
    );
    assert_actionable(&error);
}

#[test]
fn invalid_host_with_control_is_not_echoed() {
    let raw = "http://proxy-user:CONTROL_SECRET@bad\0host.example";
    let error = proxy_error(raw);
    let rendered = all_error_text(&error);

    // An unparseable host is attacker-controlled input, including its adjacent credentials.
    assert_no_bytes(
        &rendered,
        &[
            raw.as_bytes(),
            b"proxy-user",
            b"CONTROL_SECRET",
            b"bad\0host",
        ],
    );
    assert_actionable(&error);
}

#[test]
fn trustworthy_parse_reports_only_scheme_and_host() {
    let raw = "ftp://proxy-user:PARSED_SECRET@proxy.example?access_token=PARSED_QUERY_SECRET";
    let error = proxy_error(raw);
    let rendered = all_error_text(&error);
    let display = error.to_string();

    // A successfully parsed endpoint is useful, but userinfo and query stay confidential.
    assert!(display.contains("scheme `ftp`"), "{display:?}");
    assert!(display.contains("host `proxy.example`"), "{display:?}");
    assert_no_bytes(
        &rendered,
        &[
            raw.as_bytes(),
            b"proxy-user",
            b"PARSED_SECRET",
            b"access_token",
            b"PARSED_QUERY_SECRET",
        ],
    );
    assert_actionable(&error);
}

#[test]
fn valid_authenticated_proxy_still_builds() {
    let result = VerificationEngine::new(
        &[],
        VerifyConfig {
            proxy: Some("http://proxy-user:VALID_AUTH_SECRET@127.0.0.1:65535".to_owned()),
            ..VerifyConfig::default()
        },
    );

    // Construction must preserve reqwest's authenticated-proxy support without making a request.
    assert!(result.is_ok(), "valid authenticated proxy was rejected");
}

#[test]
fn display_debug_and_source_chain_are_all_redacted() {
    let raw = "http://chain-user:SOURCE_CHAIN_SECRET@";
    let error = proxy_error(raw);
    let rendered = all_error_text(&error);

    // Logging libraries may choose Display, Debug, or walk Error::source recursively.
    assert_no_bytes(
        &rendered,
        &[raw.as_bytes(), b"chain-user", b"SOURCE_CHAIN_SECRET"],
    );
    assert_eq!(error.source().map(ToString::to_string), None);
    assert_actionable(&error);
}

#[test]
fn malformed_input_without_safe_endpoint_has_exact_generic_diagnostic() {
    let error = proxy_error("http://exact-user:EXACT_NEGATIVE_SECRET@");
    let rendered = all_error_text(&error);

    // Exact generic wording prevents a future refactor from appending the raw URL or parser cause.
    assert_eq!(
        error.to_string(),
        format!("invalid verifier proxy configuration: invalid verifier proxy URL. {FIX}")
    );
    assert_no_bytes(
        &rendered,
        &[
            b"exact-user",
            b"EXACT_NEGATIVE_SECRET",
            b"invalid domain character",
        ],
    );
}
