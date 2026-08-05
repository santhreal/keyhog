use super::redact_url;
use std::borrow::Cow;

#[test]
fn no_scheme_returns_input_borrowed() {
    let got = redact_url("user:pass@host/path");
    assert_eq!(got, "user:pass@host/path");
    assert!(matches!(got, Cow::Borrowed(_)));
}

#[test]
fn scheme_without_userinfo_is_borrowed_unchanged() {
    let got = redact_url("https://host:5432/db");
    assert_eq!(got, "https://host:5432/db");
    assert!(matches!(got, Cow::Borrowed(_)));
}

#[test]
fn basic_userinfo_is_redacted() {
    assert_eq!(redact_url("https://u:p@host/path"), "https://***@host/path");
}

#[test]
fn port_and_path_survive_redaction() {
    assert_eq!(
        redact_url("postgres://user:pass@db:5432/x"),
        "postgres://***@db:5432/x"
    );
}

#[test]
fn at_inside_password_uses_last_at_not_first() {
    // rfind, not find: the whole userinfo (including the literal `@`) is
    // redacted; splitting on the first `@` would leak `ss`.
    assert_eq!(redact_url("https://u:pa@ss@host/"), "https://***@host/");
}

#[test]
fn at_only_in_query_is_not_treated_as_userinfo() {
    let got = redact_url("https://host/p?email=a@b.com");
    assert_eq!(got, "https://host/p?email=a@b.com");
    assert!(matches!(got, Cow::Borrowed(_)));
}

#[test]
fn userinfo_without_password_is_redacted() {
    assert_eq!(redact_url("https://token@host/"), "https://***@host/");
}

#[test]
fn presigned_s3_signature_and_credential_are_masked() {
    assert_eq!(
        redact_url(
            "https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Credential=AKIAEXAMPLE%2Fus-east-1&X-Amz-Signature=deadbeefcafe\
                 &X-Amz-Expires=900"
        ),
        "https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=***&X-Amz-Signature=***&X-Amz-Expires=900"
    );
}

#[test]
fn access_token_query_is_masked() {
    assert_eq!(
        redact_url("https://host/cb?token=s3cr3tvalue&state=xyz"),
        "https://host/cb?token=***&state=xyz"
    );
}

#[test]
fn azure_sas_sig_is_masked() {
    assert_eq!(
        redact_url("https://acct.blob.core.windows.net/c/b?sv=2021&sig=AbC%2Bdef&se=2030"),
        "https://acct.blob.core.windows.net/c/b?sv=2021&sig=***&se=2030"
    );
}

#[test]
fn userinfo_and_query_secret_are_both_masked() {
    assert_eq!(
        redact_url("https://u:p@host/x?sig=abc"),
        "https://***@host/x?sig=***"
    );
}

#[test]
fn fragment_after_masked_query_is_preserved() {
    assert_eq!(
        redact_url("https://host/x?token=abc#section"),
        "https://host/x?token=***#section"
    );
}

#[test]
fn benign_query_only_stays_borrowed() {
    let got = redact_url("https://host/x?page=2&sort=name");
    assert_eq!(got, "https://host/x?page=2&sort=name");
    assert!(matches!(got, Cow::Borrowed(_)));
}

#[test]
fn sensitive_key_matching_is_case_insensitive() {
    assert_eq!(
        redact_url("https://host/x?ACCESS_TOKEN=abc"),
        "https://host/x?ACCESS_TOKEN=***"
    );
}

#[test]
fn valueless_sensitive_key_is_left_alone() {
    let got = redact_url("https://host/x?token");
    assert_eq!(got, "https://host/x?token");
    assert!(matches!(got, Cow::Borrowed(_)));
}

/// `reqwest::Error`'s `Display` re-appends the request URL, so a call site that
/// prints `redact_url(url)` beside `{error}` republishes the very credential it
/// just masked. `redact_http_error` is the boundary that stops that: it must
/// keep the error text and the host (the diagnostic is useless without them)
/// while masking sensitive query values.
///
/// Measured, not assumed: reqwest lifts `user:password@` userinfo out of the
/// URL into an `Authorization` header before recording the URL on the error, so
/// the userinfo half never reaches `Display`. The QUERY half does, which is the
/// half that carries an Azure SAS `sig=`, an `?access_token=`, and an
/// `X-Amz-Signature`. The precondition assertion below fails loudly if a future
/// reqwest stops leaking it, at which point this helper can be retired.
#[cfg(any(
    feature = "azure",
    feature = "s3",
    feature = "gcs",
    feature = "slack",
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket"
))]
#[test]
fn http_error_display_no_longer_carries_query_credentials() {
    // Port 1 on loopback refuses immediately, so this is a deterministic
    // transport error that reqwest tags with the request URL.
    let url = "http://127.0.0.1:1/list?comp=list&sig=AbCdSecretSignature";
    let error = reqwest::blocking::Client::new()
        .get(url)
        .send()
        .expect_err("connecting to 127.0.0.1:1 must fail");
    assert!(
        error.to_string().contains("AbCdSecretSignature"),
        "precondition: reqwest's own Display leaks the SAS signature; got {error}"
    );

    let redacted = super::redact_http_error(error);
    assert!(
        !redacted.contains("AbCdSecretSignature"),
        "query credential leaked: {redacted}"
    );
    assert!(
        redacted.contains("for url (http://127.0.0.1:1/list?comp=list&sig=***)"),
        "the masked URL must still name the target and its benign params: {redacted}"
    );
    assert!(
        redacted.starts_with("error sending request"),
        "the reqwest error text must survive: {redacted}"
    );
}
