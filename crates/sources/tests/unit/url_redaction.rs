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
