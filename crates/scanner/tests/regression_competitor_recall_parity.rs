//! Competitor corpus recall parity regression tests (Row 161).
//! Locks recall and precision for competitor corpus secret types:
//! - `sidekiq-secret`
//! - `jumpcloud-api-key`
//! - `disqus-api-key`
//! - `configcat-sdk-key`
//! - `curl-auth-user`
//! - `datadog-application-key`
//! - `bitly-access-token`
//! - `aws-bedrock-api-key` (unanchored long-lived ABSK shape)
//! - `anthropic-admin-api-key`
//! - `airtable-api-key`

mod support;
use support::vendorgen::{alnum, hex, scan_ids, surfaces_under};

#[test]
fn test_sidekiq_secret_surfaces() {
    let text = "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef";
    assert!(
        surfaces_under(text, "sidekiq-secret", "cafebabe:deadbeef"),
        "Sidekiq enterprise bundle license token must surface"
    );
    let text_url = "https://cafebabe:deadbeef@gems.contribsys.com/";
    assert!(
        surfaces_under(text_url, "sidekiq-secret", "cafebabe:deadbeef"),
        "Sidekiq gem URL credential must surface"
    );
}

#[test]
fn test_jumpcloud_api_key_surfaces() {
    let key = format!("1a2b3c4d5e6f7g8h9i0j{}", alnum(20, 1));
    let text = format!("jumpcloud_api_key = \"{key}\"");
    assert!(
        surfaces_under(&text, "jumpcloud-api-key", &key),
        "JumpCloud 40-char API key must surface"
    );
}

#[test]
fn test_disqus_api_key_surfaces() {
    let key = alnum(64, 2);
    let text = format!("disqus_secret_key = \"{key}\"");
    assert!(
        surfaces_under(&text, "disqus-api-key", &key),
        "Disqus 64-char API key must surface"
    );
}

#[test]
fn test_configcat_sdk_key_surfaces() {
    let k1 = alnum(22, 3);
    let k2 = alnum(22, 4);
    let text = format!("CONFIGCAT_SDK_KEY=\"{k1}/{k2}\"");
    assert!(
        surfaces_under(&text, "configcat-sdk-key", &format!("{k1}/{k2}")),
        "ConfigCat standard SDK key must surface"
    );
    let text_ext = format!("configcat-sdk-1/{k1}/{k2}");
    assert!(
        surfaces_under(&text_ext, "configcat-sdk-key", &text_ext),
        "ConfigCat extended SDK key must surface"
    );
}

#[test]
fn test_datadog_application_key_variants_surface() {
    let app_key = "abcDEF0123456789abcDEF0123456789abcDEF01";
    let text = format!("DATADOG_APPLICATION_KEY={app_key}");
    assert!(
        surfaces_under(&text, "datadog-application-key", app_key),
        "Datadog application key with DATADOG_APPLICATION_KEY anchor must surface"
    );
}

#[test]
fn test_bitly_access_token_surfaces() {
    let token = hex(40, 5);
    let text = format!("bitly_token = \"{token}\"");
    assert!(
        surfaces_under(&text, "bitly-access-token", &token),
        "Bitly 40-hex access token must surface"
    );
}

#[test]
fn test_airtable_legacy_and_pat_keys_surface() {
    let legacy = format!("key{}", alnum(14, 6));
    let text_leg = format!("airtable_api_key = \"{legacy}\"");
    assert!(
        surfaces_under(&text_leg, "airtable-api-key", &legacy),
        "Airtable legacy API key must surface"
    );
    let pat = format!("pat{}.{}", alnum(14, 7), hex(64, 8));
    let text_pat = format!("AIRTABLE_API_KEY={pat}");
    assert!(
        surfaces_under(&text_pat, "airtable-api-key", &pat),
        "Airtable PAT must surface"
    );
}

#[test]
fn test_anthropic_admin_and_standard_keys() {
    let admin_key = format!("sk-ant-admin01-{}AA", alnum(93, 9));
    let ids = scan_ids(&admin_key);
    println!("Anthropic admin key ids: {ids:?}");
    assert!(
        surfaces_under(&admin_key, "anthropic-admin-api-key", &admin_key),
        "Anthropic admin key must surface under anthropic-admin-api-key"
    );
}

#[test]
fn test_aws_bedrock_long_lived_unanchored_key_surfaces() {
    // Long-lived ABSK keys without the `QmVkcm9ja0FQSUtleS` header are the
    // second pattern on `aws-bedrock-api-key`, not a separate detector: an
    // anchored key matches both shapes, so two detectors would race for the
    // reported id on an alphabetical tiebreak.
    let key = format!("ABSK{}", alnum(124, 11));
    let text = format!("BEDROCK_KEY={key}");
    assert!(
        surfaces_under(&text, "aws-bedrock-api-key", &key),
        "AWS Bedrock long-lived API key must surface"
    );
}

#[test]
fn test_curl_auth_user_surfaces() {
    let text = "curl -sw '%{http_code}' -X POST --user 'johns:h0pk1ns~21s' $GItHUB_API_URL/$GIT_COMMIT --data";
    assert!(
        surfaces_under(text, "curl-auth-user", "johns:h0pk1ns~21s"),
        "curl auth user credentials must surface"
    );
    let text_double =
        "curl -s -v --user \"j.smith:dB2yF6@qL9vZm1P#4J\" \"https://api.contoso.org/user/me\"";
    assert!(
        surfaces_under(text_double, "curl-auth-user", "j.smith:dB2yF6@qL9vZm1P#4J"),
        "curl auth user double quotes must surface"
    );
}
