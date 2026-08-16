use std::borrow::Cow;
use std::collections::HashMap;

use keyhog_profile::{
    constant_time_bytes_eq, lookup_profile_name, resolve_profile_from_env,
    resolve_profile_from_env_value, resolve_profile_from_env_var, Detail, KnownProfile,
    ProfileConfig, ProfileName, SensitiveString, PROFILE_ENV_VARS,
};
use zeroize::Zeroize;

#[test]
fn sensitive_string_redacts_display_and_debug() {
    let secret = SensitiveString::from("super-secret-token-12345");
    assert_eq!(format!("{secret}"), "<redacted 24 bytes>");
    assert_eq!(
        format!("{secret:?}"),
        "SensitiveString(<redacted 24 bytes>)"
    );
    assert_eq!(secret.as_str(), "super-secret-token-12345");
    assert_eq!(secret.len(), 24);
    assert!(!secret.is_empty());
}

#[test]
fn sensitive_string_empty_state() {
    let empty = SensitiveString::default();
    assert_eq!(format!("{empty}"), "<redacted 0 bytes>");
    assert_eq!(empty.as_str(), "");
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}

#[test]
fn sensitive_string_constant_time_equality() {
    let a = SensitiveString::from("token-abc");
    let b = SensitiveString::from("token-abc");
    let c = SensitiveString::from("token-xyz");
    let d = SensitiveString::from("token-abcdef");

    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d);

    assert!(constant_time_bytes_eq(b"hello", b"hello"));
    assert!(!constant_time_bytes_eq(b"hello", b"world"));
    assert!(!constant_time_bytes_eq(b"hello", b"hell"));
}

#[test]
fn sensitive_string_refuses_implicit_serialization() {
    let secret = SensitiveString::from("secret-api-key");
    let result = serde_json::to_string(&secret);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("refuses implicit plaintext serialization"));
}

#[test]
fn sensitive_string_deserialization_from_json() {
    let json = r#""deserialized-secret-token""#;
    let secret: SensitiveString = serde_json::from_str(json).expect("deserialize sensitive string");
    assert_eq!(secret.as_str(), "deserialized-secret-token");
}

#[test]
fn sensitive_string_zeroizes_explicitly() {
    let mut secret = SensitiveString::from("temporary-secret-value");
    assert_eq!(secret.as_str(), "temporary-secret-value");
    secret.zeroize();
    assert_eq!(secret.as_str(), "");
}

#[test]
fn known_profiles_case_insensitive_matching() {
    let cases = [
        ("default", KnownProfile::Default, "default"),
        ("DEFAULT", KnownProfile::Default, "default"),
        ("ci", KnownProfile::Ci, "ci"),
        ("CI", KnownProfile::Ci, "ci"),
        ("release", KnownProfile::Release, "release"),
        ("RELEASE", KnownProfile::Release, "release"),
        ("release-fast", KnownProfile::ReleaseFast, "release-fast"),
        ("release_fast", KnownProfile::ReleaseFast, "release-fast"),
        ("debug", KnownProfile::Debug, "debug"),
        ("dev", KnownProfile::Dev, "dev"),
        ("development", KnownProfile::Dev, "dev"),
        ("bench", KnownProfile::Bench, "bench"),
        ("benchmark", KnownProfile::Bench, "bench"),
        ("portable", KnownProfile::Portable, "portable"),
        ("deep", KnownProfile::Deep, "deep"),
        ("precision", KnownProfile::Precision, "precision"),
        ("test", KnownProfile::Test, "test"),
        ("staging", KnownProfile::Staging, "staging"),
        ("prod", KnownProfile::Production, "production"),
        ("production", KnownProfile::Production, "production"),
    ];

    for (input, expected, canonical) in cases {
        let parsed = KnownProfile::from_str_case_insensitive(input);
        assert_eq!(parsed, Some(expected), "input: {input}");
        assert_eq!(expected.as_str(), canonical);
    }

    assert_eq!(
        KnownProfile::from_str_case_insensitive("nonexistent-profile"),
        None
    );
}

#[test]
fn profile_name_parse_avoids_allocation_for_known_profiles() {
    let default_name = ProfileName::parse("default");
    assert!(default_name.is_known());
    assert_eq!(default_name.as_known(), Some(KnownProfile::Default));
    assert_eq!(default_name.as_str(), "default");

    let ci_name = ProfileName::parse("CI");
    assert!(ci_name.is_known());
    assert_eq!(ci_name.as_known(), Some(KnownProfile::Ci));
    assert_eq!(ci_name.as_str(), "ci");

    let custom_name = ProfileName::parse("my-custom-team-profile");
    assert!(!custom_name.is_known());
    assert_eq!(custom_name.as_known(), None);
    assert_eq!(custom_name.as_str(), "my-custom-team-profile");
}

#[test]
fn profile_name_from_static_borrows() {
    let custom_static = ProfileName::from_static("static-custom");
    assert!(!custom_static.is_known());
    assert_eq!(custom_static.as_str(), "static-custom");

    let known_static = ProfileName::from_static("release");
    assert!(known_static.is_known());
    assert_eq!(known_static.as_known(), Some(KnownProfile::Release));
}

#[test]
fn lookup_profile_name_returns_borrowed_slices() {
    let known_lookup = lookup_profile_name("RELEASE");
    assert!(matches!(known_lookup, Cow::Borrowed("release")));

    let custom_lookup = lookup_profile_name("custom-scan");
    assert!(matches!(custom_lookup, Cow::Borrowed("custom-scan")));
}

#[test]
fn resolve_profile_from_env_value_handles_known_and_custom() {
    let resolved_ci = resolve_profile_from_env_value("ci");
    assert_eq!(resolved_ci.as_known(), Some(KnownProfile::Ci));

    let resolved_custom = resolve_profile_from_env_value("custom-profile");
    assert_eq!(resolved_custom.as_str(), "custom-profile");
}

#[test]
fn resolve_profile_from_env_vars_honors_precedence() {
    let var_name = "KEYHOG_PROFILE_TEST_VAR_CONFIG";
    std::env::set_var(var_name, "release-fast");
    let resolved = resolve_profile_from_env_var(var_name);
    assert_eq!(
        resolved.and_then(|r| r.as_known()),
        Some(KnownProfile::ReleaseFast)
    );
    std::env::remove_var(var_name);

    assert_eq!(resolve_profile_from_env_var("UNSET_KEYHOG_VAR_12345"), None);
}

#[test]
fn profile_config_default_initialization() {
    let config = ProfileConfig::default();
    assert_eq!(config.name.as_str(), "default");
    assert!(config.enabled);
    assert_eq!(config.detail, Detail::Off);
    assert_eq!(config.endpoint, None);
    assert_eq!(config.auth_token, None);
    assert_eq!(config.api_key, None);
    assert_eq!(config.secret_key, None);
    assert_eq!(config.environment, None);
    assert_eq!(config.sample_rate, 1.0);
    assert_eq!(config.max_events, 10_000);
    assert!(config.tags.is_empty());
    assert!(config.headers.is_empty());
}

#[test]
fn profile_config_json_deserialization_with_sensitive_fields() {
    let json = r#"{
        "name": "production",
        "enabled": true,
        "detail": "off",
        "endpoint": "https://telemetry.example.internal/v1/profile",
        "auth_token": "bearer-token-xyz",
        "api_key": "kh-api-key-999",
        "secret_key": "kh-secret-sig-key",
        "environment": "production-eu",
        "sample_rate": 0.25,
        "max_events": 50000,
        "tags": {
            "service": "scanner",
            "cluster": "eu-central"
        },
        "headers": {
            "Authorization": "Bearer internal-auth",
            "X-Custom-Secret": "header-secret"
        }
    }"#;

    let config = ProfileConfig::parse_json(json).expect("parse profile config");
    assert_eq!(config.name.as_known(), Some(KnownProfile::Production));
    assert!(config.enabled);
    assert_eq!(
        config.endpoint.as_deref(),
        Some("https://telemetry.example.internal/v1/profile")
    );
    assert_eq!(
        config.auth_token.as_ref().map(|s| s.as_str()),
        Some("bearer-token-xyz")
    );
    assert_eq!(
        config.api_key.as_ref().map(|s| s.as_str()),
        Some("kh-api-key-999")
    );
    assert_eq!(
        config.secret_key.as_ref().map(|s| s.as_str()),
        Some("kh-secret-sig-key")
    );
    assert_eq!(config.environment.as_deref(), Some("production-eu"));
    assert_eq!(config.sample_rate, 0.25);
    assert_eq!(config.max_events, 50_000);
    assert_eq!(
        config.tags.get("service").map(|s| s.as_str()),
        Some("scanner")
    );
    assert_eq!(
        config.headers.get("Authorization").map(|s| s.as_str()),
        Some("Bearer internal-auth")
    );

    // Verify debug/display formatting does not reveal token plaintext
    let formatted = format!("{config:?}");
    assert!(!formatted.contains("bearer-token-xyz"));
    assert!(!formatted.contains("kh-api-key-999"));
    assert!(!formatted.contains("kh-secret-sig-key"));
    assert!(!formatted.contains("Bearer internal-auth"));
    assert!(!formatted.contains("header-secret"));
}

#[test]
fn profile_config_zeroization_clears_sensitive_fields() {
    let mut config = ProfileConfig::new(KnownProfile::Production);
    config.auth_token = Some(SensitiveString::from("secret-token"));
    config.api_key = Some(SensitiveString::from("secret-api-key"));
    config.secret_key = Some(SensitiveString::from("secret-signing-key"));
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        SensitiveString::from("secret-auth-header"),
    );
    config.headers = headers;

    config.zeroize();

    assert_eq!(config.auth_token.as_ref().map(|s| s.as_str()), Some(""));
    assert_eq!(config.api_key.as_ref().map(|s| s.as_str()), Some(""));
    assert_eq!(config.secret_key.as_ref().map(|s| s.as_str()), Some(""));
    assert_eq!(
        config.headers.get("Authorization").map(|s| s.as_str()),
        Some("")
    );
}

#[test]
fn profile_config_deserialization_failure_rejects_malformed_json() {
    let malformed_json = r#"{
        "name": "ci",
        "auth_token": "secret-token-in-transit",
        "sample_rate": "not-a-float"
    }"#;

    let result = ProfileConfig::parse_json(malformed_json);
    assert!(result.is_err());
}

#[test]
fn profile_config_rejects_unknown_fields() {
    let json_with_unknown = r#"{
        "name": "ci",
        "unknown_extra_field": "unexpected"
    }"#;

    let result = ProfileConfig::parse_json(json_with_unknown);
    assert!(result.is_err());
}
