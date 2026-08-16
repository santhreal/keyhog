use std::collections::HashMap;

use keyhog_profile::{
    lookup_profile_name, resolve_profile_from_env, resolve_profile_from_env_value,
    resolve_profile_from_env_var, Detail, KnownProfile, ProfileConfig, ProfileName,
    PROFILE_ENV_VARS,
};
use zeroize::{Zeroize, Zeroizing};

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
fn profile_name_borrow_and_map_lookup() {
    let mut map = HashMap::new();
    let dev_profile = ProfileName::from(KnownProfile::Dev);
    let custom_profile = ProfileName::from("custom-lane");

    map.insert(dev_profile.clone(), 100);
    map.insert(custom_profile.clone(), 200);

    // Borrow<str> lookup matches plain text
    assert_eq!(map.get("dev"), Some(&100));
    assert_eq!(map.get("custom-lane"), Some(&200));
    assert_eq!(map.get("nonexistent"), None);
}

#[test]
fn profile_name_whitespace_trimming() {
    let a = ProfileName::from("  my-profile  ".to_string());
    let b = ProfileName::from("my-profile".to_string());
    let c = ProfileName::parse("   my-profile \t");

    assert_eq!(a, b);
    assert_eq!(b, c);
    assert_eq!(a.as_str(), "my-profile");

    let known_padded = ProfileName::from("   ci  ".to_string());
    assert_eq!(known_padded.as_known(), Some(KnownProfile::Ci));
    assert_eq!(known_padded.as_str(), "ci");
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
    assert_eq!(known_lookup, "release");

    let custom_lookup = lookup_profile_name("custom-scan");
    assert_eq!(custom_lookup, "custom-scan");
}

#[test]
fn resolve_profile_from_env_value_handles_known_and_custom() {
    let resolved_ci = resolve_profile_from_env_value("ci");
    assert_eq!(resolved_ci.as_known(), Some(KnownProfile::Ci));

    let resolved_custom = resolve_profile_from_env_value("custom-profile");
    assert_eq!(resolved_custom.as_str(), "custom-profile");
}

struct EnvGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            if let Some(val) = v {
                std::env::set_var(k, val);
            } else {
                std::env::remove_var(k);
            }
        }
    }
}

#[test]
fn resolve_profile_from_env_vars_honors_precedence() {
    let _guard = EnvGuard {
        saved: PROFILE_ENV_VARS
            .iter()
            .map(|&var| (var, std::env::var_os(var)))
            .collect(),
    };

    for &var in PROFILE_ENV_VARS {
        std::env::remove_var(var);
    }

    std::env::set_var("KEYHOG_ENV", "staging");
    std::env::set_var("KEYHOG_PROFILE_NAME", "dev");
    std::env::set_var("KEYHOG_PROFILE", "ci");

    // Precedence 1: KEYHOG_PROFILE
    let resolved = resolve_profile_from_env();
    assert_eq!(
        resolved.as_ref().and_then(|r| r.as_known()),
        Some(KnownProfile::Ci)
    );

    // Precedence 2: KEYHOG_PROFILE_NAME
    std::env::remove_var("KEYHOG_PROFILE");
    let resolved = resolve_profile_from_env();
    assert_eq!(
        resolved.as_ref().and_then(|r| r.as_known()),
        Some(KnownProfile::Dev)
    );

    // Precedence 3: KEYHOG_ENV
    std::env::remove_var("KEYHOG_PROFILE_NAME");
    let resolved = resolve_profile_from_env();
    assert_eq!(
        resolved.as_ref().and_then(|r| r.as_known()),
        Some(KnownProfile::Staging)
    );

    std::env::remove_var("KEYHOG_ENV");
    assert_eq!(resolve_profile_from_env(), None);

    // Single var lookup and unset check
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
}

#[test]
fn profile_config_zeroization_clears_sensitive_fields() {
    let mut config = ProfileConfig::new(KnownProfile::Production);
    config.auth_token = Some(Zeroizing::new("secret-token".to_string()));
    config.api_key = Some(Zeroizing::new("secret-api-key".to_string()));
    config.secret_key = Some(Zeroizing::new("secret-signing-key".to_string()));
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        Zeroizing::new("secret-auth-header".to_string()),
    );
    config.headers = headers;

    Zeroize::zeroize(&mut config);

    assert_eq!(config.auth_token, None);
    assert_eq!(config.api_key, None);
    assert_eq!(config.secret_key, None);
    assert!(config.headers.is_empty());
}

#[test]
fn session_start_with_config_applies_settings() {
    // 1. Raising detail to Diagnostic
    let mut config = ProfileConfig::new(KnownProfile::Dev);
    config.detail = Detail::Diagnostic;
    let identity = keyhog_profile::RunIdentity::new(
        "0.5.76",
        "test-detectors",
        "test-config",
        "test-source",
        "test-workload",
        "test-backend",
    );
    let session = keyhog_profile::Session::start_with_config(&config, identity)
        .expect("start session with config")
        .expect("session is enabled");
    assert_eq!(keyhog_profile::detail(), Detail::Diagnostic);
    let profile = session.finish(keyhog_profile::RunState::Completed);
    assert_eq!(profile.status, keyhog_profile::RunState::Completed);

    // 2. Lowering detail to Off via start_with_config
    config.detail = Detail::Off;
    let identity2 = keyhog_profile::RunIdentity::new(
        "0.5.76",
        "test-detectors",
        "test-config",
        "test-source",
        "test-workload",
        "test-backend",
    );
    let session2 = keyhog_profile::Session::start_with_config(&config, identity2)
        .expect("start session with config")
        .expect("session is enabled");
    assert_eq!(keyhog_profile::detail(), Detail::Off);
    let profile2 = session2.finish(keyhog_profile::RunState::Completed);
    assert_eq!(profile2.status, keyhog_profile::RunState::Completed);

    // 3. Disabled config returns Ok(None) without starting a session
    config.enabled = false;
    let disabled_identity = keyhog_profile::RunIdentity::new(
        "0.5.76",
        "test-detectors",
        "test-config",
        "test-source",
        "test-workload",
        "test-backend",
    );
    let disabled_session = keyhog_profile::Session::start_with_config(&config, disabled_identity)
        .expect("start disabled session");
    assert!(disabled_session.is_none());
}
#[test]
fn profile_config_debug_formatting_redacts_secrets() {
    let mut config = ProfileConfig::new(KnownProfile::Production);
    config.auth_token = Some(Zeroizing::new("bearer-secret-token".to_string()));
    config.api_key = Some(Zeroizing::new("api-secret-key".to_string()));
    config.secret_key = Some(Zeroizing::new("signing-secret-key".to_string()));
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        Zeroizing::new("Bearer secret-header".to_string()),
    );
    config.headers = headers;

    let debug_output = format!("{config:?}");
    assert!(!debug_output.contains("bearer-secret-token"));
    assert!(!debug_output.contains("api-secret-key"));
    assert!(!debug_output.contains("signing-secret-key"));
    assert!(!debug_output.contains("secret-header"));
    assert!(debug_output.contains("[REDACTED]"));
}
#[test]
fn profile_config_serialization_never_leaks_secrets() {
    let mut config = ProfileConfig::new(KnownProfile::Production);
    config.auth_token = Some(Zeroizing::new("bearer-secret-token".to_string()));
    config.api_key = Some(Zeroizing::new("api-secret-key".to_string()));
    config.secret_key = Some(Zeroizing::new("signing-secret-key".to_string()));
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        Zeroizing::new("Bearer secret-header".to_string()),
    );
    config.headers = headers;

    let serialized = serde_json::to_string(&config).expect("serialize profile config");
    assert!(!serialized.contains("bearer-secret-token"));
    assert!(!serialized.contains("api-secret-key"));
    assert!(!serialized.contains("signing-secret-key"));
    assert!(!serialized.contains("secret-header"));
    assert!(!serialized.contains("auth_token"));
    assert!(!serialized.contains("api_key"));
    assert!(!serialized.contains("secret_key"));
    assert!(!serialized.contains("headers"));
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
