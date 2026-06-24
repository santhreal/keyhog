//! Regression: the `service -> env var` auto-fix map is Tier-B DATA loaded from
//! `data/service-env-vars.toml`, NOT a hardcoded `match` in `auto_fix.rs`.
//!
//! Goes red if:
//!   * the embedded data file stops parsing (or is deleted / emptied),
//!   * the curated count drifts from the data file (a stale hardcoded table
//!     re-creeps in, or someone edits one without the other),
//!   * a data row is unreachable from shipped detector service names,
//!   * a known curated service stops mapping to its conventional env var,
//!   * the screaming-snake fallback for an unknown service regresses.

use std::collections::BTreeSet;

/// The exact embedded Tier-B data the binary compiles in. Parsing it here in the
/// test is the count oracle: the data file and the runtime behavior must agree.
const EMBEDDED_DATA: &str = include_str!("../data/service-env-vars.toml");

#[derive(serde::Deserialize)]
struct Entry {
    #[serde(rename = "match")]
    needle: String,
    env: String,
    #[serde(default)]
    prefix: bool,
}

#[derive(serde::Deserialize)]
struct File {
    #[serde(default)]
    service: Vec<Entry>,
}

fn parse_embedded() -> Vec<Entry> {
    toml::from_str::<File>(EMBEDDED_DATA)
        .expect("embedded data/service-env-vars.toml must parse")
        .service
}

#[test]
fn embedded_data_parses_and_is_nonempty_with_expected_count() {
    let entries = parse_embedded();
    // Exact count pin: 17 curated provider entries. Bump this deliberately when
    // adding/removing a reachable provider; a silent drift means the data file
    // and the shipped map diverged.
    assert_eq!(
        entries.len(),
        17,
        "service-env-vars.toml curated entry count drifted; update this pin only \
         when intentionally adding/removing a provider"
    );
    // Every entry must have a non-empty needle and a SCREAMING_SNAKE env name.
    for e in &entries {
        assert!(!e.needle.is_empty(), "empty match needle in service map");
        assert!(!e.env.is_empty(), "empty env name in service map");
        assert!(
            e.env
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
            "env name '{}' is not SCREAMING_SNAKE",
            e.env
        );
    }
}

#[test]
fn every_data_entry_is_reachable_from_embedded_detector_services() {
    let detector_services = keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded detectors parse")
        .into_iter()
        .map(|detector| detector.service)
        .collect::<BTreeSet<_>>();
    let entries = parse_embedded();
    let unreachable = entries
        .iter()
        .filter(|entry| {
            !detector_services
                .iter()
                .any(|service| service_entry_matches(service, entry))
        })
        .map(|entry| entry.needle.as_str())
        .collect::<Vec<_>>();
    assert!(
        unreachable.is_empty(),
        "service-env-vars.toml has rows unreachable from shipped detector service names: {unreachable:?}"
    );
}

fn service_entry_matches(service: &str, entry: &Entry) -> bool {
    if entry.prefix {
        service
            .get(..entry.needle.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&entry.needle))
    } else {
        service
            .to_ascii_lowercase()
            .contains(&entry.needle.to_ascii_lowercase())
    }
}

#[test]
fn every_data_entry_resolves_through_the_public_api() {
    // Every needle in the data file, when fed as a service, must resolve to the
    // env name the data file declares. This proves the runtime map is actually
    // built from the data file and not from a divergent hardcoded table.
    for e in parse_embedded() {
        // Use the needle itself as the service string. For a substring needle
        // this trivially contains itself; for a prefix needle the service
        // starts with it. Either way the first matching row should be this one
        // (data is ordered so earlier, broader rows do not shadow these).
        let got = keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            &e.needle,
        );
        assert_eq!(
            got, e.env,
            "service '{}' resolved to '{}' but data file declares '{}'",
            e.needle, got, e.env
        );
    }
}

#[test]
fn curated_services_map_to_conventional_env_vars() {
    // Pin the exact provider conventions the data file ships.
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "aws"
        ),
        "AWS_ACCESS_KEY_ID"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "aws-iam"
        ),
        "AWS_ACCESS_KEY_ID"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "github"
        ),
        "GITHUB_TOKEN"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "gitlab"
        ),
        "GITLAB_TOKEN"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "slack"
        ),
        "SLACK_BOT_TOKEN"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "openai"
        ),
        "OPENAI_API_KEY"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "anthropic"
        ),
        "ANTHROPIC_API_KEY"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "stripe"
        ),
        "STRIPE_SECRET_KEY"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "twilio"
        ),
        "TWILIO_AUTH_TOKEN"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "sendgrid"
        ),
        "SENDGRID_API_KEY"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "google"
        ),
        "GOOGLE_API_KEY"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "gcp"
        ),
        "GOOGLE_API_KEY"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "azure"
        ),
        "AZURE_CLIENT_SECRET"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "npm"
        ),
        "NPM_TOKEN"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "pypi"
        ),
        "PYPI_TOKEN"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "docker"
        ),
        "DOCKER_PASSWORD"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "datadog"
        ),
        "DATADOG_API_KEY"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "snowflake"
        ),
        "SNOWFLAKE_PASSWORD"
    );
    // fix_replacement_text wraps the same name in ${...}.
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_replacement_text(
            &keyhog_core::testing::TestApi,
            "stripe"
        ),
        "${STRIPE_SECRET_KEY}"
    );
}

#[test]
fn unknown_service_falls_back_to_screaming_snake() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "acme-widget-api"
        ),
        "ACME_WIDGET_API_KEY"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "RevenueCat"
        ),
        "REVENUECAT_KEY"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            ""
        ),
        "_KEY"
    );
}
