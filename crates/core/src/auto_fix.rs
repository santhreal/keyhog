//! Auto-fix suggestions: turn each finding into "replace this credential
//! with `${ENV_VAR_NAME}`" advice.
//!
//! Tier-B moat innovation #15 + #17 from audits/legendary-2026-04-26:
//! moves keyhog from "find" to "fix." We surface the suggestion in SARIF
//! `result.fixes[]` per the v2.2.0 spec; CLI consumers can apply the edit
//! interactively or in a pre-commit hook.
//!
//! This module provides only the SUGGESTION step (deterministic env-var
//! name from service + the `${VAR}` replacement string). Actually rewriting
//! files belongs in the CLI, where we can prompt the user before clobbering
//! their working tree.

/// Map a detector's `service` string to a conventional environment-variable
/// name. Falls back to `<UPPER_SERVICE>_KEY` when the service isn't in the
/// curated map.
///
/// The curated mappings follow community conventions (12-factor, common
/// SDKs):
///   aws            → AWS_ACCESS_KEY_ID
///   github / gh-*  → GITHUB_TOKEN
///   gitlab         → GITLAB_TOKEN
///   slack          → SLACK_BOT_TOKEN
///   openai         → OPENAI_API_KEY
///   anthropic      → ANTHROPIC_API_KEY
///   stripe         → STRIPE_SECRET_KEY
///   twilio         → TWILIO_AUTH_TOKEN
///   sendgrid       → SENDGRID_API_KEY
///   google / gcp   → GOOGLE_API_KEY
///   azure          → AZURE_CLIENT_SECRET
///   npm            → NPM_TOKEN
///   pypi           → PYPI_TOKEN
///   docker         → DOCKER_PASSWORD
///   datadog        → DATADOG_API_KEY
///   snowflake      → SNOWFLAKE_PASSWORD
pub fn env_var_name_for_service(service: &str) -> String {
    let lower = service.to_lowercase();
    let curated = match lower.as_str() {
        s if s.contains("aws") => Some("AWS_ACCESS_KEY_ID"),
        s if s.contains("github") || s.starts_with("gh-") || s.starts_with("ghp_") => {
            Some("GITHUB_TOKEN")
        }
        s if s.contains("gitlab") => Some("GITLAB_TOKEN"),
        s if s.contains("slack") => Some("SLACK_BOT_TOKEN"),
        s if s.contains("openai") => Some("OPENAI_API_KEY"),
        s if s.contains("anthropic") => Some("ANTHROPIC_API_KEY"),
        s if s.contains("stripe") => Some("STRIPE_SECRET_KEY"),
        s if s.contains("twilio") => Some("TWILIO_AUTH_TOKEN"),
        s if s.contains("sendgrid") => Some("SENDGRID_API_KEY"),
        s if s.contains("google") || s.contains("gcp") => Some("GOOGLE_API_KEY"),
        s if s.contains("azure") => Some("AZURE_CLIENT_SECRET"),
        s if s.contains("npm") => Some("NPM_TOKEN"),
        s if s.contains("pypi") => Some("PYPI_TOKEN"),
        s if s.contains("docker") => Some("DOCKER_PASSWORD"),
        s if s.contains("datadog") => Some("DATADOG_API_KEY"),
        s if s.contains("snowflake") => Some("SNOWFLAKE_PASSWORD"),
        _ => None,
    };
    curated
        .map(|s| s.to_string())
        .unwrap_or_else(|| service_to_screaming_snake(service))
}

fn service_to_screaming_snake(service: &str) -> String {
    let mut out = String::with_capacity(service.len() + 4);
    for ch in service.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string() + "_KEY"
}

/// Render the `${ENV_VAR_NAME}` shell-interpolation replacement string for
/// a detector. Reporters embed this in their `fixes[]` output.
pub fn fix_replacement_text(service: &str) -> String {
    format!("${{{}}}", env_var_name_for_service(service))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_services_map_correctly() {
        assert_eq!(env_var_name_for_service("aws"), "AWS_ACCESS_KEY_ID");
        assert_eq!(env_var_name_for_service("aws-iam"), "AWS_ACCESS_KEY_ID");
        assert_eq!(env_var_name_for_service("github"), "GITHUB_TOKEN");
        assert_eq!(env_var_name_for_service("openai"), "OPENAI_API_KEY");
        assert_eq!(env_var_name_for_service("anthropic"), "ANTHROPIC_API_KEY");
        assert_eq!(env_var_name_for_service("stripe"), "STRIPE_SECRET_KEY");
        assert_eq!(env_var_name_for_service("snowflake"), "SNOWFLAKE_PASSWORD");
    }

    #[test]
    fn unknown_service_falls_back_to_screaming_snake() {
        assert_eq!(
            env_var_name_for_service("acme-widget-api"),
            "ACME_WIDGET_API_KEY"
        );
        assert_eq!(env_var_name_for_service("RevenueCat"), "REVENUECAT_KEY");
    }

    #[test]
    fn fix_replacement_text_wraps_in_dollar_braces() {
        assert_eq!(fix_replacement_text("aws"), "${AWS_ACCESS_KEY_ID}");
        assert_eq!(fix_replacement_text("acme-x"), "${ACME_X_KEY}");
    }

    #[test]
    fn empty_service_does_not_panic() {
        // "" → trim_matches('_') yields "" → "" + "_KEY" = "_KEY"
        assert_eq!(env_var_name_for_service(""), "_KEY");
    }
}
