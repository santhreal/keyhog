//! Runtime adapter for the shared verification-domain policy.

use std::collections::HashMap;

pub(crate) fn builtin_service_domains() -> &'static HashMap<&'static str, &'static [&'static str]> {
    keyhog_core::verification_domain::builtin_service_domains()
}

pub(crate) fn effective_allowlist(spec: &keyhog_core::VerifySpec) -> Option<Vec<String>> {
    keyhog_core::verification_domain::effective_allowlist(spec, None)
}

pub(crate) fn host_is_allowed(host: &str, allowlist: &[String]) -> bool {
    keyhog_core::verification_domain::host_is_allowed(host, allowlist)
}

/// Enforce the same domain policy used while compiling detector TOMLs after
/// every runtime interpolation step.
pub(crate) fn check_url_against_spec(
    raw_url: &str,
    spec: &keyhog_core::VerifySpec,
) -> Result<(), String> {
    let url = reqwest::Url::parse(raw_url)
        .map_err(|error| format!("blocked: invalid verify URL: {error}"))?;
    let host = url.host_str().unwrap_or_default();
    let Some(allowlist) = effective_allowlist(spec) else {
        return Err(format!(
            "blocked: detector service '{}' has no domain allowlist (set verify.allowed_domains in the detector TOML)",
            spec.service
        ));
    };
    if !host_is_allowed(host, &allowlist) {
        return Err(format!(
            "blocked: host '{host}' is not in the allowlist for service '{}' (allowed: {})",
            spec.service,
            allowlist.join(", ")
        ));
    }
    Ok(())
}
