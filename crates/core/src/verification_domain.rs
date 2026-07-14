//! Shared verification-domain policy.
//!
//! Detector validation and live verification use this module so a detector
//! cannot pass one hostname rule at load time and a different rule at request
//! time.

use crate::VerifySpec;
use std::borrow::Cow;
use std::collections::HashMap;

#[derive(serde::Deserialize)]
struct SharedTenantSuffixes {
    suffixes: Vec<String>,
}

#[derive(serde::Deserialize)]
struct ServicesFile {
    services: std::collections::BTreeMap<String, Vec<String>>,
}

static EXACT_ONLY_SHARED_TENANT_SUFFIXES: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| {
        toml::from_str::<SharedTenantSuffixes>(include_str!(
            "../../../rules/shared-tenant-suffixes.toml"
        ))
        .map(|parsed| parsed.suffixes)
        .unwrap_or_else(|error| {
            panic!(
                "rules/shared-tenant-suffixes.toml is invalid: {error}. Fix the bundled Tier-B shared-tenant suffix list."
            )
        })
    });

/// Built-in service to verification-domain policy.
pub fn builtin_service_domains() -> &'static HashMap<&'static str, &'static [&'static str]> {
    static MAP: std::sync::OnceLock<HashMap<&'static str, &'static [&'static str]>> =
        std::sync::OnceLock::new();
    MAP.get_or_init(|| {
        let parsed: ServicesFile = toml::from_str(include_str!(
            "../../../rules/service-verification-domains.toml"
        ))
        .unwrap_or_else(|error| {
            panic!(
                "rules/service-verification-domains.toml is invalid: {error}. Fix the bundled Tier-B verification-domain allowlist."
            )
        });
        assert!(
            !parsed.services.is_empty(),
            "rules/service-verification-domains.toml must define at least one service"
        );
        parsed
            .services
            .into_iter()
            .map(|(service, domains)| {
                let service: &'static str = Box::leak(service.into_boxed_str());
                let domains: &'static [&'static str] = domains
                    .into_iter()
                    .map(|domain| &*Box::leak(domain.into_boxed_str()))
                    .collect::<Vec<_>>()
                    .leak();
                (service, domains)
            })
            .collect()
    })
}

/// Resolve the only domains a verifier may contact. Explicit detector domains
/// replace built-ins. `detector_service` supplies the detector's service when
/// `verify.service` is omitted during compile-time validation.
pub fn effective_allowlist(
    spec: &VerifySpec,
    detector_service: Option<&str>,
) -> Option<Vec<String>> {
    if !spec.allowed_domains.is_empty() {
        return Some(
            spec.allowed_domains
                .iter()
                .filter_map(|domain| normalize_allowlist_entry(domain))
                .collect(),
        );
    }
    let service = if spec.service.trim().is_empty() {
        detector_service.unwrap_or_default().trim()
    } else {
        spec.service.trim()
    };
    if service.is_empty() {
        return None;
    }
    builtin_service_domains()
        .get(service)
        .map(|domains| domains.iter().map(|domain| (*domain).to_string()).collect())
}

/// Normalize a domain entry. Bare hosts and URL-shaped compatibility entries
/// are accepted, but credentials, paths, queries, fragments, and ports are not
/// domain identities.
pub fn normalize_allowlist_entry(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    let host = if value.contains("://") {
        let url = url::Url::parse(value).ok()?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        url.host_str()?.to_string()
    } else {
        if value.contains(['/', '?', '#', '@', ':']) {
            return None;
        }
        value.to_string()
    };
    let normalized = host.trim_end_matches('.').to_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

/// Return whether `host` exactly matches an allowed domain or is its permitted
/// subdomain. Shared multi-tenant suffixes are exact-only.
pub fn host_is_allowed(host: &str, allowlist: &[String]) -> bool {
    if host.is_empty() || allowlist.is_empty() {
        return false;
    }
    let host = lowercase_domain_if_needed(host.trim_end_matches('.'));
    allowlist.iter().any(|allowed| {
        let allowed = allowed.trim_end_matches('.');
        if allowed.is_empty() {
            return false;
        }
        let allowed = lowercase_domain_if_needed(allowed);
        if host == allowed {
            return true;
        }
        !is_exact_only_shared_tenant_suffix(&allowed)
            && host_is_subdomain_of_allowed(&host, &allowed)
    })
}

fn lowercase_domain_if_needed(value: &str) -> Cow<'_, str> {
    if value.chars().any(char::is_uppercase) {
        Cow::Owned(value.to_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

fn host_is_subdomain_of_allowed(host: &str, allowed: &str) -> bool {
    host.len() > allowed.len()
        && host.ends_with(allowed)
        && host.as_bytes()[host.len() - allowed.len() - 1] == b'.'
}

fn is_exact_only_shared_tenant_suffix(domain: &str) -> bool {
    EXACT_ONLY_SHARED_TENANT_SUFFIXES
        .iter()
        .any(|suffix| suffix == domain)
}
