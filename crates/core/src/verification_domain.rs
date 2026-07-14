//! Shared verification-domain policy.
//!
//! Detector validation and live verification use this module so a detector
//! cannot pass one hostname rule at load time and a different rule at request
//! time.

use crate::VerifySpec;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

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
        let parsed = toml::from_str::<SharedTenantSuffixes>(include_str!(
            "../../../rules/shared-tenant-suffixes.toml"
        ))
        .unwrap_or_else(|error| {
            panic!(
                "rules/shared-tenant-suffixes.toml is invalid: {error}. Fix the bundled Tier-B shared-tenant suffix list."
            )
        });
        validated_domain_entries(
            parsed.suffixes,
            "rules/shared-tenant-suffixes.toml suffixes",
            false,
        )
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
                let domains = validated_domain_entries(
                    domains,
                    &format!("rules/service-verification-domains.toml service {service:?}"),
                    true,
                );
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
        return spec
            .allowed_domains
            .iter()
            .map(|domain| normalize_allowlist_entry(domain))
            .collect();
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
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        match url.host()? {
            url::Host::Domain(domain) => domain.to_string(),
            url::Host::Ipv4(address) => return Some(address.to_string()),
            url::Host::Ipv6(address) => return Some(address.to_string()),
        }
    } else {
        if value.contains(['/', '?', '#', '@', ':']) {
            return None;
        }
        match url::Host::parse(value).ok()? {
            url::Host::Domain(domain) => domain,
            url::Host::Ipv4(address) => return Some(address.to_string()),
            url::Host::Ipv6(address) => return Some(address.to_string()),
        }
    };
    let normalized = host.trim_end_matches('.').to_lowercase();
    valid_dns_domain(&normalized).then_some(normalized)
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
        let ordinarily_allowed = host == allowed || host_is_subdomain_of_allowed(&host, &allowed);
        if !ordinarily_allowed {
            return false;
        }
        let Some(boundary) = shared_tenant_boundary(&host) else {
            return true;
        };
        if allowed == boundary {
            return host == allowed;
        }
        allowed == host
            || host_is_subdomain_of_allowed(&host, &allowed)
                && (allowed == boundary || host_is_subdomain_of_allowed(&allowed, boundary))
    })
}

fn validated_domain_entries(entries: Vec<String>, context: &str, allow_empty: bool) -> Vec<String> {
    assert!(
        allow_empty || !entries.is_empty(),
        "{context} must define at least one domain"
    );
    let mut seen = HashSet::with_capacity(entries.len());
    entries
        .into_iter()
        .map(|entry| {
            let normalized = normalize_allowlist_entry(&entry)
                .unwrap_or_else(|| panic!("{context} contains invalid domain entry {entry:?}"));
            assert!(
                seen.insert(normalized.clone()),
                "{context} contains duplicate domain {normalized:?}"
            );
            normalized
        })
        .collect()
}

fn valid_dns_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
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

fn shared_tenant_boundary(domain: &str) -> Option<&str> {
    EXACT_ONLY_SHARED_TENANT_SUFFIXES
        .iter()
        .map(String::as_str)
        .filter(|suffix| domain == *suffix || host_is_subdomain_of_allowed(domain, suffix))
        .max_by_key(|suffix| suffix.len())
}
