//! Service-domain allowlist enforcement for verifier requests.
//!
//! Defends against malicious detector TOMLs that set `verify.url = "{{match}}"`
//! (or interpolate an attacker-controlled companion) and ship credentials to
//! attacker-owned domains. See kimi-wave1 audit finding 4.1 and wave3 §1.
//!
//! Resolution order for the effective allowlist of a given `VerifySpec`:
//!   1. `spec.allowed_domains` (per-detector explicit list) - if non-empty,
//!      this is the only list used.
//!   2. Otherwise, the builtin map keyed by `spec.service`.
//!   3. Otherwise, REJECT - better to refuse verification than exfil.
//!
//! "Match" means the URL's host (lowercased) equals an allowlist entry, OR is
//! a subdomain of an allowlist entry (e.g. `api.github.com` matches
//! `github.com`). Public multi-tenant suffixes are exact-only: `tenant.example`
//! can be explicitly allowed, but the shared suffix must not become a wildcard
//! license for attacker-owned tenants.

use std::borrow::Cow;
use std::collections::HashMap;

#[derive(serde::Deserialize)]
struct SharedTenantSuffixes {
    suffixes: Vec<String>,
}

fn parse_shared_tenant_suffixes(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<SharedTenantSuffixes>(raw)
        .map(|parsed| parsed.suffixes)
        .map_err(|error| error.to_string())
}

static EXACT_ONLY_SHARED_TENANT_SUFFIXES: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| {
        match parse_shared_tenant_suffixes(include_str!(
            "../../../rules/shared-tenant-suffixes.toml"
        )) {
            Ok(suffixes) => suffixes,
            Err(error) => panic!(
                "rules/shared-tenant-suffixes.toml is invalid: {error}. \
                 Fix the bundled Tier-B shared-tenant suffix list."
            ),
        }
    });

/// Builtin map of `service` → allowed apex domains. Detectors that set
/// `service = "<key>"` and DON'T provide their own `allowed_domains` list
/// inherit this entry. Anything not in this map (and without an explicit
/// detector-level allowlist) gets refused at verify time.
///
/// Keep this list tight: every entry is a license to send a credential
/// somewhere. Add domains only after confirming they belong to the service
/// owner.
pub(crate) fn builtin_service_domains() -> &'static HashMap<&'static str, &'static [&'static str]> {
    use std::sync::OnceLock;
    static MAP: OnceLock<HashMap<&'static str, &'static [&'static str]>> = OnceLock::new();
    MAP.get_or_init(|| {
        #[derive(serde::Deserialize)]
        struct ServicesFile {
            services: std::collections::BTreeMap<String, Vec<String>>,
        }
        // Bundled at compile time (`include_str!`), so the allowlist a runtime user
        // sees is exactly what was built — editing the data file needs no Rust change
        // yet cannot be tampered with at runtime (this is a credential-exfil boundary).
        let raw = include_str!("../../../rules/service-verification-domains.toml");
        let parsed: ServicesFile = match toml::from_str(raw) {
            Ok(parsed) => parsed,
            Err(error) => panic!(
                "rules/service-verification-domains.toml is invalid: {error}. \
                 Fix the bundled Tier-B verification-domain allowlist."
            ),
        };
        assert!(
            !parsed.services.is_empty(),
            "rules/service-verification-domains.toml must define at least one service \
             (fail-closed: an empty allowlist would refuse every verification)."
        );
        // Leak the parsed data to `'static` (a one-time init of conceptually static
        // config) so the map keeps the exact `&'static str` / `&'static [&'static str]`
        // element types every caller consumes — no return-type or caller change vs the
        // former inline `m.insert` map. `jwt`/`generic` carry an intentionally EMPTY
        // domain list (structural-only, never network-verified); empty is preserved.
        let mut map: HashMap<&'static str, &'static [&'static str]> = HashMap::new();
        for (service, domains) in parsed.services {
            let leaked_domains: &'static [&'static str] = domains
                .into_iter()
                .map(|domain| &*Box::leak(domain.into_boxed_str()))
                .collect::<Vec<&'static str>>()
                .leak();
            map.insert(&*Box::leak(service.into_boxed_str()), leaked_domains);
        }
        map
    })
}

/// Resolve the effective allowlist for a `VerifySpec`. Returns `None` when
/// the verifier MUST refuse the request.
pub(crate) fn effective_allowlist(spec: &keyhog_core::VerifySpec) -> Option<Vec<String>> {
    if !spec.allowed_domains.is_empty() {
        return Some(
            spec.allowed_domains
                .iter()
                .map(|d| {
                    d.trim()
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .to_lowercase()
                })
                .filter(|d| !d.is_empty())
                .collect(),
        );
    }
    let key = spec.service.as_str();
    if key.is_empty() {
        return None;
    }
    builtin_service_domains()
        .get(key)
        .map(|domains| domains.iter().map(|d| (*d).to_string()).collect())
}

/// Check that `host` is on `allowlist` (exact or subdomain match). Empty
/// allowlist is a fail-closed reject. `host` is matched lowercased.
pub(crate) fn host_is_allowed(host: &str, allowlist: &[String]) -> bool {
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
        .any(|s| s.as_str() == domain)
}

/// Top-level guard: parse `raw_url`, look up the allowlist for `spec`, and
/// reject if the host is not allowed. Returns `Ok(())` on pass, `Err(reason)`
/// to feed straight into a `VerificationResult::Error`.
pub(crate) fn check_url_against_spec(
    raw_url: &str,
    spec: &keyhog_core::VerifySpec,
) -> Result<(), String> {
    let url =
        reqwest::Url::parse(raw_url).map_err(|e| format!("blocked: invalid verify URL: {e}"))?;
    let host = url.host_str().unwrap_or(""); // LAW10: missing/non-string field => empty/placeholder; recall-safe
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
