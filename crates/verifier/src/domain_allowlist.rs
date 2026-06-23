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
        let mut m: HashMap<&'static str, &'static [&'static str]> = HashMap::new();
        m.insert("aws", &["amazonaws.com", "aws.amazon.com", "on.aws"]);
        m.insert(
            "github",
            &["github.com", "githubusercontent.com", "githubapp.com"],
        );
        m.insert("gitlab", &["gitlab.com"]);
        m.insert("bitbucket", &["bitbucket.org", "atlassian.com"]);
        m.insert(
            "gcp",
            &["googleapis.com", "google.com", "googleusercontent.com"],
        );
        m.insert(
            "google",
            &["googleapis.com", "google.com", "googleusercontent.com"],
        );
        m.insert(
            "azure",
            &[
                "azure.com",
                "microsoft.com",
                "microsoftonline.com",
                "azurewebsites.net",
                "windows.net",
                "azure-api.net",
            ],
        );
        m.insert("slack", &["slack.com"]);
        m.insert("discord", &["discord.com", "discordapp.com"]);
        m.insert("telegram", &["telegram.org", "t.me"]);
        m.insert("twilio", &["twilio.com"]);
        m.insert("sendgrid", &["sendgrid.com", "api.sendgrid.com"]);
        m.insert("mailgun", &["mailgun.net", "mailgun.com"]);
        m.insert("postmark", &["postmarkapp.com"]);
        m.insert("stripe", &["stripe.com"]);
        m.insert("paypal", &["paypal.com", "paypalobjects.com"]);
        m.insert("square", &["squareup.com", "squarecdn.com"]);
        m.insert("braintree", &["braintreegateway.com", "braintree-api.com"]);
        m.insert("plaid", &["plaid.com"]);
        m.insert("twitter", &["twitter.com", "x.com", "twitterapi.com"]);
        m.insert("openai", &["openai.com", "openai.azure.com"]);
        m.insert("anthropic", &["anthropic.com"]);
        m.insert("huggingface", &["huggingface.co", "hf.co"]);
        m.insert("replicate", &["replicate.com", "replicate.delivery"]);
        m.insert("notion", &["notion.so", "notion.com"]);
        m.insert("airtable", &["airtable.com"]);
        m.insert("asana", &["asana.com"]);
        m.insert("trello", &["trello.com", "atlassian.com"]);
        m.insert("jira", &["atlassian.com", "atlassian.net"]);
        m.insert("confluence", &["atlassian.com", "atlassian.net"]);
        m.insert("digitalocean", &["digitalocean.com"]);
        m.insert("heroku", &["heroku.com", "herokuapp.com"]);
        m.insert("netlify", &["netlify.com", "netlify.app"]);
        m.insert("vercel", &["vercel.com", "vercel.app"]);
        m.insert("cloudflare", &["cloudflare.com"]);
        m.insert("fastly", &["fastly.com"]);
        m.insert("akamai", &["akamai.com", "akamaihd.net"]);
        m.insert("datadog", &["datadoghq.com", "datadoghq.eu"]);
        m.insert("pagerduty", &["pagerduty.com"]);
        m.insert("newrelic", &["newrelic.com"]);
        m.insert("sentry", &["sentry.io"]);
        m.insert("rollbar", &["rollbar.com"]);
        m.insert("bugsnag", &["bugsnag.com"]);
        m.insert("npm", &["npmjs.com", "npmjs.org"]);
        m.insert("pypi", &["pypi.org"]);
        m.insert("rubygems", &["rubygems.org"]);
        m.insert("dockerhub", &["docker.com", "docker.io"]);
        m.insert("docker", &["docker.com", "docker.io"]);
        m.insert("crates", &["crates.io"]);
        m.insert("npm_token", &["npmjs.com", "npmjs.org"]);
        m.insert("shopify", &["shopify.com", "myshopify.com"]);
        m.insert("zendesk", &["zendesk.com"]);
        m.insert("freshdesk", &["freshdesk.com"]);
        m.insert("hubspot", &["hubapi.com", "hubspot.com"]);
        m.insert("intercom", &["intercom.io", "intercom.com"]);
        m.insert("linear", &["linear.app"]);
        m.insert("monday", &["monday.com"]);
        m.insert("clickup", &["clickup.com"]);
        m.insert("figma", &["figma.com"]);
        m.insert(
            "dropbox",
            &["dropbox.com", "dropboxapi.com", "dropboxusercontent.com"],
        );
        m.insert("box", &["box.com", "boxcloud.com"]);
        m.insert("zoom", &["zoom.us"]);
        m.insert("okta", &["okta.com", "oktapreview.com"]);
        m.insert("auth0", &["auth0.com"]);
        m.insert("keycloak", &["keycloak.org"]);
        m.insert("upstash", &["upstash.io", "upstash.com"]);
        m.insert("redis", &["redis.com", "redislabs.com"]);
        m.insert("mongodb", &["mongodb.com", "mongodb.net"]);
        m.insert("supabase", &["supabase.co", "supabase.com"]);
        m.insert(
            "firebase",
            &["firebaseio.com", "firebaseapp.com", "googleapis.com"],
        );
        m.insert("snyk", &["snyk.io"]);
        m.insert("sonarqube", &["sonarsource.com", "sonarcloud.io"]);
        m.insert("sonarcloud", &["sonarsource.com", "sonarcloud.io"]);
        m.insert("circleci", &["circleci.com"]);
        m.insert("travisci", &["travis-ci.com", "travis-ci.org"]);
        m.insert("buildkite", &["buildkite.com"]);
        m.insert("jfrog", &["jfrog.io", "jfrog.com"]);
        m.insert("artifactory", &["jfrog.io", "jfrog.com"]);
        m.insert("nexus", &["sonatype.com"]);
        m.insert("paloalto", &["paloaltonetworks.com"]);
        m.insert("fortinet", &["fortinet.com", "fortigate.com"]);
        m.insert("cisco", &["cisco.com"]);
        m.insert("canvas", &["instructure.com"]);
        m.insert("authentik", &["goauthentik.io"]);
        m.insert("ansible", &["ansible.com", "redhat.com"]);
        m.insert("thales", &["thalesgroup.com", "ciphertrust.com"]);
        m.insert("cypress", &["cypress.io"]);
        m.insert("uploadcare", &["uploadcare.com"]);
        m.insert("bigcommerce", &["bigcommerce.com"]);
        m.insert("wechat", &["weixin.qq.com", "wechat.com"]);
        m.insert("huawei", &["huaweicloud.com", "huawei.com"]);
        m.insert("jwt", &[]); // structural validation only - no network
        m.insert("generic", &[]); // generic high-entropy - never network-verify
        m
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
    matches!(
        domain,
        "azurewebsites.net"
            | "firebaseapp.com"
            | "herokuapp.com"
            | "myshopify.com"
            | "netlify.app"
            | "vercel.app"
    )
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
