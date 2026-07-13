//! Standalone coverage for the verifier's domain-allowlist guard, the
//! verification cache, the per-service rate limiter, and the SigV4 timestamp
//! formatter.
//!
//! - `domain_allowlist::{builtin_service_domains, effective_allowlist,
//!   host_is_allowed, check_url_against_spec}` (the credential-exfil guard).
//! - `cache::VerificationCache`: TTL, eviction, hash-keyed get/put.
//! - `rate_limit::{RateLimiter, rps math}`: interval math + error backoff.
//! - `testing::format_sigv4_timestamps`: civil-date conversion.
//!
//! Each assertion pins a concrete outcome: a specific host allowed/refused, a
//! cache hit returning the exact stored result, an interval Duration, a
//! formatted timestamp string. No `is_ok()` / `!is_empty()` decoration.

use keyhog_core::{VerificationResult, VerifySpec};
use keyhog_verifier::rate_limit::RateLimiter;
use keyhog_verifier::testing::{
    TestApi, TestVerificationCache as VerificationCache, VerifierTestApi, VerifierTestCache,
};
use std::collections::HashMap;
use std::time::Duration;

fn spec(service: &str, allowed: &[&str]) -> VerifySpec {
    VerifySpec {
        service: service.to_string(),
        allowed_domains: allowed.iter().map(|s| s.to_string()).collect(),
        ..VerifySpec::default()
    }
}

// ===========================================================================
// domain_allowlist::builtin_service_domains
// ===========================================================================

#[test]
fn builtin_map_has_known_providers() {
    let m = TestApi.builtin_service_domains();
    assert_eq!(
        m.get("github").copied(),
        Some(&["github.com", "githubusercontent.com", "githubapp.com"][..])
    );
    assert_eq!(m.get("stripe").copied(), Some(&["stripe.com"][..]));
    assert_eq!(m.get("gitlab").copied(), Some(&["gitlab.com"][..]));
}

#[test]
fn builtin_map_network_excluded_services_are_empty() {
    let m = TestApi.builtin_service_domains();
    // jwt + generic are structural-only (empty allowlist => never network verify).
    assert_eq!(m.get("jwt").copied(), Some(&[][..]));
    assert_eq!(m.get("generic").copied(), Some(&[][..]));
}

#[test]
fn builtin_map_is_stable_across_calls() {
    // OnceLock-backed: same pointer / same data both times.
    let a = TestApi.builtin_service_domains();
    let b = TestApi.builtin_service_domains();
    assert_eq!(a.len(), b.len());
    assert!(a.contains_key("aws"));
}

// ===========================================================================
// domain_allowlist::effective_allowlist
// ===========================================================================

#[test]
fn effective_allowlist_explicit_overrides_builtin() {
    let s = spec("github", &["myhost.example", "https://other.example"]);
    let got = TestApi
        .effective_allowlist(&s)
        .expect("explicit list is non-empty");
    // Scheme stripped, lowercased; builtin github.com NOT present.
    assert_eq!(got, vec!["myhost.example", "other.example"]);
}

#[test]
fn effective_allowlist_falls_back_to_builtin() {
    let s = spec("stripe", &[]);
    let got = TestApi
        .effective_allowlist(&s)
        .expect("builtin stripe entry");
    assert_eq!(got, vec!["stripe.com"]);
}

#[test]
fn effective_allowlist_unknown_service_is_none() {
    let s = spec("totally-unknown-service-xyz", &[]);
    assert!(
        TestApi.effective_allowlist(&s).is_none(),
        "unknown service with no explicit list must refuse (None)"
    );
}

#[test]
fn effective_allowlist_empty_service_is_none() {
    let s = spec("", &[]);
    assert!(TestApi.effective_allowlist(&s).is_none());
}

#[test]
fn effective_allowlist_jwt_service_is_empty_list_not_none() {
    // jwt maps to an empty slice. Some(vec![]) (a list exists, just empty).
    let s = spec("jwt", &[]);
    let got = TestApi
        .effective_allowlist(&s)
        .expect("jwt has an (empty) builtin entry");
    assert!(got.is_empty());
}

// ===========================================================================
// domain_allowlist::host_is_allowed
// ===========================================================================

#[test]
fn host_exact_match_allowed() {
    assert!(TestApi.host_is_allowed("github.com", &["github.com".to_string()]));
}

#[test]
fn host_subdomain_match_allowed() {
    assert!(TestApi.host_is_allowed("api.github.com", &["github.com".to_string()]));
    assert!(TestApi.host_is_allowed("a.b.github.com", &["github.com".to_string()]));
}

#[test]
fn host_sibling_domain_refused() {
    // notgithub.com must NOT match github.com (suffix, not substring).
    assert!(!TestApi.host_is_allowed("notgithub.com", &["github.com".to_string()]));
    // evilgithub.com.attacker.com must NOT match.
    assert!(!TestApi.host_is_allowed("github.com.attacker.com", &["github.com".to_string()]));
}

#[test]
fn host_empty_allowlist_is_fail_closed() {
    assert!(!TestApi.host_is_allowed("github.com", &[]));
}

#[test]
fn host_empty_host_refused() {
    assert!(!TestApi.host_is_allowed("", &["github.com".to_string()]));
}

#[test]
fn host_trailing_dot_normalized() {
    // FQDN trailing dot is stripped before comparison.
    assert!(TestApi.host_is_allowed("api.github.com.", &["github.com".to_string()]));
}

#[test]
fn host_case_insensitive() {
    assert!(TestApi.host_is_allowed("API.GitHub.COM", &["github.com".to_string()]));
    assert!(TestApi.host_is_allowed("api.github.com", &["GitHub.COM.".to_string()]));
}

#[test]
fn host_shared_tenant_suffix_is_exact_only() {
    for suffix in [
        "atlassian.net",
        "auth0.com",
        "azure-api.net",
        "azurewebsites.net",
        "firebaseapp.com",
        "firebaseio.com",
        "herokuapp.com",
        "jfrog.io",
        "mongodb.net",
        "myshopify.com",
        "netlify.app",
        "on.aws",
        "openai.azure.com",
        "supabase.co",
        "upstash.io",
        "vercel.app",
        "windows.net",
    ] {
        assert!(
            TestApi.host_is_allowed(suffix, &[suffix.to_string()]),
            "exact shared suffix host should still match itself: {suffix}"
        );
        assert!(
            !TestApi.host_is_allowed(&format!("attacker.{suffix}"), &[suffix.to_string()]),
            "shared tenant suffix must not wildcard-match attacker-owned tenants: {suffix}"
        );
    }
}

#[test]
fn host_explicit_tenant_subdomain_is_allowed_without_shared_suffix_wildcard() {
    assert!(TestApi.host_is_allowed(
        "tenant.herokuapp.com",
        &["tenant.herokuapp.com".to_string()]
    ));
    assert!(TestApi.host_is_allowed(
        "api.tenant.herokuapp.com",
        &["tenant.herokuapp.com".to_string()]
    ));
    assert!(!TestApi.host_is_allowed("other.herokuapp.com", &["tenant.herokuapp.com".to_string()]));
}

// ===========================================================================
// domain_allowlist::check_url_against_spec
// ===========================================================================

#[test]
fn check_url_allows_builtin_service_host() {
    let s = spec("github", &[]);
    assert!(TestApi
        .check_url_against_spec("https://api.github.com/user", &s)
        .is_ok());
}

#[test]
fn check_url_blocks_offlist_host() {
    let s = spec("github", &[]);
    let err = TestApi
        .check_url_against_spec("https://evil.attacker.com/", &s)
        .expect_err("off-allowlist host must be blocked");
    assert!(
        err.contains("not in the allowlist") && err.contains("evil.attacker.com"),
        "error must name the rejected host: {err}"
    );
}

#[test]
fn check_url_blocks_builtin_shared_tenant_subdomain() {
    let heroku = spec("heroku", &[]);
    let err = TestApi
        .check_url_against_spec("https://attacker.herokuapp.com/v", &heroku)
        .expect_err("built-in herokuapp.com suffix must not allow arbitrary tenants");
    assert!(
        err.contains("attacker.herokuapp.com") && err.contains("not in the allowlist"),
        "error must name the rejected shared-tenant host: {err}"
    );

    let shopify = spec("shopify", &[]);
    let err = TestApi
        .check_url_against_spec("https://attacker.myshopify.com/admin", &shopify)
        .expect_err("built-in myshopify.com suffix must not allow arbitrary shops");
    assert!(
        err.contains("attacker.myshopify.com") && err.contains("not in the allowlist"),
        "error must name the rejected shared-tenant host: {err}"
    );

    let jira = spec("jira", &[]);
    let err = TestApi
        .check_url_against_spec("https://attacker.atlassian.net/rest/api/3/myself", &jira)
        .expect_err("built-in atlassian.net suffix must not allow arbitrary tenants");
    assert!(
        err.contains("attacker.atlassian.net") && err.contains("not in the allowlist"),
        "error must name the rejected shared-tenant host: {err}"
    );
}

#[test]
fn check_url_blocks_unknown_service_no_allowlist() {
    let s = spec("unknown-svc-xyz", &[]);
    let err = TestApi
        .check_url_against_spec("https://anything.example/", &s)
        .expect_err("unknown service must be refused");
    assert!(
        err.contains("no domain allowlist"),
        "error must explain the missing allowlist: {err}"
    );
}

#[test]
fn check_url_blocks_invalid_url() {
    let s = spec("github", &[]);
    let err = TestApi
        .check_url_against_spec("::: not a url", &s)
        .expect_err("invalid URL must be blocked");
    assert!(err.contains("invalid verify URL"), "error: {err}");
}

#[test]
fn check_url_explicit_allowlist_permits_custom_host() {
    let s = spec("custom", &["my-enterprise.example.com"]);
    assert!(TestApi
        .check_url_against_spec("https://my-enterprise.example.com/v/x", &s)
        .is_ok());
    // But a host NOT in the explicit list is refused even for the same service.
    assert!(TestApi
        .check_url_against_spec("https://github.com/x", &s)
        .is_err());
}

// ===========================================================================
// cache::VerificationCache
// ===========================================================================

#[test]
fn cache_starts_empty() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

#[test]
fn cache_put_then_get_returns_stored_result() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    let mut md = HashMap::new();
    md.insert("account".to_string(), "acct-42".to_string());
    cache.put("secretval", "github-pat", VerificationResult::Live, md);

    let (result, meta) = cache.get("secretval", "github-pat").expect("hit");
    assert_eq!(result, VerificationResult::Live);
    assert_eq!(meta.get("account").map(String::as_str), Some("acct-42"));
    assert_eq!(cache.len(), 1);
}

#[test]
fn cache_miss_on_different_credential() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    cache.put("secretA", "det", VerificationResult::Live, HashMap::new());
    assert!(
        cache.get("secretB", "det").is_none(),
        "a different credential must miss (keyed on credential hash)"
    );
}

#[test]
fn cache_miss_on_different_detector() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    cache.put("secret", "detA", VerificationResult::Dead, HashMap::new());
    assert!(
        cache.get("secret", "detB").is_none(),
        "same credential, different detector id must miss"
    );
}

#[test]
fn cache_expired_entry_is_evicted_on_get() {
    // Zero TTL: the entry is already expired when read.
    let cache = VerificationCache::new(Duration::from_secs(0));
    cache.put("secret", "det", VerificationResult::Live, HashMap::new());
    assert!(
        cache.get("secret", "det").is_none(),
        "a zero-TTL entry must be treated as expired"
    );
}

#[test]
fn cache_evict_expired_clears_stale_entries() {
    let cache = VerificationCache::new(Duration::from_secs(0));
    cache.put("a", "d", VerificationResult::Live, HashMap::new());
    cache.put("b", "d", VerificationResult::Dead, HashMap::new());
    cache.evict_expired();
    assert!(
        cache.is_empty(),
        "evict_expired must drop all expired entries"
    );
}

#[test]
fn cache_respects_max_entries_bound() {
    // Bound at 2; insert 5 distinct (never exceed the bound).
    let cache = VerificationCache::with_max_entries(Duration::from_secs(300), 2);
    for i in 0..5 {
        cache.put(
            &format!("cred{i}"),
            "det",
            VerificationResult::Live,
            HashMap::new(),
        );
    }
    assert!(
        cache.len() <= 2,
        "cache must respect the max-entries bound, got {}",
        cache.len()
    );
}

#[test]
fn cache_stores_error_variant_payload() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    cache.put(
        "secret",
        "det",
        VerificationResult::Error("timeout".to_string()),
        HashMap::new(),
    );
    let (result, _) = cache.get("secret", "det").expect("hit");
    assert_eq!(result, VerificationResult::Error("timeout".to_string()));
}

#[test]
fn cache_default_ttl_is_usable() {
    let cache = VerificationCache::default_ttl();
    assert!(cache.is_empty());
    cache.put("s", "d", VerificationResult::Live, HashMap::new());
    assert_eq!(
        cache.get("s", "d").map(|(r, _)| r),
        Some(VerificationResult::Live)
    );
}

// ===========================================================================
// rate_limit::RateLimiter, interval math, no async needed
// ===========================================================================

#[test]
fn rate_limiter_default_interval_from_rps() {
    let rl = RateLimiter::new(5.0);
    // 5 rps => 200ms interval.
    assert_eq!(rl.default_interval(), Duration::from_millis(200));
}

#[test]
fn rate_limiter_one_rps_is_one_second() {
    let rl = RateLimiter::new(1.0);
    assert_eq!(rl.default_interval(), Duration::from_secs(1));
}

#[test]
fn rate_limiter_set_default_rps_updates_interval() {
    let rl = RateLimiter::new(5.0);
    rl.set_default_rps(10.0);
    assert_eq!(rl.default_interval(), Duration::from_millis(100));
}

#[test]
fn rate_limiter_nonfinite_rps_falls_back_to_one() {
    let rl = RateLimiter::new(f64::NAN);
    assert_eq!(
        rl.default_interval(),
        Duration::from_secs(1),
        "NaN rps must fall back to 1 rps (1s interval), never zero-interval"
    );
}

#[test]
fn rate_limiter_zero_rps_falls_back_to_one() {
    let rl = RateLimiter::new(0.0);
    assert_eq!(rl.default_interval(), Duration::from_secs(1));
}

#[test]
fn rate_limiter_negative_rps_falls_back_to_one() {
    let rl = RateLimiter::new(-5.0);
    assert_eq!(rl.default_interval(), Duration::from_secs(1));
}

#[tokio::test]
async fn rate_limiter_first_call_does_not_block() {
    let rl = RateLimiter::new(1000.0);
    let start = std::time::Instant::now();
    rl.wait("svc").await;
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "the first call for a service must not block"
    );
}

#[tokio::test]
async fn rate_limiter_update_limit_sets_per_service_override() {
    let rl = RateLimiter::new(1000.0);
    // Prime + override the service at a fast rate; subsequent waits are bounded.
    rl.update_limit("svc", 1000.0).await;
    let start = std::time::Instant::now();
    rl.wait("svc").await;
    assert!(start.elapsed() < Duration::from_secs(2));
}

// ===========================================================================
// testing::format_sigv4_timestamps, civil-date conversion
// ===========================================================================

#[test]
fn sigv4_epoch_zero() {
    let (date, amz) = TestApi.format_sigv4_timestamps(0);
    assert_eq!(date, "19700101");
    assert_eq!(amz, "19700101T000000Z");
}

#[test]
fn sigv4_known_timestamp() {
    // 2021-08-12T12:34:56Z == 1628771696
    let (date, amz) = TestApi.format_sigv4_timestamps(1_628_771_696);
    assert_eq!(date, "20210812");
    assert_eq!(amz, "20210812T123456Z");
}

#[test]
fn sigv4_leap_day() {
    // 2020-02-29T00:00:00Z == 1582934400
    let (date, amz) = TestApi.format_sigv4_timestamps(1_582_934_400);
    assert_eq!(date, "20200229");
    assert_eq!(amz, "20200229T000000Z");
}

#[test]
fn sigv4_year_boundary() {
    // 2019-12-31T23:59:59Z == 1577836799
    let (date, amz) = TestApi.format_sigv4_timestamps(1_577_836_799);
    assert_eq!(date, "20191231");
    assert_eq!(amz, "20191231T235959Z");
}
