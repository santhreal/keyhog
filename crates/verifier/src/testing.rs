//! Hidden hooks for integration tests. Not covered by semver.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub use crate::cache::oldest_eviction_batch;
pub use crate::interpolate::{missing_companion_refs, MAX_TEMPLATE_TOKENS};
pub use crate::oob::redact_interactsh_error;
pub fn prewarm_oob_key_for_test() -> Result<(bool, Vec<u8>), crate::oob::InteractshError> {
    crate::oob::prewarm_key_generation();
    let pending = crate::oob::prewarmed_key_pending_for_test();
    let modulus = crate::oob::consume_prewarmed_key_for_test()?;
    Ok((pending, modulus))
}

/// Exercise the real `cache::evict_oldest_dashmap_entries` primitive (the
/// shared oldest-first bounded-cache eviction used by the DNS-resolution and
/// pinned-client caches) on an internally-built age-stamped map and return the
/// surviving keys, sorted ascending. Each key doubles as its age-in-seconds
/// (entry `k` is stamped `base + k`s, so key `0` is the oldest), making the
/// survivor set directly observable. Kept here, rather than in the
/// integration-test crate, so `dashmap` stays out of the test crate's
/// dependency set while the exact production eviction path is what runs.
pub fn evict_oldest_dashmap_survivors_for_test(ages_secs: &[u64], count: usize) -> Vec<u64> {
    let base = std::time::Instant::now();
    let cache: dashmap::DashMap<u64, (std::time::Instant, ())> = dashmap::DashMap::new();
    for &s in ages_secs {
        cache.insert(s, (base + std::time::Duration::from_secs(s), ()));
    }
    crate::cache::evict_oldest_dashmap_entries(&cache, count, |(t, _)| *t);
    let mut survivors: Vec<u64> = cache.iter().map(|e| *e.key()).collect();
    survivors.sort_unstable();
    survivors
}
pub use crate::verify::aws::INVALID_AWS_REGION_ERROR;
pub use crate::verify::credential::MAX_RETRIES_ERROR;
pub use crate::verify::request::{
    invalid_url_error, CONNECTION_FAILED_ERROR, DNS_NO_ADDRESSES_ERROR, HTTPS_ONLY_ERROR,
    PRIVATE_URL_ERROR, REDIRECT_LIMIT_ERROR, REQUEST_FAILED_ERROR, TIMEOUT_ERROR,
};

// Pinned-client cache-key seams (request.rs `canonical_pinned_addrs` /
// `pinned_keys_equal_for_test` are `pub(crate)`, so they cannot be re-exported
// with `pub use`: wrap them in `pub fn`s here, like the other `_for_test`
// accessors, so `tests/unit/pinned_client_key.rs` reaches them without widening
// the crate's public API).
pub fn canonical_pinned_addrs(addrs: &[std::net::SocketAddr]) -> Vec<std::net::SocketAddr> {
    crate::verify::request::canonical_pinned_addrs(addrs)
}
pub fn pinned_keys_equal_for_test(
    host: &str,
    addrs_a: &[std::net::SocketAddr],
    addrs_b: &[std::net::SocketAddr],
    timeout: std::time::Duration,
    insecure_tls: bool,
) -> bool {
    crate::verify::request::pinned_keys_equal_for_test(
        host,
        addrs_a,
        addrs_b,
        timeout,
        insecure_tls,
    )
}

// OOB poller-degradation decision seams, surfaced for the re-homed
// `tests/unit/oob_poller_degradation.rs` (the `oob::session` no-inline-tests
// gate forbids testing the private `poller_is_degraded` / `elapsed_verdict` /
// threshold in place). `pub fn` wrappers, not `pub use`, because the helpers
// are `pub(crate)`.
pub fn oob_poller_is_degraded(consecutive_errors: u32) -> bool {
    crate::oob::poller_is_degraded(consecutive_errors)
}
pub fn oob_elapsed_verdict(poller_degraded: bool) -> crate::oob::OobObservation {
    crate::oob::elapsed_verdict(poller_degraded)
}
pub fn oob_degraded_error_threshold() -> u32 {
    crate::oob::OOB_DEGRADED_ERROR_THRESHOLD
}

// SigV4 canonical-URI encoding seams (re-homed `sigv4::uri_encode_tests`).
pub fn aws_uri_encode(input: &str) -> String {
    crate::sigv4::aws_uri_encode(input)
}
pub fn canonical_query_string(pairs: &[(String, String)]) -> String {
    crate::sigv4::canonical_query_string(pairs)
}

// OOB combined-verdict policy-matrix seam (re-homed
// `verify::credential::oob_verdict_tests`).
pub fn oob_combined_verdict(
    policy: keyhog_core::OobPolicy,
    http_only_result: keyhog_core::VerificationResult,
    http_live: bool,
    observed: bool,
) -> keyhog_core::VerificationResult {
    crate::verify::credential::oob_combined_verdict(
        policy,
        http_only_result,
        http_live,
        observed,
    )
}

// Response body-capacity DoS-guard seams (re-homed
// `verify::response::body_capacity_tests`).
pub fn body_capacity_hint(content_length: Option<u64>) -> usize {
    crate::verify::response::body_capacity_hint(content_length)
}
pub const MAX_RESPONSE_BODY_BYTES: usize = crate::verify::response::MAX_RESPONSE_BODY_BYTES;
pub use crate::verify::response::{
    BODY_NOT_UTF8_ERROR, BODY_READ_FAILED_ERROR, RESPONSE_TOO_LARGE_ERROR,
};
pub use crate::verify::tracked_join_error_preservation_for_test;

pub struct TestApi;

#[derive(Debug, Clone)]
pub struct TestMintedUrl {
    pub unique_id: String,
    pub host: String,
    pub url: String,
}

fn test_minted_url(minted: crate::oob::MintedUrl) -> TestMintedUrl {
    TestMintedUrl {
        unique_id: minted.unique_id,
        host: minted.host,
        url: minted.url,
    }
}

pub struct TestVerificationCache(crate::cache::VerificationCache);

pub trait VerifierTestCache {
    fn new(ttl: Duration) -> Self;
    fn with_max_entries(ttl: Duration, max_entries: usize) -> Self;
    fn default_ttl() -> Self;
    fn get(
        &self,
        credential: &str,
        detector_id: &str,
    ) -> Option<(keyhog_core::VerificationResult, HashMap<String, String>)>;
    fn get_with_companions(
        &self,
        credential: &str,
        detector_id: &str,
        companions: &HashMap<String, String>,
    ) -> Option<(keyhog_core::VerificationResult, HashMap<String, String>)>;
    fn put(
        &self,
        credential: &str,
        detector_id: &str,
        result: keyhog_core::VerificationResult,
        metadata: HashMap<String, String>,
    );
    fn put_with_companions(
        &self,
        credential: &str,
        detector_id: &str,
        companions: &HashMap<String, String>,
        result: keyhog_core::VerificationResult,
        metadata: HashMap<String, String>,
    );
    fn len(&self) -> usize;
    fn queue_len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn evict_expired(&self);
    fn enforce_max_entries_bound(&self);
    fn clear_eviction_queue_for_test(&self);
    fn insert_unqueued_for_test(
        &self,
        credential: &str,
        detector_id: &str,
        result: keyhog_core::VerificationResult,
        metadata: HashMap<String, String>,
    );
}

impl VerifierTestCache for TestVerificationCache {
    fn new(ttl: Duration) -> Self {
        Self(crate::cache::VerificationCache::new(ttl))
    }

    fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self(crate::cache::VerificationCache::with_max_entries(
            ttl,
            max_entries,
        ))
    }

    fn default_ttl() -> Self {
        Self(crate::cache::VerificationCache::default_ttl())
    }

    fn get(
        &self,
        credential: &str,
        detector_id: &str,
    ) -> Option<(keyhog_core::VerificationResult, HashMap<String, String>)> {
        self.0.get(credential, detector_id)
    }

    fn get_with_companions(
        &self,
        credential: &str,
        detector_id: &str,
        companions: &HashMap<String, String>,
    ) -> Option<(keyhog_core::VerificationResult, HashMap<String, String>)> {
        self.0
            .get_with_companions(credential, detector_id, companions)
    }

    fn put(
        &self,
        credential: &str,
        detector_id: &str,
        result: keyhog_core::VerificationResult,
        metadata: HashMap<String, String>,
    ) {
        self.0.put(credential, detector_id, result, metadata);
    }

    fn put_with_companions(
        &self,
        credential: &str,
        detector_id: &str,
        companions: &HashMap<String, String>,
        result: keyhog_core::VerificationResult,
        metadata: HashMap<String, String>,
    ) {
        self.0
            .put_with_companions(credential, detector_id, companions, result, metadata);
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn queue_len(&self) -> usize {
        self.0.queue_len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn evict_expired(&self) {
        self.0.evict_expired();
    }

    fn enforce_max_entries_bound(&self) {
        self.0.enforce_max_entries_bound();
    }

    fn clear_eviction_queue_for_test(&self) {
        self.0.clear_eviction_queue_for_test();
    }

    fn insert_unqueued_for_test(
        &self,
        credential: &str,
        detector_id: &str,
        result: keyhog_core::VerificationResult,
        metadata: HashMap<String, String>,
    ) {
        self.0
            .insert_unqueued_for_test(credential, detector_id, result, metadata);
    }
}

pub trait VerifierTestApi {
    const OOB_COMPANION_URL: &'static str;
    const OOB_COMPANION_HOST: &'static str;
    const OOB_COMPANION_ID: &'static str;

    fn ip_addr_is_bogon(&self, ip: std::net::IpAddr) -> bool;
    fn resolve_field(
        &self,
        field: &str,
        credential: &str,
        companions: &HashMap<String, String>,
    ) -> String;
    fn sanitize_oob_value(&self, s: &str) -> String;
    fn sanitize_raw_value(&self, s: &str) -> String;
    fn interpolate(
        &self,
        template: &str,
        credential: &str,
        companions: &HashMap<String, String>,
    ) -> String;
    fn interpolate_url(
        &self,
        template: &str,
        credential: &str,
        companions: &HashMap<String, String>,
    ) -> String;
    fn interpolate_http_value(
        &self,
        template: &str,
        credential: &str,
        companions: &HashMap<String, String>,
    ) -> String;
    fn companions_with_oob(
        &self,
        base: &HashMap<String, String>,
        minted_host: &str,
        minted_url: &str,
        minted_id: &str,
    ) -> HashMap<String, String>;
    fn builtin_service_domains(
        &self,
    ) -> &'static HashMap<&'static str, &'static [&'static str]>;
    fn effective_allowlist(&self, spec: &keyhog_core::VerifySpec) -> Option<Vec<String>>;
    fn host_is_allowed(&self, host: &str, allowlist: &[String]) -> bool;
    fn check_url_against_spec(
        &self,
        raw_url: &str,
        spec: &keyhog_core::VerifySpec,
    ) -> Result<(), String>;
    fn engine_detector_verify_service(
        &self,
        engine: &crate::VerificationEngine,
        detector_id: &str,
    ) -> Option<String>;
    fn engine_inflight_count(&self, engine: &crate::VerificationEngine) -> usize;
    fn format_sigv4_timestamps(&self, unix_secs: u64) -> (String, String);
    fn parse_aws_sts_success_metadata(
        &self,
        body: &str,
    ) -> Result<HashMap<String, String>, String>;
    fn classify_aws_sts_failure(
        &self,
        status: u16,
        body: &str,
    ) -> (keyhog_core::VerificationResult, bool);
    fn classify_aws_sts_http_200(
        &self,
        body: &str,
    ) -> (
        keyhog_core::VerificationResult,
        HashMap<String, String>,
        bool,
    );
    fn script_auth_result_for_test(&self, output: &str) -> keyhog_core::VerificationResult;
    fn valid_aws_format_for_test(&self, access_key: &str, secret_key: &str) -> bool;
    fn validate_aws_region_for_test(
        &self,
        region: &str,
    ) -> Result<(), keyhog_core::VerificationResult>;
    fn build_aws_probe_final_for_test(
        &self,
        access_key: &str,
        secret_key: &str,
        region: &str,
    ) -> impl std::future::Future<
        Output = (
            keyhog_core::VerificationResult,
            HashMap<String, String>,
            bool,
        ),
    > + Send;
    fn rate_limit_feedback_sequence(&self) -> (usize, usize, usize, usize, usize);
    fn retry_loop_records_rate_limit_feedback(
        &self,
    ) -> impl std::future::Future<Output = usize> + Send;
    fn interactsh_client_for_test(
        &self,
        server: &str,
    ) -> Result<crate::oob::InteractshClient, crate::oob::InteractshError>;
    fn interactsh_client_correlation_id<'a>(
        &self,
        client: &'a crate::oob::InteractshClient,
    ) -> &'a str;
    fn interactsh_client_mint_url(
        &self,
        client: &crate::oob::InteractshClient,
    ) -> TestMintedUrl;
    fn oob_session_for_test(
        &self,
        client: Arc<crate::oob::InteractshClient>,
        config: crate::oob::OobConfig,
    ) -> Arc<crate::oob::OobSession>;
    fn engine_set_oob_session_for_test(
        &self,
        engine: &mut crate::VerificationEngine,
        session: Arc<crate::oob::OobSession>,
    );
    fn oob_session_mint(&self, session: &crate::oob::OobSession) -> TestMintedUrl;
    fn oob_session_default_timeout(&self, session: &crate::oob::OobSession) -> Duration;
    /// Force the degraded flag so the re-homed
    /// `tests/unit/oob_poller_degradation.rs` can assert a `wait_for` timeout
    /// on an unreachable collector fails closed (`Disabled`) instead of a
    /// false `NotObserved`.
    fn oob_session_set_degraded_for_test(
        &self,
        session: &crate::oob::OobSession,
        degraded: bool,
    );
    fn oob_session_store_and_notify(
        &self,
        session: &crate::oob::OobSession,
        interaction: crate::oob::Interaction,
    );
    fn oob_session_waiter_count(&self, session: &crate::oob::OobSession) -> usize;
    fn oob_session_active_waiter_count(&self, session: &crate::oob::OobSession) -> usize;
    fn oob_session_poll_generation(&self, session: &crate::oob::OobSession) -> u64;
    fn oob_session_abort_poller_for_drop(&self, session: &crate::oob::OobSession);
    fn decrypt_entry_for_test(
        &self,
        aes_key: &[u8],
        b64: &str,
    ) -> Result<Option<crate::oob::Interaction>, crate::oob::InteractshError>;
    fn oob_collector_ssrf_check_dns_result(
        &self,
        server: &str,
        resolved: std::io::Result<Vec<std::net::SocketAddr>>,
    ) -> Result<(), crate::oob::InteractshError>;
    /// `Ok(true)` = plan reuses the proxy client, `Ok(false)` = pins a
    /// direct client, `Err` = the resolved-IP screen rejected the host.
    /// Proves the proxied path screens resolved IPs (proxy-SSRF fix).
    fn oob_collector_reuses_proxy_client(
        &self,
        server: &str,
        proxy_in_use: bool,
        resolved: std::io::Result<Vec<std::net::SocketAddr>>,
    ) -> Result<bool, crate::oob::InteractshError>;
    /// The freshly-created rate-limit slot's initial `last_request`,
    /// clamped with `checked_sub` so a low-uptime host cannot panic.
    fn rate_limiter_initial_last_request(
        &self,
        now: std::time::Instant,
        interval: Duration,
    ) -> std::time::Instant;
    fn rate_limiter_burst_waits(
        &self,
        interval: Duration,
        burst: usize,
        reservations: usize,
    ) -> Vec<Option<Duration>>;
    fn retry_loop_preserves_metadata_on_exhaustion(
        &self,
    ) -> impl std::future::Future<
        Output = (keyhog_core::VerificationResult, HashMap<String, String>),
    > + Send;
    fn retry_delay_bounds_for_attempt(&self, attempt: usize, base_delay_ms: u64) -> (u64, u64);
    fn multi_step_rate_limit_service_name<'a>(
        &self,
        spec: &'a keyhog_core::VerifySpec,
        auth: &'a keyhog_core::AuthSpec,
    ) -> &'a str;
    fn evaluate_success_for_test(
        &self,
        spec: &keyhog_core::SuccessSpec,
        status: u16,
        body: &str,
    ) -> bool;
    fn evaluate_success_result_for_test(
        &self,
        spec: &keyhog_core::SuccessSpec,
        status: u16,
        body: &str,
    ) -> Result<bool, String>;
    fn body_indicates_error_for_test(&self, body: &str) -> bool;
    fn extract_metadata_for_test(
        &self,
        specs: &[keyhog_core::MetadataSpec],
        body: &str,
    ) -> Result<HashMap<String, String>, String>;
    fn retryable_http_status_for_test(&self, status: u16) -> bool;
    fn success_spec_is_explicit_for_test(&self, spec: &keyhog_core::SuccessSpec) -> bool;
    fn resolve_live_verdict_for_test(
        &self,
        is_live: bool,
        success_is_explicit: bool,
        body: &str,
    ) -> bool;
    fn record_inflight_cap_bypass_for_test(&self, max_inflight_keys: usize) -> usize;
    fn verification_result_is_cacheable_for_test(
        &self,
        result: &keyhog_core::VerificationResult,
    ) -> bool;
    fn ssrf_check_url_with_resolved_addrs_for_test(
        &self,
        raw_url: &str,
        addrs: &[std::net::SocketAddr],
        allow_private_ips: bool,
    ) -> Result<(), keyhog_core::VerificationResult>;
    fn proxied_request_target_for_test(
        &self,
        raw_url: &str,
        allow_private_ips: bool,
        allow_http: bool,
    ) -> impl std::future::Future<Output = Result<(), keyhog_core::VerificationResult>> + Send;
    fn clear_pinned_request_client_cache(&self);
    fn pinned_request_client_cache_len(&self) -> usize;
    fn pinned_request_client_cache_len_for_host(&self, host: &str) -> usize;
    fn pinned_request_client_for_test(
        &self,
        host: &str,
        addrs: &[std::net::SocketAddr],
        timeout: Duration,
        insecure_tls: bool,
    ) -> Result<(), keyhog_core::VerificationResult>;
    fn build_finding(
        &self,
        group: keyhog_core::DedupedMatch,
        verification: keyhog_core::VerificationResult,
        metadata: HashMap<String, String>,
    ) -> keyhog_core::VerifiedFinding;
    /// Drive the REAL outbound header/body interpolation boundary
    /// (`verify::request::apply_header_body_templates`) end to end and return
    /// the *built* `reqwest::Request`'s final header set (as `(name, value)`
    /// UTF-8-lossy pairs) and body. Unlike `interpolate_http_value`, which
    /// tests the sanitizer in isolation, this proves the sanitizer is
    /// actually WIRED into the request builder: a regression that attached a
    /// raw `header.value` (bypassing interpolation) would surface here, not in
    /// a helper-only test. `header_templates` are `(name, value-template)`
    /// pairs; the credential is interpolated into each value template.
    fn built_request_header_body_for_test(
        &self,
        header_templates: &[(&str, &str)],
        body_template: Option<&str>,
        credential: &str,
        companions: &HashMap<String, String>,
    ) -> (Vec<(String, String)>, Option<String>);
}

impl VerifierTestApi for TestApi {
    const OOB_COMPANION_URL: &'static str = crate::interpolate::OOB_COMPANION_URL;
    const OOB_COMPANION_HOST: &'static str = crate::interpolate::OOB_COMPANION_HOST;
    const OOB_COMPANION_ID: &'static str = crate::interpolate::OOB_COMPANION_ID;

    fn ip_addr_is_bogon(&self, ip: std::net::IpAddr) -> bool {
        crate::bogon::ip_addr_is_bogon(ip)
    }

    fn resolve_field(
        &self,
        field: &str,
        credential: &str,
        companions: &HashMap<String, String>,
    ) -> String {
        crate::interpolate::resolve_field(field, credential, companions)
    }

    fn sanitize_oob_value(&self, s: &str) -> String {
        crate::interpolate::sanitize_oob_value(s)
    }

    fn sanitize_raw_value(&self, s: &str) -> String {
        crate::interpolate::sanitize_raw_value(s)
    }

    fn interpolate(
        &self,
        template: &str,
        credential: &str,
        companions: &HashMap<String, String>,
    ) -> String {
        crate::interpolate::interpolate(template, credential, companions)
    }

    fn interpolate_url(
        &self,
        template: &str,
        credential: &str,
        companions: &HashMap<String, String>,
    ) -> String {
        crate::interpolate::interpolate_url(template, credential, companions)
    }

    fn interpolate_http_value(
        &self,
        template: &str,
        credential: &str,
        companions: &HashMap<String, String>,
    ) -> String {
        crate::interpolate::interpolate_http_value(template, credential, companions)
    }

    fn companions_with_oob(
        &self,
        base: &HashMap<String, String>,
        minted_host: &str,
        minted_url: &str,
        minted_id: &str,
    ) -> HashMap<String, String> {
        crate::interpolate::companions_with_oob(base, minted_host, minted_url, minted_id)
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect()
    }

    fn built_request_header_body_for_test(
        &self,
        header_templates: &[(&str, &str)],
        body_template: Option<&str>,
        credential: &str,
        companions: &HashMap<String, String>,
    ) -> (Vec<(String, String)>, Option<String>) {
        let client = reqwest::Client::new();
        // A fixed, non-routable target: the request is BUILT, never sent, so
        // no traffic leaves the test, only the assembled header/body bytes
        // are inspected.
        let builder = client.post("https://verify.example.invalid/probe");
        let specs: Vec<keyhog_core::HeaderSpec> = header_templates
            .iter()
            .map(|(name, value)| keyhog_core::HeaderSpec {
                name: (*name).to_string(),
                value: (*value).to_string(),
            })
            .collect();
        let builder = crate::verify::request::apply_header_body_templates(
            builder,
            &specs,
            body_template,
            credential,
            companions,
        );
        let request = builder
            .build()
            .expect("a sanitized verification request must always build");
        let headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        (headers, body)
    }

    fn builtin_service_domains(
        &self,
    ) -> &'static HashMap<&'static str, &'static [&'static str]> {
        crate::domain_allowlist::builtin_service_domains()
    }

    fn effective_allowlist(&self, spec: &keyhog_core::VerifySpec) -> Option<Vec<String>> {
        crate::domain_allowlist::effective_allowlist(spec)
    }

    fn host_is_allowed(&self, host: &str, allowlist: &[String]) -> bool {
        crate::domain_allowlist::host_is_allowed(host, allowlist)
    }

    fn check_url_against_spec(
        &self,
        raw_url: &str,
        spec: &keyhog_core::VerifySpec,
    ) -> Result<(), String> {
        crate::domain_allowlist::check_url_against_spec(raw_url, spec)
    }

    fn engine_detector_verify_service(
        &self,
        engine: &crate::VerificationEngine,
        detector_id: &str,
    ) -> Option<String> {
        engine
            .detectors
            .get(detector_id)
            .and_then(|detector| detector.verify.as_ref())
            .map(|verify| verify.service.clone())
    }

    fn engine_inflight_count(&self, engine: &crate::VerificationEngine) -> usize {
        engine
            .inflight_count
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn format_sigv4_timestamps(&self, unix_secs: u64) -> (String, String) {
        crate::sigv4::format_sigv4_timestamps(unix_secs)
    }

    fn parse_aws_sts_success_metadata(
        &self,
        body: &str,
    ) -> Result<HashMap<String, String>, String> {
        crate::verify::parse_aws_sts_success_metadata(body)
    }

    fn classify_aws_sts_failure(
        &self,
        status: u16,
        body: &str,
    ) -> (keyhog_core::VerificationResult, bool) {
        crate::verify::classify_aws_sts_failure(status, body)
    }

    fn classify_aws_sts_http_200(
        &self,
        body: &str,
    ) -> (
        keyhog_core::VerificationResult,
        HashMap<String, String>,
        bool,
    ) {
        crate::verify::classify_aws_sts_http_200(body)
    }

    fn script_auth_result_for_test(&self, output: &str) -> keyhog_core::VerificationResult {
        crate::verify::script_auth_result(output)
    }

    fn valid_aws_format_for_test(&self, access_key: &str, secret_key: &str) -> bool {
        crate::verify::valid_aws_format(access_key, secret_key)
    }

    fn validate_aws_region_for_test(
        &self,
        region: &str,
    ) -> Result<(), keyhog_core::VerificationResult> {
        crate::verify::validate_aws_region(region)
    }

    async fn build_aws_probe_final_for_test(
        &self,
        access_key: &str,
        secret_key: &str,
        region: &str,
    ) -> (
        keyhog_core::VerificationResult,
        HashMap<String, String>,
        bool,
    ) {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("test verifier client builds");
        let companions = HashMap::<String, String>::new();
        match crate::verify::build_aws_probe(
            access_key,
            secret_key,
            &None,
            region,
            access_key,
            &companions,
            Duration::from_millis(10),
            &client,
            false,
            false,
            false,
            false,
        )
        .await
        {
            crate::verify::RequestBuildResult::Final {
                result,
                metadata,
                transient,
            } => (result, metadata, transient),
            crate::verify::RequestBuildResult::Ready(_) => {
                panic!("AWS probe preflight unexpectedly reached network-ready request")
            }
        }
    }

    fn rate_limit_feedback_sequence(&self) -> (usize, usize, usize, usize, usize) {
        crate::verify::rate_limit_feedback_sequence_for_test()
    }

    async fn retry_loop_records_rate_limit_feedback(&self) -> usize {
        crate::verify::retry_loop_records_rate_limit_feedback_for_test().await
    }

    fn interactsh_client_for_test(
        &self,
        server: &str,
    ) -> Result<crate::oob::InteractshClient, crate::oob::InteractshError> {
        crate::oob::InteractshClient::for_test(server)
    }

    fn interactsh_client_correlation_id<'a>(
        &self,
        client: &'a crate::oob::InteractshClient,
    ) -> &'a str {
        client.correlation_id()
    }

    fn interactsh_client_mint_url(
        &self,
        client: &crate::oob::InteractshClient,
    ) -> TestMintedUrl {
        test_minted_url(client.mint_url())
    }

    fn oob_session_for_test(
        &self,
        client: Arc<crate::oob::InteractshClient>,
        config: crate::oob::OobConfig,
    ) -> Arc<crate::oob::OobSession> {
        crate::oob::OobSession::for_test(client, config)
    }

    fn engine_set_oob_session_for_test(
        &self,
        engine: &mut crate::VerificationEngine,
        session: Arc<crate::oob::OobSession>,
    ) {
        engine.oob_session = Some(session);
    }

    fn oob_session_mint(&self, session: &crate::oob::OobSession) -> TestMintedUrl {
        test_minted_url(session.mint())
    }

    fn oob_session_default_timeout(&self, session: &crate::oob::OobSession) -> Duration {
        session.config_default_timeout()
    }

    fn oob_session_set_degraded_for_test(
        &self,
        session: &crate::oob::OobSession,
        degraded: bool,
    ) {
        session.set_degraded_for_test(degraded);
    }

    fn oob_session_store_and_notify(
        &self,
        session: &crate::oob::OobSession,
        interaction: crate::oob::Interaction,
    ) {
        session.store_and_notify_for_test(interaction);
    }

    fn oob_session_waiter_count(&self, session: &crate::oob::OobSession) -> usize {
        session.waiter_count_for_test()
    }

    fn oob_session_active_waiter_count(&self, session: &crate::oob::OobSession) -> usize {
        session.active_waiter_count_for_test()
    }

    fn oob_session_poll_generation(&self, session: &crate::oob::OobSession) -> u64 {
        session.poll_generation_for_test()
    }

    fn oob_session_abort_poller_for_drop(&self, session: &crate::oob::OobSession) {
        session.abort_poller_for_drop();
    }

    fn decrypt_entry_for_test(
        &self,
        aes_key: &[u8],
        b64: &str,
    ) -> Result<Option<crate::oob::Interaction>, crate::oob::InteractshError> {
        crate::oob::decrypt_entry_for_test(aes_key, b64)
    }

    fn oob_collector_ssrf_check_dns_result(
        &self,
        server: &str,
        resolved: std::io::Result<Vec<std::net::SocketAddr>>,
    ) -> Result<(), crate::oob::InteractshError> {
        crate::oob::ssrf_check_collector_dns_result_for_test(server, resolved)
    }

    fn oob_collector_reuses_proxy_client(
        &self,
        server: &str,
        proxy_in_use: bool,
        resolved: std::io::Result<Vec<std::net::SocketAddr>>,
    ) -> Result<bool, crate::oob::InteractshError> {
        crate::oob::collector_reuses_proxy_client_for_test(server, proxy_in_use, resolved)
    }

    fn rate_limiter_initial_last_request(
        &self,
        now: std::time::Instant,
        interval: Duration,
    ) -> std::time::Instant {
        crate::rate_limit::initial_last_request(now, interval)
    }

    fn rate_limiter_burst_waits(
        &self,
        interval: Duration,
        burst: usize,
        reservations: usize,
    ) -> Vec<Option<Duration>> {
        crate::rate_limit::burst_reservation_waits_for_test(interval, burst, reservations)
    }

    async fn retry_loop_preserves_metadata_on_exhaustion(
        &self,
    ) -> (keyhog_core::VerificationResult, HashMap<String, String>) {
        crate::verify::retry_loop_preserves_metadata_on_exhaustion_for_test().await
    }

    fn retry_delay_bounds_for_attempt(&self, attempt: usize, base_delay_ms: u64) -> (u64, u64) {
        crate::verify::retry_delay_bounds_for_attempt(attempt, base_delay_ms)
    }

    fn multi_step_rate_limit_service_name<'a>(
        &self,
        spec: &'a keyhog_core::VerifySpec,
        auth: &'a keyhog_core::AuthSpec,
    ) -> &'a str {
        crate::verify::multi_step_rate_limit_service_name(spec, auth)
    }

    fn evaluate_success_for_test(
        &self,
        spec: &keyhog_core::SuccessSpec,
        status: u16,
        body: &str,
    ) -> bool {
        crate::verify::evaluate_success(spec, status, body)
            .expect("success contract should evaluate cleanly")
    }

    fn evaluate_success_result_for_test(
        &self,
        spec: &keyhog_core::SuccessSpec,
        status: u16,
        body: &str,
    ) -> Result<bool, String> {
        crate::verify::evaluate_success(spec, status, body).map_err(|error| error.to_string())
    }

    fn body_indicates_error_for_test(&self, body: &str) -> bool {
        crate::verify::body_indicates_error(body)
    }

    fn extract_metadata_for_test(
        &self,
        specs: &[keyhog_core::MetadataSpec],
        body: &str,
    ) -> Result<HashMap<String, String>, String> {
        crate::verify::extract_provider_evidence(specs, body).map_err(|error| error.to_string())
    }

    fn retryable_http_status_for_test(&self, status: u16) -> bool {
        crate::verify::retryable_http_status(status)
    }

    fn success_spec_is_explicit_for_test(&self, spec: &keyhog_core::SuccessSpec) -> bool {
        crate::verify::success_spec_is_explicit(spec)
    }

    fn resolve_live_verdict_for_test(
        &self,
        is_live: bool,
        success_is_explicit: bool,
        body: &str,
    ) -> bool {
        crate::verify::resolve_live_verdict(is_live, success_is_explicit, body)
    }

    fn record_inflight_cap_bypass_for_test(&self, max_inflight_keys: usize) -> usize {
        crate::verify::note_inflight_cap_bypass(max_inflight_keys)
    }

    fn verification_result_is_cacheable_for_test(
        &self,
        result: &keyhog_core::VerificationResult,
    ) -> bool {
        crate::verify::verification_result_is_cacheable(result)
    }

    fn ssrf_check_url_with_resolved_addrs_for_test(
        &self,
        raw_url: &str,
        addrs: &[std::net::SocketAddr],
        allow_private_ips: bool,
    ) -> Result<(), keyhog_core::VerificationResult> {
        crate::verify::ssrf_check_url_with_resolved_addrs_for_test(
            raw_url,
            addrs,
            allow_private_ips,
        )
    }

    async fn proxied_request_target_for_test(
        &self,
        raw_url: &str,
        allow_private_ips: bool,
        allow_http: bool,
    ) -> Result<(), keyhog_core::VerificationResult> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("test verifier client builds");
        crate::verify::resolved_client_for_url(
            &client,
            raw_url,
            Duration::from_millis(10),
            allow_private_ips,
            allow_http,
            true,
            false,
        )
        .await
        .map(|_| ())
    }

    fn clear_pinned_request_client_cache(&self) {
        crate::verify::clear_pinned_client_cache_for_test();
    }

    fn pinned_request_client_cache_len(&self) -> usize {
        crate::verify::pinned_client_cache_len_for_test()
    }

    fn pinned_request_client_cache_len_for_host(&self, host: &str) -> usize {
        crate::verify::pinned_client_cache_len_for_host_for_test(host)
    }

    fn pinned_request_client_for_test(
        &self,
        host: &str,
        addrs: &[std::net::SocketAddr],
        timeout: Duration,
        insecure_tls: bool,
    ) -> Result<(), keyhog_core::VerificationResult> {
        crate::verify::pinned_client_for_test(host, addrs, timeout, insecure_tls)
    }

    fn build_finding(
        &self,
        group: keyhog_core::DedupedMatch,
        verification: keyhog_core::VerificationResult,
        metadata: HashMap<String, String>,
    ) -> keyhog_core::VerifiedFinding {
        crate::into_finding(group, verification, metadata)
    }
}
