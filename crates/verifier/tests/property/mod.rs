//! Property / invariant coverage for the verifier, aggregated into the
//! `all_tests` target via `pub mod property;` so CI actually runs it.

pub mod check_url_against_spec_proptest;
pub mod domain_allowlist_proptest;
pub mod interpolate_fuzz_proptest;
pub mod rate_limiter_interval_proptest;
pub mod sigv4_canonical_stability_proptest;
pub mod ssrf_ip_screen_proptest;
