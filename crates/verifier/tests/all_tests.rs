#![allow(clippy::field_reassign_with_default, clippy::needless_update)]

mod common;

pub mod adversarial;
pub mod boundary;
pub mod contract;
pub mod error_path;
pub mod gap;
pub mod gate;
pub mod integration;
pub mod property;
pub mod regression;
pub mod unit;

// Standalone top-level `tests/*.rs` files. CI runs the verifier suite ONLY via
// `cargo test -p keyhog-verifier --test all_tests`, so a `tests/*.rs` file that
// is NOT aggregated here (and not named by a `--test <name>` CI step) is a
// CI-orphan: it compiles as its own separate test target that the CI step never
// invokes, its `#[test]`s never run, and the regression it guards can ship
// silently. These were exactly that — including the AWS SigV4 byte-exact
// known-answer locks (a wrong signature → false `Dead` verdict) and the SSRF
// short-form-IP blocklist — so they are pulled into the aggregated target here.
//
// EXCEPTION: `break_it.rs` is NOT aggregated. It is a fuzz file of engine tests
// that drive `verify_all` through the PROCESS-GLOBAL `GLOBAL_RATE_LIMITER` on a
// shared `service: "test"` slot with tight per-test watchdogs; those isolation
// assumptions only hold when it runs as its own SERIAL target. Aggregating it
// into this parallel binary makes it flaky (a delayed rate-limiter slot trips a
// 5 s watchdog). It instead runs via an explicit serial CI step
// (`cargo test -p keyhog-verifier --test break_it -- --test-threads=1`), which
// `scripts/gates/tests_wired.py` counts as wired via the `--test` flag.
//
// The gate fails the build if any top-level `tests/*.rs` becomes orphaned again.
// Keep sorted.
#[path = "new_verifier_allowlist_cache.rs"]
pub mod new_verifier_allowlist_cache;
#[path = "new_verifier_bogon_ssrf.rs"]
pub mod new_verifier_bogon_ssrf;
#[path = "new_verifier_interpolate.rs"]
pub mod new_verifier_interpolate;
#[path = "regression_sigv4_asia_security_token.rs"]
pub mod regression_sigv4_asia_security_token;
#[path = "regression_sigv4_known_answer.rs"]
pub mod regression_sigv4_known_answer;
#[path = "regression_ssrf_short_form_ip.rs"]
pub mod regression_ssrf_short_form_ip;
#[path = "regression_verify_error_fix_guidance.rs"]
pub mod regression_verify_error_fix_guidance;
#[path = "regression_verify_error_taxonomy.rs"]
pub mod regression_verify_error_taxonomy;
#[path = "regression_verify_reason_ux_contract.rs"]
pub mod regression_verify_reason_ux_contract;
#[path = "regression_verify_response_body_error_guidance.rs"]
pub mod regression_verify_response_body_error_guidance;
#[path = "regression_verify_severity_downgrade.rs"]
pub mod regression_verify_severity_downgrade;
#[path = "verifier_safety_contracts.rs"]
pub mod verifier_safety_contracts;
#[path = "verify_join_error_contract.rs"]
pub mod verify_join_error_contract;
