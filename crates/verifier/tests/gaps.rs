//! Aggregated coverage-gap + multi-OS dogfood tests (generated).
//! One binary so the many gap modules link once, isolated from all_tests.
#![allow(clippy::all)]
#[path = "gaps/oob_ratelimit.rs"]
mod oob_ratelimit;
#[path = "gaps/sigv4_signing.rs"]
mod sigv4_signing;
#[path = "gaps/ssrf_guard.rs"]
mod ssrf_guard;
