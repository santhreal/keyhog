//! Adversarial verifier tests grouped by failure surface.
#![allow(
    clippy::assertions_on_constants,
    clippy::needless_update,
    clippy::single_char_add_str
)]

include!("break_it_cases/cache_rate.rs");
include!("break_it_cases/mock_verify.rs");
include!("break_it_cases/json_aws_headers.rs");
include!("break_it_cases/ssrf.rs");
include!("break_it_cases/limits.rs");
