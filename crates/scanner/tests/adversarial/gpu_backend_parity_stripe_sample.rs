//! Live GPU backend must match CPU fallback on stripe sk_live sample.

#[path = "gpu_backend_support.rs"]
mod gpu_backend_support;
use gpu_backend_support::assert_cpu_gpu_backend_parity;

/// Locks out adapter-contention regressions that made the macOS suite abort
/// before proving exact Stripe finding parity.
#[test]
fn gpu_backend_parity_stripe_sample() {
    assert_cpu_gpu_backend_parity(
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD\n",
        "adversarial/stripe.env",
        "stripe sk_live sample",
    );
}
