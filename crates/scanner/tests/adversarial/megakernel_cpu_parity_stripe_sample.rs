//! Megakernel GPU path must match CPU fallback on stripe sk_live sample (KH-GAP-043 extension).

#[path = "megakernel_support.rs"]
mod megakernel_support;
use megakernel_support::assert_cpu_megakernel_parity;

#[test]
fn megakernel_cpu_parity_stripe_sample() {
    assert_cpu_megakernel_parity(
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD\n",
        "adversarial/stripe.env",
        "stripe sk_live sample",
    );
}
