//! Megakernel GPU path must match CPU fallback on github PAT sample (KH-GAP-043 extension).

#[path = "megakernel_support.rs"]
mod megakernel_support;
use megakernel_support::assert_cpu_megakernel_parity;

#[test]
fn megakernel_cpu_parity_github_pat_sample() {
    assert_cpu_megakernel_parity(
        "GH_TOKEN=ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ\n",
        "adversarial/github.env",
        "github PAT sample",
    );
}
