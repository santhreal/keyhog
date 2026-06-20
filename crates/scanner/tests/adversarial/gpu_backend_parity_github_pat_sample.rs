//! Live GPU backend must match CPU fallback on github PAT sample.

#[path = "gpu_backend_support.rs"]
mod gpu_backend_support;
use gpu_backend_support::assert_cpu_gpu_backend_parity;

#[test]
fn gpu_backend_parity_github_pat_sample() {
    assert_cpu_gpu_backend_parity(
        "GH_TOKEN=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\n",
        "adversarial/github.env",
        "github PAT sample",
    );
}
