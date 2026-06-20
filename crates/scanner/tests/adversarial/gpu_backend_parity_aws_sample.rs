//! Live GPU backend must match CPU fallback on aws AKIA sample.

#[path = "gpu_backend_support.rs"]
mod gpu_backend_support;
use gpu_backend_support::assert_cpu_gpu_backend_parity;

#[test]
fn gpu_backend_parity_aws_sample() {
    assert_cpu_gpu_backend_parity(
        "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n",
        "adversarial/aws.env",
        "aws AKIA sample",
    );
}
