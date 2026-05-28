//! Megakernel GPU path must match CPU fallback on aws AKIA sample (KH-GAP-043 extension).

#[path = "megakernel_support.rs"]
mod megakernel_support;
use megakernel_support::assert_cpu_megakernel_parity;

#[test]
fn megakernel_cpu_parity_aws_sample() {
    assert_cpu_megakernel_parity(
        "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n",
        "adversarial/aws.env",
        "aws AKIA sample",
    );
}
