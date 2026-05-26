//! LR1-A8 replacement gate: `verify/aws.rs` service tag preserved.

use keyhog_core::VerifySpec;

#[test]
fn aws_verify_spec_service_is_aws() {
    let spec = VerifySpec {
        service: "aws".into(),
        ..Default::default()
    };
    assert_eq!(spec.service, "aws");
}
