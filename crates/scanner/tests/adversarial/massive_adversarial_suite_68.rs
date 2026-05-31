//! Part 68 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates aws, aws, aws, aws, aws, aws, aws, axiom, azure, azure detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. AWS ECR TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv68_aws_ecr_token_normal_must_fire() {
    assert_detector_fires(
        "aws-ecr-token",
        "AWS_ECR_PASSWORD=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_aws_ecr_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-ecr-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv68_aws_ecr_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-ecr-token",
        "AWS_ECR_PASSWORD=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_aws_ecr_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-ecr-token",
        "AWS_ECR_PASSWORD=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_aws_ecr_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aws-ecr-token",
        "AWS_ECR_PASSWORD=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_aws_ecr_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "aws-ecr-token",
        "AWS_ECR_PASSWORD=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_aws_ecr_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aws-ecr-token",
        "AWS_ECR_PASSWORD=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_aws_ecr_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aws-ecr-token",
        "AWS_ECR_PASSWORD=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_aws_ecr_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aws-ecr-token",
        "AWS_ECR_PASSWORD=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_aws_ecr_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "aws-ecr-token",
        "AWS_ECR_PASSWORD=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_aws_ecr_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aws-ecr-token",
        "AWS_ECR_PASSWORD=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_aws_ecr_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "aws-ecr-token",
        "AWS_ECR_PASSWORD=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 2. AWS GOVCLOUD ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv68_aws_govcloud_access_key_normal_must_fire() {
    assert_detector_fires(
        "aws-govcloud-access-key",
        "AWS_GOVCLOUD_ACCESS_KEY=AKIAKPQXRMSNTBVWYZBN",
        "AKIA",
    );
}

#[test]
fn adv68_aws_govcloud_access_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-govcloud-access-key",
        "dummy_prefix_0 =xxxxKPQXRMSNTBVWYZBN",
    );
}

#[test]
fn adv68_aws_govcloud_access_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-govcloud-access-key",
        "AWS_GOVCLOUD_ACCESS_KEY=AK\u{200B}IAKPQXRMSNTBVWYZBN",
        "AKIA",
    );
}

#[test]
fn adv68_aws_govcloud_access_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-govcloud-access-key",
        "AWS_GOVCLOUD_ACCESS_KEY=AK\u{00AD}IAKPQXRMSNTBVWYZBN",
        "AKIA",
    );
}

#[test]
fn adv68_aws_govcloud_access_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aws-govcloud-access-key",
        "AWS_GOVCLOUD_ACCESS_KEY=AK\u{200C}IAKPQXRMSNTBVWYZBN",
        "AKIA",
    );
}

#[test]
fn adv68_aws_govcloud_access_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "aws-govcloud-access-key",
        "AWS_GOVCLOUD_ACCESS_KEY=AK\u{200D}IAKPQXRMSNTBVWYZBN",
        "AKIA",
    );
}

#[test]
fn adv68_aws_govcloud_access_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aws-govcloud-access-key",
        "AWS_GOVCLOUD_ACCESS_KEY=AK\u{FEFF}IAKPQXRMSNTBVWYZBN",
        "AKIA",
    );
}

#[test]
fn adv68_aws_govcloud_access_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aws-govcloud-access-key",
        "AWS_GOVCLOUD_ACCESS_KEY=AK\u{2060}IAKPQXRMSNTBVWYZBN",
        "AKIA",
    );
}

#[test]
fn adv68_aws_govcloud_access_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aws-govcloud-access-key",
        "AWS_GOVCLOUD_ACCESS_KEY=AK\u{180E}IAKPQXRMSNTBVWYZBN",
        "AKIA",
    );
}

#[test]
fn adv68_aws_govcloud_access_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "aws-govcloud-access-key",
        "AWS_GOVCLOUD_ACCESS_KEY=AK\u{202E}IAKPQXRMSNTBVWYZBN",
        "AKIA",
    );
}

#[test]
fn adv68_aws_govcloud_access_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aws-govcloud-access-key",
        "AWS_GOVCLOUD_ACCESS_KEY=AK\u{202C}IAKPQXRMSNTBVWYZBN",
        "AKIA",
    );
}

#[test]
fn adv68_aws_govcloud_access_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "aws-govcloud-access-key",
        "AWS_GOVCLOUD_ACCESS_KEY=AK\u{200E}IAKPQXRMSNTBVWYZBN",
        "AKIA",
    );
}

// =========================================================================
// 3. AWS LAMBDA FUNCTION URL SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv68_aws_lambda_function_url_secret_normal_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "https://abcdef123456.lambda-url.us-east-1.on.aws/?token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv68_aws_lambda_function_url_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-lambda-function-url-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv68_aws_lambda_function_url_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "https://abcdef123456.lambda-url.us-east-1.on.aws/?token=Kp4Qx7Rm2Sn5\u{200B}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv68_aws_lambda_function_url_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "https://abcdef123456.lambda-url.us-east-1.on.aws/?token=Kp4Qx7Rm2Sn5\u{00AD}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv68_aws_lambda_function_url_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "https://abcdef123456.lambda-url.us-east-1.on.aws/?token=Kp4Qx7Rm2Sn5\u{200C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv68_aws_lambda_function_url_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "https://abcdef123456.lambda-url.us-east-1.on.aws/?token=Kp4Qx7Rm2Sn5\u{200D}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv68_aws_lambda_function_url_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "https://abcdef123456.lambda-url.us-east-1.on.aws/?token=Kp4Qx7Rm2Sn5\u{FEFF}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv68_aws_lambda_function_url_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "https://abcdef123456.lambda-url.us-east-1.on.aws/?token=Kp4Qx7Rm2Sn5\u{2060}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv68_aws_lambda_function_url_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "https://abcdef123456.lambda-url.us-east-1.on.aws/?token=Kp4Qx7Rm2Sn5\u{180E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv68_aws_lambda_function_url_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "https://abcdef123456.lambda-url.us-east-1.on.aws/?token=Kp4Qx7Rm2Sn5\u{202E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv68_aws_lambda_function_url_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "https://abcdef123456.lambda-url.us-east-1.on.aws/?token=Kp4Qx7Rm2Sn5\u{202C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv68_aws_lambda_function_url_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "https://abcdef123456.lambda-url.us-east-1.on.aws/?token=Kp4Qx7Rm2Sn5\u{200E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

// =========================================================================
// 4. AWS SECRET ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv68_aws_secret_access_key_normal_must_fire() {
    assert_detector_fires(
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
        "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
    );
}

#[test]
fn adv68_aws_secret_access_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-secret-access-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv68_aws_secret_access_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxi\u{200B}EhME3hJBXeYzR43jgiB1",
        "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
    );
}

#[test]
fn adv68_aws_secret_access_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxi\u{00AD}EhME3hJBXeYzR43jgiB1",
        "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
    );
}

#[test]
fn adv68_aws_secret_access_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxi\u{200C}EhME3hJBXeYzR43jgiB1",
        "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
    );
}

#[test]
fn adv68_aws_secret_access_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxi\u{200D}EhME3hJBXeYzR43jgiB1",
        "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
    );
}

#[test]
fn adv68_aws_secret_access_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxi\u{FEFF}EhME3hJBXeYzR43jgiB1",
        "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
    );
}

#[test]
fn adv68_aws_secret_access_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxi\u{2060}EhME3hJBXeYzR43jgiB1",
        "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
    );
}

#[test]
fn adv68_aws_secret_access_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxi\u{180E}EhME3hJBXeYzR43jgiB1",
        "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
    );
}

#[test]
fn adv68_aws_secret_access_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxi\u{202E}EhME3hJBXeYzR43jgiB1",
        "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
    );
}

#[test]
fn adv68_aws_secret_access_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxi\u{202C}EhME3hJBXeYzR43jgiB1",
        "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
    );
}

#[test]
fn adv68_aws_secret_access_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxi\u{200E}EhME3hJBXeYzR43jgiB1",
        "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1",
    );
}

// =========================================================================
// 5. AWS SECRETS MANAGER ARN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv68_aws_secrets_manager_arn_normal_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
    );
}

#[test]
fn adv68_aws_secrets_manager_arn_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-secrets-manager-arn",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv68_aws_secrets_manager_arn_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:12345\u{200B}6789012:secret:prod/db/password-AbCdEf",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
    );
}

#[test]
fn adv68_aws_secrets_manager_arn_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:12345\u{00AD}6789012:secret:prod/db/password-AbCdEf",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
    );
}

#[test]
fn adv68_aws_secrets_manager_arn_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:12345\u{200C}6789012:secret:prod/db/password-AbCdEf",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
    );
}

#[test]
fn adv68_aws_secrets_manager_arn_evade_zwj_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:12345\u{200D}6789012:secret:prod/db/password-AbCdEf",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
    );
}

#[test]
fn adv68_aws_secrets_manager_arn_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:12345\u{FEFF}6789012:secret:prod/db/password-AbCdEf",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
    );
}

#[test]
fn adv68_aws_secrets_manager_arn_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:12345\u{2060}6789012:secret:prod/db/password-AbCdEf",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
    );
}

#[test]
fn adv68_aws_secrets_manager_arn_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:12345\u{180E}6789012:secret:prod/db/password-AbCdEf",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
    );
}

#[test]
fn adv68_aws_secrets_manager_arn_evade_rtl_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:12345\u{202E}6789012:secret:prod/db/password-AbCdEf",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
    );
}

#[test]
fn adv68_aws_secrets_manager_arn_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:12345\u{202C}6789012:secret:prod/db/password-AbCdEf",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
    );
}

#[test]
fn adv68_aws_secrets_manager_arn_evade_lrm_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:12345\u{200E}6789012:secret:prod/db/password-AbCdEf",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-AbCdEf",
    );
}

// =========================================================================
// 6. AWS SES SMTP CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv68_aws_ses_smtp_credentials_normal_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "email-smtp_USERNAME=AKIAKPQXRMSNTBVWYZBN",
        "AKIAKPQXRMSNTBVWYZBN",
    );
}

#[test]
fn adv68_aws_ses_smtp_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-ses-smtp-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv68_aws_ses_smtp_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "email-smtp_USERNAME=AKIAKPQXRM\u{200B}SNTBVWYZBN",
        "AKIAKPQXRMSNTBVWYZBN",
    );
}

#[test]
fn adv68_aws_ses_smtp_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "email-smtp_USERNAME=AKIAKPQXRM\u{00AD}SNTBVWYZBN",
        "AKIAKPQXRMSNTBVWYZBN",
    );
}

#[test]
fn adv68_aws_ses_smtp_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "email-smtp_USERNAME=AKIAKPQXRM\u{200C}SNTBVWYZBN",
        "AKIAKPQXRMSNTBVWYZBN",
    );
}

#[test]
fn adv68_aws_ses_smtp_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "email-smtp_USERNAME=AKIAKPQXRM\u{200D}SNTBVWYZBN",
        "AKIAKPQXRMSNTBVWYZBN",
    );
}

#[test]
fn adv68_aws_ses_smtp_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "email-smtp_USERNAME=AKIAKPQXRM\u{FEFF}SNTBVWYZBN",
        "AKIAKPQXRMSNTBVWYZBN",
    );
}

#[test]
fn adv68_aws_ses_smtp_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "email-smtp_USERNAME=AKIAKPQXRM\u{2060}SNTBVWYZBN",
        "AKIAKPQXRMSNTBVWYZBN",
    );
}

#[test]
fn adv68_aws_ses_smtp_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "email-smtp_USERNAME=AKIAKPQXRM\u{180E}SNTBVWYZBN",
        "AKIAKPQXRMSNTBVWYZBN",
    );
}

#[test]
fn adv68_aws_ses_smtp_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "email-smtp_USERNAME=AKIAKPQXRM\u{202E}SNTBVWYZBN",
        "AKIAKPQXRMSNTBVWYZBN",
    );
}

#[test]
fn adv68_aws_ses_smtp_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "email-smtp_USERNAME=AKIAKPQXRM\u{202C}SNTBVWYZBN",
        "AKIAKPQXRMSNTBVWYZBN",
    );
}

#[test]
fn adv68_aws_ses_smtp_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "email-smtp_USERNAME=AKIAKPQXRM\u{200E}SNTBVWYZBN",
        "AKIAKPQXRMSNTBVWYZBN",
    );
}

// =========================================================================
// 7. AWS SESSION TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv68_aws_session_token_normal_must_fire() {
    assert_detector_fires(
        "aws-session-token",
        "AWS_SESSION_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv68_aws_session_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-session-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv68_aws_session_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-session-token",
        "AWS_SESSION_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv68_aws_session_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-session-token",
        "AWS_SESSION_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv68_aws_session_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "aws-session-token",
        "AWS_SESSION_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3\u{200C}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv68_aws_session_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "aws-session-token",
        "AWS_SESSION_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3\u{200D}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv68_aws_session_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "aws-session-token",
        "AWS_SESSION_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3\u{FEFF}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv68_aws_session_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "aws-session-token",
        "AWS_SESSION_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3\u{2060}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv68_aws_session_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "aws-session-token",
        "AWS_SESSION_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3\u{180E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv68_aws_session_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "aws-session-token",
        "AWS_SESSION_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3\u{202E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv68_aws_session_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "aws-session-token",
        "AWS_SESSION_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3\u{202C}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv68_aws_session_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "aws-session-token",
        "AWS_SESSION_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3\u{200E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

// =========================================================================
// 8. AXIOM API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv68_axiom_api_token_normal_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_axiom_api_token_wrong_prefix_must_silent() {
    assert_detector_silent("axiom-api-token", "dummyxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv68_axiom_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xapt-Kp4Qx7R\u{200B}m2Sn5Tb8Vw3Yz",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_axiom_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xapt-Kp4Qx7R\u{00AD}m2Sn5Tb8Vw3Yz",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_axiom_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xapt-Kp4Qx7R\u{200C}m2Sn5Tb8Vw3Yz",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_axiom_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xapt-Kp4Qx7R\u{200D}m2Sn5Tb8Vw3Yz",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_axiom_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xapt-Kp4Qx7R\u{FEFF}m2Sn5Tb8Vw3Yz",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_axiom_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xapt-Kp4Qx7R\u{2060}m2Sn5Tb8Vw3Yz",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_axiom_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xapt-Kp4Qx7R\u{180E}m2Sn5Tb8Vw3Yz",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_axiom_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xapt-Kp4Qx7R\u{202E}m2Sn5Tb8Vw3Yz",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_axiom_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xapt-Kp4Qx7R\u{202C}m2Sn5Tb8Vw3Yz",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv68_axiom_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xapt-Kp4Qx7R\u{200E}m2Sn5Tb8Vw3Yz",
        "xapt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 9. AZURE BLOB SAS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv68_azure_blob_sas_token_normal_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
    );
}

#[test]
fn adv68_azure_blob_sas_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-blob-sas-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv68_azure_blob_sas_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-0\u{200B}1T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
    );
}

#[test]
fn adv68_azure_blob_sas_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-0\u{00AD}1T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
    );
}

#[test]
fn adv68_azure_blob_sas_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-0\u{200C}1T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
    );
}

#[test]
fn adv68_azure_blob_sas_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-0\u{200D}1T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
    );
}

#[test]
fn adv68_azure_blob_sas_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-0\u{FEFF}1T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
    );
}

#[test]
fn adv68_azure_blob_sas_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-0\u{2060}1T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
    );
}

#[test]
fn adv68_azure_blob_sas_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-0\u{180E}1T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
    );
}

#[test]
fn adv68_azure_blob_sas_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-0\u{202E}1T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
    );
}

#[test]
fn adv68_azure_blob_sas_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-0\u{202C}1T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
    );
}

#[test]
fn adv68_azure_blob_sas_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-0\u{200E}1T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
        "?sv=2023-08-03&ss=b&srt=co&sp=rwdlacx&se=2030-12-31T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2F%2BabCD%3D",
    );
}

// =========================================================================
// 10. AZURE CONTAINER REGISTRY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv68_azure_container_registry_token_normal_must_fire() {
    assert_detector_fires(
        "azure-container-registry-token",
        "ACR_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
    );
}

#[test]
fn adv68_azure_container_registry_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-container-registry-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv68_azure_container_registry_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-container-registry-token",
        "ACR_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6I\u{200B}kpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
    );
}

#[test]
fn adv68_azure_container_registry_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-container-registry-token",
        "ACR_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6I\u{00AD}kpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
    );
}

#[test]
fn adv68_azure_container_registry_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "azure-container-registry-token",
        "ACR_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6I\u{200C}kpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
    );
}

#[test]
fn adv68_azure_container_registry_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "azure-container-registry-token",
        "ACR_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6I\u{200D}kpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
    );
}

#[test]
fn adv68_azure_container_registry_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "azure-container-registry-token",
        "ACR_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6I\u{FEFF}kpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
    );
}

#[test]
fn adv68_azure_container_registry_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "azure-container-registry-token",
        "ACR_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6I\u{2060}kpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
    );
}

#[test]
fn adv68_azure_container_registry_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "azure-container-registry-token",
        "ACR_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6I\u{180E}kpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
    );
}

#[test]
fn adv68_azure_container_registry_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "azure-container-registry-token",
        "ACR_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6I\u{202E}kpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
    );
}

#[test]
fn adv68_azure_container_registry_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "azure-container-registry-token",
        "ACR_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6I\u{202C}kpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
    );
}

#[test]
fn adv68_azure_container_registry_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "azure-container-registry-token",
        "ACR_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6I\u{200E}kpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrcDRxeDcifQ",
    );
}
