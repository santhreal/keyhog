//! Part 11 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Avalara, Avaya, AWeber, AWS CodeCommit, AWS Cognito, AWS ECR,
//! AWS Lambda Function URL, AWS Secrets Manager, AWS SES, and AWS Session Token
//! detectors against zero-width spaces, soft hyphens, combining marks, homoglyphs,
//! and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. AVALARA API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv11_avalara_normal_must_fire() {
    assert_detector_fires(
        "avalara-api-credentials",
        "avalara_license_key = \"abcde1234567890a\"",
        "abcde1234567890a",
    );
}

#[test]
fn adv11_avalara_wrong_prefix_must_silent() {
    assert_detector_silent(
        "avalara-api-credentials",
        "bvalara_license_key = \"abcde1234567890a\"",
    );
}

#[test]
fn adv11_avalara_evade_zwsp_must_fire() {
    assert_detector_fires(
        "avalara-api-credentials",
        "avalara\u{200B}_license_key = \"abcde1234567890a\"",
        "abcde1234567890a",
    );
}

#[test]
fn adv11_avalara_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "avalara-api-credentials",
        "avalara_license_key = \"abcde12345\u{00AD}67890a\"",
        "abcde1234567890a",
    );
}

#[test]
fn adv11_avalara_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "avalara-api-credentials",
        "av\u{0430}lara_license_key = \"abcde1234567890a\"",
        "abcde1234567890a",
    );
}

// =========================================================================
// 2. AVAYA API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv11_avaya_normal_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "avaya_apikey = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_avaya_wrong_prefix_must_silent() {
    assert_detector_silent(
        "avaya-api-credentials",
        "navaya_apikey = \"abcde1234567890abcde\"",
    );
}

#[test]
fn adv11_avaya_evade_zwsp_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "avaya\u{200B}_apikey = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_avaya_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "avaya_apikey = \"abcde12345\u{00AD}67890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_avaya_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "avaya-api-credentials",
        "av\u{0430}ya_apikey = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

// =========================================================================
// 3. AWEBER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv11_aweber_normal_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "aweber_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_aweber_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aweber-api-credentials",
        "baweber_token = \"abcde1234567890abcde\"",
    );
}

#[test]
fn adv11_aweber_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "aweber\u{200B}_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_aweber_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "aweber_token = \"abcde12345\u{00AD}67890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_aweber_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "aweber-api-credentials",
        "aw\u{0435}ber_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

// =========================================================================
// 4. AWS CODECOMMIT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv11_codecommit_normal_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit-username = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_codecommit_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-codecommit-credentials",
        "modecommit-username = \"abcde1234567890abcde\"",
    );
}

#[test]
fn adv11_codecommit_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit\u{200B}-username = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_codecommit_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecommit-username = \"abcde12345\u{00AD}67890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_codecommit_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "aws-codecommit-credentials",
        "codecomm\u{0456}t-username = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

// =========================================================================
// 5. AWS COGNITO CLIENT SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv11_cognito_normal_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET = \"abcde1234567890abcde1234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

#[test]
fn adv11_cognito_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-cognito-client-secret",
        "MOGNITO_CLIENT_SECRET = \"abcde1234567890abcde1234567890abcde12345\"",
    );
}

#[test]
fn adv11_cognito_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO\u{200B}_CLIENT_SECRET = \"abcde1234567890abcde1234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

#[test]
fn adv11_cognito_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "COGNITO_CLIENT_SECRET = \"abcde1234567890abcde1\u{00AD}234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

#[test]
fn adv11_cognito_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "aws-cognito-client-secret",
        "c\u{043E}gnito_client_secret = \"abcde1234567890abcde1234567890abcde12345\"",
        "abcde1234567890abcde1234567890abcde12345",
    );
}

// =========================================================================
// 6. AWS ECR AUTHORIZATION TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv11_ecr_normal_must_fire() {
    assert_detector_fires("aws-ecr-token", "AWS_ECR_PASSWORD = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde123456789012");
}

#[test]
fn adv11_ecr_wrong_prefix_must_silent() {
    assert_detector_silent("aws-ecr-token", "BWS_ECR_PASSWORD = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde123456789012\"");
}

#[test]
fn adv11_ecr_evade_zwsp_must_fire() {
    assert_detector_fires("aws-ecr-token", "AWS_ECR\u{200B}_PASSWORD = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde123456789012");
}

#[test]
fn adv11_ecr_evade_soft_hyphen_must_fire() {
    assert_detector_fires("aws-ecr-token", "AWS_ECR_PASSWORD = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde12345\u{00AD}67890abcde123456789012\"", "abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde123456789012");
}

#[test]
fn adv11_ecr_evade_homoglyph_must_fire() {
    assert_detector_fires("aws-ecr-token", "aws_ecr_p\u{0430}ssword = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde123456789012\"", "abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde123456789012");
}

// =========================================================================
// 7. AWS LAMBDA FUNCTION URL SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv11_lambda_normal_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "lambda_url_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_lambda_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-lambda-function-url-secret",
        "lamba_url_token = \"abcde1234567890abcde\"",
    );
}

#[test]
fn adv11_lambda_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "lambda_url\u{200B}_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_lambda_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "lambda_url_token = \"abcde12345\u{00AD}67890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv11_lambda_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "aws-lambda-function-url-secret",
        "lambd\u{0430}_url_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

// =========================================================================
// 8. AWS SECRETS MANAGER SECRET ARN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv11_secretsmanager_normal_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:MyTestSecret-ab12",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:MyTestSecret-ab12",
    );
}

#[test]
fn adv11_secretsmanager_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-secrets-manager-arn",
        "brn:aws:secretsmanager:us-east-1:123456789012:secret:MyTestSecret-ab12",
    );
}

#[test]
fn adv11_secretsmanager_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws\u{200B}:secretsmanager:us-east-1:123456789012:secret:MyTestSecret-ab12",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:MyTestSecret-ab12",
    );
}

#[test]
fn adv11_secretsmanager_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:MyTestSecret\u{00AD}-ab12",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:MyTestSecret-ab12",
    );
}

#[test]
fn adv11_secretsmanager_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "aws-secrets-manager-arn",
        "arn:aws:secretsmanag\u{0435}r:us-east-1:123456789012:secret:MyTestSecret-ab12",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:MyTestSecret-ab12",
    );
}

// =========================================================================
// 9. AWS SES SMTP CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv11_ses_normal_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "SES_SMTP_USERNAME = \"AKIA1234567890ABCDEF\"",
        "AKIA1234567890ABCDEF",
    );
}

#[test]
fn adv11_ses_wrong_prefix_must_silent() {
    assert_detector_silent(
        "aws-ses-smtp-credentials",
        "SES_SMTP_USERNAME = \"BKIA1234567890ABCDEF\"",
    );
}

#[test]
fn adv11_ses_evade_zwsp_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "SES_SMTP\u{200B}_USERNAME = \"AKIA1234567890ABCDEF\"",
        "AKIA1234567890ABCDEF",
    );
}

#[test]
fn adv11_ses_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "SES_SMTP_USERNAME = \"AKIA123456\u{00AD}7890ABCDEF\"",
        "AKIA1234567890ABCDEF",
    );
}

#[test]
fn adv11_ses_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "aws-ses-smtp-credentials",
        "ses_smtp_usern\u{0430}me = \"AKIA1234567890ABCDEF\"",
        "AKIA1234567890ABCDEF",
    );
}

// =========================================================================
// 10. AWS SESSION TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv11_sessiontoken_normal_must_fire() {
    assert_detector_fires("aws-session-token", "AWS_SESSION_TOKEN = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde123456789012\"", "AWS_SESSION_TOKEN = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde123456789012\"");
}

#[test]
fn adv11_sessiontoken_wrong_prefix_must_silent() {
    assert_detector_silent("aws-session-token", "BWS_SESSION_TOKEN = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde123456789012\"");
}

#[test]
fn adv11_sessiontoken_evade_zwsp_must_fire() {
    assert_detector_fires("aws-session-token", "AWS_SESSION\u{200B}_TOKEN = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde123456789012\"", "AWS_SESSION_TOKEN = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde123456789012\"");
}

#[test]
fn adv11_sessiontoken_evade_soft_hyphen_must_fire() {
    assert_detector_fires("aws-session-token", "AWS_SESSION_TOKEN = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde12345\u{00AD}6789012\"", "AWS_SESSION_TOKEN = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde123456789012\"");
}

#[test]
fn adv11_sessiontoken_evade_homoglyph_must_fire() {
    assert_detector_fires("aws-session-token", "aws_session_t\u{043E}ken = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde123456789012\"", "aws_session_token = \"abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde123456789012\"");
}
