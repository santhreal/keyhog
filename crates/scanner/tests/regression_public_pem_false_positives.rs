//! Public PEM material is structured public data, not a credential.
//!
//! The scanner must suppress named and entropy candidates inside certificate and
//! public-key blocks while retaining private-key blocks and secrets outside them.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::CompiledScanner;

const CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBkTCB+wIJANRrU0E0X0gtMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNVBAMMBXRl\n\
c3QwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAwWjAQMQ4wDAYDVQQDDAV0\n\
ZXN0MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy\n\
-----END CERTIFICATE-----";
const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw7wL9gX0nP2qR5sT8uV1\n\
xY4zA7bC0dE3fG6hI9jK2lM5nO8pQ1rS4tU7vW0xY3zA6bC9dE2fG5hI8jK1lM4\n\
-----END PUBLIC KEY-----";
const PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIWPaVgC5bA8AjVWdjxNm\n\
-----END RSA PRIVATE KEY-----";
const GITHUB_TOKEN: &str = "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";

fn scan(text: &str, path: &str) -> Vec<RawMatch> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    scanner
        .scan(&Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some(path.into()),
                ..Default::default()
            },
        })
        .expect("scan PEM fixture")
}

fn detector_credentials(matches: &[RawMatch]) -> Vec<(String, String)> {
    matches
        .iter()
        .map(|finding| {
            (
                finding.detector_id.to_string(),
                finding.credential.to_string(),
            )
        })
        .collect()
}

/// Certificate body entropy must not turn a standard CA bundle into secret findings.
#[test]
fn certificate_block_reports_no_credentials() {
    let matches = scan(CERTIFICATE, "etc/ssl/certs/ca-certificates.crt");
    assert_eq!(
        detector_credentials(&matches),
        Vec::<(String, String)>::new()
    );
}

/// A public-key body uses the same base64 alphabet as private material but carries no secret.
#[test]
fn public_key_block_reports_no_credentials() {
    let matches = scan(PUBLIC_KEY, "etc/apk/keys/alpine-devel.rsa.pub");
    assert_eq!(
        detector_credentials(&matches),
        Vec::<(String, String)>::new()
    );
}

/// The public-block gate must never suppress a private key whose PEM label proves secret material.
#[test]
fn private_key_block_still_reports_exact_private_key() {
    let matches = scan(PRIVATE_KEY, "etc/ssl/private/server.key");
    let private_keys: Vec<_> = matches
        .iter()
        .filter(|finding| finding.detector_id.as_ref() == "private-key")
        .map(|finding| finding.credential.as_ref())
        .collect();
    assert_eq!(private_keys, vec![PRIVATE_KEY]);
}

/// A credential after a closed certificate block is outside public material and must remain visible.
#[test]
fn secret_after_certificate_block_still_reports() {
    let input = format!("{CERTIFICATE}\nGITHUB_TOKEN={GITHUB_TOKEN}\n");
    let matches = scan(&input, "config/combined.pem");
    let github: Vec<_> = matches
        .iter()
        .filter(|finding| finding.detector_id.as_ref() == "github-classic-pat")
        .map(|finding| finding.credential.as_ref())
        .collect();
    assert_eq!(github, vec![GITHUB_TOKEN]);
}

/// The context classifier must require a matching public END label, preventing an unterminated header from hiding the rest of a file.
#[test]
fn unterminated_public_block_does_not_suppress() {
    let input = format!("-----BEGIN CERTIFICATE-----\nMIIBfake\nGITHUB_TOKEN={GITHUB_TOKEN}\n");
    let offset = input.find(GITHUB_TOKEN).expect("token offset");
    assert!(
        !keyhog_scanner::testing::context::is_false_positive_match_context_for_test(
            &input, offset, None,
        )
    );
}
