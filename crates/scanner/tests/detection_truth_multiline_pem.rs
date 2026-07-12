//! Detection-truth: MULTILINE PEM private keys (#177/#184). Private keys are the
//! highest-severity leak class and span many lines. keyhog's multiline pass must
//! detect every PEM variant (RSA/EC/OpenSSH/PKCS8/DSA/encrypted/PGP) as a
//! Critical crypto private-key, and must NOT mislabel a PGP block as SSH. Law 6
//! (detector id + service + severity). Requires the `multiline` feature; ML-
//! independent; run without `ml` while the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

const BODY: &str = "MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN\n\
                    OPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP";

fn detector_ids(text: &str) -> Vec<(String, String, String)> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "pem-test".into(),
            path: Some("id_rsa".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| {
            (
                m.detector_id.to_string(),
                m.service.to_string(),
                format!("{:?}", m.severity),
            )
        })
        .collect()
}

fn pem(kind: &str) -> String {
    format!("-----BEGIN {kind}-----\n{BODY}\n-----END {kind}-----")
}

fn assert_crypto_private_key(kind: &str) {
    let ids = detector_ids(&pem(kind));
    assert!(
        ids.iter()
            .any(|(id, svc, sev)| id == "private-key" && svc == "crypto" && sev == "Critical"),
        "PEM `{kind}` must fire private-key/crypto/Critical; got {ids:?}"
    );
}

#[test]
fn rsa_private_key_is_critical_crypto() {
    assert_crypto_private_key("RSA PRIVATE KEY");
}

#[test]
fn ec_private_key_is_critical_crypto() {
    assert_crypto_private_key("EC PRIVATE KEY");
}

#[test]
fn openssh_private_key_is_critical_crypto() {
    assert_crypto_private_key("OPENSSH PRIVATE KEY");
}

#[test]
fn pkcs8_private_key_is_critical_crypto() {
    assert_crypto_private_key("PRIVATE KEY");
}

#[test]
fn dsa_private_key_is_critical_crypto() {
    assert_crypto_private_key("DSA PRIVATE KEY");
}

#[test]
fn encrypted_private_key_is_critical_crypto() {
    assert_crypto_private_key("ENCRYPTED PRIVATE KEY");
}

#[test]
fn pgp_private_key_block_is_critical_crypto() {
    assert_crypto_private_key("PGP PRIVATE KEY BLOCK");
}

#[test]
fn rsa_pem_also_flags_ssh_private_key() {
    let ids = detector_ids(&pem("RSA PRIVATE KEY"));
    assert!(
        ids.iter()
            .any(|(id, svc, _)| id == "ssh-private-key" && svc == "ssh"),
        "RSA PEM should also fire ssh-private-key/ssh; got {ids:?}"
    );
}

#[test]
fn pgp_block_is_not_mislabeled_as_ssh() {
    // A PGP private key is not an SSH key — precision: ssh-private-key must NOT fire.
    let ids = detector_ids(&pem("PGP PRIVATE KEY BLOCK"));
    assert!(
        !ids.iter().any(|(id, _, _)| id == "ssh-private-key"),
        "PGP block must not be mislabeled as ssh-private-key; got {ids:?}"
    );
}
