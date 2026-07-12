//! Focused decode-through recall locks (task #107): a secret re-encoded as
//! base64 / hex / url-percent inside a config value must be recovered by the
//! decode pipeline and fire the SAME detector on the SAME credential.
//!
//! The aggregate strict gate lives in `adversarial_explosion_runner.rs`
//! (`every_contract_positive_fires_through_decode_wrappers`, ~5400 cases); this
//! file pins a readable per-detector × per-wrapper matrix with exact credential
//! assertions (Law 6), plus the decoder-alphabet and nesting boundaries.

mod support;
use support::paths::detector_dir;

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::CompiledScanner;

// ── checksum-free firing plaintexts (all are shipped contract positives) ──

/// PEM RSA private key — fires `private-key`, no vendor checksum.
const PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
    MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
    KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIWPaVgC5bA8AjVWdjxNm\n\
    -----END RSA PRIVATE KEY-----";
const PEM_NEEDLE: &str = "MIIBOgIBAAJBAKj34Gkx";

/// `.npmrc` legacy token — fires `npmrc-auth-token`.
const NPMRC: &str = "//registry.npmjs.org/:_authToken=s0meL3gacyT0kenValue12345";
const NPMRC_NEEDLE: &str = "s0meL3gacyT0kenValue12345";

/// `.netrc` triple — fires `netrc-password`.
const NETRC: &str = "machine api.example.com login deploy password Zx9Qw3Rt7Lp2Mk";
const NETRC_NEEDLE: &str = "Zx9Qw3Rt7Lp2Mk";

/// SSH2/ssh.com private key — fires `ssh2-private-key`.
const SSH2: &str = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n\
    Comment: \"2048-bit rsa\"\n\
    P2/56wAAAgISSH2DECODEbodybodybodybodybodybody0001base64base64\n\
    ---- END SSH2 ENCRYPTED PRIVATE KEY ----";
const SSH2_NEEDLE: &str = "SSH2DECODEbody";

// ── encoders (match the wrapper functions in the explosion runner) ──

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}
fn b64_urlsafe_nopad(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
}
fn hexenc(s: &str) -> String {
    use std::fmt::Write as _;
    let mut h = String::new();
    for b in s.bytes() {
        let _ = write!(h, "{b:02x}");
    }
    h
}
fn hexenc_upper(s: &str) -> String {
    use std::fmt::Write as _;
    let mut h = String::new();
    for b in s.bytes() {
        let _ = write!(h, "{b:02X}");
    }
    h
}
fn urlenc(s: &str) -> String {
    use std::fmt::Write as _;
    let mut u = String::new();
    for b in s.bytes() {
        let _ = write!(u, "%{b:02x}");
    }
    u
}

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

/// Embed `encoded` in a config value and scan; return the surfaced matches.
fn scan_embedded(encoded: &str) -> Vec<RawMatch> {
    let text = format!("decoded_payload = \"{encoded}\"\n");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "decode-through-test".into(),
            path: Some("config.txt".into()),
            ..Default::default()
        },
    };
    scanner().scan(&chunk)
}

fn surfaces(encoded: &str, needle: &str) -> bool {
    scan_embedded(encoded)
        .iter()
        .any(|m| m.credential.as_ref().contains(needle))
}

// ── BASELINE: each plaintext fires unwrapped (else the test proves nothing) ──

#[test]
fn baseline_pem_fires_unwrapped() {
    let chunk = Chunk {
        data: PEM.into(),
        metadata: ChunkMetadata {
            source_type: "x".into(),
            path: Some("id_rsa".into()),
            ..Default::default()
        },
    };
    assert!(scanner()
        .scan(&chunk)
        .iter()
        .any(|m| m.credential.as_ref().contains(PEM_NEEDLE)));
}

// ── PEM private key through every decode wrapper ──

#[test]
fn pem_fires_through_base64() {
    assert!(surfaces(&b64(PEM), PEM_NEEDLE));
}
#[test]
fn pem_fires_through_hex() {
    assert!(surfaces(&hexenc(PEM), PEM_NEEDLE));
}
#[test]
fn pem_fires_through_url() {
    assert!(surfaces(&urlenc(PEM), PEM_NEEDLE));
}

// ── npmrc token through every decode wrapper ──

#[test]
fn npmrc_fires_through_base64() {
    assert!(surfaces(&b64(NPMRC), NPMRC_NEEDLE));
}
#[test]
fn npmrc_fires_through_hex() {
    assert!(surfaces(&hexenc(NPMRC), NPMRC_NEEDLE));
}
#[test]
fn npmrc_fires_through_url() {
    assert!(surfaces(&urlenc(NPMRC), NPMRC_NEEDLE));
}

// ── netrc password through every decode wrapper ──

#[test]
fn netrc_fires_through_base64() {
    assert!(surfaces(&b64(NETRC), NETRC_NEEDLE));
}
#[test]
fn netrc_fires_through_hex() {
    assert!(surfaces(&hexenc(NETRC), NETRC_NEEDLE));
}
#[test]
fn netrc_fires_through_url() {
    assert!(surfaces(&urlenc(NETRC), NETRC_NEEDLE));
}

// ── SSH2 private key through every decode wrapper ──

#[test]
fn ssh2_fires_through_base64() {
    assert!(surfaces(&b64(SSH2), SSH2_NEEDLE));
}
#[test]
fn ssh2_fires_through_hex() {
    assert!(surfaces(&hexenc(SSH2), SSH2_NEEDLE));
}
#[test]
fn ssh2_fires_through_url() {
    assert!(surfaces(&urlenc(SSH2), SSH2_NEEDLE));
}

// ── decoder-alphabet flexibility ──

#[test]
fn base64_urlsafe_no_pad_alphabet_fires() {
    assert!(surfaces(&b64_urlsafe_nopad(NPMRC), NPMRC_NEEDLE));
}
#[test]
fn hex_uppercase_alphabet_fires() {
    assert!(surfaces(&hexenc_upper(NETRC), NETRC_NEEDLE));
}

// ── nesting ──

#[test]
fn double_base64_pem_fires() {
    // base64(base64(plaintext)) must still recover at decode depth 2.
    assert!(surfaces(&b64(&b64(PEM)), PEM_NEEDLE));
}
#[test]
fn base64_then_hex_nested_fires() {
    assert!(surfaces(&hexenc(&b64(NPMRC)), NPMRC_NEEDLE));
}

// ── precision: decode-through must not fabricate a finding from benign text ──

#[test]
fn base64_of_benign_prose_surfaces_no_private_key() {
    let benign = "the quick brown fox jumps over the lazy dog, nothing secret here at all";
    let matches = scan_embedded(&b64(benign));
    assert!(
        !matches
            .iter()
            .any(|m| m.detector_id.as_ref() == "private-key"),
        "benign decoded prose must not trip private-key"
    );
}
#[test]
fn hex_of_benign_prose_surfaces_no_netrc() {
    let benign = "machine readable documentation describing the login flow in prose form only";
    let matches = scan_embedded(&hexenc(benign));
    assert!(!matches
        .iter()
        .any(|m| m.detector_id.as_ref() == "netrc-password"));
}

// ── identity: the recovered credential is attributed to the right detector ──

#[test]
fn npmrc_through_base64_attributed_to_npmrc_detector() {
    let m = scan_embedded(&b64(NPMRC))
        .into_iter()
        .find(|m| m.credential.as_ref().contains(NPMRC_NEEDLE))
        .expect("npmrc token recovered through base64");
    assert_eq!(m.detector_id.as_ref(), "npmrc-auth-token");
}
#[test]
fn ssh2_through_base64_attributed_to_ssh2_detector() {
    let m = scan_embedded(&b64(SSH2))
        .into_iter()
        .find(|m| m.credential.as_ref().contains(SSH2_NEEDLE))
        .expect("ssh2 key recovered through base64");
    assert_eq!(m.detector_id.as_ref(), "ssh2-private-key");
}
