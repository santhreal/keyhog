//! Recall lock: the `private-key` (PEM) detector must fire on EVERY PEM
//! private-key label its regex enumerates. RSA / EC / DSA / OPENSSH / PKCS#8
//! (`PRIVATE KEY`) / ENCRYPTED / PGP (`… BLOCK`).
//!
//! Why this matrix exists
//! ----------------------
//! `detectors/private-key.toml` enumerates the algorithm labels in an explicit
//! alternation specifically because, per its own comment. "Hyperscan's NFA can
//! drop OPENSSH matches when a greedy character class straddles `PRIVATE`". That
//! is a live recall hazard: a future regex refactor (e.g. collapsing the
//! alternation back to `[A-Z ]*`) could silently stop detecting one label while
//! the others keep passing, and `pem_private_key_recall_64.rs` only exercises
//! the RSA variant. This matrix pins each label independently so any single-label
//! recall regression fails loudly here.
//!
//! Each variant is asserted three ways: the detector FIRES (a `private-key`
//! RawMatch exists), the capture INCLUDES the PEM body (not just the header
//! header-only captures collapse under credential dedup), and the header-only
//! marker (no `END`) does NOT produce a finding (the regex requires a closed
//! BEGIN/END block, so a bare header is not a credential).

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

/// Build a closed PEM block for `label` whose base64 body embeds `marker`
/// (a body-unique substring absent from the BEGIN/END headers).
fn pem_block(label: &str, marker: &str) -> String {
    format!(
        "-----BEGIN {label}-----\n\
         MIIEowIBAAKCAQEA{marker}toqQrh3psgmPPDOlcmgZCKgFb75dy2Ykvh7t4Hfv\n\
         HpW3RqwsULLotTK1HAIPDqATPve1M6CgtxzBSBRKasyo1SSqT21dxfF1yAUHkABCD\n\
         -----END {label}-----"
    )
}

fn scan(text: &str) -> Vec<keyhog_core::RawMatch> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("secrets.pem".into()),
            ..Default::default()
        },
    };
    scanner.scan(&chunk)
}

fn detector_regex_matches(text: &str, detector_id: &str) -> bool {
    keyhog_core::load_detectors(&detector_dir())
        .expect("load detectors")
        .into_iter()
        .find(|detector| detector.id == detector_id)
        .expect("requested detector exists")
        .patterns
        .iter()
        .any(|pattern| {
            regex::Regex::new(&pattern.regex)
                .expect("validated detector regex compiles")
                .is_match(text)
        })
}

fn scan_detector(text: &str, detector_id: &str) -> Vec<keyhog_core::RawMatch> {
    let detector = keyhog_core::load_detectors(&detector_dir())
        .expect("load detectors")
        .into_iter()
        .find(|detector| detector.id == detector_id)
        .expect("requested detector exists");
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile detector");
    scanner.scan(&Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("secrets.pem".into()),
            ..Default::default()
        },
    })
}

/// The `private-key` capture for `text`, if the detector fired.
fn private_key_capture(text: &str) -> Option<String> {
    scan(text)
        .into_iter()
        .find(|m| m.detector_id.as_ref() == "private-key")
        .map(|m| m.credential.as_ref().to_string())
}

/// Each row: (test label, PEM algorithm label, body marker).
const RSA: (&str, &str) = ("RSA PRIVATE KEY", "RSAVARIANTBODYAAA1");
const EC: (&str, &str) = ("EC PRIVATE KEY", "ECVARIANTBODYBBBB2");
const DSA: (&str, &str) = ("DSA PRIVATE KEY", "DSAVARIANTBODYCCC3");
const OPENSSH: (&str, &str) = ("OPENSSH PRIVATE KEY", "OPENSSHVARIANTDDD4");
const PKCS8: (&str, &str) = ("PRIVATE KEY", "PKCS8VARIANTBODYE5");
const ENCRYPTED: (&str, &str) = ("ENCRYPTED PRIVATE KEY", "ENCRYPTEDVARIANTF6");
const PGP: (&str, &str) = ("PGP PRIVATE KEY BLOCK", "PGPVARIANTBODYGGG7");

// ===========================================================================
// Per-variant: the detector FIRES on a closed PEM block of this label.
// ===========================================================================

macro_rules! fires_test {
    ($name:ident, $variant:expr) => {
        #[test]
        fn $name() {
            let (label, marker) = $variant;
            let capture = private_key_capture(&pem_block(label, marker));
            assert!(
                capture.is_some(),
                "`private-key` MUST fire on a closed `BEGIN {label}` PEM block; \
                 a single-label recall regression (e.g. Hyperscan dropping this \
                 label) would show up here"
            );
        }
    };
}

fires_test!(rsa_pem_block_fires, RSA);
fires_test!(ec_pem_block_fires, EC);
fires_test!(dsa_pem_block_fires, DSA);
fires_test!(openssh_pem_block_fires, OPENSSH);
fires_test!(pkcs8_plain_pem_block_fires, PKCS8);
fires_test!(encrypted_pem_block_fires, ENCRYPTED);
fires_test!(pgp_pem_block_fires, PGP);

// ===========================================================================
// Per-variant: the capture INCLUDES the PEM body (not just the header).
// ===========================================================================

macro_rules! captures_body_test {
    ($name:ident, $variant:expr) => {
        #[test]
        fn $name() {
            let (label, marker) = $variant;
            let capture =
                private_key_capture(&pem_block(label, marker)).expect("detector must fire");
            assert!(
                capture.contains(marker),
                "`private-key` capture for `{label}` must include the PEM body \
                 (marker `{marker}`), not just the BEGIN/END header; captured \
                 prefix: {:?}",
                &capture[..capture.len().min(80)]
            );
            assert!(
                capture.contains(&format!("BEGIN {label}")),
                "capture must retain the BEGIN header for `{label}`"
            );
        }
    };
}

captures_body_test!(rsa_capture_includes_body, RSA);
captures_body_test!(ec_capture_includes_body, EC);
captures_body_test!(dsa_capture_includes_body, DSA);
captures_body_test!(openssh_capture_includes_body, OPENSSH);
captures_body_test!(pkcs8_capture_includes_body, PKCS8);
captures_body_test!(encrypted_capture_includes_body, ENCRYPTED);
captures_body_test!(pgp_capture_includes_body, PGP);

// ===========================================================================
// Per-variant negative twin: a header-only marker (no END) is NOT a finding.
// ===========================================================================

macro_rules! header_only_not_credential_test {
    ($name:ident, $variant:expr) => {
        #[test]
        fn $name() {
            let (label, _marker) = $variant;
            let header_only = format!("-----BEGIN {label}-----");
            assert!(
                private_key_capture(&header_only).is_none(),
                "a bare `BEGIN {label}` header with no closing END must NOT \
                 produce a `private-key` finding (the regex requires a closed \
                 block)"
            );
        }
    };
}

header_only_not_credential_test!(rsa_header_only_not_credential, RSA);
header_only_not_credential_test!(ec_header_only_not_credential, EC);
header_only_not_credential_test!(dsa_header_only_not_credential, DSA);
header_only_not_credential_test!(openssh_header_only_not_credential, OPENSSH);
header_only_not_credential_test!(pkcs8_header_only_not_credential, PKCS8);
header_only_not_credential_test!(encrypted_header_only_not_credential, ENCRYPTED);
header_only_not_credential_test!(pgp_header_only_not_credential, PGP);

// ===========================================================================
// Cross-cutting contracts.
// ===========================================================================

#[test]
fn pgp_block_is_private_key_only_not_ssh_private_key() {
    // The `ssh-private-key` detector deliberately does NOT enumerate the PGP
    // label, so a PGP key is owned solely by `private-key`. This pins that the
    // PGP `… BLOCK` suffix path is exclusive to the crypto detector.
    let (label, marker) = PGP;
    let raw = scan(&pem_block(label, marker));
    assert!(
        raw.iter().any(|m| m.detector_id.as_ref() == "private-key"),
        "PGP private-key block must be detected by `private-key`"
    );
    assert!(
        raw.iter()
            .all(|m| m.detector_id.as_ref() != "ssh-private-key"),
        "PGP private-key block must NOT be claimed by `ssh-private-key` \
         (it does not enumerate the PGP label)"
    );
}

#[test]
fn json_escaped_newline_pem_still_fires() {
    // Cloud service-account keys ship the PEM with literal `\n` escapes inside
    // a JSON string. The service-specific detector owns this collision and must
    // retain the complete closed block.
    let text = r#"{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqESCAPEDBODYZZ9\n-----END PRIVATE KEY-----\n"}"#;
    assert!(
        detector_regex_matches(text, "google-artifact-registry-key"),
        "the service detector regex must accept the raw JSON fixture"
    );
    assert!(
        scan_detector(text, "google-artifact-registry-key")
            .iter()
            .any(|matched| matched.detector_id.as_ref() == "google-artifact-registry-key"),
        "the service detector must match the raw JSON before overlap resolution"
    );
    let capture = scan(text)
        .into_iter()
        .find(|matched| matched.detector_id.as_ref() == "google-artifact-registry-key")
        .expect("JSON-escaped service-account PEM must retain service attribution")
        .credential;
    assert!(capture.contains("ESCAPEDBODYZZ9"), "captured: {capture:?}");
}

#[test]
fn two_distinct_rsa_blocks_yield_two_findings() {
    let fixture = format!(
        "{}\n\n{}",
        pem_block("RSA PRIVATE KEY", "FIRSTKEYBODYAAAA1"),
        pem_block("RSA PRIVATE KEY", "SECONDKEYBODYBBB2")
    );
    let hits: Vec<_> = scan(&fixture)
        .into_iter()
        .filter(|m| m.detector_id.as_ref() == "private-key")
        .collect();
    assert_eq!(hits.len(), 2, "two distinct RSA keys must be two findings");
    assert!(hits
        .iter()
        .any(|m| m.credential.as_ref().contains("FIRSTKEYBODYAAAA1")));
    assert!(hits
        .iter()
        .any(|m| m.credential.as_ref().contains("SECONDKEYBODYBBB2")));
}

#[test]
fn mismatched_begin_end_labels_still_match_lenient_recall() {
    // The BEGIN and END label groups are independent in the regex, so a
    // corrupted/mismatched block (BEGIN RSA … END PRIVATE KEY) is still caught
    // a leaked key with a mangled footer must not slip through.
    let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEMISMATCHEDBODYQ7\n-----END PRIVATE KEY-----";
    let capture = private_key_capture(text).expect("mismatched block must still fire");
    assert!(
        capture.contains("MISMATCHEDBODYQ7"),
        "captured: {capture:?}"
    );
}
