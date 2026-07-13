//! Recall + confidence lock for the `putty-private-key` detector. PuTTY `.ppk`
//! private-key files (the native key format of PuTTY / pageant / plink).
//!
//! Why this detector exists
//! ------------------------
//! A `.ppk` is NOT PEM: it carries no `-----BEGIN` marker, so neither
//! `private-key` nor `ssh-private-key` ever fires on it. Before this detector a
//! leaked `.ppk`: which embeds the full private key in its `Private-Lines:`
//! section, was a total recall hole. The detector anchors on the distinctive
//! `PuTTY-User-Key-File-<version>:` header and closes on the trailing
//! `Private-MAC:` hex line, requiring an interior `Private-Lines:` count so a
//! bare format mention is not a finding.
//!
//! This suite pins three contracts:
//!   1. RECALL, every real `.ppk` shape fires (v2/v3, every key type,
//!      encrypted + unencrypted, embedded in a larger file, version-forward).
//!   2. PRECISION, the structure is load-bearing: header-only, missing
//!      `Private-Lines`, missing/short `Private-MAC`, and a non-PuTTY file that
//!      merely reuses the `Private-Lines:`/`Private-MAC:` field names all stay
//!      silent.
//!   3. CONFIDENCE, the `PuTTY-User-Key-File-` entry added to the scanner's
//!      `KNOWN_PREFIXES` floors a captured `.ppk` to 0.8, clearing the CLI's
//!      0.3 `min_confidence` gate (the same mechanism that floors PEM blocks via
//!      `-----BEGIN`), and the placeholder/degenerate guards still apply.
//!
//! All assertions drive the REAL `CompiledScanner::scan` production path and
//! assert the EXACT detector id + captured bytes (Law 6, never `!is_empty`).

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::confidence::known_prefix_confidence_floor;
use keyhog_scanner::CompiledScanner;

const DETECTOR_ID: &str = "putty-private-key";
/// A syntactically valid trailing MAC (64-hex HMAC-SHA-256, v3-width).
const MAC64: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";

/// Build a full unencrypted `.ppk` of the given format version + key type. The
/// private blob line is prefixed with `priv_marker` so a test can assert the
/// capture spans the SECRET material, not just the header.
fn ppk(version: u32, keytype: &str, comment: &str, priv_marker: &str, mac: &str) -> String {
    format!(
        "PuTTY-User-Key-File-{version}: {keytype}\n\
         Encryption: none\n\
         Comment: {comment}\n\
         Public-Lines: 2\n\
         AAAAC3NzaC1lZDI1NTE5AAAAIPublicBlobPublicBlobPublicBlobPublicBlob01\n\
         Private-Lines: 1\n\
         {priv_marker}PrivateBlobPrivateBlobPrivateBlobPrivateBlobPrivat98765=\n\
         Private-MAC: {mac}\n"
    )
}

/// An encrypted v3 `.ppk`, which inserts the Argon2 KDF header lines between the
/// public blob and `Private-Lines:`. The secret-bearing structure is identical.
fn ppk_v3_encrypted(comment: &str, priv_marker: &str, mac: &str) -> String {
    format!(
        "PuTTY-User-Key-File-3: ssh-rsa\n\
         Encryption: aes256-cbc\n\
         Comment: {comment}\n\
         Public-Lines: 6\n\
         AAAAB3NzaC1yc2EAAAADAQABAAABAQPublicBlobPublicBlobPublicBlobPublic\n\
         Key-Derivation: Argon2id\n\
         Argon2-Memory: 8192\n\
         Argon2-Passes: 13\n\
         Argon2-Parallelism: 1\n\
         Argon2-Salt: 0011223344556677889900112233445566\n\
         Private-Lines: 14\n\
         {priv_marker}EncryptedPrivateBlobEncryptedPrivateBlobEncrypt98765=\n\
         Private-MAC: {mac}\n"
    )
}

fn scan(text: &str) -> Vec<keyhog_core::RawMatch> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("id_rsa.ppk".into()),
            ..Default::default()
        },
    };
    scanner.scan(&chunk)
}

/// The `putty-private-key` match for `text`, if it fired.
fn putty_match(text: &str) -> Option<keyhog_core::RawMatch> {
    scan(text)
        .into_iter()
        .find(|m| m.detector_id.as_ref() == DETECTOR_ID)
}

fn putty_fires(text: &str) -> bool {
    putty_match(text).is_some()
}

// ===========================================================================
// RECALL (every real .ppk shape fires).
// ===========================================================================

#[test]
fn v2_rsa_unencrypted_fires() {
    assert!(putty_fires(&ppk(
        2,
        "ssh-rsa",
        "rsa-key-20240101",
        "RSAPRIV",
        MAC64
    )));
}

#[test]
fn v2_ed25519_unencrypted_fires() {
    assert!(putty_fires(&ppk(
        2,
        "ssh-ed25519",
        "ed-key",
        "EDPRIV",
        MAC64
    )));
}

#[test]
fn v2_dss_unencrypted_fires() {
    assert!(putty_fires(&ppk(2, "ssh-dss", "dsa-key", "DSSPRIV", MAC64)));
}

#[test]
fn v2_ecdsa_nistp256_unencrypted_fires() {
    assert!(putty_fires(&ppk(
        2,
        "ecdsa-sha2-nistp256",
        "ec-key",
        "ECPRIV",
        MAC64
    )));
}

#[test]
fn v3_rsa_unencrypted_fires() {
    assert!(putty_fires(&ppk(3, "ssh-rsa", "v3-key", "V3PRIV", MAC64)));
}

#[test]
fn v3_encrypted_argon2_fires() {
    // The Argon2 KDF header lines between the public blob and Private-Lines must
    // not break the lazy header→MAC span.
    assert!(putty_fires(&ppk_v3_encrypted("enc-key", "ENCPRIV", MAC64)));
}

#[test]
fn future_version_4_fires() {
    // `PuTTY-User-Key-File-[0-9]+` is version-forward: a hypothetical v4 still
    // fires (Law 1, no regrets).
    assert!(putty_fires(&ppk(
        4,
        "ssh-rsa",
        "future-key",
        "F4PRIV",
        MAC64
    )));
}

#[test]
fn ppk_embedded_in_larger_file_fires() {
    let text = format!(
        "# backup of my keys\nsome preamble line\n\n{}\n# end of file\n",
        ppk(2, "ssh-rsa", "embedded-key", "EMBPRIV", MAC64)
    );
    assert!(putty_fires(&text));
}

#[test]
fn v2_mac40_sha1_width_fires() {
    // v2 uses a 40-hex SHA-1 HMAC; the `{16,}` lower bound must accept it.
    let mac40 = "0011223344556677889900112233445566778899";
    assert!(putty_fires(&ppk(2, "ssh-rsa", "old-key", "OLDPRIV", mac40)));
}

// ===========================================================================
// CAPTURE (the match spans header → private body → MAC).
// ===========================================================================

#[test]
fn capture_starts_with_putty_header() {
    let m = putty_match(&ppk(2, "ssh-rsa", "k", "CAPHDR", MAC64)).expect("fires");
    assert!(
        m.credential.as_ref().starts_with("PuTTY-User-Key-File-2:"),
        "capture must begin at the .ppk header; got prefix {:?}",
        &m.credential.as_ref()[..m.credential.as_ref().len().min(40)]
    );
}

#[test]
fn capture_includes_private_lines_body() {
    let m = putty_match(&ppk(2, "ssh-rsa", "k", "SECRETBODYMARK", MAC64)).expect("fires");
    assert!(
        m.credential.as_ref().contains("SECRETBODYMARK"),
        "capture must include the Private-Lines secret body, not just the header"
    );
}

#[test]
fn capture_ends_at_private_mac() {
    let m = putty_match(&ppk(2, "ssh-rsa", "k", "ENDP", MAC64)).expect("fires");
    let cap = m.credential.as_ref();
    assert!(
        cap.contains("Private-MAC:"),
        "capture must reach Private-MAC"
    );
    assert!(
        cap.trim_end().ends_with(MAC64),
        "capture must end at the trailing MAC hex; tail {:?}",
        &cap[cap.len().saturating_sub(20)..]
    );
}

#[test]
fn two_distinct_ppk_blocks_yield_two_findings() {
    let fixture = format!(
        "{}\n\n{}",
        ppk(2, "ssh-rsa", "first", "FIRSTPRIV", MAC64),
        ppk(2, "ssh-ed25519", "second", "SECONDPRIV", MAC64)
    );
    let hits: Vec<_> = scan(&fixture)
        .into_iter()
        .filter(|m| m.detector_id.as_ref() == DETECTOR_ID)
        .collect();
    assert_eq!(hits.len(), 2, "two .ppk blocks must be two findings");
    assert!(hits
        .iter()
        .any(|m| m.credential.as_ref().contains("FIRSTPRIV")));
    assert!(hits
        .iter()
        .any(|m| m.credential.as_ref().contains("SECONDPRIV")));
    // Lazy bounding: neither capture swallows the gap between the two blocks.
    assert!(
        hits.iter()
            .all(|m| !m.credential.as_ref().contains("FIRSTPRIV")
                || !m.credential.as_ref().contains("SECONDPRIV")),
        "a single capture must not bleed across both blocks"
    );
}

// ===========================================================================
// PRECISION (the structure is load-bearing; partial shapes stay silent).
// ===========================================================================

#[test]
fn header_only_does_not_fire() {
    assert!(!putty_fires("PuTTY-User-Key-File-2: ssh-rsa\n"));
}

#[test]
fn format_mention_does_not_fire() {
    assert!(!putty_fires(
        "See the PuTTY-User-Key-File-2 format in AppendixC for the header layout."
    ));
}

#[test]
fn missing_private_lines_does_not_fire() {
    // Header + public blob + a MAC, but no Private-Lines section.
    let text = "PuTTY-User-Key-File-2: ssh-rsa\n\
                Encryption: none\n\
                Comment: pub-only\n\
                Public-Lines: 2\n\
                AAAAC3NzaC1lZDI1NTE5AAAAIPublicBlobPublicBlobPublicBlob01\n\
                Private-MAC: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0\n";
    assert!(!putty_fires(text));
}

#[test]
fn missing_private_mac_does_not_fire() {
    let text = "PuTTY-User-Key-File-2: ssh-rsa\n\
                Encryption: none\n\
                Comment: no-mac\n\
                Public-Lines: 2\n\
                AAAAC3NzaC1lZDI1NTE5AAAAIPublicBlobPublicBlobPublicBlob01\n\
                Private-Lines: 1\n\
                PrivateBlobPrivateBlobPrivateBlobPrivat98765=\n";
    assert!(!putty_fires(text));
}

#[test]
fn short_mac_below_16_hex_does_not_fire() {
    // A 6-char MAC is not a real Private-MAC; the `{16,}` anchor rejects it.
    assert!(!putty_fires(&ppk(
        2, "ssh-rsa", "shortmac", "SHRTPRIV", "abc123"
    )));
}

#[test]
fn non_putty_file_with_same_field_names_does_not_fire() {
    // A file that reuses `Private-Lines:`/`Private-MAC:` field names but has NO
    // PuTTY-User-Key-File header must not fire (the header is the anchor).
    let text = "Private-Lines: 1\n\
                PrivateBlobPrivateBlobPrivateBlob98765=\n\
                Private-MAC: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0\n";
    assert!(!putty_fires(text));
}

// ===========================================================================
// CONFIDENCE (the KNOWN_PREFIXES floor clears the CLI min_confidence gate).
// ===========================================================================

#[test]
fn fired_match_confidence_clears_cli_floor() {
    // The CLI default min_confidence is 0.3; a captured .ppk must clear it with
    // headroom via the `PuTTY-User-Key-File-` KNOWN_PREFIXES floor.
    let m = putty_match(&ppk(2, "ssh-rsa", "conf-key", "CONFPRIV", MAC64)).expect("fires");
    let conf = m.confidence.unwrap_or(0.0);
    assert!(
        conf >= 0.5,
        "putty-private-key confidence must clear the 0.3 CLI floor with headroom; saw {conf:.3}"
    );
}

#[test]
fn known_prefix_floor_lifts_ppk_credential_to_0_8() {
    // Direct contract on the prefix floor: a credential starting with the .ppk
    // header is floored to 0.8 (same as PEM `-----BEGIN`).
    let cred = ppk(2, "ssh-rsa", "floor-key", "FLOORPRIV", MAC64);
    assert_eq!(
        known_prefix_confidence_floor(&cred),
        Some(0.8),
        "the PuTTY-User-Key-File- prefix must floor a captured .ppk to 0.8"
    );
}

#[test]
fn known_prefix_floor_denies_placeholder_ppk() {
    // A .ppk whose comment carries a placeholder word (EXAMPLE) is a doc sample,
    // not a credential: the placeholder guard denies the floor (returns None),
    // exactly as it does for `ghp_EXAMPLE…`.
    let cred = ppk(2, "ssh-rsa", "EXAMPLE-key", "EXPRIV", MAC64);
    assert_eq!(
        known_prefix_confidence_floor(&cred),
        None,
        "placeholder-bearing .ppk must NOT receive the prefix floor"
    );
}

// ===========================================================================
// IDENTITY (exact detector id + service classification).
// ===========================================================================

#[test]
fn fires_under_exact_detector_id() {
    let m = putty_match(&ppk(2, "ssh-rsa", "id-key", "IDPRIV", MAC64)).expect("fires");
    assert_eq!(m.detector_id.as_ref(), DETECTOR_ID);
    assert_eq!(m.service.as_ref(), "ssh", "PuTTY keys are SSH keys");
}

#[test]
fn ppk_is_not_double_reported_by_pem_detectors() {
    // A .ppk carries no `-----BEGIN`, so the PEM `private-key` and
    // `ssh-private-key` detectors must NOT also fire (no double-report).
    let raw = scan(&ppk(2, "ssh-rsa", "solo-key", "SOLOPRIV", MAC64));
    assert!(raw.iter().any(|m| m.detector_id.as_ref() == DETECTOR_ID));
    assert!(
        raw.iter().all(|m| m.detector_id.as_ref() != "private-key"
            && m.detector_id.as_ref() != "ssh-private-key"),
        "a .ppk must be owned solely by putty-private-key"
    );
}
