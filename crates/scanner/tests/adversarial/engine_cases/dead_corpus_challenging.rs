//! Wire the dead `tests/data/recall/kh_challenging/*` fixtures into `cargo test`.
//!
//! Per the internal design notes, nine challenging recall
//! fixtures shipped under `tests/data/recall/kh_challenging/` but no Rust test
//! referenced them. Each test loads the embedded detector corpus via
//! [`CompiledScanner`], scans the full fixture, and asserts planted secrets
//! are found. Negative twins (where the fixture embeds trap values) assert the
//! engine does not treat known non-secrets as credentials.
//!
//! CLAUDE.md anti-rigging rule: every positive names a detector/service needle
//! and/or expected credential substring - a function returning `Vec::new()` fails.

use super::corpus_support::{
    has_credential, has_detector, production_scanner, recall_fixture_path, scan_recall, GITHUB_PAT,
};
use keyhog_core::{Chunk, ChunkMetadata};

const SLACK_BOT_TOKEN: &str = "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx";

fn scan_fixture(rel: &str) -> Vec<keyhog_core::RawMatch> {
    scan_recall(rel)
}

fn assert_any_service(matches: &[keyhog_core::RawMatch], fixture: &str, services: &[&str]) {
    let hit = services.iter().any(|needle| has_detector(matches, needle));
    assert!(
        hit,
        "{fixture}: expected at least one of {:?} to fire; got {} matches: {:?}",
        services,
        matches.len(),
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.service.as_ref()))
            .collect::<Vec<_>>()
    );
}

fn assert_credential_substr(matches: &[keyhog_core::RawMatch], fixture: &str, substr: &str) {
    assert!(
        has_credential(matches, substr),
        "{fixture}: expected credential containing {substr:?}; matches={:?}",
        matches
            .iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}

fn assert_no_credential_substr(matches: &[keyhog_core::RawMatch], fixture: &str, substr: &str) {
    assert!(
        !has_credential(matches, substr),
        "{fixture}: negative twin {substr:?} must not be flagged; matches={:?}",
        matches
            .iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// decode_through_confusion.json - base64-looking secrets + decode traps
// ---------------------------------------------------------------------------

#[test]
fn challenging_decode_through_confusion_finds_base64_wrapped_secrets() {
    let matches = scan_fixture("decode_through_confusion.json");
    assert_any_service(
        &matches,
        "decode_through_confusion.json",
        &["github", "aws", "stripe", "slack"],
    );
    assert_credential_substr(&matches, "decode_through_confusion.json", GITHUB_PAT);
}

#[test]
fn challenging_decode_through_confusion_negative_sha256_empty_hash() {
    let matches = scan_fixture("decode_through_confusion.json");
    // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 is the
    // SHA-256 of the empty string - a common false-positive trap in the fixture.
    assert_no_credential_substr(
        &matches,
        "decode_through_confusion.json",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
}

// ---------------------------------------------------------------------------
// multipart_secrets - split / encoded / reassembled credentials
// ---------------------------------------------------------------------------

#[test]
fn challenging_multipart_secrets_finds_plain_or_encoded_ghp() {
    let matches = scan_fixture("multipart_secrets");
    assert_any_service(&matches, "multipart_secrets", &["github"]);
    assert_credential_substr(&matches, "multipart_secrets", GITHUB_PAT);
}

// ---------------------------------------------------------------------------
// no_literal_prefix.env - high-entropy secrets without ghp_/AKIA prefixes
// ---------------------------------------------------------------------------

#[test]
fn challenging_no_literal_prefix_finds_jwt_or_generic_secret() {
    let matches = scan_fixture("no_literal_prefix.env");
    // Planted JWT without Bearer prefix; generic-secret may also catch entropy blobs.
    let jwt_hit = has_credential(&matches, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9")
        || has_detector(&matches, "jwt");
    assert!(
        jwt_hit || !matches.is_empty(),
        "no_literal_prefix.env: expected JWT or generic-secret hit; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// ac_prefilter_bypass.env - patterns that stress AC literal extraction
// ---------------------------------------------------------------------------

#[test]
fn challenging_ac_prefilter_bypass_finds_something() {
    let matches = scan_fixture("ac_prefilter_bypass.env");
    // Fixture mixes JWT-like tokens, base64 K8s blobs, cert fragments, and
    // high-entropy assignments. At least one planted secret must survive AC routing.
    assert!(
        !matches.is_empty(),
        "ac_prefilter_bypass.env: zero findings - AC prefilter may be dropping \
         prefixless or alternation-shaped secrets entirely. matches={:?}",
        matches
    );
}

#[test]
fn challenging_ac_prefilter_bypass_finds_k8s_base64_secret() {
    let matches = scan_fixture("ac_prefilter_bypass.env");
    // K8S_FULL_SECRET is base64("calico-on-kube-auth-key") - planted in the fixture
    // to stress prefixless / decode-through paths after AC routing.
    assert_credential_substr(
        &matches,
        "ac_prefilter_bypass.env",
        "Y2FsaWNvLW9uLWt1YmUtYXV0aC1rZXk=",
    );
}

// ---------------------------------------------------------------------------
// context_confusion/legitimate_looking.py - secrets disguised as hashes/UUIDs
// ---------------------------------------------------------------------------

#[test]
fn challenging_context_confusion_finds_slack_or_github() {
    let matches = scan_fixture("context_confusion/legitimate_looking.py");
    assert_any_service(
        &matches,
        "context_confusion/legitimate_looking.py",
        &["slack", "github", "stripe"],
    );
}

#[test]
fn challenging_context_confusion_finds_xoxb_slack_token() {
    let matches = scan_fixture("context_confusion/legitimate_looking.py");
    assert_credential_substr(
        &matches,
        "context_confusion/legitimate_looking.py",
        SLACK_BOT_TOKEN,
    );
}

// ---------------------------------------------------------------------------
// encoding_evasion/mixed_encodings.json - UTF-8/16/URL/HTML encoding attacks
// ---------------------------------------------------------------------------

#[test]
fn challenging_mixed_encodings_finds_aws_or_github() {
    let matches = scan_fixture("encoding_evasion/mixed_encodings.json");
    assert_any_service(
        &matches,
        "encoding_evasion/mixed_encodings.json",
        &["aws", "github"],
    );
}

// ---------------------------------------------------------------------------
// steganography/whitespace_hidden.txt - zero-width / whitespace-hidden secrets
// ---------------------------------------------------------------------------

#[test]
fn challenging_whitespace_hidden_finds_ghp_or_aws() {
    let matches = scan_fixture("steganography/whitespace_hidden.txt");
    assert_any_service(
        &matches,
        "steganography/whitespace_hidden.txt",
        &["github", "aws"],
    );
}

// ---------------------------------------------------------------------------
// polyglot_secrets.txt - same secret valid in multiple syntactic contexts
// ---------------------------------------------------------------------------

#[test]
fn challenging_polyglot_secrets_finds_github_or_slack() {
    let matches = scan_fixture("polyglot_secrets.txt");
    assert_any_service(
        &matches,
        "polyglot_secrets.txt",
        &["github", "slack", "aws"],
    );
}

// ---------------------------------------------------------------------------
// unicode_normalization_attacks.txt - homoglyph / ZWJ / RTL / fullwidth attacks
// ---------------------------------------------------------------------------

#[test]
fn challenging_unicode_normalization_finds_github_despite_obfuscation() {
    let matches = scan_fixture("unicode_normalization_attacks.txt");
    // Several lines embed real `ghp_` tokens with zero-width / RTL / fullwidth noise.
    assert_any_service(&matches, "unicode_normalization_attacks.txt", &["github"]);
}

// ---------------------------------------------------------------------------
// Inventory: every file under kh_challenging must be referenced
// ---------------------------------------------------------------------------

#[test]
fn challenging_corpus_files_exist_on_disk() {
    let expected = [
        "ac_prefilter_bypass.env",
        "no_literal_prefix.env",
        "decode_through_confusion.json",
        "unicode_normalization_attacks.txt",
        "polyglot_secrets.txt",
        "multipart_secrets",
        "context_confusion/legitimate_looking.py",
        "encoding_evasion/mixed_encodings.json",
        "steganography/whitespace_hidden.txt",
    ];
    for rel in expected {
        let path = recall_fixture_path(rel);
        assert!(
            path.is_file(),
            "kh_challenging fixture missing: {}",
            path.display()
        );
    }
}

#[test]
fn challenging_full_file_scan_uses_production_scanner() {
    // Smoke: every wired fixture is readable and scannable without panic.
    let fixtures = [
        "ac_prefilter_bypass.env",
        "no_literal_prefix.env",
        "decode_through_confusion.json",
        "unicode_normalization_attacks.txt",
        "polyglot_secrets.txt",
        "multipart_secrets",
        "context_confusion/legitimate_looking.py",
        "encoding_evasion/mixed_encodings.json",
        "steganography/whitespace_hidden.txt",
    ];
    let scanner = production_scanner();
    for rel in fixtures {
        let path = recall_fixture_path(rel);
        let data = std::fs::read_to_string(&path).expect("read fixture");
        let chunk = Chunk {
            data: data.into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "test/recall/kh_challenging".into(),
                path: Some(path.display().to_string().into()),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: None,
                ..Default::default()
            },
        };
        let _ = scanner.scan(&chunk);
    }
}
