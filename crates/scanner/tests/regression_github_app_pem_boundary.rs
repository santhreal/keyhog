//! Precision lock: `github-app-private-key` must never let one match span TWO
//! adjacent PEM blocks (surfaced during the #124 resolution audit).
//!
//! The detector's bare-block pattern requires a `{200,}` body so a stray
//! `-----BEGIN RSA PRIVATE KEY-----` line can't match a tiny non-key. But with
//! the inter-marker class `[\s\S]` that minimum was UNSOUND: two short adjacent
//! RSA keys (each body < 200) let the lazy `{200,}?` skip the first (too-short)
//! `-----END` — `[\s\S]` happily consumes its dashes — and run on to the SECOND
//! key's `-----END`, matching ~312 chars and reporting both distinct keys as one
//! credential. In `resolve_matches` that merged span then outranks the correct
//! single-key `ssh-private-key` on the first key's line (longer id + longer
//! credential), so the operator sees `github-app-private-key` instead of two
//! clean `ssh-private-key` findings.
//!
//! The fix restricts the body to the PEM base64 alphabet plus whitespace
//! (`[A-Za-z0-9+/=\s]`), which excludes `-`, so the match ALWAYS stops at the
//! first `-----END` and can never cross a block boundary. This suite pins both
//! halves of the contract: (1) two short adjacent blocks never merge and never
//! trip the detector at all, and (2) a genuine long key (≥200 base64 body) still
//! matches — bounded to its own single block.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::resolution::resolve_matches;
use keyhog_scanner::CompiledScanner;

/// 241-char base64 body (the detector contract fixture's key body): a single
/// block built from it clears the `{200,}` floor on its own.
const B64_BODY: &str = "MIIEpQIBAAKCAQEA7n2K9xR4vQ1mWcZ8hLbF3jD5sT6yU0pN2aG4eH7iO9kB1lM3rV5wX8zC0dQ2fS4gJ6kP8mR0tU2wY4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6wX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6aB8cD0eF2gH4iJ6kL8mN0oP2qR4sT6uV8wX0yZ2aB4cD6eF8gH0iJ2kL4";

/// A PEM block whose body is far UNDER 200 base64 chars — on its own it can
/// never satisfy the GitHub App detector's `{200,}` floor.
fn short_block(label: &str, marker: &str) -> String {
    format!("-----BEGIN {label}-----\nMIIBVAIBADANBgkqhkiG9w0BAQEF{marker}Po0kjAB\n-----END {label}-----")
}

/// A PEM block whose body comfortably exceeds 200 base64 chars (a real key).
fn long_block(label: &str, marker: &str) -> String {
    format!("-----BEGIN {label}-----\n{marker}{B64_BODY}\n-----END {label}-----")
}

fn scan_raw(text: &str) -> Vec<RawMatch> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("keys.pem".into()),
            ..Default::default()
        },
    };
    scanner.scan(&chunk)
}

/// Every credential matched by `github-app-private-key`, raw (pre-resolution).
fn github_app_credentials(text: &str) -> Vec<String> {
    scan_raw(text)
        .into_iter()
        .filter(|m| m.detector_id.as_ref() == "github-app-private-key")
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

fn github_app_credentials_resolved(text: &str) -> Vec<String> {
    resolve_matches(scan_raw(text))
        .into_iter()
        .filter(|m| m.detector_id.as_ref() == "github-app-private-key")
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

// ── two short adjacent blocks must never merge or trip the detector ─────────

#[test]
fn two_adjacent_short_rsa_blocks_do_not_trip_github_app() {
    let text = format!(
        "{}\n\n{}",
        short_block("RSA PRIVATE KEY", "AAAA1111"),
        short_block("RSA PRIVATE KEY", "BBBB2222")
    );
    let creds = github_app_credentials(&text);
    assert!(
        creds.is_empty(),
        "two short (<200B) RSA blocks must NOT satisfy the {{200,}} floor by spanning both; \
         github-app matched {creds:?}"
    );
}

#[test]
fn no_github_app_credential_spans_both_short_rsa_keys() {
    let text = format!(
        "{}\n\n{}",
        short_block("RSA PRIVATE KEY", "AAAA1111"),
        short_block("RSA PRIVATE KEY", "BBBB2222")
    );
    for cred in github_app_credentials(&text) {
        assert!(
            !(cred.contains("AAAA1111") && cred.contains("BBBB2222")),
            "a single github-app match must never contain BOTH keys' bodies: {cred:?}"
        );
    }
}

#[test]
fn two_adjacent_short_openssh_blocks_do_not_trip_github_app() {
    let text = format!(
        "{}\n\n{}",
        short_block("OPENSSH PRIVATE KEY", "CCCC3333"),
        short_block("OPENSSH PRIVATE KEY", "DDDD4444")
    );
    assert!(
        github_app_credentials(&text).is_empty(),
        "two short OPENSSH blocks must not merge into a github-app match"
    );
}

#[test]
fn single_short_rsa_block_does_not_trip_github_app() {
    let creds = github_app_credentials(&short_block("RSA PRIVATE KEY", "EEEE5555"));
    assert!(
        creds.is_empty(),
        "a single sub-200B block is below the detector floor; got {creds:?}"
    );
}

#[test]
fn resolved_two_short_rsa_keys_have_no_github_app_finding() {
    // End-to-end through the resolver: the merged-span finding must not exist,
    // so it cannot outrank the two ssh-private-key findings.
    let text = format!(
        "{}\n\n{}",
        short_block("RSA PRIVATE KEY", "FFFF6666"),
        short_block("RSA PRIVATE KEY", "GGGG7777")
    );
    assert!(
        github_app_credentials_resolved(&text).is_empty(),
        "no github-app finding survives resolution for two short distinct keys"
    );
}

// ── a genuine long key still matches, bounded to its own block ──────────────

#[test]
fn single_long_rsa_block_matches_github_app() {
    let creds = github_app_credentials(&long_block("RSA PRIVATE KEY", "LONGKEY1"));
    assert_eq!(
        creds.len(),
        1,
        "a real ≥200B RSA key must still match the detector exactly once; got {creds:?}"
    );
    assert!(
        creds[0].contains("LONGKEY1"),
        "the match captures the real key body"
    );
}

#[test]
fn long_block_match_is_bounded_to_one_block() {
    let creds = github_app_credentials(&long_block("RSA PRIVATE KEY", "BOUNDED1"));
    assert_eq!(creds.len(), 1);
    // The captured credential spans exactly one BEGIN…END pair.
    assert_eq!(
        creds[0].matches("-----BEGIN RSA PRIVATE KEY-----").count(),
        1,
        "credential must contain exactly one BEGIN marker: {:?}",
        creds[0]
    );
    assert_eq!(
        creds[0].matches("-----END RSA PRIVATE KEY-----").count(),
        1,
        "credential must contain exactly one END marker"
    );
}

#[test]
fn two_adjacent_long_rsa_blocks_match_as_two_separate_keys() {
    let text = format!(
        "{}\n\n{}",
        long_block("RSA PRIVATE KEY", "FIRSTKEY"),
        long_block("RSA PRIVATE KEY", "OTHERKEY")
    );
    let creds = github_app_credentials(&text);
    // Each long key matches on its own; none merges the two.
    for cred in &creds {
        assert!(
            !(cred.contains("FIRSTKEY") && cred.contains("OTHERKEY")),
            "no single match may span both long keys: {cred:?}"
        );
        assert_eq!(
            cred.matches("-----BEGIN RSA PRIVATE KEY-----").count(),
            1,
            "each match is a single block: {cred:?}"
        );
    }
    assert_eq!(
        creds.len(),
        2,
        "two distinct long keys → two distinct matches; got {creds:?}"
    );
}

#[test]
fn context_anchored_long_block_matches_single_block() {
    // Pattern 2 (the GITHUB_APP_PRIVATE_KEY=… context anchor) shares the same
    // base64-body class, so it too cannot cross a boundary.
    let text = format!(
        "GITHUB_APP_PRIVATE_KEY=\"{}\"",
        long_block("RSA PRIVATE KEY", "CTXKEY01")
    );
    let creds = github_app_credentials(&text);
    assert!(
        creds.iter().any(|c| c.contains("CTXKEY01")),
        "context-anchored long key must match; got {creds:?}"
    );
    for cred in &creds {
        assert_eq!(
            cred.matches("-----BEGIN RSA PRIVATE KEY-----").count(),
            1,
            "context-anchored match is bounded to one block: {cred:?}"
        );
    }
}

#[test]
fn long_block_between_two_short_blocks_matches_only_the_long_one() {
    // short / LONG / short: only the middle long key clears the floor, and its
    // match must not reach into either neighbor.
    let text = format!(
        "{}\n\n{}\n\n{}",
        short_block("RSA PRIVATE KEY", "PRESHRT1"),
        long_block("RSA PRIVATE KEY", "MIDLONG1"),
        short_block("RSA PRIVATE KEY", "POSTSHT1")
    );
    let creds = github_app_credentials(&text);
    assert_eq!(
        creds.len(),
        1,
        "only the long middle key matches; got {creds:?}"
    );
    assert!(creds[0].contains("MIDLONG1"));
    assert!(
        !creds[0].contains("PRESHRT1") && !creds[0].contains("POSTSHT1"),
        "the long-key match must not reach into the short neighbors: {:?}",
        creds[0]
    );
}

/// DR-329 CONSOLIDATION GUARD — the PEM armor marker `-----BEGIN` is detection
/// signal (the load-bearing prefix of the private-key detector patterns). Scanner
/// logic also keys off it in two places — the suppression carve-out
/// (`suppression/decision.rs`, so a PEM body is not masking-pattern suppressed)
/// and the entropy plausibility gate (`entropy/plausibility.rs`). Those were two
/// bare `"-----BEGIN"` literals free to drift; they now share the single owner
/// `credential_shapes::PEM_BEGIN_MARKER` via `is_pem_block`. This binds that
/// const to its authoritative detector so it can never diverge from the pattern
/// that actually surfaces a PEM key. (Lives HERE — a regression file
/// `#[path]`-included in `all_tests`, which CI runs via `--test all_tests` — not
/// in `pem_private_key_recall_64.rs`, which is a CI-orphan; see DR-334.)
#[test]
fn pem_begin_marker_is_backed_by_the_private_key_detector() {
    let marker = keyhog_scanner::testing::pem_begin_marker();
    let path = detector_dir().join("private-key.toml");
    let toml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read private-key detector {}: {e}", path.display()));
    assert!(
        toml.contains(marker),
        "PEM marker {marker:?} (credential_shapes::PEM_BEGIN_MARKER) is absent from its \
         authoritative private-key.toml pattern — the single-owner const drifted from the \
         detector that surfaces a PEM key"
    );
}
