//! Round 1 FN-recovery regression contract: the fast entropy-run gate
//! must keep a 32+ char run intact across base64 punctuation (`+`, `/`,
//! `_`, `-`, `=`). Before the fix, a 40-char base64 token with one `+`
//! halfway through broke into two 20-char runs and bailed before reaching
//! entropy fallback - 12+ FNs in the SecretBench mirror.
//!
//! Investigator finding (generic-high-entropy-string cause #8): pre-fix
//! `has_high_entropy_run_fast` in scan_filters.rs only counted
//! `is_ascii_alphanumeric()` bytes. The fix extends the alphabet to the
//! full base64/base64url alphabet plus `=` padding.
//!
//! `has_high_entropy_run_fast` is `pub(super)` so we cannot call it
//! directly. Instead exercise the property end-to-end through the real
//! scanner: a chunk whose ONLY high-entropy-shaped credential is a
//! base64 token with internal `+`/`/` must still produce a finding for
//! the planted credential when scanned through the production pipeline.
//!
//! Adversarial style: PROPTEST 1k iterations across the internal punct
//! position and surrounding context. The contract is "internal `+`/`/`
//! does not silently drop the candidate before entropy-fallback can see
//! it." We cannot assert which detector fires (cross-detector dedup can
//! relabel), only that the credential bytes surface SOMEWHERE.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use proptest::prelude::*;
use std::path::PathBuf;
use std::sync::OnceLock;

const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// Base62 (`[A-Za-z0-9]`) — the standard base64 alphabet minus the two
/// punctuation chars. The internal-`+` proptest draws its random body from THIS
/// alphabet, not [`BASE64_ALPHABET`], on purpose: the contract under test is
/// "an internal `+` does not break the high-entropy run pre-screen", and a
/// single inserted `+` (no `/`) keeps the body clear of the byte-distribution
/// random-blob gate, which DELIBERATELY suppresses uniform-random base64 that
/// carries BOTH `+` and `/` (those are protobuf-of-random-bytes decoys — bench
/// negatives, correctly dropped). Drawing the body from the full base64
/// alphabet would let a random `/` combine with the inserted `+` to form such a
/// decoy, making the test assert survival of a value the system is meant to
/// drop — an unsound, flaky assertion (the prior generator's bug).
const BASE62_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const KEYWORD_FREE_MIN_LEN: usize = 56;

fn shannon_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut entropy = 0.0;
    for &count in &freq {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn build_token(indices: &[u8], alphabet: &[u8]) -> String {
    indices
        .iter()
        .map(|idx| alphabet[*idx as usize] as char)
        .collect()
}

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn shared_scanner() -> &'static CompiledScanner {
    // Shared single scanner (LG2): all adversarial full-detector tests
    // route through one compiled instance instead of one per file.
    crate::adversarial::oracle_support::production_scanner()
}

fn scan(body: String) -> Vec<keyhog_core::RawMatch> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("/repo/secrets.env".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    shared_scanner().scan(&chunk)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1_000, .. ProptestConfig::default() })]

    /// Property: a 60-char **base62** (alnum) body with one `+` inserted near
    /// the middle, planted as the value of a `TOKEN=` line, must surface
    /// SOMEWHERE in the finding set. Before the fix the run gate pre-screened
    /// the chunk out because the `+` split the run.
    ///
    /// The body is drawn from [`BASE62_ALPHABET`] (no `+`/`/`) and exactly ONE
    /// `+` is inserted, so the value carries `+` but never `/`. That is
    /// deliberate: the byte-distribution random-blob gate suppresses uniform
    /// base64 carrying BOTH `+` and `/` (protobuf-of-random-bytes decoys — bench
    /// negatives), so a body with both would be dropped by design and is not a
    /// valid positive for this contract. Single-`+` keeps the test on its
    /// actual subject — the run pre-screen — not the blob suppression.
    #[test]
    fn b64_secret_with_internal_plus_surfaces(
        idxs in prop::collection::vec(0u8..62u8, 59).prop_filter(
            "high-entropy-like body",
            |idxs| {
                let body = build_token(idxs, BASE62_ALPHABET);
                let (head, tail) = body.split_at(29);
                let body = format!("{head}+{tail}");
                shannon_entropy(body.as_bytes()) > 4.8_f64
            }
        ),
    ) {
        let chars: String = build_token(&idxs, BASE62_ALPHABET);
        let (head, tail) = chars.split_at(29);
        let body = format!("{head}+{tail}");
        prop_assert!(shannon_entropy(body.as_bytes()) > 4.8_f64, "generated body must clear the 4.8 entropy gate");
        prop_assert_eq!(body.len(), 60);
        let line = format!("export TOKEN={body}\n");

        let matches = scan(line.clone());
        let surfaced = matches
            .iter()
            .any(|m| m.credential.as_ref().contains(&body));
        prop_assert!(
            surfaced,
            "60-char base62 body with internal `+` must surface in some finding; line={:?} matches={:?}",
            line,
            matches
                .iter()
                .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
                .collect::<Vec<_>>()
        );
    }
}

/// Soundness: a short alnum token with `+` (well under the 32-char
/// MIN_ENTROPY_RUN) must NOT artificially trip the entropy-run gate -
/// proven indirectly by ensuring an unrelated short token does not
/// produce a credential finding for the short body.
#[test]
fn short_alnum_with_plus_does_not_create_phantom_finding() {
    // 8-char body, well under MIN_ENTROPY_RUN. Should produce no
    // entropy-fallback finding for these specific bytes.
    let body = "abc+defg";
    let line = format!("config = {body}\n");
    let matches = scan(line);
    let phantom = matches
        .iter()
        .filter(|m| m.credential.as_ref() == body)
        .count();
    assert_eq!(
        phantom, 0,
        "8-char short body must not produce a phantom credential finding"
    );
}

#[test]
fn separator_only_run_without_keywords_is_admitted() {
    let mut token_bytes = Vec::with_capacity(KEYWORD_FREE_MIN_LEN + 4);
    while token_bytes.len() < KEYWORD_FREE_MIN_LEN + 4 {
        token_bytes.extend_from_slice(BASE64_ALPHABET);
    }
    token_bytes.truncate(KEYWORD_FREE_MIN_LEN + 4);

    token_bytes[10] = b'-';
    token_bytes[24] = b'_';
    token_bytes[38] = b'-';
    token_bytes[52] = b'_';

    let token = String::from_utf8(token_bytes).expect("token bytes are printable ascii");
    assert!(
        shannon_entropy(token.as_bytes()) > 5.8_f64,
        "punctuation-separated high-entropy token must clear keyword-free entropy floor"
    );

    let matches = scan(format!("cfg: {token}\n"));
    let surfaced = matches
        .iter()
        .any(|m| m.credential.as_ref().contains(&token));
    assert!(
        surfaced,
        "punctuation-separated high-entropy run should be admitted via entropy-run gate without keyword anchors; token={token} matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn token_with_plus_is_not_dropped_as_encoded_binary() {
    let token = "TVoAAAAAAhBANBBCDDDOIAKEGGEXq+BPrbcMHUYAZCNJQIdKLeRJHOFfFCLS";
    let matches = scan(format!("SECRET={token}\n"));
    let surfaced = matches
        .iter()
        .any(|m| m.credential.as_ref().contains(token));
    assert!(
        surfaced,
        "high-entropy base64-like token with internal `+` must not be suppressed as encoded binary; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
