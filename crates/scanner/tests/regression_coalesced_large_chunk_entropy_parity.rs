//! Boundary lock: the coalesced batch producer must agree with the per-chunk
//! path on a large no-trigger chunk whose only secret is an anchorless
//! high-entropy token. Chunk size is not detection policy: source and scanner
//! windows bound work, while every window still executes the active detector
//! plan completely.
//!
//! The existing coalesced≡per-chunk locks
//! (`lane6_full_corpus_property_invariants::coalesced_equals_per_chunk_for_single_chunk`
//! 10k cases, `scanner_invariants_full_corpus_proptest`) only feed SMALL inputs
//! (≤3072 bytes), so they never cross the 32 KiB boundary. This test pins the
//! boundary explicitly: both pipelines must surface the same `entropy-token` on
//! a 40 KiB chunk. A future size cutoff would drop the token and turn this red,
//! a real recall divergence between
//! `--backend simd` (per-chunk) and `--backend gpu-wgpu` / `--batch-pipeline`
//! (coalesced), which is exactly the M-02 parity surface.
//!
//! Gated on `entropy` (the `entropy-token` detector compiles out without it, as
//! in `phase2_no_hit_branch_recall`); ci-lean carries the feature, so it runs in
//! the default CI lane. The token is GENERATED at runtime (never a literal in
//! source) so the repo's own dogfood self-scan cannot flag this file, and it is a
//! deterministic fabricated non-credential, not a real secret.
#![cfg(feature = "entropy")]

#[path = "support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::sync::LazyLock;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use support::paths::detector_dir;

/// The full production scanner, compiled once with `min_confidence = 0.0` so the
/// low-confidence anchorless entropy finding is not filtered before we can assert
/// parity on it (mirrors the CLI's `--min-confidence 0`). A load/compile failure
/// is surfaced LOUDLY (Law 10), never a silent skip.
static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("full detector corpus must load for the large-chunk entropy parity lock");
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    CompiledScanner::compile(detectors)
        .expect("full detector corpus must compile")
        .with_config(config)
});

/// A 44-char high-entropy token built from a fixed permutation of the alnum
/// alphabet. 62 and 37 are coprime, so `(i*37+11) % 62` visits distinct residues
/// 44 distinct characters, well above the entropy floor. WITHOUT ever writing
/// a secret-shaped literal into this source file (dogfood-self-scan safe).
fn entropy_token() -> String {
    const AL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..44).map(|i| AL[(i * 37 + 11) % 62] as char).collect()
}

/// A >32 KiB chunk: benign prose (passes the alphabet screen, carries no detector
/// trigger and no secret keyword) with one bare entropy token on its own line in
/// the middle. Its size crosses the removed scanner-global admission cutoff.
fn large_no_hit_chunk_with_entropy_token(token: &str) -> Chunk {
    const PROSE: &str =
        "the quick brown fox jumps over the lazy dog while walking through the forest path today morning. ";
    let mut body = String::with_capacity(48 * 1024);
    // Fill past 32 KiB, then splice the token line into the middle.
    while body.len() < 40 * 1024 {
        body.push_str(PROSE);
        body.push('\n');
    }
    let mid = body.len() / 2;
    let line_start = body[..mid].rfind('\n').map(|i| i + 1).unwrap_or(0);
    body.insert_str(line_start, &format!("{token}\n"));
    assert!(
        body.len() > 32 * 1024,
        "chunk must exceed the former 32 KiB admission cutoff, got {}",
        body.len()
    );
    Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "large-entropy-parity".into(),
            path: Some("big.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// (detector_id, credential, offset) (order-independent finding identity).
fn keyset(matches: &[keyhog_core::RawMatch]) -> BTreeSet<(String, String, usize)> {
    matches
        .iter()
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location.offset,
            )
        })
        .collect()
}

#[test]
fn coalesced_matches_per_chunk_on_large_no_hit_entropy_chunk() {
    let token = entropy_token();
    let c = large_no_hit_chunk_with_entropy_token(&token);

    SCANNER.clear_fragment_cache();
    let per_chunk = keyset(&SCANNER.scan(&c));

    SCANNER.clear_fragment_cache();
    let coalesced_nested = SCANNER.scan_coalesced(std::slice::from_ref(&c));
    assert_eq!(
        coalesced_nested.len(),
        1,
        "scan_coalesced over a 1-chunk batch must return exactly 1 result vec, got {}",
        coalesced_nested.len()
    );
    let coalesced = keyset(&coalesced_nested[0]);

    // NON-VACUITY (Law 6): the >32 KiB chunk must actually be scanned by BOTH
    // paths (the anchorless entropy token is found, not silently size-gated away).
    // A test that passed on two empty sets would be decoration.
    assert!(
        per_chunk
            .iter()
            .any(|(det, cred, _)| det == "entropy-token" && cred == &token),
        "per-chunk path must surface the anchorless entropy token on the large chunk; \
         got {per_chunk:?}"
    );

    // PARITY: the coalesced admission gate drops/adds NOTHING vs the per-chunk
    // entropy sweep on the large input.
    assert_eq!(
        per_chunk, coalesced,
        "coalesced batch producer diverged from per-chunk on a >32 KiB no-trigger entropy chunk"
    );
}
