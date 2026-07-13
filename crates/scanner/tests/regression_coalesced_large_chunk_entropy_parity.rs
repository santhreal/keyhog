//! Boundary lock: the coalesced batch producer must agree with the per-chunk
//! path on a LARGE (>32 KiB) no-trigger chunk whose only secret is an anchorless
//! high-entropy token.
//!
//! WHY THIS EXISTS (the gap the existing parity locks miss). `scan_coalesced`
//! routes no-trigger chunks through `scan_coalesced_phase2_with_admission`
//! (`engine/scan_coalesced.rs`): a chunk with no phase-1 trigger only reaches the
//! entropy/generic sweep if `should_scan_no_hit_chunk` admits it, and that
//! predicate's `no_hit_text_admits` gates the entropy/generic checks behind
//! `small_chunk = text.len() <= NO_HIT_ENTROPY_ADMISSION_MAX_BYTES` (32 KiB). The
//! per-chunk path (`scan`) has NO such size gate, any alphabet-screen-passing
//! chunk runs the full entropy sweep regardless of size. So a >32 KiB no-trigger
//! chunk carrying an anchorless entropy token is exactly where the two paths
//! COULD diverge (coalesced silently dropping a finding the per-chunk path keeps).
//!
//! The existing coalesced≡per-chunk locks
//! (`lane6_full_corpus_property_invariants::coalesced_equals_per_chunk_for_single_chunk`
//! 10k cases, `scanner_invariants_full_corpus_proptest`) only feed SMALL inputs
//! (≤3072 bytes), so they never cross the 32 KiB boundary. This test pins the
//! boundary explicitly: measured on the shipped binary, both pipelines surface
//! the same `entropy-token` on a 40 KiB chunk, the coalesced admission gate
//! admits the large chunk (chunk windowing / the always-active phase-2 pre-check
//! fire before the size gate), so parity holds. A future change that made the
//! `small_chunk` gate authoritative for the whole chunk would drop the token on
//! the coalesced path and turn this red, a real Law-10 recall divergence between
//! `--backend simd` (per-chunk) and `--backend gpu` / `--batch-pipeline`
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
///: 44 distinct characters, well above the entropy floor. WITHOUT ever writing
/// a secret-shaped literal into this source file (dogfood-self-scan safe).
fn entropy_token() -> String {
    const AL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..44).map(|i| AL[(i * 37 + 11) % 62] as char).collect()
}

/// A >32 KiB chunk: benign prose (passes the alphabet screen, carries no detector
/// trigger and no secret keyword) with one bare entropy token on its own line in
/// the middle. Larger than `NO_HIT_ENTROPY_ADMISSION_MAX_BYTES` (32 KiB) so it
/// exercises the coalesced no-hit admission size boundary.
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
        "chunk must exceed the 32 KiB small_chunk admission boundary, got {}",
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
    // entropy sweep at the >32 KiB boundary.
    assert_eq!(
        per_chunk, coalesced,
        "coalesced batch producer diverged from per-chunk on a >32 KiB no-trigger \
         entropy chunk, the small_chunk admission gate silently dropped/added a finding"
    );
}
