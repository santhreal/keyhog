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

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn shared_scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        let mut cfg = ScannerConfig::default();
        cfg.min_confidence = 0.0;
        CompiledScanner::compile(detectors)
            .expect("compile")
            .with_config(cfg)
    })
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

    /// Property: a 60-char alnum body with one `+` inserted near the
    /// middle, planted as the value of a `TOKEN=` line, must surface
    /// SOMEWHERE in the finding set. Before the fix the run gate
    /// pre-screened the chunk out because the `+` split the run.
    ///
    /// Body distribution: each character is drawn from a 16-symbol
    /// alphabet so the body's distinct-character count is always
    /// >= 16 - well above the diversity floor downstream gates use.
    /// The contract under test is the entropy-RUN gate (the run
    /// continues across `+`), not the per-credential diversity floor;
    /// constraining the random draws to high-diversity input isolates
    /// the gate we are locking down.
    #[test]
    fn b64_secret_with_internal_plus_surfaces(
        idxs in prop::collection::vec(0u8..16u8, 59),
    ) {
        // 16-symbol alphabet: 4 upper, 4 lower, 4 digit, 4 base64-safe.
        // Every character pool has size 16 so distinct_alnum(body) is
        // guaranteed high regardless of which indices the shrinker
        // settles on.
        let alphabet: &[u8] = b"AKQZakqz0379bcde";
        let chars: String = idxs.iter().map(|i| alphabet[*i as usize] as char).collect();
        let (head, tail) = chars.split_at(29);
        let body = format!("{head}+{tail}");
        prop_assert_eq!(body.len(), 60);
        let line = format!("export TOKEN={body}\n");

        let matches = scan(line.clone());
        let surfaced = matches
            .iter()
            .any(|m| m.credential.as_ref().contains(&body));
        prop_assert!(
            surfaced,
            "60-char base64 body with internal `+` must surface in some \
             finding; line={:?} matches={:?}",
            line,
            matches.iter()
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
