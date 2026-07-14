//! Property: a detector-owned `secret=` anchor survives base64 decode-through
//! for arbitrary high-entropy values. The encoded top-level bytes do not expose
//! the raw token, so an exact credential proves the decoded path retained it.
//!
//! Why `credential == token` isolates the decoded match: the token is base64
//! encoded at top level, so only a match on the decoded content can carry it.

#[path = "../support/mod.rs"]
mod support;

use crate::support::paths::detector_dir;
use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::CompiledScanner;
use proptest::prelude::*;
use std::sync::LazyLock;

/// The full on-disk detector set, compiled ONCE and amortised across every
/// proptest case (a per-case compile would dominate wall-clock).
static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load all detectors from Tier-B set");
    CompiledScanner::compile(detectors).expect("compile scanner")
});

/// Thin alias to the canonical predicate the GUARD itself gates on
/// (`keyhog_scanner::is_generic_or_entropy_detector` → `detector_ids::is_generic_or_entropy_detector`),
/// so this property validates the EXACT classification the guard uses. ONE
/// definitional home, no drift if the canonical prefix set ever changes.
fn is_generic_or_entropy(id: &str) -> bool {
    keyhog_scanner::is_generic_or_entropy_detector(id)
}

fn is_anchored_generic(id: &str) -> bool {
    is_generic_or_entropy(id) && !keyhog_scanner::is_entropy_detector(id)
}

fn scan(text: String) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "decode-guard-proptest".into(),
            path: Some("config.txt".into()),
            ..Default::default()
        },
    };
    SCANNER.scan(&chunk)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        max_global_rejects: 20_000,
        ..ProptestConfig::default()
    })]

    /// Invariant: the decoded generic assignment must surface for every
    /// high-entropy alphanumeric token.
    #[test]
    fn decoded_generic_assignment_matches_direct_assignment(
        token in "[A-Za-z0-9]{32,48}"
    ) {
        let plaintext = format!("secret={token}\n");
        let direct = scan(plaintext.clone());
        prop_assume!(direct.iter().any(|m| {
            m.credential.as_ref() == token && is_anchored_generic(m.detector_id.as_ref())
        }));
        let blob = base64::engine::general_purpose::STANDARD.encode(plaintext.as_bytes());
        let hits = scan(format!("blob = \"{blob}\"\n"));
        let recovered: Vec<(String, String)> = hits
            .iter()
            .filter(|m| {
                m.credential.as_ref() == token && is_anchored_generic(m.detector_id.as_ref())
            })
            .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
            .collect();
        prop_assert!(
            !recovered.is_empty(),
            "decoded generic assignment was lost for token {token}: hits={hits:?}",
        );
    }
}
