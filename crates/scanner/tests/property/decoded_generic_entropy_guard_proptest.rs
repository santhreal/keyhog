//! Property: the decode-through generic/entropy anchor guard
//! (`adjudicate::record_decoded_generic_entropy_suppression`, KH-L-0404) holds
//! for ARBITRARY high-entropy tokens, not just the fixed regression fixtures.
//!
//! For any high-entropy token `T`, base64-encoding `secret=T` and scanning the
//! blob with decode-through recovers `secret=T` as SYNTHESIZED decoded content 
//! where a generic/entropy detector would fire on shape/entropy ALONE, with no
//! anchor in the decoded bytes. The guard must gate EVERY such decoded
//! generic/entropy match. This proptest sweeps the token space and asserts that
//! invariant; the NON-VACUITY (that these `secret=<token>` shapes DO fire a
//! generic/entropy detector at top level, so the gate is doing real work) is
//! pinned by
//! `regression_decoded_generic_entropy_guard::control_token_fires_generic_or_entropy_at_top_level`.
//!
//! Why `credential == token` isolates the decoded match: the token is base64
//! ENCODED at top level, so no TOP-LEVEL finding can carry the raw token as its
//! credential, only a match on the DECODED content can. A leaked entry is
//! therefore proof the guard failed on the decode path, never a top-level
//! false positive on the blob.

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
    /// Invariant: no generic/entropy detector may fire on the DECODED token, for
    /// any high-entropy alphanumeric token. If the guard is ever removed or its
    /// detector-id predicate narrows, some token here surfaces a decoded
    /// generic/entropy match and this fails with the exact leaking (id, value).
    #[test]
    fn decoded_generic_entropy_gated_for_any_high_entropy_token(
        token in "[A-Za-z0-9]{32,48}"
    ) {
        let plaintext = format!("secret={token}\n");
        let blob = base64::engine::general_purpose::STANDARD.encode(plaintext.as_bytes());
        let hits = scan(format!("blob = \"{blob}\"\n"));
        let leaked: Vec<(String, String)> = hits
            .iter()
            .filter(|m| {
                m.credential.as_ref() == token && is_generic_or_entropy(m.detector_id.as_ref())
            })
            .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
            .collect();
        prop_assert!(
            leaked.is_empty(),
            "decoded generic/entropy leaked for token {token}: {leaked:?}",
        );
    }
}
