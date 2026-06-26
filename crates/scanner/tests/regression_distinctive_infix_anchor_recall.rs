//! Regression: a named detector whose regex opens with a character class (no
//! extractable literal prefix) and captures the WHOLE match (no keyword group)
//! but REQUIRES a distinctive literal infix must clear the confidence floor on
//! the strength of that infix.
//!
//! `terraform-cloud-api-token` / `terraform-enterprise-token` match
//! `[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{67,}`: every match necessarily
//! contains `.atlasv1.`, yet the match carried neither `has_literal_prefix`
//! (class start) nor `has_context_anchor` (no capture group), so its normalized
//! heuristic confidence landed below the 0.40 floor and dropped as
//! `below_min_confidence` (contracts_runner: terraform-* MISSED). The
//! `has_distinctive_inner_literal` signal credits the required `.atlasv1.` infix
//! as a third anchor form, lifting the match to NAMED_DETECTOR_ANCHOR_FLOOR.
//!
//! The precision twin pins soundness: a token of the same id/secret shape but
//! WITHOUT the `.atlasv1.` infix must not be claimed — the lift rides on the
//! required literal, not on the high-entropy body alone.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        CompiledScanner::compile(detectors).expect("compile scanner")
    })
}

fn matches_for(body: &str) -> Vec<(String, String)> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "distinctive-infix-anchor-regression".into(),
            path: Some("notes/infix-probe.txt".into()),
            ..Default::default()
        },
    };
    scanner().clear_fragment_cache();
    scanner()
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

// 14-char id + `.atlasv1.` + 70-char base62 secret (>= the detector's {67,}).
const TF_TOKEN: &str =
    "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy";

#[test]
fn terraform_atlasv1_token_surfaces_on_the_infix_anchor() {
    let matches = matches_for(TF_TOKEN);
    assert!(
        matches
            .iter()
            .any(|(id, found)| (id == "terraform-cloud-api-token"
                || id == "terraform-enterprise-token")
                && found == TF_TOKEN),
        "terraform atlasv1 token must surface on the required-infix anchor; matches={matches:?}"
    );
}

#[test]
fn same_shape_without_atlasv1_is_not_claimed() {
    // Same id/secret lengths but the required `.atlasv1.` infix is replaced by a
    // generic `.something.` — the detector regex cannot match, so it must not
    // fire. Proves the lift is anchored on the required literal, not the body.
    let bogus =
        "9X3kQp7VbT2hYR.somethin.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy";
    let matches = matches_for(bogus);
    assert!(
        !matches
            .iter()
            .any(|(id, _)| id == "terraform-cloud-api-token" || id == "terraform-enterprise-token"),
        "a token without the .atlasv1. infix must not be claimed; matches={matches:?}"
    );
}
