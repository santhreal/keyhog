//! Law-10 sibling-path contracts for phase-2 route optimizations.
//!
//! These tests drive the branch whose comment claims recall is preserved, then
//! assert the match set or set membership, not the wording of the comment.

use super::support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "probe".into(),
            path: Some("probe.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
fn failed_truncated_regexset_uses_full_set_for_marking() {
    let full_sources = [r"routeproof_[A-Z0-9]{6}", r"sk_live_[A-Za-z0-9]{20,}"];
    let invalid_truncated_sources = vec![
        "routeproof_(".to_string(),
        "sk_live_[A-Za-z0-9]{20".to_string(),
    ];

    let matches = keyhog_scanner::testing::phase2_truncated_set_failure_matches_full_set(
        &full_sources,
        &invalid_truncated_sources,
        false,
        "value = sk_live_ABCDEFGHIJKLMNOPQRST",
    )
    .expect("invalid truncated set must still return the full RegexSet");

    assert_eq!(
        matches,
        vec![1],
        "failed truncated RegexSet construction must reuse the full set so the \
         matching full-source entry remains marked"
    );
}

#[test]
fn anchor_ineligible_phase2_pattern_runs_whole_chunk_under_anchor_mode() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors load");
    let asana = detectors
        .iter()
        .find(|detector| detector.id == "asana-pat")
        .expect("asana-pat detector must be embedded");
    let regex = asana
        .patterns
        .first()
        .expect("asana-pat must have a pattern")
        .regex
        .as_str();
    assert!(
        keyhog_scanner::testing::phase2_required_prefix_literals(regex).is_none(),
        "asana-pat must be anchor-ineligible or this does not prove the sibling path"
    );

    let scanner = CompiledScanner::compile(detectors).expect("scanner compiles");
    let sample = chunk(
        "asana_token=1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU\nordinary = no secret\n",
    );
    let credential = "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU";

    keyhog_scanner::testing::set_phase2_anchor_mode(&scanner, Some(false));
    scanner.clear_fragment_cache();
    let baseline =
        scanner.scan_chunks_with_backend(std::slice::from_ref(&sample), ScanBackend::CpuFallback);
    assert!(
        baseline.iter().flatten().any(|m| {
            m.detector_id.as_ref() == "asana-pat" && m.credential.as_ref() == credential
        }),
        "the production baseline must contain the asana-pat proof match; matches={baseline:?}"
    );

    keyhog_scanner::testing::set_phase2_anchor_mode(&scanner, Some(true));
    scanner.clear_fragment_cache();
    let matches =
        scanner.scan_chunks_with_backend(std::slice::from_ref(&sample), ScanBackend::CpuFallback);
    keyhog_scanner::testing::set_phase2_anchor_mode(&scanner, None);

    assert!(
        matches.iter().flatten().any(|m| {
            m.detector_id.as_ref() == "asana-pat" && m.credential.as_ref() == credential
        }),
        "an anchor-ineligible phase-2 pattern must still run through the whole-chunk \
         sibling path when shared-anchor mode is forced on; matches={matches:?}"
    );
}
