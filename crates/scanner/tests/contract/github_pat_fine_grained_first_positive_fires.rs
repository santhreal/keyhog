//! Contract: github-pat-fine-grained first positive fires with exact credential.

use crate::support::paths::detector_dir;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

const DETECTOR_ID: &str = "github-pat-fine-grained";
const TEXT: &str =
    "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";
const CREDENTIAL: &str =
    "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";

#[test]
fn github_pat_fine_grained_first_positive_fires() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: TEXT.into(),
        metadata: ChunkMetadata {
            source_type: "contract".into(),
            path: Some("github-pat.txt".into()),
            ..Default::default()
        },
    };

    scanner.clear_fragment_cache();
    let matches = scanner.scan(&chunk);
    let hits: Vec<_> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == DETECTOR_ID)
        .collect();

    assert!(
        hits.iter()
            .any(|m| m.credential.as_ref().contains(CREDENTIAL)),
        "{DETECTOR_ID} must fire on contract positive; saw {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
