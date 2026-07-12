//! KH-GAP-164: Invalid embedded checksum must drop named-service matches.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;

use crate::support::paths::detector_dir;
fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        CompiledScanner::compile(detectors).expect("compile detectors")
    })
}

fn assert_detector_silent(detector_id: &str, text: &str) {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "probe".into(),
            path: Some("config.txt".into()),
            ..Default::default()
        },
    };
    let hits: Vec<_> = scanner()
        .scan(&chunk)
        .into_iter()
        .filter(|m| m.detector_id.as_ref() == detector_id)
        .collect();
    assert!(
        hits.is_empty(),
        "detector {detector_id} fired on invalid-checksum text {text:?}: {hits:#?}"
    );
}

#[test]
fn r5_checksum_invalid_drops_named_service_match() {
    assert_detector_silent(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaXXXXXX",
    );
    assert_detector_silent(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaBxxxxxx",
    );
}
