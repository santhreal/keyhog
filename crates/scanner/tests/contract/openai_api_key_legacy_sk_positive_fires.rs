//! Contract: openai-api-key legacy `sk-` positive fires.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

const DETECTOR_ID: &str = "openai-api-key";
const TEXT: &str = "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ";
const CREDENTIAL: &str = "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ";

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn openai_api_key_legacy_sk_positive_fires() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: TEXT.into(),
        metadata: ChunkMetadata {
            source_type: "contract".into(),
            path: Some("openai.txt".into()),
            ..Default::default()
        },
    };

    scanner.clear_fragment_cache();
    let matches = scanner.scan(&chunk);
    assert!(
        matches.iter().any(|m| {
            m.detector_id.as_ref() == DETECTOR_ID && m.credential.as_ref().contains(CREDENTIAL)
        }),
        "{DETECTOR_ID} must surface legacy sk- key; saw {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
