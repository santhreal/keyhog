//! Contract: twitch-client-id contract positive fires on canonical client id.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

const DETECTOR_ID: &str = "twitch-client-id";
const TEXT: &str = "TWITCH client        _        - -    _        -   _   - - _   id::'=  '   \" ms2uvf52y6in49bdtvr079w81jvoa4";
const CREDENTIAL: &str = "ms2uvf52y6in49bdtvr079w81jvoa4";

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn twitch_client_id_first_positive_fires() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: TEXT.into(),
        metadata: ChunkMetadata {
            source_type: "contract".into(),
            path: Some("twitch.env".into()),
            ..Default::default()
        },
    };

    scanner.clear_fragment_cache();
    let matches = scanner.scan(&chunk);
    assert!(
        matches.iter().any(|m| {
            m.detector_id.as_ref() == DETECTOR_ID && m.credential.as_ref().contains(CREDENTIAL)
        }),
        "{DETECTOR_ID} must surface client id; saw {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
