//! Contract: aws-access-key fires on canonical AKIA shape with exact
//! credential bytes and detector id.

use crate::support::paths::detector_dir;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

const DETECTOR_ID: &str = "aws-access-key";
const CANONICAL_TEXT: &str = concat!("AK", "IAQYLPMN5HFIQR7XYA");
const CANONICAL_CREDENTIAL: &str = concat!("AK", "IAQYLPMN5HFIQR7XYA");

#[test]
fn aws_access_key_fires_on_canonical_shape() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = Chunk {
        data: CANONICAL_TEXT.into(),
        metadata: ChunkMetadata {
            source_type: "contract".into(),
            path: Some("aws-canonical.txt".into()),
            ..Default::default()
        },
    };

    scanner.clear_fragment_cache();
    let matches = scanner.scan(&chunk);

    let aws_hits: Vec<_> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == DETECTOR_ID)
        .collect();

    assert!(
        !aws_hits.is_empty(),
        "aws-access-key must fire on canonical AKIA shape {:?}; saw detector ids: {:?}",
        CANONICAL_TEXT,
        matches
            .iter()
            .map(|m| m.detector_id.as_ref())
            .collect::<Vec<_>>()
    );

    assert!(
        aws_hits
            .iter()
            .any(|m| m.credential.as_ref() == CANONICAL_CREDENTIAL),
        "aws-access-key credential bytes must be exactly {:?}; got {:?}",
        CANONICAL_CREDENTIAL,
        aws_hits
            .iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}
