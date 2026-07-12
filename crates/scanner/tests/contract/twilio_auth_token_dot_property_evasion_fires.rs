//! Contract: twilio-auth-token dot-property evasion fixture still fires.

use crate::support::paths::detector_dir;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

const DETECTOR_ID: &str = "twilio-auth-token";
const TEXT: &str = "Twilio.AccountSid=AC7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d
Twilio.AuthToken=4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f";
const CREDENTIAL: &str = "4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f";

#[test]
fn twilio_auth_token_dot_property_evasion_fires() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: TEXT.into(),
        metadata: ChunkMetadata {
            source_type: "contract".into(),
            path: Some("twilio.config".into()),
            ..Default::default()
        },
    };

    scanner.clear_fragment_cache();
    let matches = scanner.scan(&chunk);
    assert!(
        matches.iter().any(|m| {
            m.detector_id.as_ref() == DETECTOR_ID && m.credential.as_ref().contains(CREDENTIAL)
        }),
        "{DETECTOR_ID} evasion (.NET dot properties) must fire; saw {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
