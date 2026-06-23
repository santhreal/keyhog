#![cfg(feature = "simdsieve")]

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use support::paths::detector_dir;

fn scanner() -> CompiledScanner {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory must load");
    CompiledScanner::compile(detectors).expect("scanner compile")
}

fn scanner_without(detector_id: &str) -> CompiledScanner {
    let mut detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory must load");
    detectors.retain(|detector| detector.id != detector_id);
    CompiledScanner::compile(detectors).expect("scanner compile")
}

#[test]
fn hot_openai_key_uses_process_false_positive_context_suppression() {
    let token = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD";
    let chunk = Chunk {
        data: format!("version https://git-lfs.github.com/spec/v1\noid sha256:{token}\n").into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("repo/.gitattributes".into()),
            ..Default::default()
        },
    };

    let matches = scanner().scan(&chunk);
    assert!(
        matches
            .iter()
            .all(|m| !(m.detector_id.as_ref() == "openai-api-key"
                && m.credential.as_ref() == token)),
        "simdsieve hot path must delegate canonical OpenAI hits through process_match false-positive context suppression; matches={matches:?}"
    );
}

#[test]
fn hot_openai_key_does_not_emit_when_canonical_detector_is_not_loaded() {
    let token = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD";
    let chunk = Chunk {
        data: format!("OPENAI_API_KEY={token}\n").into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("repo/.env".into()),
            ..Default::default()
        },
    };

    let matches = scanner_without("openai-api-key").scan(&chunk);
    assert!(
        matches
            .iter()
            .all(|m| !(m.detector_id.as_ref() == "openai-api-key"
                && m.credential.as_ref() == token)),
        "simdsieve hot path must not direct-emit a canonical detector that was not compiled; matches={matches:?}"
    );
}
