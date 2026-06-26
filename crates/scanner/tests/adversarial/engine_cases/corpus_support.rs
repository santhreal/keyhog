//! Shared helpers for corpus-backed adversarial / regression tests.

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Canonical synthetic credentials used across corpus fixtures.
// A real github-classic-pat shape: `ghp_` + a 36-char body whose trailing chars
// are a VALID checksum, so the scanner actually fires on it. The prior value
// `ghp_aBc…7890ab` had a 38-char body and an invalid checksum, so the engine
// correctly dropped it and every recall/evasion test expecting it to fire failed
// (the checksum-fabricated-token trap). This token is the github-classic-pat
// contract's must-fire positive, so it is guaranteed to pass checksum validation.
pub const GITHUB_PAT: &str = "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";
pub const AWS_ACCESS_KEY: &str = concat!("AK", "IAR7VXNPLMQ3HSKWJT");
pub fn corpus_fixture_path(subdir: &str, rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/corpus")
        .join(subdir)
        .join(rel)
}

pub fn recall_fixture_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/recall/kh_challenging")
        .join(rel)
}

pub fn load_embedded_detectors() -> Vec<DetectorSpec> {
    keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load")
}

pub fn production_scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        CompiledScanner::compile(load_embedded_detectors())
            .expect("compile production detector corpus")
    })
}

pub fn scan_corpus(subdir: &str, rel: &str) -> Vec<keyhog_core::RawMatch> {
    let path = corpus_fixture_path(subdir, rel);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: format!("test/corpus/{subdir}"),
            path: Some(path.display().to_string()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            ..Default::default()
        },
    };
    production_scanner().scan(&chunk)
}

pub fn scan_recall(rel: &str) -> Vec<keyhog_core::RawMatch> {
    let path = recall_fixture_path(rel);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "test/recall/kh_challenging".into(),
            path: Some(path.display().to_string()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            ..Default::default()
        },
    };
    production_scanner().scan(&chunk)
}

pub fn scan_text(data: &str, path: &str) -> Vec<keyhog_core::RawMatch> {
    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "test/inline".into(),
            path: Some(path.into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            ..Default::default()
        },
    };
    production_scanner().scan(&chunk)
}

pub fn has_detector(matches: &[keyhog_core::RawMatch], needle: &str) -> bool {
    matches
        .iter()
        .any(|m| m.detector_id.as_ref().contains(needle) || m.service.as_ref().contains(needle))
}

pub fn has_credential(matches: &[keyhog_core::RawMatch], credential: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref() == credential || m.credential.as_ref().contains(credential))
}
