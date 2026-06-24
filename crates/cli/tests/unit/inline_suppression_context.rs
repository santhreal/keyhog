use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::{Chunk, ChunkMetadata, MatchLocation, RawMatch, SensitiveString, Severity};
use std::collections::HashMap;
use std::sync::Arc;

fn test_hash() -> [u8; 32] {
    [9u8; 32]
}

fn filesystem_chunk(path: &std::path::Path, data: &str) -> Chunk {
    Chunk {
        data: SensitiveString::from(data),
        metadata: ChunkMetadata {
            source_type: "filesystem".to_string(),
            path: Some(path.to_string_lossy().into_owned()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn raw_match(path: &std::path::Path, data: &str) -> RawMatch {
    RawMatch {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("Demo"),
        service: Arc::from("demo"),
        severity: Severity::Low,
        credential: SensitiveString::from("secret"),
        credential_hash: test_hash().into(),
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(path.to_string_lossy().as_ref())),
            line: Some(2),
            offset: data.find("secret").expect("fixture contains credential"),
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    }
}

#[test]
fn inline_suppression_uses_scanned_bytes_when_file_mutates_after_scan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("with_ignore.rs");
    let scanned = "// keyhog:ignore\nlet token = \"secret\";\n";
    std::fs::write(&path, scanned).unwrap();

    let chunk = filesystem_chunk(&path, scanned);
    let mut matches = vec![raw_match(&path, scanned)];
    API.attach_inline_suppression_context_for_test(&chunk, &mut matches);

    std::fs::write(&path, "let token = \"secret\";\n").unwrap();

    let kept = API.filter_inline_suppressions(matches);
    assert!(
        kept.is_empty(),
        "inline suppression must use the bytes that produced the finding, not a later disk read"
    );
}

#[test]
fn inline_context_is_stripped_from_unsuppressed_findings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("without_ignore.rs");
    let scanned = "let marker = 1;\nlet token = \"secret\";\n";
    std::fs::write(&path, scanned).unwrap();

    let chunk = filesystem_chunk(&path, scanned);
    let mut matches = vec![raw_match(&path, scanned)];
    API.attach_inline_suppression_context_for_test(&chunk, &mut matches);

    let kept = API.filter_inline_suppressions(matches);
    assert_eq!(kept.len(), 1);
    assert!(
        kept[0]
            .companions
            .keys()
            .all(|key| !key.starts_with("__keyhog_internal_inline_")),
        "internal inline-suppression context must not leak into reports"
    );
}
