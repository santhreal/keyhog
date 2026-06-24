use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::{Chunk, ChunkMetadata, MatchLocation, RawMatch, SensitiveString, Severity};
use std::collections::HashMap;
use std::sync::Arc;

fn test_hash() -> [u8; 32] {
    [9u8; 32]
}

fn filesystem_chunk(path: &std::path::Path, data: &str) -> Chunk {
    filesystem_chunk_at(path, data, 0)
}

fn filesystem_chunk_at(path: &std::path::Path, data: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: SensitiveString::from(data),
        metadata: ChunkMetadata {
            source_type: "filesystem".to_string(),
            path: Some(path.to_string_lossy().into_owned()),
            base_offset,
            ..Default::default()
        },
    }
}

fn raw_match(path: &std::path::Path, data: &str) -> RawMatch {
    raw_match_at(
        path,
        "secret",
        data.find("secret").expect("fixture contains credential"),
        Some(2),
    )
}

fn raw_match_at(
    path: &std::path::Path,
    credential: &str,
    offset: usize,
    line: Option<usize>,
) -> RawMatch {
    RawMatch {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("Demo"),
        service: Arc::from("demo"),
        severity: Severity::Low,
        credential: SensitiveString::from(credential),
        credential_hash: test_hash().into(),
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(path.to_string_lossy().as_ref())),
            line,
            offset,
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

#[test]
fn inline_suppression_context_resolves_boundary_match_owner_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("boundary.rs");
    let chunk_a_text = "// keyhog:ignore\nSTRADDLE_SE";
    let chunk_b_text = "CRET\n";
    let scanned = format!("{chunk_a_text}{chunk_b_text}");
    std::fs::write(&path, &scanned).unwrap();

    let chunks = vec![
        filesystem_chunk_at(&path, chunk_a_text, 0),
        filesystem_chunk_at(&path, chunk_b_text, chunk_a_text.len()),
    ];
    let boundary_offset = chunk_a_text
        .find("STRADDLE")
        .expect("fixture contains boundary credential start");
    let boundary_match = raw_match_at(&path, "STRADDLE_SECRET", boundary_offset, Some(2));
    let mut per_chunk = vec![Vec::new(), vec![boundary_match]];

    API.attach_inline_suppression_context_for_chunks_for_test(&chunks, &mut per_chunk);
    std::fs::write(&path, "STRADDLE_SECRET\n").unwrap();

    let matches = per_chunk.into_iter().flatten().collect();
    let kept = API.filter_inline_suppressions(matches);
    assert!(
        kept.is_empty(),
        "boundary findings assigned to the right-hand bucket must still use the owner chunk bytes for inline suppression"
    );
}
