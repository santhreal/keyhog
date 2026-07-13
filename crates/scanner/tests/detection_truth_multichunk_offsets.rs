//! Detection-truth: MULTI-CHUNK scanning + global OFFSET correctness (#177/#184).
//! Real files are scanned in chunks; a finding's reported offset must be the
//! GLOBAL byte position (base_offset + local), the per-chunk result vectors must
//! line up 1:1 with the input chunks in order, and a file with several distinct
//! secrets must surface every one. Law 6 (exact offsets + values). ML-
//! independent; run without `ml` while the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn chunk(data: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "multichunk-test".into(),
            path: Some("s.txt".into()),
            base_offset,
            ..Default::default()
        },
    }
}

fn scan(chunks: &[Chunk]) -> Vec<Vec<(usize, String)>> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    scanner
        .scan_chunks_with_backend(chunks, ScanBackend::CpuFallback)
        .iter()
        .map(|per_chunk| {
            per_chunk
                .iter()
                .map(|m| (m.location.offset, m.credential.as_ref().to_string()))
                .collect()
        })
        .collect()
}

#[test]
fn base_offset_propagates_into_global_finding_offset() {
    // "key = AKIA...". AWS key starts at local offset 6; base_offset 1000.
    let results = scan(&[chunk("key = AKIAQYLPMN5HFIQR7BBB", 1000)]);
    assert!(
        results[0]
            .iter()
            .any(|(off, cred)| *off == 1006 && cred == "AKIAQYLPMN5HFIQR7BBB"),
        "expected AWS key at global offset 1006; got {:?}",
        results[0]
    );
}

#[test]
fn per_chunk_results_line_up_with_input_order() {
    let results = scan(&[
        chunk("a = glpat-ABCDEF1234567890abcd", 0),
        chunk("b = AKIAQYLPMN5HFIQR7BBB", 500),
    ]);
    assert_eq!(results.len(), 2, "one result vec per input chunk");
    assert!(
        results[0]
            .iter()
            .any(|(off, cred)| *off == 4 && cred == "glpat-ABCDEF1234567890abcd"),
        "chunk 0 gitlab token at offset 4; got {:?}",
        results[0]
    );
    assert!(
        results[1]
            .iter()
            .any(|(off, cred)| *off == 504 && cred == "AKIAQYLPMN5HFIQR7BBB"),
        "chunk 1 AWS key at global offset 504; got {:?}",
        results[1]
    );
}

#[test]
fn result_count_matches_chunk_count_even_when_some_are_empty() {
    let results = scan(&[
        chunk("nothing to see here", 0),
        chunk("key = AKIAQYLPMN5HFIQR7BBB", 100),
        chunk("also no secrets", 200),
    ]);
    assert_eq!(results.len(), 3, "3 chunks in → 3 result vecs out");
    assert!(results[0].is_empty(), "chunk 0 has no secret");
    assert!(!results[1].is_empty(), "chunk 1 has the AWS key");
    assert!(results[2].is_empty(), "chunk 2 has no secret");
}

#[test]
fn a_file_with_many_distinct_secrets_surfaces_every_one() {
    let file = "aws=AKIAQYLPMN5HFIQR7BBB\n\
                gitlab=glpat-ABCDEF1234567890abcd\n\
                google=AIzaSyA1234567890abcdefghijklmnopqrstuv\n\
                slack=xoxb-2345678901234-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx\n\
                stripe=sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000\n";
    let results = scan(&[chunk(file, 0)]);
    let creds: Vec<&String> = results[0].iter().map(|(_, c)| c).collect();
    for expected in [
        "AKIAQYLPMN5HFIQR7BBB",
        "glpat-ABCDEF1234567890abcd",
        "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        "xoxb-2345678901234-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
    ] {
        assert!(
            creds.iter().any(|c| c.as_str() == expected),
            "missing `{expected}`; found: {creds:?}"
        );
    }
}

#[test]
fn empty_input_yields_no_result_vectors() {
    let results = scan(&[]);
    assert!(results.is_empty(), "no chunks in → no result vecs");
}
