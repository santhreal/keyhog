use crate::engine::{scan_chunk_boundaries_for_test, CompiledScanner};
use crate::telemetry::{boundary_result_cardinality_mismatch_count, testing::reset};
use keyhog_core::{Chunk, ChunkMetadata, RawMatch, SensitiveString};

fn chunk(data: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: SensitiveString::from(data),
        metadata: ChunkMetadata {
            source_type: "boundary-cardinality-regression".into(),
            path: Some("fixtures/boundary-cardinality.env".into()),
            base_offset,
            ..Default::default()
        },
    }
}

#[test]
fn boundary_reassembly_cardinality_mismatch_is_counted() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    reset();
    let scanner = CompiledScanner::compile(Vec::new()).expect("empty scanner compiles");
    let chunks = vec![chunk("left", 0), chunk("right", 4)];
    let mut per_chunk_results: Vec<Vec<RawMatch>> = vec![Vec::new()];

    scan_chunk_boundaries_for_test(&scanner, &chunks, &mut per_chunk_results);

    assert_eq!(
        boundary_result_cardinality_mismatch_count(),
        1,
        "boundary chunk/result cardinality drift must be scanner coverage-gap telemetry"
    );
    assert_eq!(
        per_chunk_results.len(),
        1,
        "mismatch path must not append into an unrelated result slot"
    );
    reset();
}
