//! Migrated from src/engine/batch_topology.rs

use keyhog_core::Chunk;
use keyhog_scanner::engine::batch_topology::{BatchEvidence, BatchTopology};

#[test]
fn test_batch_evidence_measurement() {
    let chunks = vec![
        Chunk {
            data: keyhog_core::SensitiveString::from("a".repeat(100)),
            metadata: Default::default(),
        },
        Chunk {
            data: keyhog_core::SensitiveString::from("a".repeat(100_000)),
            metadata: Default::default(),
        },
    ];
    let evidence = BatchEvidence::measure(&chunks);
    assert_eq!(evidence.total_chunks, 2);
    assert_eq!(evidence.small_chunks, 1);
    assert_eq!(evidence.large_chunks, 1);
    assert_eq!(evidence.max_chunk_bytes, 100_000);
}

#[test]
fn test_batch_topology_selection_bounds() {
    let evidence = BatchEvidence {
        total_chunks: 100,
        small_chunks: 99,
        large_chunks: 1,
        total_bytes: 100_000,
        max_chunk_bytes: 70_000,
    };
    let topology = BatchTopology::select(&evidence, 4);
    assert!(topology.lane_width >= 1);
    assert!(topology.max_memory_per_lane_bytes > 0);
    assert!(topology.fused_waves >= 1);
}

#[test]
fn test_all_large_chunks_topology() {
    let evidence = BatchEvidence {
        total_chunks: 10,
        small_chunks: 0,
        large_chunks: 10,
        total_bytes: 10_000_000,
        max_chunk_bytes: 1_000_000,
    };
    let topology = BatchTopology::select(&evidence, 4);
    assert_eq!(topology.lane_width, 1);
}

#[test]
fn test_empty_batch_topology() {
    let evidence = BatchEvidence {
        total_chunks: 0,
        small_chunks: 0,
        large_chunks: 0,
        total_bytes: 0,
        max_chunk_bytes: 0,
    };
    let topology = BatchTopology::select(&evidence, 4);
    assert_eq!(topology.lane_width, 1);
    assert_eq!(topology.fused_waves, 1);
    assert_eq!(topology.max_memory_per_lane_bytes, 0);
}
#[test]
fn test_fused_waves_ceiling_division_non_multiple() {
    let evidence = BatchEvidence {
        total_chunks: 5,
        small_chunks: 5,
        large_chunks: 0,
        total_bytes: 5 * 100,
        max_chunk_bytes: 100,
    };
    let topology = BatchTopology::select(&evidence, 1);
    assert!(topology.fused_waves >= 1);
    assert_eq!(
        topology.fused_waves,
        evidence.total_chunks.div_ceil(topology.lane_width)
    );
}
