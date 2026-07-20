#[cfg(test)]
use super::{
    autoroute_state_recovery_status, Chunk, ChunkMetadata, RecoveredInputRangeStatus, ScanBackend,
};
#[cfg(test)]
use crate::orchestrator::AutorouteStateRecovery;

#[cfg(test)]
#[test]
fn autoroute_state_recovery_receipt_covers_every_nonempty_daemon_chunk() {
    let chunks = vec![
        Chunk {
            data: "first".into(),
            metadata: ChunkMetadata::default(),
        },
        Chunk {
            data: String::new().into(),
            metadata: ChunkMetadata::default(),
        },
        Chunk {
            data: "second-secret".into(),
            metadata: ChunkMetadata::default(),
        },
    ];
    let recovery = AutorouteStateRecovery {
        reason: "missing proof".to_string(),
        announce: true,
    };

    let status = autoroute_state_recovery_status(&chunks, ScanBackend::CpuFallback, &recovery);

    assert_eq!(status.failed_backend, "autoroute-invalid");
    assert_eq!(status.recovery_backend, "cpu-fallback");
    assert_eq!(status.recovered_chunks, 2);
    assert_eq!(status.recovered_bytes, 18);
    assert_eq!(
        status.recovered_ranges,
        vec![
            RecoveredInputRangeStatus {
                chunk_index: 0,
                byte_start: 0,
                byte_end: 5,
            },
            RecoveredInputRangeStatus {
                chunk_index: 2,
                byte_start: 0,
                byte_end: 13,
            },
        ]
    );
    assert_eq!(status.reason, "missing proof");
}
