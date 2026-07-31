#[cfg(test)]
use super::{
    autoroute_state_recovery_status, validate_mass_batch, Chunk, ChunkMetadata,
    RecoveredInputRangeStatus, ScanBackend, MASS_BATCH_BYTES, MASS_BATCH_CHUNKS,
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

#[cfg(test)]
fn mass_chunk(bytes: usize) -> Chunk {
    Chunk {
        data: "x".repeat(bytes).into(),
        metadata: ChunkMetadata::default(),
    }
}

/// An empty batch must fail before scanner execution instead of becoming a clean receipt.
#[cfg(test)]
#[test]
fn mass_batch_rejects_empty_input() {
    assert_eq!(
        validate_mass_batch(&[]),
        Err("daemon: MassBatch must contain at least one chunk".to_string())
    );
}

/// The documented 8 MiB raw-byte ceiling is inclusive for one exact chunk.
#[cfg(test)]
#[test]
fn mass_batch_accepts_exact_raw_byte_ceiling() {
    assert_eq!(
        validate_mass_batch(&[mass_chunk(MASS_BATCH_BYTES)]),
        Ok((1, MASS_BATCH_BYTES))
    );
}

/// One byte beyond the raw payload ceiling must fail before allocating scanner work.
#[cfg(test)]
#[test]
fn mass_batch_rejects_raw_byte_ceiling_plus_one() {
    assert_eq!(
        validate_mass_batch(&[mass_chunk(MASS_BATCH_BYTES + 1)]),
        Err(format!(
            "daemon: MassBatch contains {} raw bytes; maximum is {MASS_BATCH_BYTES}",
            MASS_BATCH_BYTES + 1
        ))
    );
}

/// The documented 1,024-chunk ceiling is inclusive when the byte budget also fits.
#[cfg(test)]
#[test]
fn mass_batch_accepts_exact_chunk_ceiling() {
    let chunks = (0..MASS_BATCH_CHUNKS)
        .map(|_| mass_chunk(1))
        .collect::<Vec<_>>();
    assert_eq!(
        validate_mass_batch(&chunks),
        Ok((MASS_BATCH_CHUNKS as u64, MASS_BATCH_CHUNKS))
    );
}

/// A 1,025th chunk must fail even when the total payload is only 1,025 bytes.
#[cfg(test)]
#[test]
fn mass_batch_rejects_chunk_ceiling_plus_one() {
    let chunks = (0..=MASS_BATCH_CHUNKS)
        .map(|_| mass_chunk(1))
        .collect::<Vec<_>>();
    assert_eq!(
        validate_mass_batch(&chunks),
        Err(format!(
            "daemon: MassBatch contains {} chunks; maximum is {MASS_BATCH_CHUNKS}",
            MASS_BATCH_CHUNKS + 1
        ))
    );
}
