#[cfg(test)]
use super::{validate_mass_batch, Chunk, ChunkMetadata, MASS_BATCH_BYTES, MASS_BATCH_CHUNKS};

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
