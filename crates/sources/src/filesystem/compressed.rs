use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use std::path::Path;

use super::read;

pub(super) fn extract_compressed_chunks(
    path: &Path,
    max_size: u64,
) -> Vec<Result<Chunk, SourceError>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let format = match ext.as_str() {
        "gz" => ziftsieve::CompressionFormat::Gzip,
        "zst" => ziftsieve::CompressionFormat::Zstd,
        "lz4" => ziftsieve::CompressionFormat::Lz4,
        _ => ziftsieve::CompressionFormat::Snappy,
    };

    let file_bytes = match read::read_file_for_compressed_input(path, max_size) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let bytes = file_bytes.as_slice();

    let total_budget: usize = max_size.saturating_mul(4) as usize;

    let mut chunks = Vec::new();

    if let Ok(blocks) = ziftsieve::extract_from_bytes(format, bytes) {
        let mut current_chunk_literals = String::new();
        let mut total_decompressed: usize = 0;
        for block in blocks {
            if let Ok(s) = std::str::from_utf8(block.literals()) {
                total_decompressed = total_decompressed.saturating_add(s.len());
                if total_decompressed > total_budget {
                    tracing::warn!(
                        path = %path.display(),
                        bytes = total_decompressed,
                        cap = total_budget,
                        "aborting compressed extraction: total decompressed size exceeds 4x file cap (gzip-bomb guard)"
                    );
                    break;
                }
                current_chunk_literals.push_str(s);
                current_chunk_literals.push('\n');
            }

            if current_chunk_literals.len() > 8 * 1024 * 1024 {
                chunks.push(Ok(Chunk {
                    data: std::mem::take(&mut current_chunk_literals).into(),
                    metadata: ChunkMetadata {
                        source_type: "filesystem/compressed".into(),
                        path: Some(path.display().to_string()),
                        ..Default::default()
                    },
                }));
            }
        }
        if !current_chunk_literals.is_empty() {
            chunks.push(Ok(Chunk {
                data: current_chunk_literals.into(),
                metadata: ChunkMetadata {
                    source_type: "filesystem/compressed".into(),
                    path: Some(path.display().to_string()),
                    ..Default::default()
                },
            }));
        }
    }
    chunks
}
