use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

#[test]
fn test_large_chunk_skip() {
    let scanner = CompiledScanner::compile(vec![]).unwrap();

    // Create a 513MB string
    let data = "a".repeat(513 * 1024 * 1024);

    let chunk = Chunk {
        data,
        metadata: ChunkMetadata::default(),
    };

    // This should return immediately because of the 512MB check in scan_windowed
    let matches = scanner.scan(&chunk);
    assert!(matches.is_empty());
}
