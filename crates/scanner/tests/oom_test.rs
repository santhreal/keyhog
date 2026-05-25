use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

#[test]
fn test_large_chunk_skip() {
    let scanner = CompiledScanner::compile(vec![]).unwrap();

    // Create a 513MB string
    let data = "a".repeat(513 * 1024 * 1024);

    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata::default(),
    };

    // The 512MB skip-too-large gate in scan_windowed must:
    // (a) return immediately with zero matches, AND
    // (b) finish in well under the time a full 513MB scan would take.
    //     A full scan across ~900 detectors hits 30s+ on this hardware;
    //     the skip path is dominated by the 513MB string alloc (~4-5s)
    //     plus a few microseconds of length check. Budget 10s leaves
    //     enough room for slow CI hardware while still failing loud
    //     if the skip-gate is removed and the scan actually runs.
    // Previous assertion was just `is_empty()`, which would still pass
    // if the scanner ran the full 513MB scan and merely produced zero
    // findings.
    let start = std::time::Instant::now();
    let matches = scanner.scan(&chunk);
    let elapsed = start.elapsed();
    assert!(matches.is_empty(), "skipped chunk must produce zero matches");
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "skip-gate must short-circuit; got {elapsed:?} (expected < 10s — \
         if this fails the 512MB scan_windowed gate has regressed and the \
         scanner is doing real work on a 513MB chunk)"
    );
}
