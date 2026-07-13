use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::telemetry::{self, DogfoodEvent, ScanTelemetry};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};
use std::sync::{Arc, Barrier};

fn scanner() -> CompiledScanner {
    CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("compile embedded detector corpus")
        .with_config(ScannerConfig::thorough())
}

fn example_chunks(count: usize, owner: &str) -> Vec<Chunk> {
    (0..count)
        .map(|index| Chunk {
            data: concat!(
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
                "const malformed = [256]; const xorKey = [1]; ",
                "String.fromCharCode(...malformed.map((b, i) => ",
                "b ^ xorKey[i % xorKey.length]));\n"
            )
            .into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some(format!("{owner}-{index}.env").into()),
                ..Default::default()
            },
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct ScopedCounts {
    suppressions: u64,
    static_rejections: usize,
}

fn scoped_parallel_counts(scanner: &CompiledScanner, chunks: &[Chunk]) -> ScopedCounts {
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    telemetry::with_scan_telemetry(&trace, || {
        let findings = scanner.scan_chunks_with_backend(chunks, ScanBackend::CpuFallback);
        assert!(
            findings.iter().all(Vec::is_empty),
            "published example credentials must be suppressed"
        );
    });
    let snapshot = trace.drain();
    ScopedCounts {
        suppressions: snapshot.example_suppressions,
        static_rejections: snapshot
            .dogfood_events
            .iter()
            .filter(|event| matches!(event, DogfoodEvent::StaticRecoveryRejected { .. }))
            .count(),
    }
}

#[test]
fn concurrent_request_scopes_propagate_to_rayon_workers_without_leakage() {
    let per_chunk = scoped_parallel_counts(&scanner(), &example_chunks(1, "baseline"));
    assert!(
        per_chunk.suppressions > 0,
        "baseline suppression must be counted"
    );
    assert_eq!(per_chunk.static_rejections, 1);

    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let first = std::thread::spawn(move || {
        let scanner = scanner();
        let chunks = example_chunks(5, "first");
        first_barrier.wait();
        scoped_parallel_counts(&scanner, &chunks)
    });
    let second_barrier = Arc::clone(&barrier);
    let second = std::thread::spawn(move || {
        let scanner = scanner();
        let chunks = example_chunks(9, "second");
        second_barrier.wait();
        scoped_parallel_counts(&scanner, &chunks)
    });
    barrier.wait();

    assert_eq!(
        first.join().expect("first scan thread"),
        ScopedCounts {
            suppressions: per_chunk.suppressions * 5,
            static_rejections: 5,
        }
    );
    assert_eq!(
        second.join().expect("second scan thread"),
        ScopedCounts {
            suppressions: per_chunk.suppressions * 9,
            static_rejections: 9,
        }
    );
}
