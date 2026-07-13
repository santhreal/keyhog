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
    static_rejection_aggregate: u64,
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
        static_rejection_aggregate: snapshot
            .static_recovery_rejections
            .get("literal_byte_array_element")
            .copied()
            .unwrap_or(0),
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
    assert_eq!(per_chunk.static_rejection_aggregate, 1);

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
            static_rejection_aggregate: 5,
        }
    );
    assert_eq!(
        second.join().expect("second scan thread"),
        ScopedCounts {
            suppressions: per_chunk.suppressions * 9,
            static_rejections: 9,
            static_rejection_aggregate: 9,
        }
    );
}

#[test]
fn dogfood_detail_budget_keeps_exact_static_recovery_aggregates() {
    let total = keyhog_scanner::telemetry::DOGFOOD_DETAIL_EVENT_LIMIT + 7;
    let chunks: Vec<Chunk> = (0..total)
        .map(|index| Chunk {
            data: concat!(
                "const malformed = [256]; const xorKey = [1]; ",
                "String.fromCharCode(...malformed.map((b, i) => ",
                "b ^ xorKey[i % xorKey.length]));\n"
            )
            .into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some(format!("budget-{index}.js").into()),
                ..Default::default()
            },
        })
        .collect();
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    telemetry::with_scan_telemetry(&trace, || {
        let findings = scanner().scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback);
        assert!(findings.iter().all(Vec::is_empty));
    });
    let snapshot = trace.drain();
    assert_eq!(
        snapshot
            .static_recovery_rejections
            .get("literal_byte_array_element"),
        Some(&(total as u64))
    );
    assert_eq!(
        snapshot
            .dogfood_events
            .iter()
            .filter(|event| matches!(event, DogfoodEvent::StaticRecoveryRejected { .. }))
            .count(),
        keyhog_scanner::telemetry::DOGFOOD_DETAIL_EVENT_LIMIT
    );
    assert_eq!(snapshot.dogfood_detail_events_dropped, 7);
}

#[cfg(feature = "simd")]
#[test]
fn oversized_coalesced_window_workers_inherit_the_request_scope() {
    let prefix = concat!(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        "const malformed = [256]; const xorKey = [1]; ",
        "String.fromCharCode(...malformed.map((b, i) => ",
        "b ^ xorKey[i % xorKey.length]));\n"
    );
    let mut source = String::with_capacity(1024 * 1024 + 256);
    source.push_str(prefix);
    source.extend(std::iter::repeat_n('x', 1024 * 1024 + 256 - prefix.len()));
    let chunk = Chunk {
        data: source.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("windowed.js".into()),
            ..Default::default()
        },
    };
    let scanner = scanner();
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    telemetry::with_scan_telemetry(&trace, || {
        let findings = scanner.scan_coalesced_with_backend(&[chunk], ScanBackend::SimdCpu);
        assert!(findings.iter().all(Vec::is_empty));
    });
    let snapshot = trace.drain();
    assert!(snapshot.example_suppressions > 0);
    assert!(
        snapshot
            .dogfood_events
            .iter()
            .any(|event| matches!(event, DogfoodEvent::ExampleSuppressed { .. })),
        "window worker must emit its suppression detail into the request trace"
    );
}

#[cfg(feature = "simd")]
#[test]
fn coalesced_simd_phase_two_workers_inherit_the_request_scope() {
    let scanner = scanner();
    let chunks = example_chunks(6, "simd-phase-two");
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    telemetry::with_scan_telemetry(&trace, || {
        let findings = scanner.scan_coalesced_with_backend(&chunks, ScanBackend::SimdCpu);
        assert!(findings.iter().all(Vec::is_empty));
    });
    let snapshot = trace.drain();
    assert_eq!(
        snapshot
            .static_recovery_rejections
            .get("literal_byte_array_element"),
        Some(&6)
    );
    assert_eq!(
        snapshot
            .dogfood_events
            .iter()
            .filter(|event| matches!(event, DogfoodEvent::StaticRecoveryRejected { .. }))
            .count(),
        6
    );
}
