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
fn skewed_small_chunks_enforce_actual_lane_bytes_for_worker_siblings() {
    for outlier_index in [0, 49, 99] {
        let chunks: Vec<Chunk> = (0..100)
            .map(|index| Chunk {
                data: keyhog_core::SensitiveString::from("x".repeat(if index == outlier_index {
                    64 * 1_024
                } else {
                    1_024
                })),
                metadata: Default::default(),
            })
            .collect();
        let evidence = BatchEvidence::measure(&chunks);
        for workers in [1, 2, 4, 8] {
            let topology = BatchTopology::select(&evidence, workers);
            let actual_max_lane_bytes = chunks
                .chunks(topology.lane_width)
                .map(|lane| lane.iter().map(|chunk| chunk.data.len()).sum::<usize>())
                .max()
                .unwrap();
            assert!(
                actual_max_lane_bytes <= 512 * 1_024,
                "workers={workers} outlier={outlier_index} lane_width={}",
                topology.lane_width
            );
            assert!(topology.max_memory_per_lane_bytes <= 512 * 1_024);
        }
    }
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

#[test]
fn test_mixed_batch_with_adjacent_large_chunks() {
    let evidence = BatchEvidence {
        total_chunks: 10,
        small_chunks: 8,
        large_chunks: 2,
        total_bytes: 400_000,
        max_chunk_bytes: 150_000,
    };
    let topology = BatchTopology::select(&evidence, 4);
    assert_eq!(topology.lane_width, 1);
    assert_eq!(topology.max_memory_per_lane_bytes, 150_000);
}
#[cfg(target_os = "linux")]
fn proc_status_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .expect("read isolated child process status")
        .lines()
        .find_map(|line| {
            line.strip_prefix(field)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .expect("requested resident-memory field is present")
}

#[cfg(target_os = "linux")]
fn partition_detector() -> keyhog_core::DetectorSpec {
    keyhog_core::DetectorSpec {
        id: "partition-rss-probe".into(),
        name: "Partition RSS probe".into(),
        service: "test".into(),
        severity: keyhog_core::Severity::High,
        patterns: vec![keyhog_core::PatternSpec {
            regex: r"TOKEN_[0-9]_[A-Z]{32}".into(),
            ..Default::default()
        }],
        keywords: vec!["TOKEN_".into()],
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

#[cfg(target_os = "linux")]
#[test]
fn concurrent_production_partitions_obey_process_rss_bound() {
    const CHILD_ENV: &str = "KEYHOG_PARTITION_RSS_CHILD";
    const PARTITIONS: usize = 4;
    const CHUNKS_PER_PARTITION: usize = 8;
    const CHUNK_BYTES: usize = 1024 * 1024;
    const MAX_PEAK_DELTA_KIB: u64 = 128 * 1024;
    const MAX_RETAINED_DELTA_KIB: u64 = 64 * 1024;

    if std::env::var_os(CHILD_ENV).is_none() {
        let module = module_path!()
            .strip_prefix("keyhog_scanner::")
            .unwrap_or(module_path!());
        let test_name =
            format!("{module}::concurrent_production_partitions_obey_process_rss_bound");
        let output = std::process::Command::new(
            std::env::current_exe().expect("resolve current test executable"),
        )
        .args(["--exact", &test_name, "--nocapture"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("run isolated partition RSS workflow");
        assert!(
            output.status.success(),
            "isolated partition RSS workflow failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("partition-rss-evidence"),
            "isolated workflow did not emit resident evidence"
        );
        return;
    }

    let baseline_rss_kib = proc_status_kib("VmRSS:");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(PARTITIONS));
    std::thread::scope(|scope| {
        for partition in 0..PARTITIONS {
            let barrier = barrier.clone();
            scope.spawn(move || {
                let scanner = keyhog_scanner::engine::CompiledScanner::compile_for_backend(
                    vec![partition_detector()],
                    keyhog_scanner::hw_probe::ScanBackend::CpuFallback,
                )
                .expect("compile partition scanner");
                let chunks: Vec<Chunk> = (0..CHUNKS_PER_PARTITION)
                    .map(|chunk_index| {
                        let mut data =
                            format!("TOKEN_{partition}_ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF\n");
                        data.push_str(&"x".repeat(CHUNK_BYTES - data.len()));
                        Chunk {
                            data: keyhog_core::SensitiveString::from(data),
                            metadata: keyhog_core::ChunkMetadata {
                                path: Some(
                                    format!("partition-{partition}/chunk-{chunk_index}").into(),
                                ),
                                ..Default::default()
                            },
                        }
                    })
                    .collect();
                barrier.wait();
                let results = scanner
                    .scan_chunks_with_backend(
                        &chunks,
                        keyhog_scanner::hw_probe::ScanBackend::CpuFallback,
                    )
                    .expect("scan real concurrent partition");
                assert_eq!(results.len(), CHUNKS_PER_PARTITION);
                assert!(results.iter().all(|matches| !matches.is_empty()));
                scanner.finish_partition();
            });
        }
    });
    let peak_kib = proc_status_kib("VmHWM:");
    let retained_kib = proc_status_kib("VmRSS:");
    let peak_delta_kib = peak_kib.saturating_sub(baseline_rss_kib);
    let retained_delta_kib = retained_kib.saturating_sub(baseline_rss_kib);
    println!(
        "partition-rss-evidence baseline={baseline_rss_kib}KiB peak={peak_kib}KiB retained={retained_kib}KiB"
    );
    assert!(
        peak_delta_kib <= MAX_PEAK_DELTA_KIB,
        "concurrent production partitions added {peak_delta_kib} KiB peak RSS"
    );
    assert!(
        retained_delta_kib <= MAX_RETAINED_DELTA_KIB,
        "finished production partitions retained {retained_delta_kib} KiB RSS"
    );
}
