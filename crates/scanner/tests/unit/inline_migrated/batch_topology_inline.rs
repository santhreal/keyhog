//! Migrated from src/engine/batch_topology.rs

use keyhog_core::Chunk;

#[test]
fn skewed_small_chunks_bound_lane_bytes_by_the_largest_chunk() {
    const TARGET_BYTES: usize = 512 * 1024;
    const THRESHOLD: usize = 64 * 1024;

    for outlier_index in [0, 49, 99] {
        let sizes: Vec<usize> = (0..100)
            .map(|index| {
                if index == outlier_index {
                    THRESHOLD
                } else {
                    1_024
                }
            })
            .collect();
        for workers in [1, 2, 4, 8] {
            let lanes =
                keyhog_scanner::testing::chunk_lane_topology_for_test(&sizes, THRESHOLD, workers);
            let mut scheduled = Vec::with_capacity(sizes.len());
            for (is_large, indices) in lanes {
                assert!(!is_large);
                let lane_bytes = indices.iter().map(|&index| sizes[index]).sum::<usize>();
                assert!(
                    lane_bytes <= TARGET_BYTES,
                    "workers={workers} outlier={outlier_index} lane_bytes={lane_bytes}"
                );
                scheduled.extend(indices);
            }
            scheduled.sort_unstable();
            assert_eq!(scheduled, (0..sizes.len()).collect::<Vec<_>>());
        }
    }
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
