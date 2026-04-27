
fn benchmark_memory_detector_loading(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_detector_loading");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    let detectors = load_all_detectors();

    // Measure memory per detector
    group.bench_function("memory_per_detector", |b| {
        b.iter(|| {
            let scanner =
                CompiledScanner::compile(black_box(detectors.clone())).expect("Failed to compile");
            black_box(scanner.detector_count());
        });
    });

    group.finish();
}

fn benchmark_memory_scan_growth(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_scan_growth");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    let detectors = load_all_detectors();
    let scanner = CompiledScanner::compile(detectors).expect("Failed to compile scanner");

    // Benchmark scanning increasing data sizes to detect memory growth patterns
    for size_kb in [100, 500, 1000, 5000].iter() {
        let size = *size_kb * 1024;
        let data = "x".repeat(size);
        let chunk = make_chunk(&data, Some("test.txt"));

        group.bench_with_input(
            BenchmarkId::new("scan_memory", format!("{}kb", size_kb)),
            &chunk,
            |b, chk| {
                b.iter(|| {
                    let matches = scanner.scan(black_box(chk));
                    black_box(matches)
                });
            },
        );
    }

    group.finish();
}

// VERIFICATION CACHE BENCHMARKS

fn benchmark_verification_cache_growth(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_cache_growth");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    // Simulate 10,000 verifications
    let test_secrets: Vec<String> = (0..10000)
        .map(|i| format!("sk-{}{}", i, "x".repeat(45)))
        .collect();

    group.bench_function("simulate_10k_verifications", |b| {
        b.iter(|| {
            // Simulate a simple verification cache
            let mut verified: std::collections::HashSet<String> = std::collections::HashSet::new();
            for secret in &test_secrets {
                if !verified.contains(secret) {
                    // Simulate verification
                    verified.insert(secret.clone());
                }
            }
            black_box(verified.len())
        });
    });

    group.finish();
}
