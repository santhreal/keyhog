// COMBINED WORKLOAD BENCHMARKS

fn benchmark_combined_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("combined_full_pipeline");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(20));
    group.warm_up_time(std::time::Duration::from_secs(3));

    let data = generate_mixed_source_code_1mb();
    let detectors = load_all_detectors();
    let scanner = CompiledScanner::compile(detectors).expect("Failed to compile scanner");

    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("scan_with_entropy_and_decode", |b| {
        let chunk = make_chunk(&data, Some("source.py"));
        b.iter(|| {
            // Pattern matching
            let mut matches = scanner.scan(&chunk);

            // Decode-through scanning
            for decoded in decode::decode_chunk(&chunk, 2, false, None, None) {
                matches.extend(scanner.scan(&decoded));
            }

            // Entropy scanning
            let entropy_matches =
                entropy::find_entropy_secrets(&chunk.data, 16, 2, 4.5, &[], &[], &[]);

            black_box((matches.len(), entropy_matches.len()))
        });
    });

    group.finish();
}

// CRITERION CONFIGURATION
