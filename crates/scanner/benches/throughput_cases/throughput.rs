// THROUGHPUT BENCHMARKS

fn benchmark_throughput_1mb_mixed_source(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_1mb_mixed_source");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(20));
    group.warm_up_time(std::time::Duration::from_secs(3));

    let data = generate_mixed_source_code_1mb();
    let detectors = load_all_detectors();
    let scanner = CompiledScanner::compile(detectors).expect("Failed to compile scanner");

    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("scan_1mb", |b| {
        let chunk = make_chunk(&data, Some("test.py"));
        b.iter(|| {
            let matches = scanner.scan(black_box(&chunk));
            black_box(matches)
        });
    });

    group.finish();
}

fn benchmark_throughput_10mb_env_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_10mb_env_files");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(30));
    group.warm_up_time(std::time::Duration::from_secs(5));

    let data = generate_env_files_10mb();
    let detectors = load_all_detectors();
    let scanner = CompiledScanner::compile(detectors).expect("Failed to compile scanner");

    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("scan_10mb", |b| {
        let chunk = make_chunk(&data, Some(".env"));
        b.iter(|| {
            let matches = scanner.scan(black_box(&chunk));
            black_box(matches)
        });
    });

    group.finish();
}

fn benchmark_throughput_base64_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_base64_decode");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    let data = generate_base64_encoded_data_100kb();
    let detectors = load_all_detectors();
    let scanner = CompiledScanner::compile(detectors).expect("Failed to compile scanner");

    group.throughput(Throughput::Bytes(data.len() as u64));

    // Benchmark base64 detection and decoding
    group.bench_function("decode_100kb", |b| {
        let chunk = make_chunk(&data, Some("config.env"));
        b.iter(|| {
            let decoded = decode::decode_chunk(black_box(&chunk), 2, false, None, None);
            black_box(decoded)
        });
    });

    // Benchmark full scan with decode-through
    group.bench_function("scan_with_decode_100kb", |b| {
        let chunk = make_chunk(&data, Some("config.env"));
        b.iter(|| {
            let mut matches = scanner.scan(&chunk);
            for decoded in decode::decode_chunk(&chunk, 2, false, None, None) {
                matches.extend(scanner.scan(&decoded));
            }
            black_box(matches)
        });
    });

    group.finish();
}
