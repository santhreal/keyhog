// LATENCY BENCHMARKS

fn benchmark_latency_single_line(c: &mut Criterion) {
    let mut group = c.benchmark_group("latency_single_line");
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(std::time::Duration::from_secs(30));

    let data = generate_single_line_secret();
    let detectors = load_all_detectors();
    let scanner = CompiledScanner::compile(detectors).expect("Failed to compile scanner");

    group.bench_function("p50_p99_latency", |b| {
        let chunk = make_chunk(&data, Some("config.py"));
        b.iter(|| {
            let matches = scanner.scan(black_box(&chunk));
            black_box(matches)
        });
    });

    group.finish();
}

fn benchmark_latency_ml_inference(c: &mut Criterion) {
    let mut group = c.benchmark_group("latency_ml_inference");
    group.sampling_mode(SamplingMode::Flat);

    let test_credentials = [
        ("github_pat", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        (
            "openai_key",
            "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ),
        ("aws_key", "AKIAIOSFODNN7EXAMPLE"),
        (
            "slack_token",
            "xoxb-1234567890-1234567890-abcdefghijABCDEFGHIJklmn",
        ),
        ("generic_secret", "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL"),
    ];

    for (name, credential) in &test_credentials {
        let context = format!("API_KEY={}", credential);
        group.bench_with_input(BenchmarkId::new("score", name), credential, |b, cred| {
            b.iter(|| {
                let score = ml_scorer::score(black_box(cred), &context);
                black_box(score)
            });
        });
    }

    group.finish();
}

fn benchmark_latency_entropy_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("latency_entropy_calculation");
    group.sampling_mode(SamplingMode::Flat);

    let test_candidates = [
        ("short_secret", "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL"),
        (
            "medium_secret",
            "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ),
        (
            "long_secret",
            "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ),
        ("hex_hash", "d41d8cd98f00b204e9800998ecf8427e"),
    ];

    for (name, candidate) in &test_candidates {
        group.bench_with_input(
            BenchmarkId::new("shannon_entropy", name),
            candidate,
            |b, cand| {
                b.iter(|| {
                    let entropy = entropy::shannon_entropy(black_box(cand.as_bytes()));
                    black_box(entropy)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("token_efficiency", name),
            candidate,
            |b, cand| {
                b.iter(|| {
                    let eff = entropy::normalized_entropy(black_box(cand.as_bytes()));
                    black_box(eff)
                });
            },
        );
    }

    group.finish();
}

fn benchmark_latency_regex_compilation(c: &mut Criterion) {
    let mut group = c.benchmark_group("latency_regex_compilation");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    let detectors = load_all_detectors();

    group.bench_function("compile_all_detectors", |b| {
        b.iter(|| {
            let scanner = CompiledScanner::compile(black_box(detectors.clone()));
            black_box(scanner)
        });
    });

    group.finish();
}

// MEMORY BENCHMARKS
