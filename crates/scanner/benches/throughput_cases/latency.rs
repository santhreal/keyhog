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
        (
            "github_pat",
            concat!("gh", "p_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ),
        (
            "openai_key",
            "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ),
        ("aws_key", concat!("AK", "IAIOSFODNN7EXAMPLE")),
        (
            "slack_token",
            concat!("xox", "b-1234567890-1234567890-abcdefghijABCDEFGHIJklmn"),
        ),
        ("generic_secret", "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL"),
    ];

    for (name, credential) in &test_credentials {
        let context = format!("API_KEY={}", credential);
        group.bench_with_input(BenchmarkId::new("score", name), credential, |b, cred| {
            b.iter(|| {
                let score = keyhog_scanner::testing::ml_score(black_box(cred), &context);
                black_box(score)
            });
        });
    }

    group.finish();
}

fn benchmark_latency_entropy_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("latency_entropy_calculation");
    group.sampling_mode(SamplingMode::Flat);

    fn sized_candidate(seed: &str, length: usize) -> String {
        let mut value = String::with_capacity(length);
        while value.len() < length {
            value.push_str(seed);
        }
        value.truncate(length);
        value
    }

    let test_candidates = [
        ("random_16", "aK7xP9mQ2wE5rT8y"),
        ("random_17", "aK7xP9mQ2wE5rT8yU"),
        ("random_32", "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJ"),
        (
            "prefixed_64",
            "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ),
        (
            "prefixed_128",
            "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ),
        ("hex_hash", "d41d8cd98f00b204e9800998ecf8427e"),
        (
            "encoded_base64",
            "U2FsdGVkX18AESIzRFVmd4gAG90IBfANYeQRW2joYGicJIAQKVwfQhcc0SZhoi6",
        ),
        (
            "word_like",
            "CorrectHorseBatteryStapleConfigurationIdentifier",
        ),
    ];
    let boundary_candidates = [
        // These are the detector policy boundaries: keeping both sides in
        // every input class catches tokenizer cost or threshold drift at the
        // exact lengths where entropy/BPE admission changes.
        ("random", "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJ"),
        (
            "word_like",
            "CorrectHorseBatteryStapleConfigurationIdentifier",
        ),
        (
            "encoded_base64",
            "U2FsdGVkX18AESIzRFVmd4gAG90IBfANYeQRW2joYGicJIAQKVwfQhcc0SZhoi6",
        ),
    ]
    .into_iter()
    .flat_map(|(class, seed)| {
        [24usize, 25, 40, 41]
            .into_iter()
            .map(move |length| (format!("{class}_{length}"), sized_candidate(seed, length)))
    })
    .collect::<Vec<_>>();

    group.bench_function("bpe_tokenizer_build", |b| {
        b.iter(|| {
            let tokenizer = keyhog_scanner::testing::build_entropy_bpe_tokenizer()
                .expect("embedded cl100k ranks must construct");
            black_box(tokenizer)
        });
    });

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
                    let eff = keyhog_scanner::testing::entropy_bpe_bytes_per_token(black_box(cand));
                    black_box(eff)
                });
            },
        );
    }

    for (name, candidate) in &boundary_candidates {
        debug_assert!(matches!(candidate.len(), 24 | 25 | 40 | 41));
        group.bench_with_input(
            BenchmarkId::new("token_efficiency_boundary", name),
            candidate,
            |b, cand| {
                b.iter(|| {
                    let eff = keyhog_scanner::testing::entropy_bpe_bytes_per_token(black_box(cand));
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
