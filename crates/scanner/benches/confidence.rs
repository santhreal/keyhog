use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use keyhog_scanner::confidence::{compute_confidence, ConfidenceSignals};

fn bench_confidence(c: &mut Criterion) {
    let signals = vec![
        (
            "low",
            ConfidenceSignals {
                has_literal_prefix: false,
                has_context_anchor: false,
                entropy: 2.5,
                keyword_nearby: false,
                sensitive_file: false,
                match_length: 16,
                has_companion: false,
            },
        ),
        (
            "medium",
            ConfidenceSignals {
                has_literal_prefix: true,
                has_context_anchor: false,
                entropy: 4.0,
                keyword_nearby: true,
                sensitive_file: false,
                match_length: 32,
                has_companion: false,
            },
        ),
        (
            "high",
            ConfidenceSignals {
                has_literal_prefix: true,
                has_context_anchor: true,
                entropy: 6.0,
                keyword_nearby: true,
                sensitive_file: true,
                match_length: 64,
                has_companion: true,
            },
        ),
    ];

    let mut group = c.benchmark_group("confidence");
    for (name, sig) in &signals {
        group.bench_with_input(BenchmarkId::new("compute", *name), sig, |b, s| {
            b.iter(|| criterion::black_box(compute_confidence(criterion::black_box(s))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_confidence);
criterion_main!(benches);
