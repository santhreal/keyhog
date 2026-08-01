use criterion::{criterion_group, criterion_main, Criterion};
use keyhog_profile::{enabled, reset, set_enabled, span, Stage};
use std::hint::black_box;

fn span_overhead(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("profile-span");

    set_enabled(false);
    group.bench_function("disabled", |bencher| {
        bencher.iter(|| drop(black_box(span(Stage::Preprocess))));
    });
    group.bench_function("enabled-check-only", |bencher| {
        bencher.iter(|| black_box(enabled()));
    });

    set_enabled(true);
    group.bench_function("enabled", |bencher| {
        bencher.iter(|| drop(black_box(span(Stage::Preprocess))));
    });
    set_enabled(false);
    reset();
    group.finish();
}

criterion_group!(benches, span_overhead);
criterion_main!(benches);
