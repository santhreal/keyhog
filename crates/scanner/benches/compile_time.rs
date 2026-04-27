use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use keyhog_core::load_detectors;
use keyhog_scanner::CompiledScanner;
use std::path::Path;

fn bench_compile_time(c: &mut Criterion) {
    let all_detectors = load_detectors(Path::new("detectors")).expect("load detectors");
    let counts = [100, 500, all_detectors.len()];

    let mut group = c.benchmark_group("compile_time");
    for &count in &counts {
        let detectors: Vec<_> = all_detectors.iter().take(count).cloned().collect();
        group.bench_with_input(
            BenchmarkId::new("detectors", count),
            &detectors,
            |b, dets| {
                b.iter(|| {
                    let scanner = CompiledScanner::compile(dets.clone()).expect("compile");
                    criterion::black_box(scanner);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_compile_time);
criterion_main!(benches);
