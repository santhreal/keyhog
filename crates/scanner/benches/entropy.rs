use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use keyhog_scanner::entropy::shannon_entropy;
use keyhog_scanner::entropy_fast::shannon_entropy_simd;

fn bench_entropy_lengths(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy");
    let lengths = [16, 64, 256, 1_000, 4_096, 16_384, 65_536, 1_024 * 1024];

    for len in lengths {
        let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::new("shannon", len), &data, |b, bytes| {
            b.iter(|| black_box(shannon_entropy(black_box(bytes))));
        });
        group.bench_with_input(BenchmarkId::new("simd", len), &data, |b, bytes| {
            b.iter(|| black_box(shannon_entropy_simd(black_box(bytes))));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_entropy_lengths);
criterion_main!(benches);
