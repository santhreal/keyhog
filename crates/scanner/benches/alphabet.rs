use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use keyhog_scanner::alphabet_filter::{AlphabetMask, AlphabetScreen};

fn bench_alphabet_mask_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("alphabet_mask_building");
    let data = vec![0u8; 1024 * 1024]; // 1MB

    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("from_bytes_1mb", |b| {
        b.iter(|| black_box(AlphabetMask::from_bytes(black_box(&data))));
    });
    group.finish();
}

fn bench_alphabet_screen(c: &mut Criterion) {
    let mut group = c.benchmark_group("alphabet_screen");
    let mut data = vec![b'a'; 1024 * 1024]; // 1MB
    let screen = AlphabetScreen::new(&["z".to_string()]);

    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("screen_1mb_no_match", |b| {
        b.iter(|| black_box(screen.screen(black_box(&data))));
    });

    data[1024 * 512] = b'z';
    group.bench_function("screen_1mb_with_match", |b| {
        b.iter(|| black_box(screen.screen(black_box(&data))));
    });

    group.finish();
}

criterion_group!(benches, bench_alphabet_mask_building, bench_alphabet_screen);
criterion_main!(benches);
