use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use keyhog_core::{load_detectors, Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::PathBuf;
use std::time::Duration;

fn make_chunk(data: &str, path: Option<&str>) -> Chunk {
    Chunk {
        data: data.to_string(),
        metadata: ChunkMetadata {
            source_type: "benchmark".into(),
            path: path.map(|p| p.into()),
            commit: None,
            author: None,
            date: None,
        },
    }
}

fn generate_dense_hit_text(size: usize) -> String {
    let mut s = String::with_capacity(size);
    let line = "const api_key = \"sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\";\n";
    while s.len() + line.len() <= size {
        s.push_str(line);
    }
    while s.len() < size {
        s.push('x');
    }
    s.truncate(size);
    s
}

fn generate_no_hit_text(size: usize) -> String {
    let mut s = String::with_capacity(size);
    let line = "fn ordinary_function() { println!(\"hello world\"); }\n";
    while s.len() + line.len() <= size {
        s.push_str(line);
    }
    while s.len() < size {
        s.push('x');
    }
    s.truncate(size);
    s
}

fn detectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

fn bench_scan_throughput(c: &mut Criterion) {
    let detectors = load_detectors(&detectors_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let sizes = [1024, 10 * 1024, 100 * 1024];

    let mut group = c.benchmark_group("scan_inner_throughput");
    for size in sizes {
        let data = generate_dense_hit_text(size);
        let chunk = make_chunk(&data, Some("bench.txt"));
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("cpu_fallback", format!("{}B", size)),
            &chunk,
            |b, chk| {
                b.iter(|| {
                    black_box(scanner.scan_with_backend(black_box(chk), ScanBackend::CpuFallback))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("simd_cpu", format!("{}B", size)),
            &chunk,
            |b, chk| {
                b.iter(|| {
                    black_box(scanner.scan_with_backend(black_box(chk), ScanBackend::SimdCpu))
                });
            },
        );
        #[cfg(feature = "gpu")]
        group.bench_with_input(
            BenchmarkId::new("vyre_gpu", format!("{}B", size)),
            &chunk,
            |b, chk| {
                b.iter(|| black_box(scanner.scan_with_backend(black_box(chk), ScanBackend::Gpu)));
            },
        );
    }
    group.finish();
}

fn bench_scan_no_hit_throughput(c: &mut Criterion) {
    let detectors = load_detectors(&detectors_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let sizes = [1024, 1024 * 1024, 8 * 1024 * 1024];

    let mut group = c.benchmark_group("scan_no_hit_throughput");
    for size in sizes {
        let data = generate_no_hit_text(size);
        let chunk = make_chunk(&data, Some("src/main.rs"));
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("cpu_fallback", format!("{}B", size)),
            &chunk,
            |b, chk| {
                b.iter(|| {
                    black_box(scanner.scan_with_backend(black_box(chk), ScanBackend::CpuFallback))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("simd_cpu", format!("{}B", size)),
            &chunk,
            |b, chk| {
                b.iter(|| {
                    black_box(scanner.scan_with_backend(black_box(chk), ScanBackend::SimdCpu))
                });
            },
        );
        #[cfg(feature = "gpu")]
        group.bench_with_input(
            BenchmarkId::new("vyre_gpu", format!("{}B", size)),
            &chunk,
            |b, chk| {
                b.iter(|| black_box(scanner.scan_with_backend(black_box(chk), ScanBackend::Gpu)));
            },
        );
    }
    group.finish();
}

#[cfg(feature = "gpu")]
fn bench_raw_vyre_gpu(c: &mut Criterion) {
    let patterns = vec![b"needle".to_vec()];
    let pattern_refs: Vec<&[u8]> = patterns.iter().map(Vec::as_slice).collect();

    let dq = vyre_wgpu::runtime::cached_device().expect("failed to get GPU device");
    let (device, _) = &*dq;

    let scanner = vyre_libs::matching::GpuLiteralSet::compile(&pattern_refs);

    let sizes = [1024, 1024 * 1024, 8 * 1024 * 1024];
    let mut group = c.benchmark_group("vyre_raw_scan");
    for size in sizes {
        let mut buffer = vec![0u8; size];
        if size > 16 {
            buffer[size / 2..size / 2 + 6].copy_from_slice(b"needle");
        }

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("one_match", format!("{}B", size)),
            &buffer,
            |b, data| {
                b.iter(|| black_box(scanner.scan_shared(black_box(data)).expect("vyre GPU scan")));
            },
        );
    }
    group.finish();
}

#[cfg(not(feature = "gpu"))]
fn bench_raw_vyre_gpu(_c: &mut Criterion) {}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = bench_scan_throughput, bench_scan_no_hit_throughput, bench_raw_vyre_gpu
}
criterion_main!(benches);
