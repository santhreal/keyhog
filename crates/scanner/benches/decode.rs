use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::decode::decode_chunk;

fn make_chunk(data: &str) -> Chunk {
    Chunk {
        data: data.to_string(),
        metadata: ChunkMetadata {
            source_type: "benchmark".into(),
            path: Some("bench.txt".into()),
            commit: None,
            author: None,
            date: None,
        },
    }
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_chunk");

    let base64_input = make_chunk(
        "api_key=\"c2stbGl2ZS14eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4\"",
    );
    group.bench_with_input(
        BenchmarkId::new("base64", "1kb"),
        &base64_input,
        |b, chk| {
            b.iter(|| {
                criterion::black_box(decode_chunk(
                    criterion::black_box(chk),
                    3,
                    false,
                    None,
                    None,
                ))
            });
        },
    );

    let hex_input = make_chunk(
        "secret=\"736b2d6c6976652d78787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878\"",
    );
    group.bench_with_input(BenchmarkId::new("hex", "1kb"), &hex_input, |b, chk| {
        b.iter(|| {
            criterion::black_box(decode_chunk(
                criterion::black_box(chk),
                3,
                false,
                None,
                None,
            ))
        });
    });

    let url_input = make_chunk(
        "token=%73%6b%2d%6c%69%76%65%2d%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78%78",
    );
    group.bench_with_input(BenchmarkId::new("url", "1kb"), &url_input, |b, chk| {
        b.iter(|| {
            criterion::black_box(decode_chunk(
                criterion::black_box(chk),
                3,
                false,
                None,
                None,
            ))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
