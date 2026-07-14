//! Decoder admission and decode-through performance.
//!
//! Record a comparison baseline with:
//! `cargo bench -p keyhog-scanner --bench decode -- --save-baseline decode-admission`.
//! Compare a changed implementation with the same command using
//! `--baseline decode-admission`. Criterion reports byte throughput for every
//! case. It does not expose allocation counts without an additional allocator
//! harness, so this benchmark does not claim allocation measurements.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::decode::{decode_admission_sketch, DecodeWorkloadPlan};
use keyhog_scanner::testing::{
    decode_admission_sketch_with_custom_unknown, decode_chunk, max_scan_chunk_bytes,
};
use std::hint::black_box;
use std::time::Duration;

const KIB: usize = 1024;
const STANDARD_CASE_BYTES: usize = 64 * KIB;
const MAX_DEPTH: usize = 3;

struct DecodeCases {
    plain: Chunk,
    sparse: Chunk,
    dense: Chunk,
    custom_unknown: Chunk,
    maximum: Chunk,
}

fn make_chunk(data: String, label: &str) -> Chunk {
    let size = data.len() as u64;
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "benchmark/decode".into(),
            path: Some(format!("{label}.txt").into()),
            size_bytes: Some(size),
            ..Default::default()
        },
    }
}

fn repeat_to_len(unit: &str, size: usize) -> String {
    assert!(unit.is_ascii() && !unit.is_empty());
    let mut text = String::with_capacity(size);
    while text.len() < size {
        let remaining = size - text.len();
        text.push_str(&unit[..unit.len().min(remaining)]);
    }
    text
}

fn sparse_escape_source(size: usize) -> String {
    const FILLER: &str = "let record_count = rows.len();\n";
    const ESCAPE: &str = "token=%73%6b%5f%6c%69%76%65%5f%41%42%43%44%45%46%47%48\n";
    let mut text = String::with_capacity(size);
    let mut since_escape = 0usize;
    while text.len() < size {
        let unit = if since_escape >= 8 * KIB {
            since_escape = 0;
            ESCAPE
        } else {
            since_escape += FILLER.len();
            FILLER
        };
        let remaining = size - text.len();
        text.push_str(&unit[..unit.len().min(remaining)]);
    }
    text
}

fn maximum_admitted_source(size: usize) -> String {
    const TAIL: &str = "token=%73%6b%5f%6c%69%76%65%5f%41%42%43%44%45%46%47%48\n";
    assert!(size > TAIL.len());
    let mut text = repeat_to_len("let x = 1;\n", size - TAIL.len());
    text.push_str(TAIL);
    assert_eq!(text.len(), size);
    text
}

fn cases() -> DecodeCases {
    let maximum = max_scan_chunk_bytes();
    DecodeCases {
        plain: make_chunk(
            repeat_to_len(
                "fn add(a: usize, b: usize) -> usize { a + b }\n",
                STANDARD_CASE_BYTES,
            ),
            "plain-source",
        ),
        sparse: make_chunk(sparse_escape_source(STANDARD_CASE_BYTES), "sparse-escapes"),
        dense: make_chunk(
            repeat_to_len(
                "YXBpX2tleT1za19saXZlXzAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2\n",
                STANDARD_CASE_BYTES,
            ),
            "dense-encoded",
        ),
        custom_unknown: make_chunk(
            repeat_to_len("custom.value = c.u.s.t.o.m;\n", STANDARD_CASE_BYTES),
            "custom-unknown",
        ),
        maximum: make_chunk(maximum_admitted_source(maximum), "maximum-admitted"),
    }
}

fn validate_cases(cases: &DecodeCases) {
    let plain = decode_admission_sketch(&cases.plain);
    assert_eq!(
        plain.kind_mask(),
        0,
        "plain source unexpectedly admits decode work"
    );
    assert!(!plain.has_unknown());

    let sparse = decode_admission_sketch(&cases.sparse);
    assert_ne!(sparse.kind_mask(), 0, "sparse escapes must be admitted");

    let dense = decode_admission_sketch(&cases.dense);
    assert_ne!(
        dense.kind_mask() & keyhog_scanner::decode::DecodeAdmissionSketch::BASE64,
        0,
        "dense base64 must be admitted"
    );

    let custom = decode_admission_sketch_with_custom_unknown(&cases.custom_unknown);
    assert!(
        custom.has_unknown(),
        "custom decoder default must fail open"
    );
    assert_eq!(custom.candidate_count(), u16::MAX);
    assert_eq!(custom.candidate_bytes(), u32::MAX);

    let maximum = max_scan_chunk_bytes();
    let plan = DecodeWorkloadPlan::from_limits(MAX_DEPTH, maximum);
    assert_eq!(cases.maximum.data.len(), maximum);
    assert!(plan.admits(&cases.maximum));
    assert_ne!(plan.sketch(&cases.maximum).kind_mask(), 0);

    let over_limit = make_chunk(repeat_to_len("x", maximum + 1), "over-maximum-admission");
    assert!(!plan.admits(&over_limit));
    assert_eq!(plan.sketch(&over_limit).kind_mask(), 0);

    assert!(decode_chunk(&cases.plain, MAX_DEPTH, false, None, None).is_empty());
    assert!(!decode_chunk(&cases.sparse, MAX_DEPTH, false, None, None).is_empty());
    assert!(!decode_chunk(&cases.dense, MAX_DEPTH, false, None, None).is_empty());
    assert!(!decode_chunk(&cases.maximum, MAX_DEPTH, false, None, None).is_empty());
}

fn set_throughput(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    chunk: &Chunk,
) {
    group.throughput(Throughput::Bytes(chunk.data.len() as u64));
}

fn bench_admission(c: &mut Criterion, cases: &DecodeCases) {
    let mut group = c.benchmark_group("decoder_admission");
    for (label, chunk) in [
        ("plain-source", &cases.plain),
        ("sparse-escapes", &cases.sparse),
        ("dense-encoded", &cases.dense),
    ] {
        set_throughput(&mut group, chunk);
        group.bench_with_input(BenchmarkId::from_parameter(label), chunk, |b, chunk| {
            b.iter(|| black_box(decode_admission_sketch(black_box(chunk))));
        });
    }

    set_throughput(&mut group, &cases.custom_unknown);
    group.bench_with_input(
        BenchmarkId::from_parameter("custom-unknown"),
        &cases.custom_unknown,
        |b, chunk| {
            b.iter(|| {
                black_box(decode_admission_sketch_with_custom_unknown(black_box(
                    chunk,
                )))
            });
        },
    );

    let plan = DecodeWorkloadPlan::from_limits(MAX_DEPTH, max_scan_chunk_bytes());
    set_throughput(&mut group, &cases.maximum);
    group.bench_with_input(
        BenchmarkId::from_parameter("maximum-admitted-chunk"),
        &cases.maximum,
        |b, chunk| b.iter(|| black_box(plan.sketch(black_box(chunk)))),
    );
    group.finish();
}

fn bench_decode_behavior(c: &mut Criterion, cases: &DecodeCases) {
    let mut group = c.benchmark_group("decode_behavior");
    for (label, chunk) in [
        ("plain-source", &cases.plain),
        ("sparse-escapes", &cases.sparse),
        ("dense-encoded", &cases.dense),
        ("custom-unknown", &cases.custom_unknown),
        ("maximum-admitted-chunk", &cases.maximum),
    ] {
        set_throughput(&mut group, chunk);
        group.bench_with_input(BenchmarkId::from_parameter(label), chunk, |b, chunk| {
            b.iter(|| black_box(decode_chunk(black_box(chunk), MAX_DEPTH, false, None, None)));
        });
    }
    group.finish();
}

fn bench_format_microcases(c: &mut Criterion) {
    let formats = [
        (
            "base64",
            "c2stbGl2ZS14eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4\n",
        ),
        (
            "hex",
            "736b5f6c6976655f303132333435363738396162636465666768696a6b6c6d6e6f70\n",
        ),
        (
            "url",
            "%73%6b%5f%6c%69%76%65%5f%30%31%32%33%34%35%36%37%38%39\n",
        ),
    ];
    let chunks: Vec<(&str, Chunk)> = formats
        .into_iter()
        .map(|(label, unit)| {
            (
                label,
                make_chunk(repeat_to_len(unit, 4 * KIB), &format!("format-{label}")),
            )
        })
        .collect();

    let mut group = c.benchmark_group("decode_formats");
    for (label, chunk) in &chunks {
        set_throughput(&mut group, chunk);
        group.bench_with_input(BenchmarkId::from_parameter(label), chunk, |b, chunk| {
            b.iter(|| black_box(decode_chunk(black_box(chunk), MAX_DEPTH, false, None, None)));
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let cases = cases();
    validate_cases(&cases);
    bench_admission(c, &cases);
    bench_decode_behavior(c, &cases);
    bench_format_microcases(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .measurement_time(Duration::from_secs(3));
    targets = bench_decode
}
criterion_main!(benches);
