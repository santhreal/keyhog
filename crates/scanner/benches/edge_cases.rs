use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{decode, CompiledScanner};

fn make_chunk(data: &str, path: Option<&str>) -> Chunk {
    Chunk {
        data: data.to_string(),
        metadata: ChunkMetadata {
                    base_offset: 0,
            source_type: "benchmark".into(),
            path: path.map(|p| p.into()),
            commit: None,
            author: None,
            date: None,
        },
    }
}

fn create_minimal_detectors() -> Vec<DetectorSpec> {
    vec![DetectorSpec {
        id: "openai-api-key".into(),
        name: "OpenAI API Key".into(),
        service: "openai".into(),
        severity: Severity::Critical,
        patterns: vec![
            PatternSpec {
                regex: "sk-proj-[a-zA-Z0-9_-]{40,}".into(),
                description: Some("OpenAI project key".into()),
                group: None,
            },
            PatternSpec {
                regex: "sk-[a-zA-Z0-9]{48}".into(),
                description: Some("OpenAI legacy key".into()),
                group: None,
            },
        ],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["sk-proj-".into(), "sk-".into(), "openai".into()],
    }]
}

// Edge case 1: Pathological backtracking
// The regex "sk-[a-zA-Z0-9]{48}" can be tricky if we have "sk-123..." missing the last character, repeated in a long line.
fn generate_pathological_backtracking(count: usize) -> String {
    let base = "sk-";
    let almost_match = "A".repeat(47); // One char short of matching {48}
    let mut s = String::new();
    for _ in 0..count {
        s.push_str(base);
        s.push_str(&almost_match);
        s.push('-'); // fails regex, forces backtracking
    }
    s
}

fn benchmark_pathological_backtracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("edge_case_pathological_backtracking");
    let data = generate_pathological_backtracking(10_000); // 500KB
    let scanner = CompiledScanner::compile(create_minimal_detectors()).unwrap();
    let chunk = make_chunk(&data, Some("test.txt"));
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("scan_pathological", |b| {
        b.iter(|| black_box(scanner.scan(black_box(&chunk))))
    });
    group.finish();
}

// Edge Case 2: 1MB single-line without spaces (e.g. minified JS array/binary blob)
fn benchmark_single_long_line(c: &mut Criterion) {
    let mut group = c.benchmark_group("edge_case_single_long_line");
    let data = "x".repeat(1_048_576); // 1MB string
    let scanner = CompiledScanner::compile(create_minimal_detectors()).unwrap();
    let chunk = make_chunk(&data, Some("minified.js"));
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("scan_long_line", |b| {
        b.iter(|| black_box(scanner.scan(black_box(&chunk))))
    });
    group.finish();
}

// Edge Case 3: Very deeply nested Base64
// Decoding layers of base64
fn benchmark_deep_base64(c: &mut Criterion) {
    use base64::{engine::general_purpose, Engine};
    let mut group = c.benchmark_group("edge_case_deep_base64");

    // Create base64 that decodes to base64 that decodes to base64
    let mut data = "sk-proj-12345678901234567890123456789012345678901234567890".to_string();
    for _ in 0..5 {
        data = general_purpose::STANDARD.encode(&data);
    }
    // replicate it heavily
    let full_data = data.repeat(1000); // ~140KB of nested base64
    let chunk = make_chunk(&full_data, Some("payload.json"));

    group.throughput(Throughput::Bytes(full_data.len() as u64));
    group.bench_function("recursive_decode", |b| {
        b.iter(|| {
            let decoded = decode::decode_chunk(black_box(&chunk), 3, false, None, None);
            black_box(decoded)
        })
    });
    group.finish();
}

// Edge case 4: Extremely high number of regex matches (highly dense secrets file)
fn benchmark_dense_secrets(c: &mut Criterion) {
    let mut group = c.benchmark_group("edge_case_dense_secrets");
    // Just the secret over and over again, triggers standard match flow, creating span structures
    let secret = "sk-proj-0000000000000000000000000000000000000000\n";
    let data = secret.repeat(10_000); // 10k exact matches
    let scanner = CompiledScanner::compile(create_minimal_detectors()).unwrap();
    let chunk = make_chunk(&data, Some("test.txt"));
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("scan_dense", |b| {
        b.iter(|| black_box(scanner.scan(black_box(&chunk))))
    });
    group.finish();
}

criterion_group!(
    edge_cases,
    benchmark_pathological_backtracking,
    benchmark_single_long_line,
    benchmark_deep_base64,
    benchmark_dense_secrets,
);

criterion_main!(edge_cases);
