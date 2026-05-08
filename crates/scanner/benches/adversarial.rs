//! Adversarial benchmarks — designed to stress weaknesses, not the
//! happy path. Each fixture targets a class of input where naive
//! scanners regress, so we can keep an eye on whether incidental
//! refactors hurt the cases that matter most in real repos.
//!
//! Cases:
//!
//! - `false_prefix_storm`: 1 MiB of strings that look like real
//!   credential prefixes (AKIA…, ghp_…, sk_live_…) but each is
//!   truncated or otherwise invalid. A correct scanner must enter
//!   regex evaluation for every prefix and reject — exactly the
//!   path AC would have skipped on a fully-uninteresting buffer.
//!   This is where regex backtracking + companion lookups dominate.
//!
//! - `entropy_noise`: 1 MiB of random-looking-but-low-entropy junk
//!   designed to trip the entropy fallback. Tests how aggressively
//!   the entropy gate filters real noise vs. burning cycles on it.
//!
//! - `long_lines`: a single 64 KiB line — no newlines anywhere.
//!   Stresses the `code_lines.collect()` + line-offset path and
//!   any per-line accumulator that scales badly without bounds.
//!
//! - `keyword_dense_no_match`: 1 MiB of code that mentions "secret",
//!   "token", "api_key" etc. on most lines but never assigns a
//!   high-entropy value. Stresses `scan_generic_assignments` after
//!   the AC pre-filter passes — every line runs the regex.
//!
//! - `deep_concat_chain`: 64 KiB of deeply-fragmented concatenation
//!   chains (`"AK" + "IA" + "EXAMPLE…"`). Stresses multiline
//!   reassembly + the proximity-aware fragment cache.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use keyhog_core::{load_detectors, Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::PathBuf;
use std::time::Duration;

fn detectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

fn make_chunk(data: String, path: Option<&str>) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            source_type: "adversarial-bench".into(),
            path: path.map(|p| p.into()),
            commit: None,
            author: None,
            date: None,
                    mtime_ns: None,
            size_bytes: None,
},
    }
}

fn false_prefix_storm(target: usize) -> String {
    // Each line starts with a real-looking credential prefix but is
    // truncated to length / character class that won't validate.
    // The keyword pre-filter MUST trigger; the regex MUST reject.
    let lines = [
        "config.aws_key = \"AKIA12345\"; // too short\n",
        "github_pat = \"ghp_short\";\n",
        "stripe_test = \"sk_live_only9chars\";\n",
        "slack_bot = \"xoxb-bad\";\n",
        "openai = \"sk-proj-truncated\";\n",
        "google_key = \"AIzaShortSyntheticForBench\";\n",
        "private_key = \"-----BEGIN BUT NO REAL KEY-----\";\n",
        "AKIA = 'this is just a label';\n",
        "auth_header = \"Bearer not_a_real_token\";\n",
    ];
    let mut s = String::with_capacity(target);
    let mut i = 0;
    while s.len() < target {
        s.push_str(lines[i % lines.len()]);
        i += 1;
    }
    s.truncate(target);
    s
}

fn entropy_noise(target: usize) -> String {
    // FNV-deterministic pseudo-random ASCII. Looks high-entropy
    // but never overlaps a real detector. Stresses the entropy
    // gate without producing matches.
    let mut s = String::with_capacity(target);
    let mut state: u64 = 0xcbf29ce484222325;
    while s.len() < target {
        state ^= s.len() as u64;
        state = state.wrapping_mul(0x100000001b3);
        let printable = ((state >> 16) & 0x5f) as u8 + b' ';
        let ch = if printable.is_ascii_graphic() {
            printable as char
        } else {
            '.'
        };
        s.push(ch);
        if s.len().is_multiple_of(80) {
            s.push('\n');
        }
    }
    s.truncate(target);
    s
}

fn long_lines(target: usize) -> String {
    // One single line, no newlines. Stresses the line-offset /
    // code_lines pipeline that allocates per-line.
    let chunk = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-.";
    let mut s = String::with_capacity(target);
    while s.len() < target {
        s.push_str(chunk);
    }
    s.truncate(target);
    s
}

fn keyword_dense_no_match(target: usize) -> String {
    // Every line mentions a credential keyword but the value is a
    // valid English word, not a high-entropy secret. Forces the
    // regex pass to run, then the entropy filter to reject every
    // candidate. This is `scan_generic_assignments`'s worst case.
    let lines = [
        "secret = \"placeholder value\"\n",
        "token = \"another harmless string\"\n",
        "api_key = \"todo_replace_before_deploy\"\n",
        "password = \"changeme\"\n",
        "auth = \"see config docs for the real value\"\n",
        "private_key = \"path/to/key/file\"\n",
        "client_secret = \"see vault\"\n",
    ];
    let mut s = String::with_capacity(target);
    let mut i = 0;
    while s.len() < target {
        s.push_str(lines[i % lines.len()]);
        i += 1;
    }
    s.truncate(target);
    s
}

fn deep_concat_chain(target: usize) -> String {
    // Fragmented credentials across many short lines connected by
    // `+`. Multiline reassembly has to collapse them.
    let mut s = String::with_capacity(target);
    while s.len() < target {
        s.push_str("const k = \"AK\" + \"IA\" + \"EXAMPLE_DUMMY_FRAGMENT_\" + \"123456\";\n");
    }
    s.truncate(target);
    s
}

fn bench_adversarial(c: &mut Criterion) {
    let detectors = load_detectors(&detectors_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let mut group = c.benchmark_group("adversarial");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    type AdversarialCase = (&'static str, fn(usize) -> String, usize);
    let cases: &[AdversarialCase] = &[
        ("false_prefix_storm/1MiB", false_prefix_storm, 1024 * 1024),
        ("entropy_noise/1MiB", entropy_noise, 1024 * 1024),
        ("long_lines/64KiB", long_lines, 64 * 1024),
        (
            "keyword_dense_no_match/1MiB",
            keyword_dense_no_match,
            1024 * 1024,
        ),
        ("deep_concat_chain/64KiB", deep_concat_chain, 64 * 1024),
    ];

    for (label, gen, size) in cases {
        let data = gen(*size);
        let chunk = make_chunk(data, Some("bench/adversarial.rs"));
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("cpu_fallback", label), &chunk, |b, chk| {
            b.iter(|| {
                black_box(scanner.scan_with_backend(black_box(chk), ScanBackend::CpuFallback))
            });
        });
        group.bench_with_input(BenchmarkId::new("simd_cpu", label), &chunk, |b, chk| {
            b.iter(|| black_box(scanner.scan_with_backend(black_box(chk), ScanBackend::SimdCpu)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_adversarial);
criterion_main!(benches);
