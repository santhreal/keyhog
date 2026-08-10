//! E2E: the coalesced batch pipeline and the fused pipeline report the same
//! bytes, run after run.
//!
//! The fused consumer retires explicit CPU and SIMD batches in bounded worker
//! waves. Repeated large-file windows may reuse a byte-identical prior result,
//! while every replay rebases locations and preserves scan accounting.
//!
//! That is a big change to make silently. These contracts pin the two things a
//! user can observe and would never forgive breaking: the pipeline choice must
//! not change the report, and the report must not change between runs. Both
//! would fail on a lost batch, a duplicated batch, a torn merge, or an
//! ordering that leaked into the output file.

use crate::e2e::support::binary;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

/// A corpus wide enough that the producer emits many batches, so the parallel
/// consumer really does overlap them, with a distinct finding in every file
/// rather than one hotspot the merge could accidentally preserve.
///
/// Keys are AWS access key IDs in the real shape (`AKIA` plus sixteen
/// uppercase base32 characters) because the detector rejects a low-entropy
/// placeholder, and each is distinct so deduplication cannot mask a batch the
/// consumer dropped.
fn corpus(dir: &Path) -> usize {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    for index in 0..600u32 {
        let key: String = (0..16)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                ALPHABET[(state >> 33) as usize % ALPHABET.len()] as char
            })
            .collect();
        let body = format!(
            "// file {index}\nconst AWS: &str = \"AKIA{key}\";\nlet padding = \"{}\";\n",
            "x".repeat(256)
        );
        std::fs::write(dir.join(format!("f{index}.rs")), body).expect("write fixture");
    }
    600
}

fn scan_with_options(dir: &Path, pipeline: &str, backend: &str, extra: &[&str]) -> String {
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--no-config",
            "--max-file-size",
            "100MB",
            "--backend",
            backend,
            pipeline,
            "--dedup",
            "none",
            "--no-suppress-test-fixtures",
            "--format",
            "jsonl",
        ])
        .args(extra)
        .arg(dir)
        .env_remove("KEYHOG_BACKEND")
        .output()
        .expect("spawn keyhog scan");
    assert_eq!(
        output.status.code(),
        Some(1),
        "corpus plants findings, so the scan must exit 1; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8 report")
}

fn scan(dir: &Path, pipeline: &str) -> String {
    scan_with_options(dir, pipeline, "cpu", &[])
}

/// Choosing the pipeline is a throughput decision, never a recall decision.
///
/// If the parallel consumer ever drops a batch, scans one twice, or merges
/// findings through a racy path, this is where it shows: the two reports stop
/// matching byte for byte.
#[test]
fn batch_pipeline_report_is_byte_identical_to_fused() {
    let dir = TempDir::new().expect("tempdir");
    let planted = corpus(dir.path());

    let fused = scan(dir.path(), "--no-batch-pipeline");
    let batched = scan(dir.path(), "--batch-pipeline");

    assert_eq!(
        fused.lines().count(),
        planted,
        "fixture must plant exactly one detectable finding per file"
    );
    assert_eq!(
        batched, fused,
        "the batch pipeline must report exactly what the fused pipeline reports"
    );
}

/// Parallel batches complete in whatever order the pool finishes them, so a
/// report that carried that order would differ from run to run and break every
/// diff, baseline, and `--fail-on-diff` workflow downstream.
///
/// Findings are canonically ordered after the scan precisely so this holds.
#[test]
fn batch_pipeline_report_is_stable_across_runs() {
    let dir = TempDir::new().expect("tempdir");
    corpus(dir.path());

    let first = scan(dir.path(), "--batch-pipeline");
    for run in 2..=4 {
        assert_eq!(
            scan(dir.path(), "--batch-pipeline"),
            first,
            "run {run} of the batch pipeline reported a different byte sequence"
        );
    }
}

/// WHY: repeated-window reuse must be indistinguishable from scanning every
/// overlapping window, including absolute offsets and line numbers.
#[test]
fn repeated_window_reuse_matches_the_batch_pipeline() {
    const WINDOW: usize = 1024 * 1024;
    const OVERLAP: usize = 128 * 1024;
    const STRIDE: usize = WINDOW - OVERLAP;
    const WINDOWS: usize = 20;
    const SECRET: &[u8] = b"AWS_ACCESS_KEY_ID=AKIAFD5HUC556YILCDMN\n";

    let dir = TempDir::new().expect("tempdir");
    let mut block = vec![b' '; STRIDE];
    block[100..100 + SECRET.len()].copy_from_slice(SECRET);
    let mut body = Vec::with_capacity(STRIDE * WINDOWS + OVERLAP);
    for _ in 0..WINDOWS {
        body.extend_from_slice(&block);
    }
    body.extend_from_slice(&block[..OVERLAP]);
    std::fs::write(dir.path().join("periodic.txt"), body).expect("write periodic fixture");

    let fused = scan(dir.path(), "--no-batch-pipeline");
    let batched = scan(dir.path(), "--batch-pipeline");
    assert!(!fused.is_empty(), "periodic fixture must produce findings");
    assert_eq!(
        batched, fused,
        "reused windows must preserve every finding identity and absolute location"
    );
}

/// WHY: the sampled fingerprint is only an admission key. Distinct windows
/// with identical samples, invalid UTF-8, overlap-boundary credentials, and
/// identical bytes under different paths must still match the uncached path.
#[test]
fn repeated_window_reuse_rejects_collisions_and_preserves_metadata() {
    const WINDOW: usize = 1024 * 1024;
    const OVERLAP: usize = 128 * 1024;
    const STRIDE: usize = WINDOW - OVERLAP;
    const SECRET: &[u8] = b"AWS_ACCESS_KEY_ID=AKIAFD5HUC556YILCDMN\n";

    let dir = TempDir::new().expect("tempdir");

    let mut collision = vec![b'x'; STRIDE + WINDOW];
    let collision_at = WINDOW + 100;
    collision[collision_at - 1] = b'\n';
    collision[collision_at..collision_at + SECRET.len()].copy_from_slice(SECRET);
    std::fs::write(dir.path().join("collision.txt"), collision)
        .expect("write fingerprint-collision fixture");

    let mut boundary = vec![b'y'; STRIDE + WINDOW];
    let boundary_at = WINDOW - SECRET.len() / 2;
    boundary[boundary_at - 1] = b'\n';
    boundary[boundary_at..boundary_at + SECRET.len()].copy_from_slice(SECRET);
    std::fs::write(dir.path().join("boundary.txt"), boundary)
        .expect("write overlap-boundary fixture");

    let mut invalid_block = vec![b' '; STRIDE];
    invalid_block[200] = 0xff;
    invalid_block[300..300 + SECRET.len()].copy_from_slice(SECRET);
    let mut invalid = Vec::with_capacity(STRIDE * 3 + OVERLAP);
    for _ in 0..3 {
        invalid.extend_from_slice(&invalid_block);
    }
    invalid.extend_from_slice(&invalid_block[..OVERLAP]);
    std::fs::write(dir.path().join("invalid-utf8.txt"), invalid)
        .expect("write invalid UTF-8 fixture");

    let mut shared_block = vec![b' '; STRIDE];
    shared_block[500..500 + SECRET.len()].copy_from_slice(SECRET);
    let mut shared = Vec::with_capacity(STRIDE * 2 + OVERLAP);
    for _ in 0..2 {
        shared.extend_from_slice(&shared_block);
    }
    shared.extend_from_slice(&shared_block[..OVERLAP]);
    std::fs::write(dir.path().join("same-a.txt"), &shared).expect("write first shared fixture");
    std::fs::write(dir.path().join("same-b.txt"), shared).expect("write second shared fixture");

    let fused = scan(dir.path(), "--no-batch-pipeline");
    let batched = scan(dir.path(), "--batch-pipeline");
    assert_eq!(
        batched, fused,
        "fingerprint collisions and metadata changes must fall back to exact scanning"
    );
    for path in [
        "collision.txt",
        "boundary.txt",
        "invalid-utf8.txt",
        "same-a.txt",
        "same-b.txt",
    ] {
        assert!(
            fused.contains(path),
            "fixture {path} must retain its own finding provenance"
        );
    }
}

/// WHY: SIMD uses the same repeated-window wave retirement as scalar CPU.
/// Feature builds must prove that optimization does not change output.
#[cfg(feature = "simd")]
#[test]
fn repeated_window_reuse_matches_simd_batch_pipeline() {
    const WINDOW: usize = 1024 * 1024;
    const OVERLAP: usize = 128 * 1024;
    const STRIDE: usize = WINDOW - OVERLAP;
    const SECRET: &[u8] = b"AWS_ACCESS_KEY_ID=AKIAFD5HUC556YILCDMN\n";

    let dir = TempDir::new().expect("tempdir");
    let mut block = vec![b' '; STRIDE];
    block[100..100 + SECRET.len()].copy_from_slice(SECRET);
    let mut body = Vec::with_capacity(STRIDE * 4 + OVERLAP);
    for _ in 0..4 {
        body.extend_from_slice(&block);
    }
    body.extend_from_slice(&block[..OVERLAP]);
    std::fs::write(dir.path().join("simd-periodic.txt"), body)
        .expect("write SIMD periodic fixture");

    let fused = scan_with_options(dir.path(), "--no-batch-pipeline", "simd", &[]);
    let batched = scan_with_options(dir.path(), "--batch-pipeline", "simd", &[]);
    assert_eq!(batched, fused, "SIMD replay must preserve exact output");
}

/// WHY: incremental scans must record and check every window instead of using
/// the non-incremental replay cache. Separate cache files keep both pipelines'
/// state transitions directly comparable across cold and warm runs.
#[test]
fn repeated_windows_preserve_incremental_state_transitions() {
    const WINDOW: usize = 1024 * 1024;
    const OVERLAP: usize = 128 * 1024;
    const STRIDE: usize = WINDOW - OVERLAP;
    const SECRET: &[u8] = b"AWS_ACCESS_KEY_ID=AKIAFD5HUC556YILCDMN\n";

    let dir = TempDir::new().expect("tempdir");
    let cache_dir = TempDir::new().expect("cache tempdir");
    let mut block = vec![b' '; STRIDE];
    block[100..100 + SECRET.len()].copy_from_slice(SECRET);
    let mut body = Vec::with_capacity(STRIDE * 4 + OVERLAP);
    for _ in 0..4 {
        body.extend_from_slice(&block);
    }
    body.extend_from_slice(&block[..OVERLAP]);
    std::fs::write(dir.path().join("incremental-periodic.txt"), body)
        .expect("write incremental periodic fixture");

    let fused_cache = cache_dir.path().join("fused.idx");
    let batched_cache = cache_dir.path().join("batched.idx");
    let fused_cache = fused_cache.to_str().expect("UTF-8 cache path");
    let batched_cache = batched_cache.to_str().expect("UTF-8 cache path");
    let fused_args = ["--incremental", "--incremental-cache", fused_cache];
    let batched_args = ["--incremental", "--incremental-cache", batched_cache];

    let fused_cold = scan_with_options(dir.path(), "--no-batch-pipeline", "cpu", &fused_args);
    let batched_cold = scan_with_options(dir.path(), "--batch-pipeline", "cpu", &batched_args);
    assert_eq!(
        batched_cold, fused_cold,
        "cold incremental output must match"
    );

    let fused_warm = scan_with_options(dir.path(), "--no-batch-pipeline", "cpu", &fused_args);
    let batched_warm = scan_with_options(dir.path(), "--batch-pipeline", "cpu", &batched_args);
    assert_eq!(
        batched_warm, fused_warm,
        "warm incremental output must match"
    );
    assert_eq!(
        fused_warm, fused_cold,
        "finding-bearing windows must remain reportable on warm incremental scans"
    );
}
