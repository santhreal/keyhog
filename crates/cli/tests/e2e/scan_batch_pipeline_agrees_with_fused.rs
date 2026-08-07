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

fn scan(dir: &Path, pipeline: &str) -> String {
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--no-config",
            "--backend",
            "cpu",
            pipeline,
            "--dedup",
            "none",
            "--no-suppress-test-fixtures",
            "--format",
            "jsonl",
        ])
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
