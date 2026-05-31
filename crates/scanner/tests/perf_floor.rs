//! Throughput regression floor for the scanner.
//!
//! Asserts that `CompiledScanner::scan` on a representative
//! source-code fixture stays AT OR ABOVE a hard MiB/s floor. The
//! floor is intentionally conservative (well below current steady-
//! state numbers) so that ordinary noise doesn't redden the gate,
//! but a 2× slowdown - the kind of regression a real algorithm
//! change would introduce - will reliably fail this.
//!
//! Why a test, not a criterion bench: criterion benches run on
//! demand and aren't part of CI's `cargo test`. A floor test runs
//! every CI build, so a perf regression hits the same review surface
//! as any other red gate. The criterion benches in
//! `crates/scanner/benches/` are the right place for fine-grained
//! perf trends; this file is the throughput TRIPWIRE.
//!
//! Fixture shape: 4 MiB of pseudo-Go-source with NO planted
//! credentials - the test measures the fast-path (alphabet screen +
//! bigram bloom + AC pre-filter early-reject) throughput on benign
//! code, which is what 99%+ of a real repository looks like. A
//! credential-dense workload would primarily measure ML scoring +
//! suppression-heuristic overhead, which is a different gate.
//!
//! For the K8s differential bench (1.8x faster than gitleaks on
//! 1.2 GiB) the rayon-parallel + per-file shape pushes throughput to
//! ~540 MiB/s; this per-chunk single-thread test floors at ~12 MiB/s
//! and asserts at 8 MiB/s with 33% headroom under measured.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::time::Instant;

const FIXTURE_BYTES: usize = 4 * 1024 * 1024;

// Single-thread floor on a 4 MiB benign Go-source fixture. Measured
// steady-state on the dev machine (RTX 5090 + 9950X) was ~12 MiB/s
// per-chunk single-thread for 894 detectors loaded. The K8s
// differential bench's ~540 MiB/s number is rayon-parallelized
// across many small files; this test is the per-chunk single-thread
// floor.
//
// Floor of 8 MiB/s gives ~60% headroom under measured. A real 2×
// algorithmic regression (e.g. a new regex with catastrophic
// backtracking, or a per-byte cost in the AC pre-filter)
// reliably trips this. Bump the floor when the per-chunk number
// ratchets up AND is stable across 3 runs on the dev box.
const MIN_THROUGHPUT_MIB_PER_S: f64 = 8.0;

/// Build a 4 MiB fixture of pseudo-Go source with ZERO planted
/// credentials. Real K8s code has ~0.14 findings per MiB, so the
/// honest throughput floor is what the fast path (alphabet screen +
/// bigram bloom + AC pre-filter early-reject) sustains on benign
/// code, NOT what regex-confirm + ML-scoring achieve on a credential
/// storm.
///
/// The text intentionally avoids triggering generic- detectors:
/// short variable names, no `key`/`secret`/`token` in identifiers,
/// no base64-shaped strings, no hex sequences > 8 chars.
fn build_fixture() -> String {
    let mut s = String::with_capacity(FIXTURE_BYTES + 1024);
    let blocks: &[&str] = &[
        "// Copyright 2024 The Kubernetes Authors. Licensed under Apache-2.0.\n",
        "package controller\n\n",
        "import (\n\t\"context\"\n\t\"fmt\"\n\tcorev1 \"k8s.io/api/core/v1\"\n)\n\n",
        "func (c *Controller) reconcile(ctx context.Context, name string) error {\n",
        "\tlog := log.FromContext(ctx).WithName(\"reconcile\").WithValues(\"name\", name)\n",
        "\tif err := c.client.Get(ctx, types.NamespacedName{Name: name}, &corev1.Pod{}); err != nil {\n",
        "\t\treturn fmt.Errorf(\"get pod %q: %w\", name, err)\n",
        "\t}\n",
        "\treturn nil\n",
        "}\n\n",
        "var DefaultClientID = \"controller-manager\"\n",
        "var DefaultIssuer = \"https://issuer.example.com/v1\"\n",
        "const maxBackoff = 5 * time.Minute\n\n",
        "// reconcile loops until the desired state matches the observed state.\n",
        "for i := 0; i < len(pods); i++ {\n\tprocess(pods[i])\n}\n\n",
    ];
    let mut block_idx = 0usize;
    while s.len() < FIXTURE_BYTES {
        s.push_str(blocks[block_idx % blocks.len()]);
        block_idx += 1;
    }
    s.truncate(FIXTURE_BYTES);
    s
}

#[test]
fn scanner_throughput_above_floor() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let text = build_fixture();
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "perf-floor".into(),
            path: Some("perf_floor_fixture.go".into()),
            ..Default::default()
        },
    };

    // Warm-up: first scan pays detector caches + first-touch alloc.
    // Measure the SECOND scan for steady-state.
    let warm = Instant::now();
    let warm_matches = scanner.scan(&chunk);
    let warm_elapsed = warm.elapsed();

    let start = Instant::now();
    let matches = scanner.scan(&chunk);
    let elapsed = start.elapsed();

    let mib = FIXTURE_BYTES as f64 / (1024.0 * 1024.0);
    let mib_per_s = mib / elapsed.as_secs_f64();

    eprintln!(
        "perf_floor: warm-up {} matches in {:.3} ms; steady-state {} matches in {:.3} ms = {:.1} MiB/s (floor {:.1} MiB/s)",
        warm_matches.len(),
        warm_elapsed.as_millis(),
        matches.len(),
        elapsed.as_millis(),
        mib_per_s,
        MIN_THROUGHPUT_MIB_PER_S,
    );

    assert!(
        mib_per_s >= MIN_THROUGHPUT_MIB_PER_S,
        "throughput regression: got {:.1} MiB/s, floor is {:.1} MiB/s. \
         The scanner has slowed substantially vs the steady-state \
         single-thread baseline. Investigate the most recent algorithmic \
         change - likely culprits: new regex with catastrophic \
         backtracking, a per-byte cost added to the AC pre-filter, or \
         a suppression heuristic that now walks the full credential on \
         every hit.",
        mib_per_s,
        MIN_THROUGHPUT_MIB_PER_S,
    );

    // Also assert: scanner found 0 findings on the benign fixture.
    // If THIS regresses (the benign fixture starts firing detectors)
    // the perf number above is no longer measuring the fast-path -
    // it's measuring the slow regex + ML scoring path, which is the
    // wrong gate. Catch the test going stale before it lies.
    assert_eq!(
        matches.len(),
        0,
        "perf_floor fixture started firing {} detector(s) - the fixture \
         has drifted out of the benign-code shape and is now measuring \
         the slow regex+ML path. Regenerate the fixture or tighten the \
         text so the alphabet-screen + bigram-bloom fast-path rejects \
         every chunk.",
        matches.len(),
    );
}
