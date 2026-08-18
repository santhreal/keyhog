//! Calibration-reference determinism: explicit `SimdCpu` coalesced scans must
//! return a byte-identical canonical match set on every call over the SAME fixed chunk set.
//!
//! WHY: Closes the defect class of scan_coalesced finding parity divergence across
//! thread pool worker counts and concurrency scheduling. Coalesced batch scanning and
//! cross-chunk seam reassembly must produce byte-identical canonical findings regardless
//! of thread pool size or worker count on both in-chunk and seam-straddling credentials.
//! What it does not catch: thread allocation exhaustion outside rayon pools.
//!
//! On mismatch the test prints the symmetric difference of the canonical record
//! sets (which `(detector, credential_hash, file, line, offset)` tuples appeared
//! or vanished between trials) so the nondeterministic producer is pinpointed,
//! not just flagged.

#[path = "support/mod.rs"]
mod support;

use std::collections::BTreeSet;

use keyhog_core::{Chunk, ChunkMetadata};

/// One fully-comparable projection of a `RawMatch`, mirroring the calibration's
/// `CanonicalMatch` tuple (chunk index, detector, credential hash, file, line,
/// offset) (every field the reference-consistency check compares).
type Record = (usize, String, String, Option<String>, Option<usize>, usize);

fn canonical(results: &[Vec<keyhog_core::RawMatch>]) -> BTreeSet<Record> {
    let mut out = BTreeSet::new();
    for (chunk_idx, chunk_matches) in results.iter().enumerate() {
        for m in chunk_matches {
            out.insert((
                chunk_idx,
                m.detector_id.as_ref().to_string(),
                hex::encode(m.credential_hash.as_bytes()),
                m.location.file_path.as_deref().map(str::to_string),
                m.location.line,
                m.location.offset,
            ));
        }
    }
    out
}

/// Build a fixed chunk set from the committed `demo/` tree, the exact corpus
/// whose calibration aborted. The committed files are repeated only as needed
/// to saturate the rayon pool, so concurrency coverage does not depend on a
/// private mirror corpus or turn this correctness gate into a scale benchmark.
fn fixed_chunks() -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut push_file = |path: std::path::PathBuf| {
        if let Ok(bytes) = std::fs::read(&path) {
            if bytes.is_empty() {
                return;
            }
            let text = String::from_utf8_lossy(&bytes).into_owned();
            chunks.push(Chunk {
                data: text.into(),
                metadata: ChunkMetadata {
                    source_type: "ref-determinism".into(),
                    path: Some(path.to_string_lossy().into_owned().into()),
                    ..Default::default()
                },
            });
        }
    };

    let demo = {
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.pop();
        d.pop();
        d.push("demo");
        d
    };
    let mut stack = vec![demo];
    while let Some(dir) = stack.pop() {
        // Fail loud on a real directory-read or entry error instead of the old
        // ignore-the-Result-and-flatten silent-skip (Law 10): a permission/IO
        // error must surface, not quietly shrink the reference corpus and weaken
        // the determinism check. A simply-absent demo dir is the one benign case
        // and is tolerated explicitly.
        if !dir.exists() {
            continue;
        }
        let rd = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("read_dir({}) failed: {error}", dir.display()));
        for entry in rd {
            let entry = entry.unwrap_or_else(|error| {
                panic!("read_dir entry in {} failed: {error}", dir.display())
            });
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                push_file(p);
            }
        }
    }

    assert!(
        !chunks.is_empty(),
        "fixed chunk set is empty, demo/ corpus missing"
    );
    // Eight deterministic real files provide varied syntax and findings; the
    // repetition below supplies concurrency. Scanning the entire demo tree on
    // every one of eight debug-profile trials made this correctness test
    // dominate the workspace despite adding no additional scheduling pressure.
    chunks.sort_by(|a, b| a.metadata.path.as_deref().cmp(&b.metadata.path.as_deref()));
    chunks.truncate(8);
    let worker_chunks = std::thread::available_parallelism()
        .map_or(32, std::num::NonZeroUsize::get)
        .clamp(8, 64);
    let seed = chunks.clone();
    while chunks.len() < worker_chunks {
        let remaining = worker_chunks - chunks.len();
        chunks.extend(seed.iter().take(remaining).cloned());
    }
    chunks
}

/// Constructs chunks containing real credentials placed across chunk seams by construction.
fn seam_straddling_chunks() -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let credentials = [
        ("AKIAIOSFODNN7EXAMPLE", 8),                      // AWS access key ID
        ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 15), // GitHub PAT
        (
            "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx",
            20,
        ), // Slack token
        (
            "postgres://app_user:s3cr3t_p4ssw0rd@db.example.com:5432/production_db",
            30,
        ), // DB URL
    ];

    for (file_idx, (secret, split_at)) in credentials.iter().enumerate() {
        let path = format!("src/seam_file_{file_idx}.rs");
        let pad_a = "const PADDING_A: &str = \"filler line\\n\";\n".repeat(20);
        let pad_b = "const PADDING_B: &str = \"filler line\\n\";\n".repeat(20);

        let mut data_a = pad_a;
        data_a.push_str(&secret[..*split_at]);

        let mut data_b = secret[*split_at..].to_string();
        data_b.push_str("\";\n");
        data_b.push_str(&pad_b);

        let len_a = data_a.len();
        let chunk_a = Chunk {
            data: data_a.into(),
            metadata: ChunkMetadata {
                source_type: "file".into(),
                path: Some(path.clone().into()),
                base_offset: 0,
                base_line: 1,
                ..Default::default()
            },
        };

        let chunk_b = Chunk {
            data: data_b.into(),
            metadata: ChunkMetadata {
                source_type: "file".into(),
                path: Some(path.into()),
                base_offset: len_a,
                base_line: 21,
                ..Default::default()
            },
        };

        chunks.push(chunk_a);
        chunks.push(chunk_b);
    }

    chunks
}

#[test]
fn scan_coalesced_is_deterministic_across_trials() {
    let detectors =
        keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
    let scanner = keyhog_scanner::CompiledScanner::compile_for_backend(
        detectors,
        keyhog_scanner::ScanBackend::SimdCpu,
    )
    .expect("compile exact SIMD scanner");
    let chunks = fixed_chunks();

    // Match the production autoroute evidence count. Each trial saturates the
    // rayon pool with the bounded corpus above; multiplying that by an arbitrary
    // 40 made the default integration gate take tens of minutes and serialized
    // every other Cargo gate behind its target lock.
    const TRIALS: usize = 7;

    scanner.clear_fragment_cache();
    let reference_rows = scanner
        .scan_coalesced_with_backend(&chunks, keyhog_scanner::ScanBackend::SimdCpu)
        .expect("reference coalesced determinism scan should succeed");
    let reference = canonical(&reference_rows);
    assert!(
        !reference.is_empty(),
        "determinism corpus must exercise real findings, not only empty scans"
    );

    for trial in 1..TRIALS {
        scanner.clear_fragment_cache();
        let got_rows = scanner
            .scan_coalesced_with_backend(&chunks, keyhog_scanner::ScanBackend::SimdCpu)
            .expect("repeated coalesced determinism scan should succeed");
        let got = canonical(&got_rows);
        if got != reference {
            let only_ref: Vec<&Record> = reference.difference(&got).collect();
            let only_got: Vec<&Record> = got.difference(&reference).collect();
            panic!(
                "scan_coalesced diverged on trial {trial} (chunks={}, ref={} records, got={} records)\n\
                 PRESENT in reference but MISSING in trial {trial} ({}):\n{:#?}\n\
                 PRESENT in trial {trial} but ABSENT from reference ({}):\n{:#?}",
                chunks.len(),
                reference.len(),
                got.len(),
                only_ref.len(),
                only_ref,
                only_got.len(),
                only_got,
            );
        }
    }
}

#[test]
fn scan_coalesced_finding_parity_across_worker_counts() {
    let detectors =
        keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
    let scanner = keyhog_scanner::CompiledScanner::compile_for_backend(
        detectors,
        keyhog_scanner::ScanBackend::SimdCpu,
    )
    .expect("compile exact SIMD scanner");
    let mut chunks = fixed_chunks();
    chunks.extend(seam_straddling_chunks());

    // Get reference matches using default pool
    scanner.clear_fragment_cache();
    let reference_rows = scanner
        .scan_coalesced_with_backend(&chunks, keyhog_scanner::ScanBackend::SimdCpu)
        .expect("reference scan should succeed");
    let reference = canonical(&reference_rows);
    assert!(
        !reference.is_empty(),
        "reference finding set must not be empty"
    );

    // Derive worker count variant space dynamically at run time:
    // 1 worker, 2 workers, an odd count, and host maximum from pool / available parallelism.
    let host_max = rayon::current_num_threads()
        .max(std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get));
    let odd_count = if host_max > 3 { (host_max / 2) | 1 } else { 3 };
    let mut worker_counts = std::collections::BTreeSet::new();
    worker_counts.insert(1);
    worker_counts.insert(2);
    worker_counts.insert(odd_count);
    worker_counts.insert(host_max);

    for worker_count in worker_counts {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count)
            .build()
            .expect("build thread pool");

        let got = pool.install(|| {
            scanner.clear_fragment_cache();
            let got_rows = scanner
                .scan_coalesced_with_backend(&chunks, keyhog_scanner::ScanBackend::SimdCpu)
                .expect("scan with custom thread pool should succeed");
            canonical(&got_rows)
        });

        assert_eq!(
            got, reference,
            "finding set diverged at worker count {worker_count}"
        );
    }
}
