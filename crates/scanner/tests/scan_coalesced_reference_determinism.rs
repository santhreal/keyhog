//! Calibration-reference determinism: explicit `SimdCpu` coalesced scans must
//! return a byte-identical
//! canonical match set on every call over the SAME fixed chunk set.
//!
//! This is the contract autoroute calibration relies on: it measures an
//! explicit `SimdCpu` backend and rejects inconsistent reference trials.
//! Repeated parallel scans matter because Hyperscan scratch, fragment
//! reassembly, and per-chunk scanning share concurrent state on high-core
//! hosts.
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
/// offset) — every field the reference-consistency check compares.
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

/// Build a fixed chunk set from the committed `demo/` tree — the exact corpus
/// whose calibration aborted — padded out with a bounded mirror-corpus sample
/// when present so there are enough chunks to saturate the rayon pool and
/// surface a concurrency race without turning the default suite into an
/// unbounded corpus benchmark. Falls back to demo-only if the mirror tree is
/// absent.
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

    if let Some(root) = support::paths::corpus_dir() {
        // One non-empty chunk per logical worker exercises concurrent scratch
        // ownership without multiplying this correctness gate into a corpus
        // benchmark. Bound extreme CI hosts so the test remains a gate, not a
        // scale run.
        let worker_chunks = std::thread::available_parallelism()
            .map_or(32, std::num::NonZeroUsize::get)
            .clamp(8, 64);
        for (label, bytes) in support::paths::corpus_files_with_paths(&root, worker_chunks) {
            if bytes.is_empty() {
                continue;
            }
            let text = String::from_utf8_lossy(&bytes).into_owned();
            chunks.push(Chunk {
                data: text.into(),
                metadata: ChunkMetadata {
                    source_type: "ref-determinism".into(),
                    path: Some(label.into()),
                    ..Default::default()
                },
            });
        }
    }

    assert!(
        !chunks.is_empty(),
        "fixed chunk set is empty — demo/ corpus missing"
    );
    chunks
}

#[test]
fn scan_coalesced_is_deterministic_across_trials() {
    let scanner = support::compile_full_detector_scanner();
    let chunks = fixed_chunks();

    // Match the production autoroute evidence count. Each trial saturates the
    // rayon pool with the bounded corpus above; multiplying that by an arbitrary
    // 40 made the default integration gate take tens of minutes and serialized
    // every other Cargo gate behind its target lock.
    const TRIALS: usize = 7;

    scanner.clear_fragment_cache();
    let reference = canonical(
        &scanner.scan_coalesced_with_backend(&chunks, keyhog_scanner::ScanBackend::SimdCpu),
    );

    for trial in 1..TRIALS {
        scanner.clear_fragment_cache();
        let got = canonical(
            &scanner.scan_coalesced_with_backend(&chunks, keyhog_scanner::ScanBackend::SimdCpu),
        );
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
