//! SOUNDNESS GATE for the Hyperscan always-active fallback prefilter.
//!
//! The HS engine replaces the `regex::RegexSet` whole-chunk prefilter that marks
//! which always-active fallback patterns to extract. A prefilter swap is sound
//! iff it does not change the SCANNER'S FINAL FINDINGS — the marked active set
//! may differ (HS marks a superset; extraction filters), but the
//! `(detector, credential, offset)` set the scanner emits must be byte-identical.
//!
//! This scans the real mirror corpus twice on the SAME compiled scanner —
//! `scanner.tuning().set_fallback_hs(Some(true))` (SIMD path) and `Some(false)`
//! (RegexSet reference) — and asserts the finding sets are identical per file. A mismatch
//! is a recall/precision regression (Law 6/Law 10) and fails the gate.
//!
//! Run: cargo test -p keyhog-scanner --features simd \
//!        --test fallback_prefilter_hs_findings_parity -- --ignored --nocapture
#![cfg(feature = "simd")]

use std::collections::BTreeSet;
use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

#[path = "support/mod.rs"]
mod support;
use support::paths::{corpus_dir, detector_dir};

/// `(detector_id, credential, offset)` — the finding identity the swap must
/// preserve exactly.
type FindingKey = (String, String, usize);

fn collect_files(root: &PathBuf, limit: usize) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                if let Ok(b) = std::fs::read(&p) {
                    files.push((p.to_string_lossy().into_owned(), b));
                    if files.len() >= limit {
                        return files;
                    }
                }
            }
        }
    }
    files
}

fn scan_file(scanner: &CompiledScanner, path: &str, bytes: &[u8]) -> BTreeSet<FindingKey> {
    let chunk = Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "hs-parity".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::SimdCpu)
        .iter()
        .flat_map(|r| r.iter())
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location.offset,
            )
        })
        .collect()
}

#[test]
#[ignore = "real-corpus soundness gate; run with --ignored --nocapture"]
fn hs_prefilter_findings_identical_to_regexset() {
    // Mirror files are all well under the HS size threshold, so `set_fallback_hs` on the scanner's tuning
    // toggles HS vs the RegexSet reference on every file. Both engines are always
    // built, so no env setup is needed.
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let Some(root) = corpus_dir() else {
        eprintln!("SKIP: mirror corpus absent");
        return;
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let files = collect_files(&root, 6000);
    assert!(!files.is_empty(), "mirror corpus must have files");

    let mut mismatched = 0usize;
    let mut shown = 0usize;
    let mut total_hs = 0usize;
    let mut total_legacy = 0usize;
    for (path, bytes) in &files {
        scanner.tuning().set_fallback_hs(Some(true));
        let hs = scan_file(&scanner, path, bytes);
        scanner.tuning().set_fallback_hs(Some(false));
        let legacy = scan_file(&scanner, path, bytes);
        total_hs += hs.len();
        total_legacy += legacy.len();
        if hs != legacy {
            mismatched += 1;
            if shown < 12 {
                let only_hs: Vec<_> = hs.difference(&legacy).take(4).collect();
                let only_legacy: Vec<_> = legacy.difference(&hs).take(4).collect();
                eprintln!(
                    "MISMATCH {path}\n    only-HS={only_hs:?}\n    only-legacy={only_legacy:?}"
                );
                shown += 1;
            }
        }
    }
    scanner.tuning().set_fallback_hs(None);

    eprintln!(
        "\nfindings parity: {} / {} files identical | HS findings={total_hs} legacy findings={total_legacy}",
        files.len() - mismatched,
        files.len(),
    );
    assert_eq!(
        mismatched, 0,
        "HS prefilter changed findings on {mismatched} file(s) — recall/precision regression"
    );
}
