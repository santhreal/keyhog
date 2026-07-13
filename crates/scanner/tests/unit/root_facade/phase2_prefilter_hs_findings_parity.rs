//! SOUNDNESS GATE for the Hyperscan always-active phase-2 prefilter.
//!
//! The HS engine replaces the `regex::RegexSet` whole-chunk prefilter that marks
//! which always-active phase-2 patterns to extract. A prefilter swap is sound
//! iff it does not change the SCANNER'S FINAL FINDINGS, the marked active set
//! may differ (HS marks a superset; extraction filters), but the
//! `(detector, credential, offset)` set the scanner emits must be byte-identical.
//!
//! This scans the real mirror corpus twice on the SAME compiled scanner
//! `keyhog_scanner::testing::set_phase2_hs(&scanner, Some(true))` (SIMD path) and `Some(false)`
//! (RegexSet reference), and asserts the finding sets are identical per file. A mismatch
//! is a recall/precision regression (Law 6/Law 10) and fails the gate.
//!
//! Run: cargo test -p keyhog-scanner --features simd \
//!        --test phase2_prefilter_hs_findings_parity -- --ignored --nocapture
#![cfg(feature = "simd")]

use std::collections::BTreeSet;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

use super::support;
use support::paths::{corpus_dir, corpus_files_with_paths, detector_dir};

/// `(detector_id, credential, offset)`: the finding identity the swap must
/// preserve exactly.
type FindingKey = (String, String, usize);

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
    // Mirror files are all well under the HS size threshold, so `set_phase2_hs` on the scanner's tuning
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
    let files = corpus_files_with_paths(&root, 6000);
    assert!(!files.is_empty(), "mirror corpus must have files");

    let mut mismatched = 0usize;
    let mut shown = 0usize;
    let mut total_hs = 0usize;
    let mut total_legacy = 0usize;
    for (path, bytes) in &files {
        keyhog_scanner::testing::set_phase2_hs(&scanner, Some(true));
        let hs = scan_file(&scanner, path, bytes);
        keyhog_scanner::testing::set_phase2_hs(&scanner, Some(false));
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
    keyhog_scanner::testing::set_phase2_hs(&scanner, None);

    eprintln!(
        "\nfindings parity: {} / {} files identical | HS findings={total_hs} legacy findings={total_legacy}",
        files.len() - mismatched,
        files.len(),
    );
    assert_eq!(
        mismatched, 0,
        "HS prefilter changed findings on {mismatched} file(s), recall/precision regression"
    );
}
