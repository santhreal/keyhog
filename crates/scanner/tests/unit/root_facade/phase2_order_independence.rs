//! Does the final finding set depend on the ORDER phase-2 patterns are
//! extracted? If NOT, an O(text) literal prefilter (which marks the active set
//! in a different order than the RegexSet) is safe to adopt, the key blocker
//! for a much faster prefilter. Scans each corpus chunk with the fallback
//! extraction order normal vs reversed and asserts identical findings.

use super::support;
use support::paths::{corpus_dir, corpus_files, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata, MatchLocation, RawMatch, Severity};
use keyhog_scanner::testing::scan_state_drain;
#[cfg(any(feature = "entropy", feature = "simdsieve"))]
use keyhog_scanner::testing::{
    scan_state_lazy_duplicate_probe_for_test, scan_state_lazy_identity_tiebreak_probe_for_test,
    scan_state_lazy_overestimated_priority_probe_for_test,
};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::HashMap;
use std::sync::Arc;

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "order-indep".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn canonical(matches: &[Vec<RawMatch>]) -> Vec<(String, String, String)> {
    let mut v: Vec<(String, String, String)> = matches
        .iter()
        .flatten()
        .map(|m| {
            (
                m.detector_id.to_string(),
                m.credential.as_str().to_string(),
                format!("{:?}", m.location),
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
#[ignore = "diagnostic: run with --ignored --nocapture"]
fn phase2_order_independence() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let Some(root) = corpus_dir() else {
        eprintln!("no corpus; skipping");
        return;
    };
    let files = corpus_files(&root, 6000);
    // Raw small files + 16 KiB chunks, the two regimes.
    let mut chunks: Vec<Vec<u8>> = files.clone();
    let mut cur = Vec::new();
    for f in &files {
        cur.extend_from_slice(f);
        cur.push(b'\n');
        if cur.len() >= 16 * 1024 {
            chunks.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }

    let mut diverged = 0;
    for (i, c) in chunks.iter().enumerate() {
        let chunk = chunk_of(c, &format!("c-{i}"));
        keyhog_scanner::testing::set_phase2_reverse(&scanner, Some(false));
        scanner.clear_fragment_cache();
        let normal = canonical(
            &scanner
                .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback),
        );
        keyhog_scanner::testing::set_phase2_reverse(&scanner, Some(true));
        scanner.clear_fragment_cache();
        let reversed = canonical(
            &scanner
                .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback),
        );
        if normal != reversed {
            diverged += 1;
            if diverged <= 5 {
                eprintln!(
                    "== ORDER-DEPENDENT divergence on chunk {i} ({} bytes) ==",
                    c.len()
                );
                use std::collections::BTreeSet;
                let n: BTreeSet<_> = normal.iter().collect();
                let r: BTreeSet<_> = reversed.iter().collect();
                for only in n.difference(&r) {
                    eprintln!("  only-in-normal: {only:?}");
                }
                for only in r.difference(&n) {
                    eprintln!("  only-in-reversed: {only:?}");
                }
            }
        }
    }
    keyhog_scanner::testing::set_phase2_reverse(&scanner, None);
    eprintln!(
        "phase2_order_independence: {} chunks, {diverged} order-dependent",
        chunks.len()
    );
    assert_eq!(
        diverged, 0,
        "phase-2 finding set depends on extraction order"
    );
}

/// A candidate that ties on EVERY primary Ord key (confidence, severity,
/// detector, credential) and differs ONLY by byte offset, so the
/// `(offset, line)` tie-break is the sole thing that totally orders it.
fn tied_match(offset: usize) -> RawMatch {
    RawMatch {
        detector_id: Arc::from("generic-secret"),
        detector_name: Arc::from("Generic Secret"),
        service: Arc::from("generic"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from("AKIAIOSFODNN7EXAMPLE"),
        credential_hash: [0u8; 32].into(),
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("f.env")),
            line: Some(1),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.5),
    }
}

/// The MECHANISM behind `phase2_order_independence`, gated directly and without
/// a corpus so it runs in CI (the corpus test above is `#[ignore]` and the mirror
/// chunks may not even overflow the cap). When a chunk produces more than
/// `max_matches_per_chunk` matches, `ScanState::push_match` keeps the top-N by
/// `RawMatch::Ord` in a bounded heap. If two candidates ever compared Equal at the
/// survival boundary, eviction among them would fall back to INSERTION ORDER
/// which is the phase-2 extraction order the diagnostic test perturbs, and is
/// HashMap-/thread-nondeterministic in production. These 24 candidates tie on every
/// primary key and differ only by offset, so only the total-order `(offset, line)`
/// tie-break makes the kept set well-defined. Inserting ascending vs descending
/// MUST yield the identical surviving set; a divergence means `RawMatch::Ord` lost
/// totality (e.g. someone dropped the offset key) and the finding set will flicker.
#[test]
fn push_match_eviction_set_is_insertion_order_independent() {
    const LIMIT: usize = 8;
    let offsets: Vec<usize> = (0..24).map(|i| i * 7).collect();

    let asc = offsets.iter().map(|&o| tied_match(o)).collect();
    let desc = offsets.iter().rev().map(|&o| tied_match(o)).collect();

    let kept = |matches| {
        let mut v: Vec<usize> = scan_state_drain(matches, LIMIT)
            .iter()
            .map(|m| m.location.offset)
            .collect();
        v.sort_unstable();
        v
    };
    let a = kept(asc);
    let d = kept(desc);
    assert_eq!(
        a.len(),
        LIMIT,
        "the bounded heap must retain exactly the cap of distinct findings, got {a:?}"
    );
    assert_eq!(
        a, d,
        "push_match kept a DIFFERENT set for ascending vs descending insertion. \
         eviction is insertion-order-dependent (RawMatch::Ord is not total): {a:?} vs {d:?}"
    );
}

#[test]
fn push_match_eviction_keeps_highest_confidence_when_capped() {
    const LIMIT: usize = 2;

    let mut low = tied_match(7);
    low.credential = keyhog_core::SensitiveString::from("low");
    low.confidence = Some(0.10);
    let mut high = tied_match(14);
    high.credential = keyhog_core::SensitiveString::from("high");
    high.confidence = Some(0.90);
    let mut mid = tied_match(21);
    mid.credential = keyhog_core::SensitiveString::from("mid");
    mid.confidence = Some(0.50);

    let kept: Vec<_> = scan_state_drain(vec![low, high, mid], LIMIT)
        .into_iter()
        .map(|m| m.credential.as_str().to_string())
        .collect();
    assert_eq!(
        kept,
        ["high", "mid"],
        "bounded heap must evict the lowest-confidence finding, not the highest"
    );
}

#[test]
fn push_match_duplicate_identity_keeps_best_single_slot() {
    const LIMIT: usize = 2;

    let mut duplicate_low = tied_match(7);
    duplicate_low.credential = keyhog_core::SensitiveString::from("duplicate");
    duplicate_low.confidence = Some(0.10);

    let mut filler = tied_match(14);
    filler.credential = keyhog_core::SensitiveString::from("filler");
    filler.confidence = Some(0.50);

    let mut duplicate_high = tied_match(7);
    duplicate_high.credential = keyhog_core::SensitiveString::from("duplicate");
    duplicate_high.confidence = Some(0.90);

    let kept = scan_state_drain(vec![duplicate_low, filler, duplicate_high], LIMIT);

    assert_eq!(
        kept.len(),
        LIMIT,
        "duplicate identities must use one heap slot so another finding can survive: {kept:?}"
    );
    let duplicate = kept
        .iter()
        .find(|m| m.credential.as_ref() == "duplicate")
        .expect("duplicate identity retained");
    assert_eq!(
        duplicate.confidence,
        Some(0.90),
        "a later duplicate with better ordering must replace the retained identity"
    );
    assert!(
        kept.iter().any(|m| m.credential.as_ref() == "filler"),
        "the second heap slot must remain available for a distinct finding: {kept:?}"
    );
}

#[test]
#[cfg(any(feature = "entropy", feature = "simdsieve"))]
fn push_match_lazy_duplicate_identity_skips_worse_build_and_replaces_better() {
    let (worse_built, better_built, kept) = scan_state_lazy_duplicate_probe_for_test();
    assert!(
        !worse_built,
        "lazy duplicate below the retained identity must not build an owned RawMatch"
    );
    assert!(
        better_built,
        "lazy duplicate above the retained identity must build so it can replace"
    );

    assert_eq!(kept.len(), 1, "duplicate identity must keep one slot");
    assert_eq!(
        kept[0].confidence,
        Some(0.90),
        "lazy duplicate replacement must keep the best candidate"
    );
}

#[test]
#[cfg(any(feature = "entropy", feature = "simdsieve"))]
fn push_match_lazy_rechecks_built_match_before_replacing_worst() {
    let (built, kept) = scan_state_lazy_overestimated_priority_probe_for_test();
    assert!(
        built,
        "an overestimated lazy priority can require building before final ordering is known"
    );
    assert_eq!(kept.len(), 1, "cap-one heap must still retain one finding");
    assert_eq!(
        kept[0].credential.as_ref(),
        "retained",
        "lazy candidate whose built RawMatch is worse than the heap worst must not replace it"
    );
}

#[test]
#[cfg(any(feature = "entropy", feature = "simdsieve"))]
fn push_match_lazy_builds_equal_priority_before_identity_tiebreak() {
    let (built, kept) = scan_state_lazy_identity_tiebreak_probe_for_test();
    assert!(
        built,
        "an equal borrowed priority must build before identity-only fields can break the tie"
    );
    assert_eq!(
        kept.len(),
        1,
        "duplicate identity must still occupy one slot"
    );
    assert_eq!(
        kept[0].detector_name.as_ref(),
        "Alpha detector",
        "lazy and eager insertion must choose the same full RawMatch ordering winner"
    );
}
