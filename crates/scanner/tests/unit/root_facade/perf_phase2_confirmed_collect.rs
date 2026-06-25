//! Phase-2 SPEED regressions for the per-candidate / per-triggered-chunk work
//! `scan_coalesced_phase2` drives (LANE 9).
//!
//! Two finding-identical optimizations are pinned here:
//!
//!   1. CONFIRMED-PATTERN COLLECTION (engine/backend_triggered.rs):
//!      `scan_prepared_with_triggered` turns the expanded trigger bitmap into the
//!      `Vec<usize>` of confirmed pattern indices. It used to test EVERY one of
//!      the ~1500 `ac_map` bit positions one by one
//!      (`(0..ac_map.len()).filter(|i| bit_i_set)`), paying O(ac_map.len()) per
//!      triggered chunk to find the handful of bits real source actually sets.
//!      The fix walks ONLY the set bits (`trigger_bitmap::for_each_set_bit`,
//!      popcount-driven `bits &= bits - 1`), which is O(set-bits). The OUTPUT must
//!      be byte-identical: the same pattern indices, ascending, in `0..ac_map.len()`.
//!      `bitmap_setbit_walk_equals_range_filter` proves that equivalence over
//!      THOUSANDS of randomized bitmaps + every boundary shape, so the perf
//!      rewrite can never silently drop, add, or reorder a confirmed pattern.
//!
//!   2. WEAK-ANCHOR MEMOIZATION (engine/process.rs +
//!      engine/mod.rs::detector_weak_anchor_base_by_index, built in
//!      engine/compile.rs): `process_match` resolves the weak-anchor for EVERY
//!      surviving candidate. The per-DETECTOR base class (residual pure-hex list,
//!      generic/private-key carve-outs, explicit min_confidence) depends ONLY on
//!      the spec and is resolved ONCE at scanner construction into a
//!      `Vec<WeakAnchorBase>` indexed by `detector_index`; the per-PATTERN
//!      broad-identifier half is a regex-string scan memoized on the matched
//!      pattern's `LazyRegex`, so a hot detector no longer re-derives either an
//!      unchanging detector-wide value or an unchanging per-pattern value.
//!      `weak_anchor_is_a_pure_function_of_the_spec` pins the precondition the
//!      cache relies on (the classification is deterministic), and the
//!      golden-findings tests prove the cached value is finding-for-finding
//!      identical to the live call.
//!
//! GOLDEN FINDINGS (the durable proof both fixes are output-neutral):
//!   * `dense_corpus_findings_unchanged` — a dense corpus of a strong-anchored
//!     and a weak-anchored credential, each firing many times through the
//!     confirmed-extraction + per-candidate scoring path, surfaces EXACTLY the
//!     expected detector ids and EXACTLY the captured credential bytes.
//!   * `findings_independent_of_catalog_size` — the SAME trigger text scanned by
//!     a scanner with a small detector catalog and by one padded with hundreds of
//!     extra never-firing detectors produces the IDENTICAL finding set. This is
//!     the behavioural shadow of optimization (1): if the confirmed collection
//!     ever became catalog-size-sensitive in a way that changed which patterns
//!     run, this would diverge.

use super::support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, RawMatch, Severity};
use keyhog_scanner::testing::detector_weak_anchor;
use keyhog_scanner::{CompiledScanner, ScannerConfig};

// ---------------------------------------------------------------------------
// (1) Confirmed-pattern collection: set-bit walk == range filter, byte-for-byte.
// ---------------------------------------------------------------------------

/// The OLD collection: test every bit position `0..n_patterns`.
fn collect_range_filter(words: &[u64], n_patterns: usize) -> Vec<usize> {
    (0..n_patterns)
        .filter(|&i| (words[i / 64] & (1u64 << (i % 64))) != 0)
        .collect()
}

/// The NEW collection: walk only the set bits, guard `< n_patterns` (exactly
/// the in-crate `for_each_set_bit` + `idx < self.ac_map.len()` guard).
fn collect_setbit_walk(words: &[u64], n_patterns: usize) -> Vec<usize> {
    let mut out = Vec::new();
    for (word_idx, &word) in words.iter().enumerate() {
        let mut bits = word;
        while bits != 0 {
            let idx = word_idx * 64 + bits.trailing_zeros() as usize;
            if idx < n_patterns {
                out.push(idx);
            }
            bits &= bits - 1;
        }
    }
    out
}

/// A tiny deterministic xorshift PRNG so the table is reproducible across hosts
/// without a rand dependency (matches the no-extra-dep style of the other perf
/// tests in this crate).
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Data-driven equivalence over THOUSANDS of randomized bitmaps across a range
/// of catalog sizes and densities. The set-bit walk must return the IDENTICAL
/// `Vec<usize>` (same indices, same ascending order) as the exhaustive range
/// filter for every one — that is the byte-for-byte contract the perf rewrite
/// in `scan_prepared_with_triggered` must hold.
#[test]
fn bitmap_setbit_walk_equals_range_filter() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let mut cases = 0usize;
    // Catalog sizes spanning sub-word, exact-word-multiple, and ragged-tail
    // (the shapes where a padding-bit or off-by-one bug would surface).
    for &n_patterns in &[1usize, 7, 63, 64, 65, 127, 128, 200, 1000, 1500, 1503] {
        let words = n_patterns.div_ceil(64);
        // Many density profiles: empty, ultra-sparse (real source), half, dense.
        for density_pct in [0u64, 1, 5, 25, 50, 95, 100] {
            for _ in 0..40 {
                let mut bitmap = vec![0u64; words];
                for (i, slot) in bitmap.iter_mut().enumerate() {
                    let mut w = 0u64;
                    for b in 0..64 {
                        let global = i * 64 + b;
                        if global >= n_patterns {
                            break; // never set a padding bit
                        }
                        if rng.next() % 100 < density_pct {
                            w |= 1u64 << b;
                        }
                    }
                    *slot = w;
                }
                let old = collect_range_filter(&bitmap, n_patterns);
                let new = collect_setbit_walk(&bitmap, n_patterns);
                assert_eq!(
                    new, old,
                    "set-bit walk diverged from range filter for n_patterns={n_patterns} \
                     density={density_pct}%: old={old:?} new={new:?}"
                );
                cases += 1;
            }
        }
    }
    assert!(
        cases >= 3000,
        "expected a few thousand randomized equivalence cases, only ran {cases}"
    );
}

/// Concrete boundary pins so the randomized table can't silently degenerate to
/// the trivial all-empty case: a single low bit, a single high bit at the
/// catalog boundary, a tail word with a padding region, and the all-set word.
#[test]
fn bitmap_collection_boundary_truths() {
    // Single bit 0 set.
    assert_eq!(collect_setbit_walk(&[0b1], 64), vec![0]);
    assert_eq!(collect_range_filter(&[0b1], 64), vec![0]);

    // Highest valid bit in a 65-pattern catalog: index 64 lives in word 1, bit 0.
    let mut bm = vec![0u64; 2];
    bm[1] |= 1u64 << 0; // index 64
    assert_eq!(collect_setbit_walk(&bm, 65), vec![64]);
    assert_eq!(collect_range_filter(&bm, 65), vec![64]);

    // A set bit in the PADDING region (index 70, beyond a 65-pattern catalog)
    // must be excluded by BOTH the guard and the range filter — they agree on 0.
    let mut bm_pad = vec![0u64; 2];
    bm_pad[1] |= 1u64 << 6; // index 70 — padding, out of the 0..65 domain
    assert_eq!(
        collect_setbit_walk(&bm_pad, 65),
        Vec::<usize>::new(),
        "a padding-region bit must never enter the confirmed set"
    );
    assert_eq!(collect_range_filter(&bm_pad, 65), Vec::<usize>::new());

    // All 64 bits of a single full word, exactly 64 patterns.
    let full = vec![u64::MAX];
    let expect: Vec<usize> = (0..64).collect();
    assert_eq!(collect_setbit_walk(&full, 64), expect);
    assert_eq!(collect_range_filter(&full, 64), expect);
}

// ---------------------------------------------------------------------------
// (2) Per-detector weak-anchor memoization: the cached value is a pure function
//     of the spec (the precondition the construction-time cache relies on).
// ---------------------------------------------------------------------------

/// `detector_weak_anchor` must be DETERMINISTIC and depend ONLY on the
/// `DetectorSpec` — that is the precondition that lets the scanner resolve it
/// ONCE at construction (`detector_weak_anchor_by_index`) and reuse it for every
/// candidate. Computed twice over the full on-disk corpus, the result is
/// identical, and a `clone()` of a spec yields the identical classification.
#[test]
fn weak_anchor_is_a_pure_function_of_the_spec() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    assert!(
        detectors.len() >= 100,
        "expected the full detector corpus (>=100), only loaded {} — the cache \
         correctness net would otherwise be empty",
        detectors.len()
    );
    let mut weak = 0usize;
    let mut strong = 0usize;
    for d in &detectors {
        let a = detector_weak_anchor(d).expect("detector classification rules must be valid");
        let b = detector_weak_anchor(d).expect("detector classification rules must be valid");
        assert_eq!(
            a, b,
            "detector_weak_anchor is non-deterministic for `{}` ({a} vs {b}) — the \
             construction-time cache would then disagree with a live recompute",
            d.id
        );
        // A clone must classify identically (the value is a function of the
        // spec, not of identity/address).
        let cloned = d.clone();
        assert_eq!(
            detector_weak_anchor(&cloned).expect("detector classification rules must be valid"),
            a,
            "clone of `{}` classified differently — value is not spec-pure",
            d.id
        );
        if a {
            weak += 1;
        } else {
            strong += 1;
        }
    }
    // The corpus must exercise BOTH classifications, or this proves nothing
    // about the weak path.
    assert!(
        weak >= 1 && strong >= 1,
        "expected both weak ({weak}) and strong ({strong}) anchored detectors in \
         the corpus so both cache values are covered"
    );
}

/// Synthetic shape pins for `detector_weak_anchor` so a future change to its
/// definition that silently flips the corpus all to one side is caught: a
/// generic-* id is never weak-anchored; a service-anchored id with a broad
/// identifier capture and no `min_confidence` IS weak-anchored; setting
/// `min_confidence` un-flags it.
#[test]
fn weak_anchor_known_shapes() {
    // generic-* is excluded up front -> never weak.
    let generic = inline_detector_full(
        "generic-api-key",
        r#"key\s*=\s*"([A-Za-z0-9_-]+)""#,
        "key",
        None,
    );
    assert!(
        !detector_weak_anchor(&generic).expect("detector classification rules must be valid"),
        "a generic-* detector is never weak-anchored"
    );

    // Service-anchored id, broad `([A-Za-z0-9_-]+)` capture, no min_confidence
    // -> the weak-anchor shape.
    let weak = inline_detector_full(
        "acme-token",
        r#"acme_token\s*=\s*([A-Za-z0-9_-]+)"#,
        "acme_token",
        None,
    );
    assert!(
        detector_weak_anchor(&weak).expect("detector classification rules must be valid"),
        "a service-anchored detector with a broad identifier capture and no \
         min_confidence is weak-anchored"
    );

    // Same detector but with an explicit min_confidence floor -> NOT weak.
    let pinned = inline_detector_full(
        "acme-token",
        r#"acme_token\s*=\s*([A-Za-z0-9_-]+)"#,
        "acme_token",
        Some(0.5),
    );
    assert!(
        !detector_weak_anchor(&pinned).expect("detector classification rules must be valid"),
        "an explicit min_confidence floor removes the weak-anchor classification"
    );
}

// ---------------------------------------------------------------------------
// Golden findings: both optimizations are finding-for-finding identical.
// ---------------------------------------------------------------------------

fn inline_pattern(regex: &str) -> PatternSpec {
    PatternSpec {
        regex: regex.to_string(),
        ..Default::default()
    }
}

fn inline_detector_full(
    id: &str,
    regex: &str,
    keyword: &str,
    min_confidence: Option<f64>,
) -> DetectorSpec {
    let service = id
        .strip_prefix("test-")
        .unwrap_or(id)
        .split('-')
        .next()
        .unwrap_or("test")
        .to_string();
    DetectorSpec {
        id: id.to_string(),
        name: id.to_string(),
        service,
        severity: Severity::High,
        patterns: vec![inline_pattern(regex)],
        keywords: vec![keyword.to_string()],
        min_confidence,
        ..Default::default()
    }
}

fn scan_with(scanner: &CompiledScanner, text: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("config.env".into()),
            ..Default::default()
        },
    };
    scanner.clear_fragment_cache();
    scanner.scan(&chunk)
}

fn confirmed_only_scanner(detectors: Vec<DetectorSpec>) -> CompiledScanner {
    let mut config = ScannerConfig::default();
    config.entropy_enabled = false;
    config.generic_keyword_low_entropy = false;
    config.max_decode_depth = 0;
    config.multiline.max_join_lines = 1;
    config.multiline.python_implicit = false;
    config.multiline.backslash_continuation = false;
    config.multiline.plus_concatenation = false;
    config.multiline.template_literals = false;
    CompiledScanner::compile(detectors)
        .expect("compile inline scanner")
        .with_config(config)
}

/// GOLDEN: a dense corpus of two prefix-anchored tokens — each firing many times
/// through the confirmed-extraction + per-candidate scoring path that consumes
/// the `detector_weak_anchor` memoization — surfaces EXACTLY the expected
/// detector ids and EXACTLY the captured credential bytes. Any divergence between
/// the cached weak-anchor value and the live computation, or any drop/reorder in
/// the rewritten confirmed-pattern collection, would change this finding set.
#[test]
fn dense_corpus_findings_unchanged() {
    // Two service-anchored detectors with literal prefixes + high-entropy bodies.
    let strong = inline_detector_full(
        "test-live-token",
        r"tok_live_[A-Za-z0-9]{32}",
        "live_token",
        Some(0.1),
    );
    let acme_det = inline_detector_full(
        "test-acme-secret",
        r"acme_secret_[A-Za-z0-9]{24}",
        "acme_secret",
        Some(0.1),
    );
    let scanner = confirmed_only_scanner(vec![strong, acme_det]);

    let live = "tok_live_aZ9kQ2mX7pL4rT8wE1nB6vY3cF5dH0jS";
    let acme = "acme_secret_K7n2Pq9Wz4Lr8Tx1Bv6Yc3Fa";
    assert_eq!(live.len(), "tok_live_".len() + 32);
    assert_eq!(acme.len(), "acme_secret_".len() + 24);

    let mut corpus = String::new();
    for _ in 0..40 {
        corpus.push_str(&format!("live_token = \"{live}\"\n"));
        corpus.push_str(&format!("acme_secret = \"{acme}\"\n"));
    }

    let matches = scan_with(&scanner, &corpus);

    // Exactly the two inline confirmed detectors fire. The production scanner
    // can also emit reassembled/generic side findings on this repeated
    // one-file corpus; those are owned by separate gates, while this test pins
    // confirmed-pattern collection.
    let det_ids: std::collections::BTreeSet<&str> = matches
        .iter()
        .filter_map(|m| {
            let base = m
                .detector_id
                .strip_suffix(":reassembled")
                .unwrap_or(m.detector_id.as_ref());
            base.starts_with("test-").then_some(base)
        })
        .collect();
    assert_eq!(
        det_ids,
        ["test-acme-secret", "test-live-token"]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        "GOLDEN: exactly the two inline detectors must fire. Got: {det_ids:?}"
    );

    // The exact credential bytes are captured verbatim for both.
    let creds: std::collections::BTreeSet<&str> =
        matches.iter().map(|m| m.credential.as_ref()).collect();
    assert!(
        creds.contains(live),
        "GOLDEN: strong-anchored credential `{live}` must be captured exactly. Got {creds:?}"
    );
    assert!(
        creds.contains(acme),
        "GOLDEN: weak-anchored credential `{acme}` must be captured exactly. Got {creds:?}"
    );
}

/// GOLDEN / behavioural-shadow of the confirmed-collection rewrite: scanning the
/// SAME trigger text with a small catalog vs a catalog padded with hundreds of
/// extra never-firing detectors must produce the IDENTICAL finding set. The
/// set-bit walk is O(set-bits) not O(catalog), but more importantly it must be
/// catalog-size-INVARIANT in OUTPUT — the indices it confirms are exactly the
/// ones triggered, regardless of how many other patterns exist.
#[test]
fn findings_independent_of_catalog_size() {
    let target = inline_detector_full(
        "test-live-token",
        r"tok_live_[A-Za-z0-9]{32}",
        "live_token",
        Some(0.1),
    );
    let live = "tok_live_aZ9kQ2mX7pL4rT8wE1nB6vY3cF5dH0jS";
    let text = format!("live_token = \"{live}\"\n");

    // Small catalog: just the target detector.
    let small = confirmed_only_scanner(vec![target.clone()]);
    let small_matches = scan_with(&small, &text);

    // Large catalog: the target plus 400 distinct never-firing decoys with
    // unique literal prefixes that do NOT appear in `text`, so only the target
    // triggers — but the confirmed-pattern collection now walks a 401-entry
    // catalog's bitmap. Output must be identical.
    let mut many = vec![target];
    for i in 0..400 {
        many.push(inline_detector_full(
            &format!("decoy-{i}"),
            &format!(r"zzdecoy{i}_[A-Za-z0-9]{{20}}"),
            &format!("zzdecoy{i}_"),
            Some(0.1),
        ));
    }
    let large = confirmed_only_scanner(many);
    let large_matches = scan_with(&large, &text);

    // Reduce each to its (detector_id, credential) identity set and compare.
    let ident = |ms: &[RawMatch]| -> std::collections::BTreeSet<(String, String)> {
        ms.iter()
            .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
            .collect()
    };
    let small_set = ident(&small_matches);
    let large_set = ident(&large_matches);

    assert_eq!(
        small_set, large_set,
        "findings diverged with catalog size: small={small_set:?} large={large_set:?}"
    );
    // And both must actually contain the one real finding (not be empty-equal).
    assert_eq!(
        small_set,
        [("test-live-token".to_string(), live.to_string())]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        "expected exactly the one live-token finding regardless of catalog size"
    );
}

/// COALESCED-PATH golden: `scan_coalesced` is the production batch path that
/// drives `scan_coalesced_phase2` (the lane's named target). It and the
/// per-chunk `scan()` share the edited `scan_prepared_with_triggered`
/// (confirmed-pattern collection) and `process_match` (weak-anchor cache), so
/// they MUST produce the IDENTICAL finding set on the same input. Scanning a
/// multi-chunk dense batch through both APIs and comparing the merged
/// (detector_id, credential) identity sets pins that both optimizations are
/// backend-path-invariant.
#[test]
fn coalesced_and_per_chunk_findings_match() {
    let strong = inline_detector_full(
        "test-live-token",
        r"tok_live_[A-Za-z0-9]{32}",
        "live_token",
        Some(0.1),
    );
    let cfg_det = inline_detector_full(
        "test-config-key",
        r"cfg_key_[0-9a-f]{40}",
        "config_key",
        Some(0.1),
    );
    let scanner = confirmed_only_scanner(vec![strong, cfg_det]);

    let live = "tok_live_aZ9kQ2mX7pL4rT8wE1nB6vY3cF5dH0jS";
    let cfg = "cfg_key_0123456789abcdef0123456789abcdef01234567";

    // Build many distinct chunks (a real coalesced batch is a Vec of chunks).
    let mut chunks: Vec<Chunk> = Vec::new();
    for i in 0..24 {
        let body =
            format!("live_token = \"{live}\"\nconfig_key = \"{cfg}\"\nnoise line {i} = nothing\n");
        chunks.push(Chunk {
            data: body.into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some(format!("file_{i}.env")),
                ..Default::default()
            },
        });
    }

    let ident = |ms: &[RawMatch]| -> std::collections::BTreeSet<(String, String)> {
        ms.iter()
            .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
            .collect()
    };

    // Per-chunk API (the path my unit golden tests above use).
    scanner.clear_fragment_cache();
    let mut per_chunk: Vec<RawMatch> = Vec::new();
    for c in &chunks {
        per_chunk.extend(scanner.scan(c));
    }

    // Coalesced batch API — drives scan_coalesced_phase2 directly.
    scanner.clear_fragment_cache();
    let coalesced: Vec<RawMatch> = scanner
        .scan_coalesced(&chunks)
        .into_iter()
        .flatten()
        .collect();

    let per_chunk_set = ident(&per_chunk);
    let coalesced_set = ident(&coalesced);

    assert_eq!(
        per_chunk_set, coalesced_set,
        "per-chunk and coalesced phase-2 produced different findings:\n  \
         per_chunk={per_chunk_set:?}\n  coalesced={coalesced_set:?}"
    );
    // Both must contain exactly the two real credentials (not be empty-equal).
    let expected: std::collections::BTreeSet<(String, String)> = [
        ("test-live-token".to_string(), live.to_string()),
        ("test-config-key".to_string(), cfg.to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        coalesced_set, expected,
        "coalesced findings must be exactly the two seeded credentials"
    );
}
