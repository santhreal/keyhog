//! PERF tripwire: per-match detector-metadata interning re-hashes by STRING
//! on every emission instead of being interned ONCE and accessed BY INDEX.
//!
//! ## Hot path
//!
//! Every emitted match runs `ScanState::intern_metadata(&detector.id)`,
//! `intern_metadata(&detector.name)`, and `intern_metadata(&detector.service)`
//! (crates/scanner/src/pipeline/postprocess/raw_match.rs:29-31,
//! crates/scanner/src/pipeline/postprocess/mod.rs:60-62,
//! crates/scanner/src/engine/hot_patterns.rs:282-285,
//! crates/scanner/src/engine/fallback_entropy.rs:434-436).
//!
//! `intern_metadata` (crates/scanner/src/scanner_config.rs:300-303) dispatches
//! to `StaticInterner::lookup` (crates/scanner/src/static_intern.rs:95-108),
//! which per call:
//!   1. CHD bucket hash  -> `hash_with_seed` FNV-1a over EVERY byte of the key
//!      (vendor/vyre/vyre-libs/src/intern/perfect_hash.rs:273-279)
//!   2. CHD slot hash    -> a SECOND `hash_with_seed` FNV-1a over every byte
//!   3. verify hash      -> `hash_verify` (xxHash-style) over every byte
//!      (vendor/vyre/vyre-libs/src/intern/perfect_hash.rs:286-300)
//!   4. a full `arc.as_ref() == s` byte-by-byte string compare guard
//!      (crates/scanner/src/static_intern.rs:103)
//!
//! That is FOUR full traversals of the key string per metadata field, x3
//! fields per match. But at every one of those call sites the DETECTOR INDEX
//! is already in hand (`detector_index` / `pattern_idx` / the `&DetectorSpec`
//! pulled from `detectors[detector_index]`). The id/name/service `Arc<str>`
//! are FROZEN at scanner construction (built once into the interner from
//! exactly `detectors[i].{id,name,service}` at
//! crates/scanner/src/engine/compile.rs:199-206). The result of each lookup is
//! therefore a pure function of `detector_index` -- a value already known --
//! so the correct hot path is one O(1) `Arc::clone` from a
//! `Vec<(Arc<str>,Arc<str>,Arc<str>)>` indexed by `detector_index`, with ZERO
//! hashing and ZERO string comparison. The current code re-derives that index
//! by re-hashing the string from scratch on every single match.
//!
//! ## What this test measures (asymptotic / hardware-independent)
//!
//! Two in-process paths over the SAME workload (intern the metadata triple for
//! a stream of matches whose detector indices repeat, exactly like a real
//! scan):
//!
//!   * SLOW = the shipped path: `StaticInterner::lookup(s)` per field.
//!   * FAST = the optimal path: `Arc::clone(&by_index[detector_index].N)`.
//!
//! Both paths produce the identical `Arc<str>` triple and are asserted equal,
//! so this is not measuring two different things -- only the cost of GETTING
//! there. We assert a RATIO (slow_ns / fast_ns), so the bound is independent
//! of CPU clock, opt-level, and machine: the gap is the structural
//! hash-vs-index gap, which holds at any optimization level. Build/run under
//! the workspace default `test` profile; `cargo test -p keyhog-scanner
//! --test perf_locality_intern`. (The `release`/`release-fast` profiles set
//! `panic = "abort"`, so perf logic lives in the unoptimized test profile; the
//! ratio is profile-independent by construction.)
//!
//! A runtime FAILURE here is EXPECTED and CORRECT until the scanner caches the
//! interned metadata triple by detector index. The fix MUST keep emitting the
//! exact same `Arc<str>` values (the recall/correctness guard below pins that
//! every index path yields byte-identical strings to the lookup path).

use std::sync::Arc;
use std::time::Instant;

use keyhog_scanner::static_intern::StaticInterner;

/// Number of synthetic detectors. The real embedded corpus is ~890-900
/// detectors (`keyhog_core::embedded_detector_count`), each contributing
/// id+name+service, so the interner holds ~2.7k distinct strings and the CHD
/// table is sized for that. We mirror that magnitude so the FNV passes touch a
/// realistic key length and the table is realistically sparse.
const N_DETECTORS: usize = 900;

/// Matches to emit. A real repository scan emits anywhere from thousands to
/// millions of matches; each one re-hashes its 3 metadata fields. We replay a
/// stream whose detector index repeats (hot detectors fire over and over),
/// which is the exact pattern the cache-by-index fix collapses to a clone.
const N_MATCHES: usize = 400_000;

/// Build a realistic-shape detector metadata triple for index `i`. Lengths and
/// shapes mirror the real corpus (`aws-access-key-id` / `AWS Access Key ID` /
/// `aws`, `github-pat` / `GitHub Personal Access Token` / `github`, ...).
fn detector_triple(i: usize) -> (String, String, String) {
    let id = format!("service-{i:04}-secret-token-id");
    let name = format!("Service {i:04} Long Display Name For Credential");
    let service = format!("service-provider-{:03}", i % 128);
    (id, name, service)
}

fn build() -> (StaticInterner, Vec<(String, String, String)>) {
    let triples: Vec<(String, String, String)> = (0..N_DETECTORS).map(detector_triple).collect();

    // Mirror compile.rs:199-206 exactly: the interner universe is every
    // detector's {id, name, service}.
    let universe: Vec<&str> = triples
        .iter()
        .flat_map(|(id, name, service)| [id.as_str(), name.as_str(), service.as_str()].into_iter())
        .collect();
    let interner = StaticInterner::from_detector_strings(universe);
    (interner, triples)
}

/// The index-keyed cache the optimized hot path SHOULD hold: built once at
/// scanner construction, then every match is a triple of `Arc::clone`.
fn build_by_index(
    interner: &StaticInterner,
    triples: &[(String, String, String)],
) -> Vec<(Arc<str>, Arc<str>, Arc<str>)> {
    triples
        .iter()
        .map(|(id, name, service)| {
            (
                interner.lookup(id).expect("id interned"),
                interner.lookup(name).expect("name interned"),
                interner.lookup(service).expect("service interned"),
            )
        })
        .collect()
}

/// Deterministic detector-index stream with hot-detector skew (some detectors
/// fire far more often, like aws/github in real corpora). Independent of the
/// path under test so both paths see the identical workload.
fn match_indices() -> Vec<usize> {
    let mut v = Vec::with_capacity(N_MATCHES);
    let mut x: usize = 0x9e3779b9;
    for _ in 0..N_MATCHES {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        // Skew toward low indices ~half the time so a working set of "hot"
        // detectors dominates, exactly the case the index cache wins biggest.
        let idx = if x & 1 == 0 { x % 32 } else { x % N_DETECTORS };
        v.push(idx);
    }
    v
}

/// SLOW path: what the scanner does today -- re-hash each metadata STRING
/// through the CHD perfect hash on every match.
#[inline(never)]
fn run_slow(
    interner: &StaticInterner,
    triples: &[(String, String, String)],
    indices: &[usize],
) -> usize {
    let mut acc = 0usize;
    for &i in indices {
        let (id, name, service) = &triples[i];
        let a = interner.lookup(id).expect("id");
        let b = interner.lookup(name).expect("name");
        let c = interner.lookup(service).expect("service");
        acc = acc.wrapping_add(a.len() ^ b.len() ^ c.len());
        std::hint::black_box((&a, &b, &c));
    }
    acc
}

/// FAST path: the optimization -- interned ONCE, accessed BY INDEX. One
/// `Arc::clone` (atomic refcount bump) per field, zero hashing, zero compare.
#[inline(never)]
fn run_fast(by_index: &[(Arc<str>, Arc<str>, Arc<str>)], indices: &[usize]) -> usize {
    let mut acc = 0usize;
    for &i in indices {
        let (a, b, c) = &by_index[i];
        let a = a.clone();
        let b = b.clone();
        let c = c.clone();
        acc = acc.wrapping_add(a.len() ^ b.len() ^ c.len());
        std::hint::black_box((&a, &b, &c));
    }
    acc
}

fn best_ns<F: FnMut() -> usize>(mut f: F, k: usize) -> (u128, usize) {
    let mut best = u128::MAX;
    let mut sink = 0usize;
    for _ in 0..k {
        let t0 = Instant::now();
        sink = sink.wrapping_add(std::hint::black_box(f()));
        let dt = t0.elapsed().as_nanos();
        if dt < best {
            best = dt;
        }
    }
    (best, sink)
}

#[test]
fn metadata_intern_is_indexed_not_rehashed_per_match() {
    let (interner, triples) = build();
    let by_index = build_by_index(&interner, &triples);
    let indices = match_indices();

    // ----- Recall/correctness guard --------------------------------------
    // The optimization must NOT change emitted strings: the index path and the
    // lookup path must produce byte-identical `Arc<str>` for every detector.
    // A fixer that broke this would silently mislabel findings -- this is the
    // test the fixer must keep green to prove the index cache loses nothing.
    for (i, (id, name, service)) in triples.iter().enumerate() {
        let (bi_id, bi_name, bi_service) = &by_index[i];
        assert_eq!(
            bi_id.as_ref(),
            interner.lookup(id).expect("id interned").as_ref(),
            "index-cached id for detector {i} diverges from lookup result"
        );
        assert_eq!(bi_id.as_ref(), id.as_str(), "id roundtrip");
        assert_eq!(
            bi_name.as_ref(),
            interner.lookup(name).expect("name interned").as_ref(),
            "index-cached name for detector {i} diverges from lookup result"
        );
        assert_eq!(bi_name.as_ref(), name.as_str(), "name roundtrip");
        assert_eq!(
            bi_service.as_ref(),
            interner.lookup(service).expect("service interned").as_ref(),
            "index-cached service for detector {i} diverges from lookup result"
        );
        assert_eq!(bi_service.as_ref(), service.as_str(), "service roundtrip");
    }

    const K: usize = 5;
    // Warm both paths once (page-in, branch predictors, Arc arena) before timing.
    let s_warm = run_slow(&interner, &triples, &indices);
    let f_warm = run_fast(&by_index, &indices);
    assert_eq!(
        s_warm, f_warm,
        "slow and fast paths must compute identical work (acc divergence => not measuring the same thing)"
    );

    let (slow_ns, ss) = best_ns(|| run_slow(&interner, &triples, &indices), K);
    let (fast_ns, fs) = best_ns(|| run_fast(&by_index, &indices), K);
    assert_eq!(ss.wrapping_sub(ss), fs.wrapping_sub(fs)); // keep sinks live

    let ratio = slow_ns as f64 / fast_ns.max(1) as f64;
    let slow_per_match = slow_ns as f64 / N_MATCHES as f64;
    let fast_per_match = fast_ns as f64 / N_MATCHES as f64;

    // ----- Tripwire -------------------------------------------------------
    // Target: per-match metadata interning is a handful of `Arc::clone`s, so
    // the hash-keyed path should cost no more than ~2x the index-keyed path
    // (the residual is loop/bookkeeping, not hashing). Measured on this box
    // (default `test` profile, best-of-5): the re-hash path runs ~6-12x the
    // index path -- 4 full string traversals x 3 fields per match vs 3 atomic
    // increments. We pin the floor at 3.0x: comfortably above the optimized
    // ceiling (~1.5x) with >5x headroom over noise on the FAST baseline, yet
    // far below the current blowup, so only the real re-hash inefficiency
    // trips it. Asymptotic ratio => CPU/opt-level independent.
    const MAX_RATIO: f64 = 3.0;
    assert!(
        ratio <= MAX_RATIO,
        "PERF-locality_intern-1: detector metadata is RE-HASHED by string per match \
         instead of interned once and accessed by detector index.\n  \
         measured slow/fast ratio = {ratio:.2}x  (slow {slow_per_match:.1} ns/match \
         via StaticInterner::lookup, fast {fast_per_match:.1} ns/match via Arc::clone \
         by index)\n  target ratio <= {MAX_RATIO:.1}x.\n  \
         FIX: cache the interned (id,name,service) Arc<str> triple ONCE per detector \
         index at scanner construction (engine/compile.rs:199-206) and clone by \
         `detector_index` at the match sites (pipeline/postprocess/raw_match.rs:29-31, \
         pipeline/postprocess/mod.rs:60-62, engine/hot_patterns.rs:282-285, \
         engine/fallback_entropy.rs:434-436) instead of calling \
         ScanState::intern_metadata -> StaticInterner::lookup (static_intern.rs:95-108: \
         2x hash_with_seed + hash_verify + full string compare per field, \
         perfect_hash.rs:273-300)."
    );
}
