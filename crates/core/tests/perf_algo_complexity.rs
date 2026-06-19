//! PERF tripwire — `algo_complexity` vector.
//!
//! TARGET HOT PATH: `keyhog_core::dedup_matches` (crates/core/src/dedup.rs).
//!
//! DEFECT (file:line evidence):
//!   crates/core/src/dedup.rs:179-186 — for every raw match that lands in an
//!   already-seen `(detector_id, credential, file)` group, the duplicate arm does
//!
//!       if !is_same_location(&existing.primary_location, &matched.location)
//!           && !existing
//!               .additional_locations
//!               .iter()                                  // <-- LINEAR SCAN
//!               .any(|loc| is_same_location(loc, &matched.location))
//!       {
//!           existing.additional_locations.push(matched.location);
//!       }
//!
//!   `is_same_location` compares (source, file_path, line, commit). When the SAME
//!   credential is hardcoded on K *distinct lines* of ONE file (a generated
//!   fixtures dump, an exported `.env`, a `.tfvars`, a large config with a shared
//!   token repeated per stanza), all K matches collapse into a single group. The
//!   i-th match scans the i-1 already-recorded `additional_locations`, finds no
//!   match (each line is distinct), then pushes. Total work is
//!   0+1+2+...+(K-1) = K(K-1)/2 = **O(K^2)** comparisons, and there is NO cap on
//!   `additional_locations` length anywhere in the workspace
//!   (`rg additional_locations.truncate|max_additional` → none).
//!
//!   Every other per-match cost in that branch is O(1): `sha256_hash` runs once
//!   per group (only in the `None` insert arm, dedup.rs:191), `merge_companions`
//!   is O(empty), `is_decoder_alias_pair` is O(1). The up-front
//!   `matches.sort_by` (dedup.rs:130) is O(N log N) and the final key sort
//!   (dedup.rs:215) is O(G log G). With all matches in one group, the quadratic
//!   `.any()` sweep is the sole super-linear term — so doubling K must NOT
//!   roughly quadruple the wall time. The dedup pass should collapse K repeats
//!   into one finding with K-1 additional locations in O(K) (e.g. a HashSet of
//!   seen-locations per group, or skipping the membership check entirely when the
//!   sort already orders by location so a same-as-previous test suffices).
//!
//! RATIO TRIPWIRE (hardware-independent): measure dedup of N vs 2N repeats of the
//! same credential on distinct lines (one group). A linear/log-linear dedup
//! doubles (~2x, +sort log factor); the current O(K^2) sweep ~4x. We require the
//! doubling ratio to stay under SUBQUADRATIC_RATIO (3.0). Best-of-K (min) timing
//! removes scheduler/allocator noise; the assertion is on a RATIO so it is
//! immune to absolute clock speed. Run with the release-fast profile
//! characteristics (the workspace CI/e2e profile): opt-level=3, thin LTO,
//! debug-assertions=on — build/run via
//!   CARGO_TARGET_DIR=/mnt/FlareTraining/santh-archive/cargo-target \
//!   cargo test -p keyhog-core --test perf_algo_complexity --release
//! (a plain `cargo test` debug build also trips it; the ratio holds either way).
//!
//! A runtime FAILURE here is EXPECTED and CORRECT until dedup.rs is fixed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use keyhog_core::{dedup_matches, DedupScope, MatchLocation, RawMatch, Severity};

/// Doubling input must not roughly quadruple time for the dedup pass. A
/// log-linear dedup ratios ~2.0-2.4 (the +log term); the O(K^2)
/// additional_locations sweep ratios ~3.6-4.0. 3.0 sits well above the
/// optimized target and well below the quadratic blowup, so only the real
/// regression trips it.
const SUBQUADRATIC_RATIO: f64 = 3.0;

/// Best-of-K wall-clock samples; keep the min to drop scheduler/alloc noise.
const TIMING_SAMPLES: usize = 5;

/// Base group size. Chosen so the quadratic term is clearly measurable
/// (N^2 = ~36M same-location comparisons at N) without making the optimized
/// path slow. The group is a SINGLE (detector, credential, file) cluster.
const BASE_N: usize = 6_000;

/// Build `n` RawMatches: identical detector_id + credential + file_path, but
/// each on a DISTINCT line/offset. They all hash to one DedupKey, so every
/// match after the first hits the duplicate arm and scans additional_locations.
fn build_repeated_credential_group(n: usize) -> Vec<RawMatch> {
    let detector_id: Arc<str> = Arc::from("aws-access-key");
    let detector_name: Arc<str> = Arc::from("AWS Access Key");
    let service: Arc<str> = Arc::from("aws");
    // One credential value repeated across the whole file.
    let credential =
        keyhog_core::SensitiveString::from("AKIAIOSFODNN7EXAMPLEKEYREPEATEDEVERYWHERE");
    let source: Arc<str> = Arc::from("filesystem");
    let file_path: Option<Arc<str>> = Some(Arc::from("generated/credentials_dump.tfvars"));

    (0..n)
        .map(|i| RawMatch {
            detector_id: Arc::clone(&detector_id),
            detector_name: Arc::clone(&detector_name),
            service: Arc::clone(&service),
            severity: Severity::High,
            credential: credential.clone(),
            credential_hash: [0u8; 32],
            companions: std::collections::HashMap::new(),
            location: MatchLocation {
                source: Arc::clone(&source),
                file_path: file_path.clone(),
                // DISTINCT line per match -> is_same_location() never short-circuits,
                // so each duplicate appends to additional_locations.
                line: Some(i + 1),
                offset: i * 64,
                commit: None,
                author: None,
                date: None,
            },
            entropy: Some(4.5),
            confidence: Some(0.9),
        })
        .collect()
}

/// Min over TIMING_SAMPLES of the wall time to dedup a freshly-built group of
/// `n` matches. Build is excluded from the timed region.
fn best_dedup_time(n: usize) -> Duration {
    let mut best = Duration::from_secs(u64::MAX);
    for _ in 0..TIMING_SAMPLES {
        let matches = build_repeated_credential_group(n);
        let start = Instant::now();
        let deduped = dedup_matches(matches, &DedupScope::Credential);
        let elapsed = start.elapsed();
        // Guard against dead-code elimination AND assert the dedup actually
        // collapsed the group (so we are timing the real additional_locations
        // accumulation, not an early bail).
        assert_eq!(
            deduped.len(),
            1,
            "expected the {n} repeats of one credential to collapse into a single \
             DedupedMatch; got {} — the perf measurement is only valid when all \
             matches land in ONE group and exercise the additional_locations sweep",
            deduped.len()
        );
        assert_eq!(
            deduped[0].additional_locations.len(),
            n - 1,
            "expected {} additional_locations (one per distinct line beyond the \
             primary); got {} — distinct lines must all be retained, confirming \
             the O(K^2) membership scan is exercised",
            n - 1,
            deduped[0].additional_locations.len()
        );
        if elapsed < best {
            best = elapsed;
        }
    }
    best
}

#[test]
fn dedup_additional_locations_is_subquadratic_in_group_size() {
    // Warm up allocator / caches so the first timed run is not penalized.
    let _ = best_dedup_time(BASE_N / 4);

    let t_n = best_dedup_time(BASE_N);
    let t_2n = best_dedup_time(BASE_N * 2);

    let ratio = t_2n.as_secs_f64() / t_n.as_secs_f64().max(1e-9);

    assert!(
        ratio < SUBQUADRATIC_RATIO,
        "dedup_matches is super-linear in the size of a single \
         (detector, credential, file) group.\n\
         MEASURED: dedup(N={BASE_N}) = {:.3} ms, dedup(2N={}) = {:.3} ms, \
         doubling ratio = {ratio:.2}x (best-of-{TIMING_SAMPLES}).\n\
         TARGET: ratio < {SUBQUADRATIC_RATIO:.1}x (log-linear dedup doubles ~2.0-2.4x).\n\
         ROOT CAUSE: crates/core/src/dedup.rs:179-186 — `existing.additional_locations\
         .iter().any(|loc| is_same_location(loc, &matched.location))` is a LINEAR \
         scan run once per duplicate match, making a K-repeat group O(K^2). No cap \
         on additional_locations exists. FIX: track seen locations in a per-group \
         HashSet, or rely on the existing offset sort (dedup.rs:130) and compare \
         only against the last-pushed location, reducing the pass to O(K).",
        t_n.as_secs_f64() * 1e3,
        BASE_N * 2,
        t_2n.as_secs_f64() * 1e3,
    );
}
