//! PERF tripwire: `algo_complexity` vector.
//!
//! TARGET HOT PATH: `keyhog_core::dedup_matches` (crates/core/src/dedup.rs).
//!
//! DEFECT (file:line evidence):
//!   crates/core/src/dedup.rs:179-186, for every raw match that lands in an
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
//!   `.any()` sweep is the sole super-linear term, so doubling K must NOT
//!   roughly quadruple the wall time. The dedup pass should collapse K repeats
//!   into one finding with K-1 additional locations in O(K) (e.g. a HashSet of
//!   seen-locations per group, or skipping the membership check entirely when the
//!   sort already orders by location so a same-as-previous test suffices).
//!
//! CPU-TIME TRIPWIRE: measure dedup of N vs 2N repeats of the same credential
//! on distinct lines (one group). A linear/log-linear dedup doubles (~2x, plus
//! the sort log factor); the old O(K^2) sweep approached 4x. We require the
//! doubling ratio to stay under SUBQUADRATIC_RATIO (3.5). Paired best-of-K thread CPU
//! samples remove scheduler contention from parallel CI jobs while retaining
//! the algorithmic cost of sorting, hashing, allocation, and location
//! accumulation. Run with the release-fast profile characteristics (the
//! workspace CI/e2e profile): opt-level=3, thin LTO, debug-assertions=on.
//! A debug build exercises the same complexity boundary.
//!
//! A failure means the linear seen-location index or its surrounding sort regressed.

use std::sync::Arc;
use std::time::Duration;

use keyhog_core::{dedup_matches, DedupScope, MatchLocation, RawMatch, Severity};

/// Doubling input must not roughly quadruple time for the dedup pass. A
/// log-linear dedup ratios ~2.0-2.4 (the +log term); the O(K^2)
/// additional_locations sweep ratios ~3.6-4.0. 3.5 sits above observed
/// tip CI jitter (3.03x then 3.36x) and still below the quadratic band.
/// Ratios are measured as paired N/2N samples so an independently lucky
/// `min(t_n)` cannot inflate the doubling ratio against an unlucky `min(t_2n)`.
const SUBQUADRATIC_RATIO: f64 = 3.5;

/// Best-of-K paired thread CPU samples; keep the minimum ratio to drop noise.
const TIMING_SAMPLES: usize = 9;

/// Base group size. Large enough to distinguish the prior quadratic location
/// sweep from the current log-linear sort and constant-time location index.
const BASE_N: usize = 6_000;

/// Build `n` RawMatches with one detector, credential, and file path but a
/// distinct line and offset. Every match lands in one deduplication group.
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
            credential_hash: [0u8; 32].into(),
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

#[cfg(unix)]
fn thread_cpu_time() -> Duration {
    let mut timestamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime initializes the pointed-to timespec on success. The
    // pointer is valid for the duration of the call and is read only after rc=0.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, timestamp.as_mut_ptr()) };
    assert_eq!(
        rc, 0,
        "CLOCK_THREAD_CPUTIME_ID must be available for the deterministic complexity gate"
    );
    // SAFETY: the successful call above initialized every timespec field.
    let timestamp = unsafe { timestamp.assume_init() };
    Duration::new(
        u64::try_from(timestamp.tv_sec).expect("thread CPU seconds must be nonnegative"),
        u32::try_from(timestamp.tv_nsec).expect("thread CPU nanoseconds must fit u32"),
    )
}

#[cfg(not(unix))]
fn thread_cpu_time() -> Duration {
    static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    ORIGIN.get_or_init(std::time::Instant::now).elapsed()
}

/// One thread-CPU sample of dedup for a freshly built group.
/// Building the fixture is outside the measured region.
fn measure_dedup_time(n: usize) -> Duration {
    let matches = build_repeated_credential_group(n);
    let start = thread_cpu_time();
    let deduped = dedup_matches(matches, &DedupScope::Credential);
    let elapsed = thread_cpu_time().saturating_sub(start);
    assert_eq!(
        deduped.len(),
        1,
        "expected the {n} repeats of one credential to collapse into one finding"
    );
    assert_eq!(
        deduped[0].additional_locations.len(),
        n - 1,
        "every distinct line beyond the primary must remain visible"
    );
    elapsed
}

#[test]
fn dedup_additional_locations_is_subquadratic_in_group_size() {
    // Warm up allocator / caches so the first timed run is not penalized.
    let _ = measure_dedup_time(BASE_N / 4);

    let mut best_ratio = f64::INFINITY;
    let mut best_t_n = Duration::MAX;
    let mut best_t_2n = Duration::MAX;

    for _ in 0..TIMING_SAMPLES {
        let t_n = measure_dedup_time(BASE_N);
        let t_2n = measure_dedup_time(BASE_N * 2);
        let ratio = t_2n.as_secs_f64() / t_n.as_secs_f64().max(1e-9);
        if ratio < best_ratio {
            best_ratio = ratio;
            best_t_n = t_n;
            best_t_2n = t_2n;
        }
    }

    assert!(
        best_ratio < SUBQUADRATIC_RATIO,
        "dedup_matches is super-linear in the size of a single \
         (detector, credential, file) group.\n\
         MEASURED: dedup(N={BASE_N}) = {:.3} ms, dedup(2N={}) = {:.3} ms, \
         paired best-of-{TIMING_SAMPLES} doubling ratio = {best_ratio:.2}x.\n\
         TARGET: ratio < {SUBQUADRATIC_RATIO:.1}x (log-linear dedup doubles ~2.0-2.4x).\n\
         The thread CPU clock excludes scheduler stalls from parallel CI jobs. A \
         ratio over target therefore indicates that the O(1) per-group \
         seen_locations membership contract regressed toward an O(K^2) location \
         scan.",
        best_t_n.as_secs_f64() * 1e3,
        BASE_N * 2,
        best_t_2n.as_secs_f64() * 1e3,
    );
}
