use super::*;

fn stats(hits: u64, causes: &[(AutorouteCacheMiss, u64)]) -> AutorouteCacheStats {
    AutorouteCacheStats {
        hits,
        misses: causes.iter().map(|(_, count)| *count).sum(),
        by_cause: causes.to_vec(),
        missing_buckets: Vec::new(),
        missing_buckets_elided: 0,
    }
}

#[test]
fn a_scan_that_never_consulted_the_cache_reports_no_rate() {
    // Reporting 0% here would send an operator to recalibrate a corpus the
    // cache was never asked about. There is no rate, and saying so is the
    // only honest answer.
    let empty = stats(0, &[]);
    assert_eq!(empty.hit_rate_percent(), None);
    assert_eq!(render_summary(&empty), None);
}

#[test]
fn hit_rate_counts_every_consultation_as_its_denominator() {
    let mixed = stats(3, &[(AutorouteCacheMiss::BucketAbsent, 1)]);
    assert_eq!(mixed.lookups(), 4);
    assert_eq!(mixed.hit_rate_percent(), Some(75.0));
    let summary = render_summary(&mixed).expect("a consulted cache reports a rate");
    assert!(summary.contains("75.0% hit"), "{summary}");
    assert!(summary.contains("bucket-absent=1"), "{summary}");
    assert!(
        summary.contains("affected batches unscanned")
            && summary.contains("coverage is incomplete"),
        "{summary}",
    );
    assert!(
        !summary.contains("every byte was still scanned"),
        "{summary}",
    );
}

#[test]
fn the_dominant_miss_cause_is_the_one_reported_first() {
    // An operator fixes one thing. It has to be the thing that cost the
    // most lookups, not whichever cause happens to sort first.
    let skewed = stats(
        0,
        &[
            (AutorouteCacheMiss::CacheRejected, 2),
            (AutorouteCacheMiss::BucketAbsent, 40),
        ],
    );
    assert_eq!(
        skewed.primary_cause(),
        Some(AutorouteCacheMiss::BucketAbsent)
    );
}

#[test]
fn missing_buckets_are_listed_most_expensive_first() {
    // One recalibration should be planned against the buckets that cost the
    // most batches, so the ledger cannot be rendered in arbitrary order.
    let ledger = AutorouteCacheStats {
        hits: 0,
        misses: 12,
        by_cause: vec![(AutorouteCacheMiss::BucketAbsent, 12)],
        missing_buckets: vec![("bucket-a".to_string(), 2), ("bucket-b".to_string(), 10)],
        missing_buckets_elided: 0,
    };
    assert_eq!(
        render_missing_buckets(&ledger),
        vec![
            "10 batch(es): bucket-b".to_string(),
            "2 batch(es): bucket-a".to_string(),
        ]
    );
}
