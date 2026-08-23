//! Profiling instrumentation contract for the merkle incremental index.
//!
//! Locks the stage mapping for merkle load/lookup (IncrementalLookup) and
//! mutation/commit (ResultMerge) so a future refactor cannot silently drop
//! the measurements the profiling goal depends on.

use keyhog_profile::{Stage, StageMeasurement};

fn measure(f: impl FnOnce()) -> Vec<StageMeasurement> {
    keyhog_profile::reset();
    let runtime = keyhog_profile::Runtime::new();
    let measurements = runtime.scope(|| {
        f();
        keyhog_profile::take_stage_measurements()
    });
    keyhog_profile::reset();
    measurements
}

fn calls(measurements: &[StageMeasurement], stage: Stage) -> u64 {
    measurements
        .iter()
        .filter(|m| m.stage == stage)
        .map(|m| m.calls)
        .sum()
}

/// WHY: merkle lookup and mutation spans are the only per-file cost signal for
/// incremental scans; if a refactor drops them, cache-hit cost becomes
/// invisible in run profiles. Locks exact call counts per operation.
#[test]
fn merkle_lookup_mutation_forget_record_mapped_stages() {
    let index = keyhog_core::MerkleIndex::default();
    let measurements = measure(|| {
        let first =
            index.record_chunk_at_offset_and_check_unchanged("a.txt".into(), 0, 10, 11, 3, b"abc");
        assert!(!first, "first record of a path cannot be unchanged");
        let second =
            index.record_chunk_at_offset_and_check_unchanged("a.txt".into(), 0, 10, 11, 3, b"abc");
        assert!(second, "identical re-record must report unchanged");
        assert!(index.metadata_unchanged(std::path::Path::new("a.txt"), 10, 11, 3));
        index.forget(std::path::Path::new("a.txt"));
    });
    assert_eq!(
        calls(&measurements, Stage::ResultMerge),
        3,
        "two record mutations plus one forget must each open one ResultMerge span"
    );
    assert_eq!(
        calls(&measurements, Stage::IncrementalLookup),
        1,
        "one metadata_unchanged lookup must open one IncrementalLookup span"
    );
}

/// WHY: merkle commit (save) and load are the cold-start cost drivers for CI
/// re-runs; this pins save to ResultMerge and load to IncrementalLookup so the
/// commit/load split stays visible in profiles.
#[test]
fn merkle_save_and_load_record_mapped_stages() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache_path = dir.path().join("merkle.idx");
    let spec_hash = [7u8; 32];
    let index = keyhog_core::MerkleIndex::default();
    let loaded_status = std::cell::Cell::new(false);
    let measurements = measure(|| {
        index.record_chunk_at_offset_and_check_unchanged("b.txt".into(), 0, 20, 21, 4, b"data");
        index
            .save_with_spec(&cache_path, &spec_hash)
            .expect("save fresh cache");
        let report = keyhog_core::MerkleIndex::load_with_spec_report(&cache_path, &spec_hash);
        loaded_status.set(
            matches!(
                report.status(),
                keyhog_core::MerkleLoadStatus::Loaded { .. }
            ) || !matches!(
                report.status(),
                keyhog_core::MerkleLoadStatus::Missing { .. }
            ),
        );
    });
    assert!(loaded_status.get(), "freshly saved cache must load back");
    assert_eq!(
        calls(&measurements, Stage::ResultMerge),
        3,
        "one record mutation + one save commit + one entry insert while the load populates the index"
    );
    assert_eq!(
        calls(&measurements, Stage::IncrementalLookup),
        1,
        "saving to a fresh path performs no merge-base reload; the explicit load opens the only IncrementalLookup span"
    );
}

/// WHY: profiling must be free when no runtime is active; this guards against
/// instrumentation that records (or allocates) unconditionally.
#[test]
fn merkle_paths_are_silent_without_active_runtime() {
    keyhog_profile::reset();
    let index = keyhog_core::MerkleIndex::default();
    index.record_chunk_at_offset_and_check_unchanged("c.txt".into(), 0, 1, 2, 1, b"x");
    index.metadata_unchanged(std::path::Path::new("c.txt"), 1, 2, 1);
    index.forget(std::path::Path::new("c.txt"));
    let measurements = keyhog_profile::take_stage_measurements();
    keyhog_profile::reset();
    assert_eq!(
        calls(&measurements, Stage::ResultMerge),
        0,
        "no runtime entered: mutation spans must not record"
    );
    assert_eq!(
        calls(&measurements, Stage::IncrementalLookup),
        0,
        "no runtime entered: lookup spans must not record"
    );
}
