//! Regression: the post-process profiler module references the atomic ordering
//! `Relaxed` exactly one way. The always-compiled confirmed-pass counters used
//! the fully-qualified `std::sync::atomic::Ordering::Relaxed` while the
//! ml/decode-gated code used the imported `Relaxed` alias (its `use` was behind
//! `#[cfg(any(feature = "decode", feature = "ml"))]`). That split meant the same
//! ordering was spelled two ways in one file. The import is now unconditional
//! and every atomic op uses the `Relaxed` alias, byte-identical (the alias
//! resolves to the same enum variant), a pure coherence/dedup normalization.
//! It also pins the ML batch recorder's migration onto the keyhog-profile
//! typed counters + batch-size distribution (no scanner-owned histogram array).

fn profile_src() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join("src/engine/scan_postprocess/profile.rs"))
        .expect("profiler source readable")
}

#[test]
fn profiler_uses_one_relaxed_ordering_reference() {
    let src = profile_src();
    // The fully-qualified spelling appears exactly once, the `use` import, and
    // every atomic op uses the `Relaxed` alias instead.
    assert_eq!(
        src.matches("std::sync::atomic::Ordering::Relaxed").count(),
        1,
        "the only fully-qualified Ordering::Relaxed must be the `use` import; all ops use the alias"
    );

    // The import is present and unconditional (not behind a cfg gate).
    assert!(
        src.contains("use std::sync::atomic::Ordering::Relaxed;"),
        "the Relaxed alias must be imported"
    );
    assert!(
        !src.contains(
            "#[cfg(any(feature = \"decode\", feature = \"ml\"))]\nuse std::sync::atomic::Ordering::Relaxed;"
        ),
        "the Relaxed import must no longer be cfg-gated (the always-compiled counters use it)"
    );

    // The always-compiled confirmed-pass recorder now uses the alias, proving the
    // always-compiled path no longer needs the fully-qualified form.
    let record_start = src
        .find("fn confirmed_prof_record(")
        .expect("confirmed_prof_record present");
    let record_body = &src[record_start..record_start + 300];
    assert!(
        record_body.contains("fetch_add(1, Relaxed)"),
        "confirmed_prof_record must use the Relaxed alias"
    );
}

#[test]
fn ml_batch_metrics_flow_through_profile_runtime() {
    let src = profile_src();
    // The ML batch-size histogram and totals migrated off the scanner-owned
    // atomics onto the keyhog-profile runtime: typed counters for the totals,
    // the bounded log-scale distribution for the per-call batch sizes.
    for needle in [
        "CounterId::MlBatchCalls",
        "CounterId::MlBatchCandidates",
        "CounterId::MlBatchCallsGe64",
        "CounterId::MlBatchCandidatesGe64",
        "record_distribution(MetricId::MlBatchSize",
    ] {
        assert!(
            src.contains(needle),
            "ml_batch_record must record through {needle}"
        );
    }
    assert!(
        !src.contains("ML_BATCH_BUCKETS"),
        "the scanner-owned ML batch histogram array must be gone; the profile runtime owns it"
    );
}
