//! Regression: the post-process profiler module references the atomic ordering
//! `Relaxed` exactly one way. The always-compiled confirmed-pass counters used
//! the fully-qualified `std::sync::atomic::Ordering::Relaxed` while the
//! ml/decode-gated code used the imported `Relaxed` alias (its `use` was behind
//! `#[cfg(any(feature = "decode", feature = "ml"))]`). That split meant the same
//! ordering was spelled two ways in one file. The import is now unconditional
//! and every atomic op uses the `Relaxed` alias — byte-identical (the alias
//! resolves to the same enum variant), a pure coherence/dedup normalization.
//!
//! This is a source-shape gate (the module is private `mod
//! scan_postprocess_profile` included via `#[path]`, so its measurement fns are
//! not reachable behaviorally). It also pins the ml histogram array/bucket-fn
//! coherence so the catch-all bucket can never index past the array bound.

fn profile_src() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join("src/engine/scan_postprocess/profile.rs"))
        .expect("profiler source readable")
}

#[test]
fn profiler_uses_one_relaxed_ordering_reference() {
    let src = profile_src();
    // The fully-qualified spelling appears exactly once — the `use` import — and
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
fn ml_histogram_array_and_bucket_fn_stay_coherent() {
    let src = profile_src();
    // 10-slot histogram array; the bucket fn's catch-all must map to the last
    // valid index (9), so `ML_BATCH_BUCKETS[ml_batch_bucket(n)]` is always in
    // bounds for every n.
    assert!(
        src.contains("static ML_BATCH_BUCKETS: [AtomicU64; 10]"),
        "the ML batch histogram is a 10-slot array"
    );
    assert!(
        src.contains("_ => 9,"),
        "the bucket catch-all must map to index 9 (last slot of the 10-element array)"
    );
}
