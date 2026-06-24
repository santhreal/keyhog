use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};

#[test]
fn mmap_toctou_sanity_cap_counted_as_over_max_size() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grown-after-walk.bin");
    let file = std::fs::File::create(&path).expect("create sparse file");
    file.set_len(TestApi.mmap_toctou_sanity_cap_bytes() + 1)
        .expect("grow sparse file past mmap sanity cap");
    drop(file);

    let decoded = TestApi.read_file_mmap(&path);
    assert!(
        decoded.is_none(),
        "TOCTOU-grown whole-file mmap input must be refused"
    );

    let counts = skip_counts();
    assert!(
        counts.over_max_size >= 1,
        "post-open mmap sanity-cap refusal must be visible as an over-size skip"
    );
    assert_eq!(
        counts.unreadable, 0,
        "post-open mmap sanity-cap refusal is a size policy refusal, not unreadable input"
    );
}

#[test]
fn windowed_mmap_toctou_sanity_cap_stops_before_stream_fallback() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grown-after-walk-windowed.bin");
    let file = std::fs::File::create(&path).expect("create sparse file");
    file.set_len(TestApi.mmap_toctou_sanity_cap_bytes() + 1)
        .expect("grow sparse file past mmap sanity cap");
    drop(file);

    let windows = TestApi.read_file_windowed_mmap_len(&path, 1024, 32);
    assert_eq!(
        windows,
        Some(0),
        "TOCTOU-grown windowed mmap input must be consumed as a visible skip, not fall through to streaming fallback"
    );

    let counts = skip_counts();
    assert!(
        counts.over_max_size >= 1,
        "windowed mmap sanity-cap refusal must be visible as an over-size skip"
    );
    assert_eq!(
        counts.unreadable, 0,
        "windowed mmap sanity-cap refusal is a size policy refusal, not unreadable input"
    );
}
