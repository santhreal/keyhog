use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{reset_skipped_over_max_size, skip_counts, FilesystemSource};

#[test]
fn reset_skipped_over_max_size_clears_counter() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.bump_skipped_over_max_size(3);
    reset_skipped_over_max_size();
    assert_eq!(skip_counts().over_max_size, 0);
}

#[test]
fn filesystem_source_name_is_stable() {
    let source = FilesystemSource::new(std::path::PathBuf::from("/tmp"));
    assert_eq!(source.name(), "filesystem");
}
