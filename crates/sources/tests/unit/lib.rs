use keyhog_core::Source;
use keyhog_sources::{reset_skipped_over_max_size, FilesystemSource, SKIPPED_OVER_MAX_SIZE};

#[test]
fn reset_skipped_over_max_size_clears_counter() {
    SKIPPED_OVER_MAX_SIZE.store(3, std::sync::atomic::Ordering::Relaxed);
    reset_skipped_over_max_size();
    assert_eq!(
        SKIPPED_OVER_MAX_SIZE.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn filesystem_source_name_is_stable() {
    let source = FilesystemSource::new(std::path::PathBuf::from("/tmp"));
    assert_eq!(source.name(), "filesystem");
}
