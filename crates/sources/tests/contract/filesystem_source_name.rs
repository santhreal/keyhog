//! FilesystemSource name must remain stable for CLI routing.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn filesystem_source_name() {
    let source = FilesystemSource::new(std::path::PathBuf::from("."));
    assert_eq!(source.name(), "filesystem");
}
