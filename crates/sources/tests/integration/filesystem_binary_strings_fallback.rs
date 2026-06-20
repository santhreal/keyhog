//! Non-text binary files must fall back to printable-string extraction.

use crate::support::collect_chunks;
use keyhog_sources::FilesystemSource;

#[test]
fn filesystem_binary_strings_fallback() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("blob.dat"),
        b"\x00\x01\x02HARDCODED_KEY=AKIAINTEGRATIONFALLBACK00\x00\xFF",
    )
    .expect("write");

    let chunks: Vec<_> = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .collect();
    assert!(
        chunks.iter().any(|c| {
            c.metadata.source_type == "filesystem:binary-strings"
                && c.data.contains("AKIAINTEGRATIONFALLBACK00")
        }),
        "binary fallback must emit printable strings; got {chunks:?}"
    );
}
