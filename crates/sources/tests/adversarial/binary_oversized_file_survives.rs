//! Oversized binary file must not OOM - strings extraction completes via capped read.

#[cfg(feature = "binary")]
mod capped {
    use super::super::support::split_chunk_results;
    use keyhog_core::Source;
    use keyhog_sources::testing::{SourceTestApi, TestApi};
    use std::io::Write;

    #[test]
    fn oversized_binary_yields_chunks_without_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("big.bin");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(&vec![0x41u8; 64 * 1024 * 1024 + 4096])
            .expect("write");

        let source = TestApi.binary_strings_only(&path);
        let rows: Vec<_> = source.chunks().collect();
        let (chunks, errors) = split_chunk_results(&rows);
        assert!(
            !chunks.is_empty(),
            "capped binary read must emit chunks for printable-run file"
        );
        assert_eq!(
            errors.len(),
            1,
            "capped binary read must also surface the partial-read error row"
        );
        let err = errors[0].to_string();
        assert!(
            err.contains("strings-read cap")
                && err.contains("remaining binary bytes were not scanned"),
            "error should describe the capped binary prefix scan, got {err}"
        );
        let path_str = path.to_str().unwrap();
        assert!(
            chunks
                .iter()
                .all(|c| c.metadata.path.as_deref() == Some(path_str)),
            "every chunk must carry source path metadata"
        );
    }
}

#[cfg(not(feature = "binary"))]
#[test]
fn binary_feature_required_for_oversized_test() {
    assert!(
        !cfg!(feature = "binary"),
        "compile with --features binary to run oversized binary adversarial test"
    );
}
