//! Binary strings extraction ignores runs shorter than eight chars.

#[cfg(feature = "binary")]
use crate::support::split_chunk_results;
#[cfg(feature = "binary")]
#[test]
fn binary_strings_only_min_len_eight() {
    use keyhog_core::Source;
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tiny.bin");
    std::fs::write(&path, b"\0short\0AKIAIOSFODNN7EXAMPLE\0").expect("write");

    let source = TestApi.binary_strings_only(path);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "binary strings extraction should not emit SourceError rows: {errors:?}"
    );
    let joined = chunks
        .iter()
        .map(|c| c.data.to_string())
        .collect::<Vec<_>>()
        .join(
            "
",
        );
    assert!(
        joined.contains("AKIAIOSFODNN7EXAMPLE"),
        "8+ char run must appear; got {joined:?}"
    );
    assert!(
        !joined.contains("short"),
        "runs under MIN_STRING_LEN must be omitted"
    );
    assert!(
        chunks.iter().all(|chunk| {
            chunk.metadata.source_type == "binary:strings"
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("tiny.bin"))
        }),
        "binary string chunks must carry source type and path metadata; chunks={chunks:?}"
    );
}

#[cfg(not(feature = "binary"))]
#[test]
fn binary_strings_min_len_requires_binary_feature() {
    assert!(!cfg!(feature = "binary"));
}
