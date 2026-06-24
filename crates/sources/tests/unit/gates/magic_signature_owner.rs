//! Gate shared file-format magic-byte ownership.

use std::path::Path;

fn source(path: impl AsRef<Path>) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

#[test]
fn gzip_and_zstd_magic_bytes_have_one_sources_owner() {
    let magic = source("src/magic.rs");
    assert!(
        magic.contains("GZIP_PREFIX") && magic.contains(r#"b"\x1f\x8b""#),
        "gzip magic bytes must be owned by src/magic.rs"
    );
    assert!(
        magic.contains("ZSTD_FRAME_MAGIC") && magic.contains(r#"b"\x28\xb5\x2f\xfd""#),
        "zstd frame magic bytes must be owned by src/magic.rs"
    );

    let decode = source("src/filesystem/read/decode.rs");
    assert!(
        decode.contains("crate::magic::GZIP_PREFIX")
            && decode.contains("crate::magic::ZSTD_FRAME_MAGIC"),
        "filesystem text decode must consume the shared magic constants"
    );

    let docker = source("src/docker.rs");
    assert!(
        docker.contains("crate::magic::starts_with_gzip")
            && docker.contains("crate::magic::starts_with_zstd_frame"),
        "Docker layer encoding detection must consume shared magic predicates"
    );

    for path in [
        "src/filesystem/read/decode.rs",
        "src/docker.rs",
        "src/filesystem/extract/compressed.rs",
    ] {
        let body = source(path);
        assert_eq!(
            occurrences(&body, r#"\x1f\x8b"#),
            0,
            "{path} must not repeat raw gzip magic bytes"
        );
        assert_eq!(
            occurrences(&body, r#"\x28\xb5\x2f\xfd"#),
            0,
            "{path} must not repeat raw zstd frame magic bytes"
        );
        assert!(
            !body.contains("[0x1f, 0x8b]"),
            "{path} must not repeat raw gzip magic bytes as an integer array"
        );
        assert!(
            !body.contains("[0x28, 0xb5, 0x2f, 0xfd]"),
            "{path} must not repeat raw zstd frame magic bytes as an integer array"
        );
    }
}
