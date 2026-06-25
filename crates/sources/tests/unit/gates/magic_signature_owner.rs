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
fn binary_magic_bytes_have_one_sources_owner() {
    let magic = source("src/magic.rs");
    assert!(
        magic.contains("GZIP_PREFIX") && magic.contains(r#"b"\x1f\x8b""#),
        "gzip magic bytes must be owned by src/magic.rs"
    );
    assert!(
        magic.contains("ZSTD_FRAME_MAGIC") && magic.contains(r#"b"\x28\xb5\x2f\xfd""#),
        "zstd frame magic bytes must be owned by src/magic.rs"
    );
    assert!(
        magic.contains("UNAMBIGUOUS_BINARY_PREFIXES")
            && magic.contains("PDF_PREFIX")
            && magic.contains(r#"b"%PDF-""#)
            && magic.contains("ZIP_LOCAL_FILE_PREFIX")
            && magic.contains(r#"b"PK\x03\x04""#)
            && magic.contains("ZIP_LOCAL_FILE_HEADER_SIGNATURE")
            && magic.contains("0x0403_4b50")
            && magic.contains("ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE")
            && magic.contains("0x0201_4b50")
            && magic.contains("ZIP_END_OF_CENTRAL_DIRECTORY_PREFIX")
            && magic.contains(r#"b"PK\x05\x06""#)
            && magic.contains("ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE")
            && magic.contains("0x0605_4b50")
            && magic.contains(r#"b"\x89PNG\r\n\x1a\n""#)
            && magic.contains(r#"b"\x7fELF""#)
            && magic.contains("WASM_MAGIC"),
        "common binary signature prefixes must be owned by src/magic.rs"
    );

    let decode = source("src/filesystem/read/decode.rs");
    assert!(
        decode.contains("crate::magic::has_unambiguous_binary_prefix"),
        "filesystem text decode must consume the shared binary magic predicate"
    );
    assert!(
        !decode.contains("UNAMBIGUOUS_BINARY_PREFIXES"),
        "filesystem text decode must not iterate the shared binary magic table directly"
    );
    assert!(
        decode.contains("crate::magic::starts_with_python_pickle_protocol2"),
        "filesystem full-file binary detection must consume the shared pickle magic predicate"
    );
    assert!(
        magic.contains("fn has_bmp_header(")
            && magic.contains("fn has_pe_header(")
            && magic.contains("fn has_bzip2_header("),
        "structural BMP/PE/BZip2 signatures must be owned by src/magic.rs"
    );
    assert!(
        decode.contains("crate::magic::has_bmp_header")
            && decode.contains("crate::magic::has_pe_header")
            && decode.contains("crate::magic::has_bzip2_header")
            && !decode.contains("fn has_bmp_header(")
            && !decode.contains("fn has_pe_header(")
            && !decode.contains("fn has_bzip2_header("),
        "filesystem text decode must consume shared structural magic predicates instead of owning local copies"
    );

    let docker = source("src/docker/archive.rs");
    assert!(
        docker.contains("crate::magic::starts_with_gzip")
            && docker.contains("crate::magic::starts_with_zstd_frame"),
        "Docker layer encoding detection must consume shared magic predicates"
    );

    let web = source("src/web.rs");
    assert!(
        web.contains("crate::magic::starts_with_wasm_module"),
        "web WASM validation must consume the shared WASM magic predicate"
    );

    let pdf = source("src/filesystem/extract/pdf.rs");
    assert!(
        pdf.contains("crate::magic::starts_with_pdf") && !pdf.contains(r#"starts_with(b"%PDF-")"#),
        "PDF extractor must consume the shared PDF magic predicate"
    );

    let archive = source("src/filesystem/extract/archive.rs");
    assert!(
        archive.contains("crate::magic::starts_with_zip_container_prefix")
            && !archive.contains(r#"starts_with(b"PK")"#),
        "OpenPack archive sniffing must consume the shared ZIP container prefix predicate"
    );

    for path in [
        "src/filesystem/read/decode.rs",
        "src/docker.rs",
        "src/docker/archive.rs",
        "src/web.rs",
        "src/filesystem/extract/compressed.rs",
        "src/filesystem/extract/archive.rs",
        "src/filesystem/extract/archive/zip_scan/duplicates.rs",
    ] {
        let body = source(path);
        for (needle, name) in [
            (r#"\x1f\x8b"#, "gzip"),
            (r#"\x28\xb5\x2f\xfd"#, "zstd frame"),
            (r#"%PDF-"#, "PDF"),
            (r#"PK\x03\x04"#, "ZIP"),
            (r#"\x89PNG\r\n\x1a\n"#, "PNG"),
            (r#"\x7fELF"#, "ELF"),
            (r#"\x00asm"#, "WASM"),
        ] {
            assert_eq!(
                occurrences(&body, needle),
                0,
                "{path} must not repeat raw {name} magic bytes"
            );
        }
        for (needle, name) in [
            ("[0x1f, 0x8b]", "gzip"),
            ("[0x28, 0xb5, 0x2f, 0xfd]", "zstd frame"),
            ("0x0403_4b50", "ZIP local file header"),
            ("0x0201_4b50", "ZIP central directory file header"),
            ("0x0605_4b50", "ZIP end of central directory"),
        ] {
            assert!(
                !body.contains(needle),
                "{path} must not repeat raw {name} magic bytes as an integer array"
            );
        }
    }
}
