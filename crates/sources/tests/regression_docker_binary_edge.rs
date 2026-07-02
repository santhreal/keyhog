//! Regression coverage for the sources docker + binary edge:
//!
//!   * an ELF / Mach-O carrying a secret in a high-value section
//!     (`.rodata` / `.data` / `__cstring`) is section-classified EXACTLY and
//!     the extracted chunk carries the exact secret bytes;
//!   * a non-object / truncated binary is still handled (whole-file printable
//!     strings fallback, recall preserved) instead of vanishing;
//!   * OCI descriptor index-vs-manifest classification is exact — declared
//!     `mediaType` is authoritative, structural shape is the tiebreaker;
//!   * a Docker `docker image save` layer archive is enumerated to its exact
//!     blob path and its secret payload reaches filesystem scan chunks;
//!   * root metadata (`manifest.json`) is labelled exactly and scanned;
//!   * a traversal (`../escape`) layer path is refused loudly.
//!
//! Gated on BOTH `docker` and `binary` so the file is a no-op empty test binary
//! when either feature is off (matches the crate's self-gated test convention).

#![cfg(all(feature = "docker", feature = "binary"))]

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::FilesystemSource;

// ---------------------------------------------------------------------------
// Minimal ELF64 builder (little-endian, x86-64) with caller-chosen sections.
// ---------------------------------------------------------------------------

fn push_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}
fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}
fn push_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const ELF_EHSIZE: usize = 64;
const ELF_SHENTSIZE: usize = 64;

#[allow(clippy::too_many_arguments)]
fn push_shdr(
    buf: &mut Vec<u8>,
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
) {
    push_u32(buf, sh_name);
    push_u32(buf, sh_type);
    push_u64(buf, sh_flags);
    push_u64(buf, sh_addr);
    push_u64(buf, sh_offset);
    push_u64(buf, sh_size);
    push_u32(buf, sh_link);
    push_u32(buf, sh_info);
    push_u64(buf, sh_addralign);
    push_u64(buf, sh_entsize);
}

/// Build a minimal parseable ELF64 whose section header table declares one
/// index-0 NULL section, each caller-provided `(name, sh_type, data)` section,
/// and a trailing `.shstrtab`. `e_shstrndx` points at the `.shstrtab`.
fn build_elf64(sections: &[(&str, u32, &[u8])]) -> Vec<u8> {
    // Section-name string table: mandatory empty first entry at index 0.
    let mut shstrtab = vec![0u8];
    let mut name_offsets = Vec::new();
    for (name, _, _) in sections {
        name_offsets.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab");
    shstrtab.push(0);

    // Data region begins right after the ELF header.
    let mut data_region = Vec::new();
    let mut data_offsets = Vec::new();
    for (_, _, sdata) in sections {
        data_offsets.push(ELF_EHSIZE + data_region.len());
        data_region.extend_from_slice(sdata);
    }
    let shstrtab_offset = ELF_EHSIZE + data_region.len();
    data_region.extend_from_slice(&shstrtab);

    let shoff = ELF_EHSIZE + data_region.len();
    let shnum = sections.len() + 2; // NULL + user sections + shstrtab
    let shstrndx = shnum - 1;

    let mut buf = Vec::new();
    // e_ident: magic, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, SysV ABI, padding.
    buf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    push_u16(&mut buf, 2); // e_type = ET_EXEC
    push_u16(&mut buf, 0x3e); // e_machine = EM_X86_64
    push_u32(&mut buf, 1); // e_version
    push_u64(&mut buf, 0); // e_entry
    push_u64(&mut buf, 0); // e_phoff
    push_u64(&mut buf, shoff as u64); // e_shoff
    push_u32(&mut buf, 0); // e_flags
    push_u16(&mut buf, ELF_EHSIZE as u16); // e_ehsize
    push_u16(&mut buf, 0); // e_phentsize
    push_u16(&mut buf, 0); // e_phnum
    push_u16(&mut buf, ELF_SHENTSIZE as u16); // e_shentsize
    push_u16(&mut buf, shnum as u16); // e_shnum
    push_u16(&mut buf, shstrndx as u16); // e_shstrndx
    assert_eq!(buf.len(), ELF_EHSIZE, "ELF header must be 64 bytes");

    buf.extend_from_slice(&data_region);
    assert_eq!(
        buf.len(),
        shoff,
        "section headers must follow the data region"
    );

    // Section header 0: SHT_NULL (all-zero).
    push_shdr(&mut buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    for (i, (_, sh_type, sdata)) in sections.iter().enumerate() {
        push_shdr(
            &mut buf,
            name_offsets[i],
            *sh_type,
            0,
            0,
            data_offsets[i] as u64,
            sdata.len() as u64,
            0,
            0,
            1,
            0,
        );
    }
    push_shdr(
        &mut buf,
        shstrtab_name_off,
        SHT_STRTAB,
        0,
        0,
        shstrtab_offset as u64,
        shstrtab.len() as u64,
        0,
        0,
        1,
        0,
    );
    buf
}

// ---------------------------------------------------------------------------
// Minimal single-arch Mach-O (64-bit) with one `__cstring` section.
// ---------------------------------------------------------------------------

fn push_name<const N: usize>(bytes: &mut Vec<u8>, name: &[u8]) {
    let mut field = [0u8; N];
    field[..name.len()].copy_from_slice(name);
    bytes.extend_from_slice(&field);
}

fn minimal_macho64_with_cstring(secret: &[u8]) -> Vec<u8> {
    const MACH_HEADER_64_BYTES: usize = 32;
    const SEGMENT_COMMAND_64_BYTES: usize = 72;
    const SECTION_64_BYTES: usize = 80;
    const LC_SEGMENT_64: u32 = 0x19;
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
    const MH_EXECUTE: u32 = 2;

    let section_offset =
        (MACH_HEADER_64_BYTES + SEGMENT_COMMAND_64_BYTES + SECTION_64_BYTES) as u32;
    let cmdsize = (SEGMENT_COMMAND_64_BYTES + SECTION_64_BYTES) as u32;
    let mut bytes = Vec::new();

    push_u32(&mut bytes, 0xfeed_facf);
    push_u32(&mut bytes, CPU_TYPE_X86_64);
    push_u32(&mut bytes, CPU_SUBTYPE_X86_64_ALL);
    push_u32(&mut bytes, MH_EXECUTE);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, cmdsize);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);

    push_u32(&mut bytes, LC_SEGMENT_64);
    push_u32(&mut bytes, cmdsize);
    push_name::<16>(&mut bytes, b"__TEXT");
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, secret.len() as u64);
    push_u64(&mut bytes, section_offset as u64);
    push_u64(&mut bytes, secret.len() as u64);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 0);

    push_name::<16>(&mut bytes, b"__cstring");
    push_name::<16>(&mut bytes, b"__TEXT");
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, secret.len() as u64);
    push_u32(&mut bytes, section_offset);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);

    assert_eq!(bytes.len(), section_offset as usize);
    bytes.extend_from_slice(secret);
    bytes
}

// ---------------------------------------------------------------------------
// Docker tar-layer fixture builders (mirrors the crate's existing fixtures).
// ---------------------------------------------------------------------------

fn tar_layer_bytes(path: &str, payload: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path(path).expect("set layer path");
    header.set_size(payload.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append(&header, payload)
        .expect("append layer payload");
    builder.finish().expect("finish tar");
    builder.into_inner().expect("tar bytes")
}

fn gzip_tar_layer_bytes(path: &str, payload: &[u8]) -> Vec<u8> {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&tar_layer_bytes(path, payload))
        .expect("write gzip tar bytes");
    encoder.finish().expect("finish gzip")
}

// ===========================================================================
// BINARY: section classification is exact and carries the exact secret.
// ===========================================================================

#[test]
fn elf_rodata_section_yields_exact_secret_chunk() {
    let secret = b"AKIAELFRODATASECRET01234567\0";
    let elf = build_elf64(&[(".rodata", SHT_PROGBITS, secret)]);

    let chunks = TestApi
        .extract_sections(&elf, "app.elf")
        .expect("an ELF with a .rodata section must yield section chunks");

    let rodata: Vec<_> = chunks
        .iter()
        .filter(|c| c.metadata.source_type == "binary:elf:.rodata")
        .collect();
    assert_eq!(
        rodata.len(),
        1,
        "exactly one .rodata section chunk expected, got {:?}",
        chunks
            .iter()
            .map(|c| &c.metadata.source_type)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        rodata[0].metadata.path.as_deref(),
        Some("app.elf"),
        "section chunk must carry the source path label"
    );
    assert!(
        rodata[0].data.contains("AKIAELFRODATASECRET01234567"),
        "the .rodata chunk must contain the exact embedded secret, got {:?}",
        rodata[0].data
    );
}

#[test]
fn elf_data_section_is_classified_as_data_not_rodata() {
    let secret = b"GHPDATASECTIONSECRET_abcdef012345\0";
    let elf = build_elf64(&[(".data", SHT_PROGBITS, secret)]);

    let chunks = TestApi
        .extract_sections(&elf, "app.elf")
        .expect(".data is a high-value section and must be extracted");

    // Exact classification: the chunk is labelled binary:elf:.data, NOT .rodata.
    assert_eq!(
        chunks
            .iter()
            .filter(|c| c.metadata.source_type == "binary:elf:.data")
            .count(),
        1
    );
    assert_eq!(
        chunks
            .iter()
            .filter(|c| c.metadata.source_type == "binary:elf:.rodata")
            .count(),
        0,
        "a .data section must never be mislabelled as .rodata"
    );
    assert!(chunks
        .iter()
        .any(|c| c.data.contains("GHPDATASECTIONSECRET_abcdef012345")));
}

#[test]
fn elf_non_target_text_section_is_not_section_extracted_but_strings_recovered() {
    // `.text` is not in the high-value target list, so section extraction must
    // return None; the whole-file strings fallback must still recover the run.
    let marker = b"TEXTSECTION_NONTARGET_MARKER_98765\0";
    let elf = build_elf64(&[(".text", SHT_PROGBITS, marker)]);

    assert!(
        TestApi.extract_sections(&elf, "app.elf").is_none(),
        "a binary whose only section is non-target must yield no section chunks"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("code.elf");
    std::fs::write(&path, &elf).expect("write elf");

    let rows: Vec<_> = TestApi.binary_strings_only(path).chunks().collect();
    let chunks: Vec<_> = rows.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(
        chunks
            .iter()
            .filter(|c| c.metadata.source_type.starts_with("binary:elf:"))
            .count(),
        0,
        "no ELF section chunk expected for a .text-only binary"
    );
    assert_eq!(
        chunks
            .iter()
            .filter(|c| c.metadata.source_type == "binary:strings"
                && c.data.contains("TEXTSECTION_NONTARGET_MARKER_98765"))
            .count(),
        1,
        "the non-target section's printable run must still reach the whole-file strings chunk (recall preserved)"
    );
}

#[test]
fn elf_binarysource_pipeline_yields_both_section_and_strings_chunk() {
    let secret = b"AKIAELFPIPELINE7SECRETX0000001\0";
    let elf = build_elf64(&[(".rodata", SHT_PROGBITS, secret)]);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("pipeline.elf");
    std::fs::write(&path, &elf).expect("write elf");

    let rows: Vec<_> = TestApi.binary_strings_only(path).chunks().collect();
    let chunks: Vec<_> = rows
        .iter()
        .map(|r| {
            r.as_ref()
                .expect("no source error expected for a valid ELF")
        })
        .collect();

    assert_eq!(
        chunks
            .iter()
            .filter(|c| c.metadata.source_type == "binary:elf:.rodata"
                && c.data.contains("AKIAELFPIPELINE7SECRETX0000001"))
            .count(),
        1,
        "the file->BinarySource path must classify the .rodata section exactly"
    );
    assert_eq!(
        chunks
            .iter()
            .filter(|c| c.metadata.source_type == "binary:strings")
            .count(),
        1,
        "the whole-file strings supplement must always be emitted alongside sections"
    );
}

#[test]
fn truncated_elf_falls_back_to_whole_file_strings() {
    // Build a valid ELF, then lop off the section header table so goblin's
    // Object::parse fails; the secret still lives in the surviving prefix and
    // must be recovered via whole-file strings (the loud recall-preserving path).
    let secret = b"AKIATRUNCATEDELF7SECRET000001\0";
    let full = build_elf64(&[(".rodata", SHT_PROGBITS, secret)]);
    // 3 section headers (NULL + .rodata + .shstrtab) * 64 bytes each.
    let truncated = &full[..full.len() - 3 * ELF_SHENTSIZE];
    assert!(
        truncated
            .windows(secret.len() - 1)
            .any(|w| w == &secret[..secret.len() - 1]),
        "fixture invariant: the secret must survive in the truncated prefix"
    );
    assert!(
        TestApi.extract_sections(truncated, "trunc.elf").is_none(),
        "a header-truncated ELF must fail structural parse and yield no section chunks"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("trunc.elf");
    std::fs::write(&path, truncated).expect("write truncated elf");

    let rows: Vec<_> = TestApi.binary_strings_only(path).chunks().collect();
    let chunks: Vec<_> = rows.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(
        chunks
            .iter()
            .filter(|c| c.metadata.source_type == "binary:strings"
                && c.data.contains("AKIATRUNCATEDELF7SECRET000001"))
            .count(),
        1,
        "a truncated binary must still be scanned via whole-file strings, not dropped"
    );
}

#[test]
fn macho_cstring_section_yields_exact_secret_chunk() {
    let secret = b"SANTH_MACHO_CSTRING_SECRET_0001";
    let macho = minimal_macho64_with_cstring(secret);

    let chunks = TestApi
        .extract_sections(&macho, "app.macho")
        .expect("a Mach-O __cstring section must yield section chunks");

    let cstring: Vec<_> = chunks
        .iter()
        .filter(|c| c.metadata.source_type == "binary:macho:__cstring")
        .collect();
    assert_eq!(
        cstring.len(),
        1,
        "exactly one __cstring section chunk expected, got {:?}",
        chunks
            .iter()
            .map(|c| &c.metadata.source_type)
            .collect::<Vec<_>>()
    );
    assert!(
        cstring[0].data.contains("SANTH_MACHO_CSTRING_SECRET_0001"),
        "the __cstring chunk must contain the exact embedded secret, got {:?}",
        cstring[0].data
    );
}

#[test]
fn non_binary_text_file_is_handled_via_strings_only() {
    // Plain UTF-8 text is not a recognized object format: no section chunks,
    // but the file is still scanned as printable strings (not silently dropped).
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("notes.txt");
    std::fs::write(
        &path,
        b"harmless prose\nAWS_SECRET=AKIANONBINARYTEXT7SECRET01\nmore prose\n",
    )
    .expect("write text file");

    let rows: Vec<_> = TestApi.binary_strings_only(path).chunks().collect();
    let chunks: Vec<_> = rows
        .iter()
        .map(|r| {
            r.as_ref()
                .expect("readable text file yields no source error")
        })
        .collect();
    assert_eq!(
        chunks
            .iter()
            .filter(|c| c.metadata.source_type.starts_with("binary:elf:")
                || c.metadata.source_type.starts_with("binary:pe:")
                || c.metadata.source_type.starts_with("binary:macho:"))
            .count(),
        0,
        "a non-object text file must produce no section chunks"
    );
    assert_eq!(
        chunks
            .iter()
            .filter(|c| c.metadata.source_type == "binary:strings"
                && c.data.contains("AKIANONBINARYTEXT7SECRET01"))
            .count(),
        1,
        "a non-binary file must still be scanned as printable strings"
    );
}

#[test]
fn decompiled_string_literal_extraction_honors_min_length() {
    // Ghidra-mode literal extraction: a >= 8 char quoted literal is recovered;
    // a shorter one is dropped (MIN_STRING_LEN boundary).
    let literals = TestApi
        .extract_string_literals(r#"  char *k = "AKIA_C_LITERAL_SECRET_777"; short = "abc";"#);
    assert_eq!(
        literals,
        vec!["AKIA_C_LITERAL_SECRET_777".to_string()],
        "only the >= 8-char literal must be extracted; the 3-char literal is below MIN_STRING_LEN"
    );
}

// ===========================================================================
// DOCKER: OCI classification, layer enumeration, metadata labelling.
// ===========================================================================

#[test]
fn oci_descriptor_classification_is_exact() {
    // Declared mediaType is authoritative.
    assert!(
        TestApi
            .oci_descriptor_points_to_index(Some("application/vnd.oci.image.index.v1+json"), b"{}"),
        "an image.index mediaType must classify as a nested index"
    );
    assert!(
        TestApi.oci_descriptor_points_to_index(
            Some("application/vnd.docker.distribution.manifest.list.v2+json"),
            b"{}"
        ),
        "a manifest.list mediaType must classify as a nested index"
    );
    assert!(
        !TestApi.oci_descriptor_points_to_index(
            Some("application/vnd.oci.image.manifest.v1+json"),
            b"{}"
        ),
        "an image.manifest mediaType must classify as an image manifest"
    );
    assert!(
        !TestApi.oci_descriptor_points_to_index(
            Some("application/vnd.docker.distribution.manifest.v2+json"),
            b"{}"
        ),
        "a distribution.manifest.v2 mediaType must classify as an image manifest"
    );
}

#[test]
fn oci_descriptor_media_type_wins_over_body_shape() {
    // Body structurally looks like an image manifest (`config`, no `manifests`),
    // but the authoritative index mediaType must still classify it as an index.
    assert!(
        TestApi.oci_descriptor_points_to_index(
            Some("application/vnd.oci.image.index.v1+json"),
            br#"{"config":{"digest":"sha256:1"}}"#,
        ),
        "declared index mediaType must override a manifest-shaped body"
    );
    // No / unrecognized mediaType => structural classification is the tiebreaker.
    assert!(
        TestApi.oci_descriptor_points_to_index(None, br#"{"manifests":[{"digest":"sha256:1"}]}"#),
        "a body carrying `manifests` and no `config` is an image index"
    );
    assert!(
        !TestApi.oci_descriptor_points_to_index(
            Some("application/octet-stream"),
            br#"{"config":{"digest":"sha256:2"},"layers":[]}"#,
        ),
        "an unrecognized mediaType with a `config`-carrying body is an image manifest"
    );
    // Adversarial: an unparseable blob is classified NOT-an-index so the caller
    // parses it as a manifest and surfaces a loud parse error (never silent skip).
    assert!(
        !TestApi.oci_descriptor_points_to_index(None, b"{not-json"),
        "an unparseable descriptor body must classify as not-an-index (fail-loud path)"
    );
}

#[test]
fn docker_gzip_layer_enumerated_exactly_and_secret_reaches_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    let blobs = root.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs).expect("mkdir blobs");
    let layer_hash = "b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184";
    let layer_path = blobs.join(layer_hash);
    std::fs::write(
        &layer_path,
        gzip_tar_layer_bytes("app/.env", b"DB_PASSWORD=AKIADOCKERLAYER7SECRET01\n"),
    )
    .expect("write gzip layer blob");

    std::fs::write(
        root.join("manifest.json"),
        format!(
            r#"[{{"Config":"blobs/sha256/config","RepoTags":["keyhog:edge"],"Layers":["blobs/sha256/{layer_hash}"]}}]"#
        ),
    )
    .expect("write manifest");

    // Exact enumeration: the one declared layer resolves to exactly its blob path.
    let layers = TestApi.docker_manifest_layer_archives(&root).unwrap();
    assert_eq!(layers, vec![layer_path.clone()]);

    // Unpack + rescan: the layer payload must reach filesystem scan chunks.
    let unpacked = dir.path().join("unpacked");
    std::fs::create_dir(&unpacked).expect("mkdir unpacked");
    let entry_errors = TestApi
        .unpack_docker_layer_archive(&layer_path, &unpacked)
        .expect("gzip layer must unpack");
    assert_eq!(
        entry_errors.len(),
        0,
        "a well-formed gzip layer must unpack with no per-entry errors"
    );

    let chunks: Vec<_> = FilesystemSource::new(unpacked)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("layer filesystem chunks must drain without source errors");
    assert_eq!(
        chunks
            .iter()
            .filter(|c| c.data.contains("AKIADOCKERLAYER7SECRET01"))
            .count(),
        1,
        "the exact layer secret must appear once in the rescanned filesystem chunks"
    );
}

#[test]
fn docker_root_manifest_metadata_labelled_and_scanned_exactly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir root");
    std::fs::write(
        root.join("manifest.json"),
        r#"[{"Config":"config.json","RepoTags":["ghp_manifestEdgeToken0000000000000001"],"Layers":[]}]"#,
    )
    .expect("write manifest metadata");

    let chunks = TestApi
        .docker_archive_metadata_chunks(&root, "keyhog:edge")
        .unwrap();
    assert_eq!(
        chunks.len(),
        1,
        "only manifest.json is present, so exactly one metadata chunk is expected"
    );
    assert_eq!(chunks[0].metadata.source_type, "docker");
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("keyhog:edge:metadata:manifest.json"),
        "root metadata chunk must carry the exact image:metadata:file label"
    );
    assert!(
        chunks[0]
            .data
            .contains("ghp_manifestEdgeToken0000000000000001"),
        "manifest.json content must be scan-visible: {}",
        chunks[0].data
    );
}

#[test]
fn docker_manifest_rejects_parent_traversal_layer_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir root");
    std::fs::write(
        root.join("manifest.json"),
        r#"[{"Config":"config","RepoTags":["keyhog:edge"],"Layers":["../escape/layer.tar"]}]"#,
    )
    .expect("write manifest");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unsafe layer path") && msg.contains("../escape/layer.tar"),
        "a traversal layer path must be refused loudly with the offending path, got {msg:?}"
    );
}
