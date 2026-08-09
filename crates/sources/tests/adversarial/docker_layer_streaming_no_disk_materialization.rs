//! Docker layer streaming scans members in memory without disk materialization.
//!
//! The competitive container loss was unpack-to-disk then FilesystemSource: gzip
//! layers were inflated twice and every member paid a write/read syscall tax.
//! Streaming must preserve finding parity, image-scoped budgets, and the
//! every-layer-independent whiteout contract.

#[cfg(feature = "docker")]
use keyhog_profile::Stage;
#[cfg(feature = "docker")]
use keyhog_sources::testing::TestApi;

#[cfg(feature = "docker")]
fn layer_tar_with_entries(
    dir: &std::path::Path,
    name: &str,
    entries: &[(&str, &[u8])],
) -> std::path::PathBuf {
    let path = dir.join(name);
    let file = std::fs::File::create(&path).expect("create layer tar");
    let mut builder = tar::Builder::new(file);
    for (entry_path, payload) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_path(entry_path).expect("set path");
        header.set_size(payload.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, *payload).expect("append");
    }
    builder.finish().expect("finish");
    path
}

#[cfg(feature = "docker")]
fn gzip_layer_tar(
    dir: &std::path::Path,
    name: &str,
    entries: &[(&str, &[u8])],
) -> std::path::PathBuf {
    use std::io::Write;
    let raw = layer_tar_with_entries(dir, &format!("{name}.raw"), entries);
    let raw_bytes = std::fs::read(&raw).expect("read raw");
    let path = dir.join(name);
    let file = std::fs::File::create(&path).expect("create gzip");
    let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    encoder.write_all(&raw_bytes).expect("gzip write");
    encoder.finish().expect("gzip finish");
    path
}

/// A secret inside a gzip-compressed layer must surface from the streaming path
/// without unpacking that layer onto disk first.
#[cfg(feature = "docker")]
#[test]
fn stream_gzip_layer_surfaces_secret_without_disk_unpack() {
    let dir = tempfile::tempdir().expect("tempdir");
    let payload = b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
    let layer = gzip_layer_tar(dir.path(), "layer.tar.gz", &[("etc/creds.env", payload)]);

    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream gzip layer");

    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk
            .data
            .contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")),
        "streamed gzip layer must surface the planted secret, got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.contains("etc/creds.env"))
        }),
        "streamed chunk path must carry the tar member name"
    );
}

/// Gzip/zstd inflate returns short reads; window fill must loop until the
/// requested size or real EOF. Otherwise secrets past the first ~1 MiB of a
/// large plain layer member are silently dropped.
#[cfg(feature = "docker")]
#[test]
fn stream_gzip_layer_surfaces_secret_past_first_megabyte() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = b"PERF2_PAST_1MIB_SECRET=ghp_PastOneMibStreamToken00000000001\n";
    let mut payload = vec![b'a'; 1024 * 1024 + 64 * 1024];
    payload.extend_from_slice(marker);
    let layer = gzip_layer_tar(
        dir.path(),
        "layer.tar.gz",
        &[("var/log/big.log", payload.as_slice())],
    );

    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream large gzip layer member");

    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk
            .data
            .contains("PERF2_PAST_1MIB_SECRET=ghp_PastOneMibStreamToken00000000001")),
        "secret past the first megabyte must survive gzip short-read windowing, got {} chunks",
        chunks.len()
    );
}

/// Whiteout markers do not suppress members from other layers: each layer is
/// streamed independently. A `.wh.secret` marker in layer B must not hide
/// `secret` content from layer A, and the marker itself remains an ordinary
/// (usually empty) member rather than a host-path deletion.
#[cfg(feature = "docker")]
#[test]
fn stream_layers_preserve_independent_whiteout_semantics() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = b"AKIAIOSFODNN7EXAMPLE\n";
    let layer_a = layer_tar_with_entries(dir.path(), "a.tar", &[("app/secret.env", secret)]);
    let layer_b = layer_tar_with_entries(
        dir.path(),
        "b.tar",
        &[(".wh.secret.env", b""), ("app/.wh..wh..opq", b"")],
    );

    // One ordered session so layer B cannot retroactively hide layer A content.
    let rows = TestApi
        .stream_docker_layers_with_shared_budget(&[&layer_a, &layer_b], 1024 * 1024, true)
        .expect("stream both layers");

    assert!(
        rows.iter().all(|row| row.is_ok()),
        "whiteout/opaque markers must not abort the shared layer stream: {rows:?}"
    );
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("AKIAIOSFODNN7EXAMPLE")),
        "layer A secret must remain visible even when a later layer carries a whiteout"
    );
    // Empty whiteout/opaque markers emit no text chunks of their own.
    let whiteout_chunk = chunks.iter().any(|chunk| {
        chunk
            .metadata
            .path
            .as_ref()
            .is_some_and(|p| p.contains(".wh."))
    });
    assert!(
        !whiteout_chunk,
        "whiteout/opaque marker paths must not produce text chunks: {chunks:?}"
    );
}

/// Image-scoped budget still fails closed on the streaming path: the second
/// layer that would exceed the shared ceiling returns a coverage-gap error
/// instead of silently stopping with a clean scan.
#[cfg(feature = "docker")]
#[test]
fn stream_layers_share_image_wide_budget_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    const PAYLOAD: usize = 4096;
    let payload = vec![b'Q'; PAYLOAD];
    let first = layer_tar_with_entries(dir.path(), "l1.tar", &[("a.bin", &payload)]);
    let second = layer_tar_with_entries(dir.path(), "l2.tar", &[("b.bin", &payload)]);
    let cap = (PAYLOAD as u64) + 512;
    let err = TestApi
        .stream_docker_layers_with_shared_budget(&[&first, &second], cap, true)
        .expect_err("second layer must exhaust the shared image budget");
    let message = err.to_string();
    assert!(
        message.contains("image-wide budget") || message.contains("image unpack exceeded"),
        "budget exhaustion must name the image-wide ceiling, got {message}"
    );
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_layer_streaming_requires_docker_feature() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(feature = "docker")]
#[test]
fn stream_layer_accepts_gnu_tar_dot_slash_member_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("layer.tar");
    let file = std::fs::File::create(&tar_path).expect("create");
    let mut builder = tar::Builder::new(file);
    let payload = b"AWS_ACCESS_KEY_ID=AKIA0PERF2CANARYKEY0\n";
    let mut header = tar::Header::new_gnu();
    header.set_path("./etc/creds.env").expect("path");
    header.set_size(payload.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &payload[..]).expect("append");
    builder.finish().expect("finish");

    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &tar_path,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream");
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("AKIA0PERF2CANARYKEY0")),
        "GNU ./ prefixed member must still be scanned, got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
}

/// Skip-extension Git-LFS pointer placeholders must record GitLfsPointer, not
/// a generic Binary skip (process_entry parity).
#[cfg(feature = "docker")]
#[test]
fn stream_layer_records_git_lfs_pointer_for_skip_extension() {
    let dir = tempfile::tempdir().expect("tempdir");
    let oid = "a".repeat(64);
    let pointer =
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 12345\n");
    let layer = layer_tar_with_entries(
        dir.path(),
        "layer.tar",
        &[("assets/model.bin", pointer.as_bytes())],
    );
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream lfs pointer member");
    // Pointer bodies are skip events, not scannable chunks.
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().all(|chunk| !chunk.data.contains("sha256:")),
        "LFS pointer must not be scanned as text, got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
}

/// Image skip-extensions that are really Git-LFS pointers must record
/// GitLfsPointer (process_entry order), not fall through to Binary/metadata.
/// Oversized binary skip-extension members must Binary-skip quietly before the
/// OverMaxSize coverage-gap row (process_entry order).
#[cfg(feature = "docker")]
#[test]
fn stream_layer_large_skip_extension_is_quiet_binary_not_over_cap_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let payload = vec![0u8; 2 * 1024 * 1024];
    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("lib/libhuge.so", &payload)]);
    let limits = keyhog_sources::SourceLimits {
        docker_tar_entry_bytes: 1024 * 1024,
        ..keyhog_sources::SourceLimits::default()
    };
    let rows = TestApi
        .stream_docker_layer_archive_chunks(&layer, limits, limits.docker_tar_total_bytes, true)
        .expect("stream large .so");
    let errors: Vec<_> = rows.into_iter().filter_map(Result::err).collect();
    assert!(
        errors.is_empty(),
        "large skip-extension must not emit OverMaxSize coverage-gap errors: {errors:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn stream_layer_records_git_lfs_pointer_for_image_skip_extension() {
    let dir = tempfile::tempdir().expect("tempdir");
    let oid = "b".repeat(64);
    let pointer =
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 999\n");
    let layer = layer_tar_with_entries(
        dir.path(),
        "layer.tar",
        &[("assets/logo.png", pointer.as_bytes())],
    );
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream image lfs pointer");
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().all(|chunk| !chunk.data.contains("sha256:")),
        "image LFS pointer must not be scanned as text/metadata, got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "docker")]
#[test]
fn stream_layer_skips_extensionless_elf_without_string_mining() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Minimal ELF magic + planted ASCII that string-mining would otherwise surface.
    let mut elf = b"\x7fELF".to_vec();
    elf.extend_from_slice(&[1, 1, 1, 0]);
    elf.extend_from_slice(&[0u8; 32]);
    elf.extend_from_slice(b"AWS_ACCESS_KEY_ID=AKIA0PERF2ELFBINSKIP0\n");
    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("usr/bin/app", &elf)]);

    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream");
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks
            .iter()
            .all(|chunk| !chunk.data.contains("AKIA0PERF2ELFBINSKIP0")),
        "extensionless ELF must be Binary-skipped, not string-mined; got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
}

/// Extensionless text whose *prefix* is ordinary source must still be scanned
/// even when a NUL run appears later in the member. `looks_binary_prefix` trips
/// on any 4-byte NUL run in the slice it is given; the Docker streaming path
/// and FilesystemSource both sniff only the opening 512 bytes (not the whole member).
#[cfg(feature = "docker")]
#[test]
fn stream_layer_scans_extensionless_text_with_late_nul_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = b"AWS_ACCESS_KEY_ID=AKIA0PERF2LATENULSCAN01\n";
    let mut payload = secret.to_vec();
    payload.extend(vec![b'x'; 2048]);
    payload.extend_from_slice(&[0, 0, 0, 0]);
    payload.extend_from_slice(b"trailing\n");
    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("opt/appconfig", &payload)]);
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream");
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("AKIA0PERF2LATENULSCAN01")),
        "extensionless text with late NUL run must still be scanned; got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
}

/// Large extensionless UTF-16 (BOM) must whole-member decode, not lossy plain
/// windows — otherwise every other byte is garbled and secrets are missed.
/// Signature-less high-C0 binaries must not take lossy plain windows. Density
/// hits buffer into archive-binary / printable-strings (extensioned parity).
/// A NUL run between offsets 512 and 1024 must not binary-skip under the shared
/// 512-byte extensionless sniff (process_entry parity).
#[cfg(feature = "docker")]
#[test]
fn stream_layer_scans_extensionless_text_with_nul_after_512() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = b"AWS_ACCESS_KEY_ID=AKIA0PERF2MIDNULSCAN001\n";
    let mut payload = secret.to_vec();
    payload.extend(vec![b'x'; 600usize.saturating_sub(payload.len())]);
    payload.extend_from_slice(&[0, 0, 0, 0]);
    payload.extend_from_slice(b"trailing\n");
    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("opt/appconfig", &payload)]);
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream");
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("AKIA0PERF2MIDNULSCAN001")),
        "extensionless text with NUL after byte 512 must still be scanned; got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "docker")]
#[test]
fn stream_layer_density_binary_extensionless_uses_archive_binary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = b"DENSITY_STREAM_SECRET=ghp_DensityBinToken00000000000001";
    // >5% C0 controls in the 1 KiB sniff window, no 4-byte NUL run, no magic.
    let mut prefix = Vec::with_capacity(1024);
    while prefix.len() < 1024 {
        prefix.push(0x01);
        prefix.extend_from_slice(b"abcd");
    }
    prefix.truncate(1024);
    let mut payload = prefix;
    payload.extend(vec![0x01; 1024 * 1024]);
    payload.extend_from_slice(secret);
    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("opt/blob", &payload)]);
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream density binary");
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| {
            chunk
                .data
                .contains("DENSITY_STREAM_SECRET=ghp_DensityBinToken00000000000001")
                && chunk.metadata.source_type.contains("archive-binary")
        }),
        "density binary must take archive-binary strings, got {:?}",
        chunks
            .iter()
            .map(|c| (c.metadata.source_type.as_ref(), c.metadata.path.as_deref()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "docker")]
#[test]
fn stream_layer_scans_large_extensionless_utf16_le() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = "AWS_ACCESS_KEY_ID=AKIA0PERF2UTF16LESCAN01";
    let mut payload = vec![0xFF, 0xFE]; // UTF-16 LE BOM
    for unit in secret.encode_utf16() {
        payload.extend_from_slice(&unit.to_le_bytes());
    }
    // Pad past the 1 MiB plain-window threshold with UTF-16 LE 'a' (0x61 0x00).
    while payload.len() < 1024 * 1024 + 64 {
        payload.extend_from_slice(&[0x61, 0x00]);
    }
    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("opt/appconfig", &payload)]);
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream utf16 layer member");
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains(secret)),
        "large extensionless UTF-16 LE must decode, got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
}

/// A layer member whose name starts with `#` must stay scannable; HAR `#url`
/// peeling must not treat it as an empty path body.
#[cfg(feature = "docker")]
#[test]
fn stream_layer_hash_prefixed_member_name_still_scans() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = b"HASH_NAME_SECRET=ghp_HashPrefixedMemberToken000000001";
    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("#config", secret)]);
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream hash-prefixed member");
    let rewritten: Vec<_> = rows
        .into_iter()
        .map(|row| match row {
            Ok(chunk) => TestApi.rewrite_streamed_docker_layer_chunk(chunk, "img", "layer.tar"),
            Err(error) => Err(error),
        })
        .collect();
    assert!(
        rewritten.iter().all(|row| row.is_ok()),
        "hash-prefixed member must not become unsafe-path: {rewritten:?}"
    );
    let chunks: Vec<_> = rewritten.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk
            .data
            .contains("HASH_NAME_SECRET=ghp_HashPrefixedMemberToken000000001")),
        "hash-prefixed member content must remain scannable, got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
}

/// HAR request URLs are opaque provenance (`member#url`). A `/../` segment in
/// the captured URL must not fail streamed path normalization.
#[cfg(feature = "docker")]
#[test]
fn stream_layer_har_url_with_parent_segments_still_scans() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = "HAR_STREAM_SECRET=ghp_HarParentSegToken0000000000001";
    let har = format!(
        r#"{{"log":{{"version":"1.2","entries":[{{"request":{{"method":"GET","url":"https://example.invalid/api/../token","headers":[],"queryString":[],"headersSize":-1,"bodySize":0}},"response":{{"status":200,"statusText":"OK","headers":[],"content":{{"size":{size},"mimeType":"text/plain","text":"{secret}"}},"headersSize":-1,"bodySize":{size}}}}}]}}}}"#,
        size = secret.len(),
        secret = secret,
    );
    let layer = layer_tar_with_entries(
        dir.path(),
        "layer.tar",
        &[("var/log/session.har", har.as_bytes())],
    );
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream har layer member");
    let rewritten: Vec<_> = rows
        .into_iter()
        .map(|row| match row {
            Ok(chunk) => TestApi.rewrite_streamed_docker_layer_chunk(chunk, "img", "layer.tar"),
            Err(error) => Err(error),
        })
        .collect();
    assert!(
        rewritten.iter().all(|row| row.is_ok()),
        "HAR #url with /../ must not become unsafe-path errors: {rewritten:?}"
    );
    let chunks: Vec<_> = rewritten.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains(secret)),
        "HAR response body must remain scannable after rewrite, got {:?}",
        chunks
            .iter()
            .map(|c| (c.metadata.source_type.as_ref(), c.metadata.path.as_deref()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "docker")]
#[test]
fn stream_layer_emits_png_text_metadata_for_image_extensions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = "PNG_STREAM_SECRET=ghp_PngStreamMetadataToken00000000001";
    let mut text_payload = b"Comment\0".to_vec();
    text_payload.extend_from_slice(secret.as_bytes());

    fn png_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(payload);
        chunk.extend_from_slice(&[0; 4]);
        chunk
    }
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
    png.extend_from_slice(&png_chunk(b"tEXt", &text_payload));
    png.extend_from_slice(&png_chunk(b"IEND", &[]));

    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("opt/badge.png", &png)]);
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream");
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains(secret)),
        "PNG tEXt metadata must emit from the streaming path, got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.contains("PNG:tEXt@"))
        }),
        "streamed PNG metadata chunks must keep the tagged path provenance"
    );
}

#[cfg(feature = "docker")]
#[test]
fn stream_layer_emits_tiff_metadata_without_skip_extension() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Minimal little-endian TIFF with one XMP packet tag (0x02BC). TIFF is not
    // on the binary skip-extension list, so metadata probing must not be gated
    // on skip_extension alone.
    let secret = b"TIFF_STREAM_SECRET=ghp_TiffStreamMetadataToken000000001";
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"II");
    tiff.extend_from_slice(&42u16.to_le_bytes());
    tiff.extend_from_slice(&8u32.to_le_bytes()); // IFD offset
    tiff.extend_from_slice(&1u16.to_le_bytes()); // one entry
    tiff.extend_from_slice(&0x02BCu16.to_le_bytes()); // XMP
    tiff.extend_from_slice(&1u16.to_le_bytes()); // BYTE
    tiff.extend_from_slice(&(secret.len() as u32).to_le_bytes());
    tiff.extend_from_slice(&26u32.to_le_bytes()); // value offset
    tiff.extend_from_slice(&0u32.to_le_bytes()); // next IFD
    tiff.extend_from_slice(secret);

    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("opt/scan.tif", &tiff)]);
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream");
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk
            .data
            .contains("TIFF_STREAM_SECRET=ghp_TiffStreamMetadataToken000000001")),
        "TIFF metadata must emit even though tif is not a skip-extension, got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "docker")]
#[test]
fn stream_layer_extracts_pdf_text_without_disk_unpack() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = "PDF_STREAM_SECRET=ghp_PdfStreamToken00000000000000001";
    // Minimal PDF with a literal string the extractor can recover.
    let pdf = format!(
        "%PDF-1.4\n1 0 obj<<>>endobj\n2 0 obj<< /Length {} >>stream\n({})\nendstream\nendobj\ntrailer<<>>\n%%EOF\n",
        secret.len() + 2,
        secret
    );
    let layer = layer_tar_with_entries(
        dir.path(),
        "layer.tar",
        &[("opt/notes.pdf", pdf.as_bytes())],
    );
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream");
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains(secret)),
        "PDF text must be extracted on the streaming path, got {:?}",
        chunks
            .iter()
            .map(|c| c.metadata.path.as_deref())
            .collect::<Vec<_>>()
    );
}

/// PDF extraction on the streaming path must open Decode and charge derived
/// bytes, matching FilesystemSource `process_entry` after unpack.
#[cfg(feature = "docker")]
#[test]
fn stream_layer_pdf_records_decode_and_derived_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = "PDF_PROFILE_SECRET=ghp_PdfProfileToken00000000000000001";
    let pdf = format!(
        "%PDF-1.4\n1 0 obj<<>>endobj\n2 0 obj<< /Length {} >>stream\n({})\nendstream\nendobj\ntrailer<<>>\n%%EOF\n",
        secret.len() + 2,
        secret
    );
    let layer = layer_tar_with_entries(
        dir.path(),
        "layer.tar",
        &[("opt/notes.pdf", pdf.as_bytes())],
    );
    let (profile, rows) = crate::support::profile::run_with_profile(|| {
        TestApi
            .stream_docker_layer_archive_chunks(
                &layer,
                keyhog_sources::SourceLimits::default(),
                keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
                true,
            )
            .expect("stream")
    });
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains(secret)),
        "PDF text must still extract under profiling"
    );
    let derived: u64 = chunks.iter().map(|chunk| chunk.data.len() as u64).sum();
    assert!(
        crate::support::profile::stage_calls(&profile, Stage::Decode) >= 1,
        "streamed PDF must open Decode: {profile:?}"
    );
    assert_eq!(
        profile.workload.derived_decoder_bytes,
        Some(derived),
        "streamed PDF derived bytes must match emitted chunk lengths"
    );
}

/// Image-metadata extraction on the streaming path must open Decode and charge
/// derived bytes so container profiles stay honest.
#[cfg(feature = "docker")]
#[test]
fn stream_layer_png_records_decode_and_derived_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = "PNG_PROFILE_SECRET=ghp_PngProfileMetadataToken000000001";
    let mut text_payload = b"Comment\0".to_vec();
    text_payload.extend_from_slice(secret.as_bytes());

    fn png_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(payload);
        chunk.extend_from_slice(&[0; 4]);
        chunk
    }
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
    png.extend_from_slice(&png_chunk(b"tEXt", &text_payload));
    png.extend_from_slice(&png_chunk(b"IEND", &[]));

    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("opt/badge.png", &png)]);
    let (profile, rows) = crate::support::profile::run_with_profile(|| {
        TestApi
            .stream_docker_layer_archive_chunks(
                &layer,
                keyhog_sources::SourceLimits::default(),
                keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
                true,
            )
            .expect("stream")
    });
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains(secret)),
        "PNG metadata must still extract under profiling"
    );
    let derived: u64 = chunks.iter().map(|chunk| chunk.data.len() as u64).sum();
    assert!(
        crate::support::profile::stage_calls(&profile, Stage::Decode) >= 1,
        "streamed PNG metadata must open Decode: {profile:?}"
    );
    assert_eq!(
        profile.workload.derived_decoder_bytes,
        Some(derived),
        "streamed PNG derived bytes must match emitted chunk lengths"
    );
}

/// Nested zip members on the streaming path must open Decode and charge the
/// extracted member bytes, matching FilesystemSource top-level zip accounting.
#[cfg(feature = "docker")]
#[test]
fn stream_layer_nested_zip_records_decode_and_derived_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let member_body = "ZIP_PROFILE_SECRET=ghp_ZipProfileToken00000000000000001\n";
    let zip_bytes = crate::support::archive::zip_with_entries(&[("inner.txt", member_body.as_bytes())]);
    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("opt/bundle.zip", &zip_bytes)]);
    let (profile, rows) = crate::support::profile::run_with_profile(|| {
        TestApi
            .stream_docker_layer_archive_chunks(
                &layer,
                keyhog_sources::SourceLimits::default(),
                keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
                true,
            )
            .expect("stream")
    });
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("ZIP_PROFILE_SECRET")),
        "nested zip member must scan under profiling: {chunks:?}"
    );
    assert!(
        crate::support::profile::stage_calls(&profile, Stage::Decode) >= 1,
        "streamed nested zip must open Decode: {profile:?}"
    );
    assert_eq!(
        profile.workload.derived_decoder_bytes,
        Some(member_body.len() as u64),
        "streamed nested zip derived bytes must match the extracted member"
    );
}

/// Plain leaf layer members must not open Decode / charge derived bytes.
#[cfg(feature = "docker")]
#[test]
fn stream_layer_plain_text_skips_derived_decode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let body = "PLAIN_PROFILE_SECRET=ghp_PlainProfileToken000000000000001\n";
    let layer = layer_tar_with_entries(dir.path(), "layer.tar", &[("opt/notes.txt", body.as_bytes())]);
    let (profile, rows) = crate::support::profile::run_with_profile(|| {
        TestApi
            .stream_docker_layer_archive_chunks(
                &layer,
                keyhog_sources::SourceLimits::default(),
                keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
                true,
            )
            .expect("stream")
    });
    let chunks: Vec<_> = rows.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("PLAIN_PROFILE_SECRET")),
        "plain text must still scan"
    );
    assert_eq!(
        crate::support::profile::stage_calls(&profile, Stage::Decode),
        0,
        "plain leaf members must stay outside Decode: {profile:?}"
    );
    assert_eq!(
        profile.workload.derived_decoder_bytes.unwrap_or(0),
        0,
        "plain leaf members must not charge derived decoder bytes: {profile:?}"
    );
}

/// Launcher-prefixed Spring Boot / SFX zip-family members must still unpack on
/// the streaming path (EOCD from end), not die on a PK-prefix-only gate.
#[cfg(feature = "docker")]
#[test]
fn stream_layer_scans_launcher_prefixed_jar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = "JAR_PREFIX_SECRET=ghp_JarPrefixedToken00000000000000001\n";
    let zip_bytes =
        crate::support::archive::zip_with_entries(&[("BOOT-INF/secret.txt", secret.as_bytes())]);
    let mut prefixed = b"#!/bin/bash\necho spring-boot-launcher\n".to_vec();
    prefixed.extend_from_slice(&zip_bytes);
    assert!(
        matches!(prefixed.starts_with(b"PK"), false),
        "fixture must not begin with the zip local-file signature"
    );
    let layer =
        layer_tar_with_entries(dir.path(), "layer.tar", &[("opt/app.jar", &prefixed)]);
    let rows = TestApi
        .stream_docker_layer_archive_chunks(
            &layer,
            keyhog_sources::SourceLimits::default(),
            keyhog_sources::SourceLimits::default().docker_tar_total_bytes,
            true,
        )
        .expect("stream");
    let mut saw_secret = false;
    let mut saw_no_extractor_gap = false;
    for row in rows {
        match row {
            Ok(chunk) => {
                if chunk.data.contains("JAR_PREFIX_SECRET") {
                    saw_secret = true;
                }
            }
            Err(error) => {
                if error.to_string().contains("no in-memory extractor") {
                    saw_no_extractor_gap = true;
                }
            }
        }
    }
    assert!(
        saw_secret,
        "launcher-prefixed jar members must scan on the streaming path"
    );
    assert!(
        matches!(saw_no_extractor_gap, false),
        "prefixed jar must not be reported as an unscannable openpack gap"
    );
}


