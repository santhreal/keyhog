//! Docker layer streaming scans members in memory without disk materialization.
//!
//! The competitive container loss was unpack-to-disk then FilesystemSource: gzip
//! layers were inflated twice and every member paid a write/read syscall tax.
//! Streaming must preserve finding parity, image-scoped budgets, and the
//! every-layer-independent whiteout contract.

#[cfg(feature = "docker")]
use keyhog_sources::testing::TestApi;

#[cfg(feature = "docker")]
fn layer_tar_with_entries(dir: &std::path::Path, name: &str, entries: &[(&str, &[u8])]) -> std::path::PathBuf {
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
fn gzip_layer_tar(dir: &std::path::Path, name: &str, entries: &[(&str, &[u8])]) -> std::path::PathBuf {
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
        chunks.iter().any(|chunk| chunk.data.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")),
        "streamed gzip layer must surface the planted secret, got {:?}",
        chunks.iter().map(|c| c.metadata.path.as_deref()).collect::<Vec<_>>()
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

    let rows_a = TestApi
        .stream_docker_layer_archive_chunks(
            &layer_a,
            keyhog_sources::SourceLimits::default(),
            1024 * 1024,
            true,
        )
        .expect("stream layer a");
    let rows_b = TestApi
        .stream_docker_layer_archive_chunks(
            &layer_b,
            keyhog_sources::SourceLimits::default(),
            1024 * 1024,
            true,
        )
        .expect("stream layer b");

    let chunks_a: Vec<_> = rows_a.into_iter().filter_map(Result::ok).collect();
    assert!(
        chunks_a.iter().any(|chunk| chunk.data.contains("AKIAIOSFODNN7EXAMPLE")),
        "layer A secret must remain visible even when a later layer carries a whiteout"
    );
    // Empty whiteout/opaque markers emit no text chunks; the important contract is
    // that streaming them does not fail the layer or invent a deletion side effect.
    assert!(
        rows_b.into_iter().all(|row| row.is_ok()),
        "whiteout/opaque markers must not abort the layer stream"
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
