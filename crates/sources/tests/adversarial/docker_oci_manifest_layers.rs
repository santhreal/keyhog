//! Docker save archives with OCI blob layers must produce scan chunks.

#[cfg(feature = "docker")]
use keyhog_sources::testing::{SourceTestApi, TestApi};

#[cfg(feature = "docker")]
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

#[cfg(feature = "docker")]
fn gzip_tar_layer_bytes(path: &str, payload: &[u8]) -> Vec<u8> {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&tar_layer_bytes(path, payload))
        .expect("write gzip tar bytes");
    encoder.finish().expect("finish gzip")
}

#[cfg(feature = "docker")]
fn zstd_tar_layer_bytes(path: &str, payload: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(tar_layer_bytes(path, payload).as_slice(), 3).expect("zstd encode")
}

#[cfg(feature = "docker")]
#[test]
fn docker_manifest_gzip_layer_yields_chunks() {
    use keyhog_core::Source;
    use keyhog_sources::FilesystemSource;

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    let blobs = root.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs).expect("mkdir blobs");
    let layer_path = blobs.join("a063ccef06db3ade9b9cd4bbd9467dcdcc807ff3150ff1af58317341f108c85c");

    let payload = b"SECRET=AKIAIOSFODNN7EXAMPLE\n";
    std::fs::write(
        &layer_path,
        gzip_tar_layer_bytes("keyhog-autoroute-probe.txt", payload),
    )
    .expect("write gzip layer");

    std::fs::write(
        root.join("manifest.json"),
        r#"[{"Config":"blobs/sha256/config","RepoTags":["keyhog:test"],"Layers":["blobs/sha256/a063ccef06db3ade9b9cd4bbd9467dcdcc807ff3150ff1af58317341f108c85c"]}]"#,
    )
    .expect("write manifest");

    let layers = TestApi.docker_manifest_layer_archives(&root).unwrap();
    assert_eq!(layers, vec![layer_path.clone()]);

    let unpacked = dir.path().join("unpacked");
    std::fs::create_dir(&unpacked).expect("mkdir unpacked");
    TestApi
        .unpack_docker_layer_archive(&layer_path, &unpacked)
        .unwrap();

    let chunks: Vec<_> = FilesystemSource::new(unpacked)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("Docker layer filesystem chunks must drain without source errors");
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("AKIAIOSFODNN7EXAMPLE")),
        "OCI gzip layer payload must reach filesystem chunks; chunks={}",
        chunks.len()
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_fallback_layer_discovery_finds_compressed_layers() {
    use keyhog_core::Source;
    use keyhog_sources::FilesystemSource;

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    let fixtures = [
        (
            "gzip/layer.tar.gz",
            gzip_tar_layer_bytes(
                "metadata-less-gzip.env",
                b"SECRET=AKIAFALLBACKGZIP7EXAMPLE\n",
            ),
            "AKIAFALLBACKGZIP7EXAMPLE",
        ),
        (
            "tgz/layer.tgz",
            gzip_tar_layer_bytes("metadata-less-tgz.env", b"SECRET=AKIAFALLBACKTGZ7EXAMPLE\n"),
            "AKIAFALLBACKTGZ7EXAMPLE",
        ),
        (
            "zstd/layer.tar.zst",
            zstd_tar_layer_bytes(
                "metadata-less-zstd.env",
                b"SECRET=AKIAFALLBACKZSTD7EXAMPLE\n",
            ),
            "AKIAFALLBACKZSTD7EXAMPLE",
        ),
        (
            "zstd-long/layer.tar.zstd",
            zstd_tar_layer_bytes(
                "metadata-less-zstd-long.env",
                b"SECRET=AKIAFALLBACKZSTDLEXAMPLE\n",
            ),
            "AKIAFALLBACKZSTDLEXAMPLE",
        ),
    ];
    let mut expected_layers = Vec::new();
    for (relative_path, bytes, _) in &fixtures {
        let layer_path = root.join(relative_path);
        std::fs::create_dir_all(layer_path.parent().expect("layer parent")).expect("mkdir layer");
        std::fs::write(&layer_path, bytes).expect("write metadata-less compressed layer");
        expected_layers.push(layer_path);
    }

    let layers = TestApi.docker_manifest_layer_archives(&root).unwrap();
    assert_eq!(
        layers, expected_layers,
        "metadata-less compressed Docker layers must not disappear during fallback discovery"
    );

    for (idx, (relative_path, _, needle)) in fixtures.iter().enumerate() {
        let layer_path = root.join(relative_path);
        let unpacked = dir.path().join(format!("unpacked-fallback-{idx}"));
        std::fs::create_dir(&unpacked).expect("mkdir unpacked");
        TestApi
            .unpack_docker_layer_archive(&layer_path, &unpacked)
            .unwrap();
        let chunks: Vec<_> = FilesystemSource::new(unpacked)
            .chunks()
            .collect::<Result<Vec<_>, _>>()
            .expect("fallback compressed layer filesystem chunks must drain without source errors");
        assert!(
            chunks.iter().any(|chunk| chunk.data.contains(needle)),
            "fallback-discovered compressed layer payload must reach scan chunks for {relative_path}; chunks={}",
            chunks.len()
        );
    }
}

#[cfg(feature = "docker")]
#[test]
fn docker_gzip_layer_reads_concatenated_members() {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    fn append_file(builder: &mut tar::Builder<Vec<u8>>, path: &str, payload: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).expect("set layer path");
        header.set_size(payload.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append(&header, payload)
            .expect("append layer payload");
    }

    let mut builder = tar::Builder::new(Vec::new());
    append_file(&mut builder, "first.env", b"FIRST=visible\n");
    append_file(&mut builder, "second.env", b"SECOND=AKIAIOSFODNN7EXAMPLE\n");
    builder.finish().expect("finish tar");
    let tar_bytes = builder.into_inner().expect("tar bytes");
    let second_header = tar_bytes
        .windows("second.env".len())
        .position(|window| window == b"second.env")
        .expect("second header marker");
    assert!(
        second_header > 0,
        "fixture must split after the first complete tar member"
    );

    let mut first_member = GzEncoder::new(Vec::new(), Compression::default());
    first_member
        .write_all(&tar_bytes[..second_header])
        .expect("write first gzip member");
    let first_member = first_member.finish().expect("finish first gzip member");

    let mut second_member = GzEncoder::new(Vec::new(), Compression::default());
    second_member
        .write_all(&tar_bytes[second_header..])
        .expect("write second gzip member");
    let second_member = second_member.finish().expect("finish second gzip member");

    let dir = tempfile::tempdir().expect("tempdir");
    let layer_path = dir.path().join("layer.tar.gz");
    let mut concatenated = first_member;
    concatenated.extend_from_slice(&second_member);
    std::fs::write(&layer_path, concatenated).expect("write concatenated gzip layer");

    let unpacked = dir.path().join("unpacked");
    std::fs::create_dir(&unpacked).expect("mkdir unpacked");
    TestApi
        .unpack_docker_layer_archive(&layer_path, &unpacked)
        .expect("concatenated gzip Docker layer must unpack");

    let second = std::fs::read_to_string(unpacked.join("second.env"))
        .expect("second gzip member file must be extracted");
    assert!(
        second.contains("AKIAIOSFODNN7EXAMPLE"),
        "Docker gzip layer extraction must not stop after the first gzip member"
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_zstd_layer_refuses_window_above_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layer_path = dir.path().join("layer.tar.zst");

    let mut builder = tar::Builder::new(Vec::new());
    let mut payload = b"SECOND=AKIAIOSFODNN7EXAMPLE\n".to_vec();
    payload.extend_from_slice(&vec![b'A'; 9 * 1024 * 1024]);
    let mut header = tar::Header::new_gnu();
    header.set_path("oversize-window.env").expect("set path");
    header.set_size(payload.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append(&header, payload.as_slice())
        .expect("append zstd payload");
    builder.finish().expect("finish tar");
    let tar_bytes = builder.into_inner().expect("tar bytes");
    let compressed = zstd::stream::encode_all(tar_bytes.as_slice(), 19).expect("zstd encode");
    assert!(
        compressed.len() < 512 * 1024,
        "repetitive zstd layer should be small on disk; got {} bytes",
        compressed.len()
    );
    std::fs::write(&layer_path, compressed).expect("write zstd layer");

    let allowed = dir.path().join("allowed");
    std::fs::create_dir(&allowed).expect("mkdir allowed");
    TestApi
        .unpack_docker_layer_archive(&layer_path, &allowed)
        .expect("default Docker zstd budget must accept the fixture");
    assert!(
        std::fs::read_to_string(allowed.join("oversize-window.env"))
            .expect("read extracted zstd layer file")
            .contains("AKIAIOSFODNN7EXAMPLE"),
        "control leg must prove the zstd layer is otherwise valid"
    );

    let refused = dir.path().join("refused");
    std::fs::create_dir(&refused).expect("mkdir refused");
    let err = TestApi
        .unpack_docker_layer_archive_with_total_cap(&layer_path, &refused, 2 * 1024 * 1024)
        .expect_err("zstd layer window above Docker budget must be refused");
    assert!(
        !refused.join("oversize-window.env").exists(),
        "oversize-window zstd layer must not be extracted after refusal"
    );
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("window") || msg.contains("memory") || msg.contains("frame"),
        "zstd refusal should identify the decompression-window failure, got {err}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_layer_filesystem_error_propagates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = TestApi
        .docker_rewrite_layer_chunks(
            vec![Err(keyhog_core::SourceError::Other(
                "layer reader failed".into(),
            ))],
            "keyhog:test",
            dir.path(),
            "layer.tar",
        )
        .expect_err("layer source error must propagate");
    assert!(
        err.to_string().contains("layer reader failed"),
        "unexpected docker layer error: {err}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_layer_rewrite_preserves_offsets_and_rejects_bad_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layer_root = dir.path().join("layer");
    std::fs::create_dir(&layer_root).expect("mkdir layer");
    let file = layer_root.join("etc").join("secret.env");
    std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir parent");
    std::fs::write(&file, b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n").expect("write");

    let chunk = keyhog_core::Chunk {
        data: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n".into(),
        metadata: keyhog_core::ChunkMetadata {
            source_type: "filesystem/windowed".into(),
            path: Some(file.display().to_string()),
            base_offset: 4096,
            base_line: 33,
            size_bytes: Some(128),
            mtime_ns: Some(99),
            decoded_span: Some((2, 8)),
            ..Default::default()
        },
    };
    let rewritten = TestApi
        .docker_rewrite_layer_chunks(
            vec![Ok(chunk)],
            "keyhog:test",
            &layer_root,
            "blobs/sha256/layer.tar",
        )
        .expect("rewrite");
    assert_eq!(rewritten.len(), 1);
    let chunk = &rewritten[0];
    assert_eq!(chunk.metadata.source_type, "docker");
    assert_eq!(
        chunk.metadata.path.as_deref(),
        Some("keyhog:test:blobs/sha256/layer.tar:etc/secret.env")
    );
    assert_eq!(chunk.metadata.base_offset, 4096);
    assert_eq!(chunk.metadata.base_line, 33);
    assert_eq!(chunk.metadata.size_bytes, Some(128));
    assert_eq!(chunk.metadata.mtime_ns, Some(99));
    assert_eq!(chunk.metadata.decoded_span, Some((2, 8)));

    let missing_path = keyhog_core::Chunk {
        data: "x".into(),
        metadata: keyhog_core::ChunkMetadata::default(),
    };
    let err = TestApi
        .docker_rewrite_layer_chunks(
            vec![Ok(missing_path)],
            "keyhog:test",
            &layer_root,
            "layer.tar",
        )
        .expect_err("missing path must fail");
    assert!(
        err.to_string().contains("without a file path"),
        "unexpected missing-path error: {err}"
    );

    let outside = tempfile::NamedTempFile::new().expect("outside");
    let outside_chunk = keyhog_core::Chunk {
        data: "x".into(),
        metadata: keyhog_core::ChunkMetadata {
            path: Some(outside.path().display().to_string()),
            ..Default::default()
        },
    };
    let err = TestApi
        .docker_rewrite_layer_chunks(
            vec![Ok(outside_chunk)],
            "keyhog:test",
            &layer_root,
            "layer.tar",
        )
        .expect_err("outside path must fail");
    assert!(
        err.to_string().contains("outside layer root"),
        "unexpected outside-root error: {err}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_manifest_rejects_parent_layer_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir root");
    std::fs::write(
        root.join("manifest.json"),
        r#"[{"Config":"config","RepoTags":["keyhog:test"],"Layers":["../escape/layer.tar"]}]"#,
    )
    .expect("write manifest");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unsafe layer path"),
        "expected unsafe manifest path rejection, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_manifest_deduplicates_repeated_layer_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    let blobs = root.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs).expect("mkdir blobs");
    let layer_a = blobs.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let layer_b = blobs.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    std::fs::write(&layer_a, b"identical layer archive bytes").expect("write layer a");
    std::fs::write(&layer_b, b"identical layer archive bytes").expect("write layer b");
    std::fs::write(
        root.join("manifest.json"),
        r#"[{"Config":"config","RepoTags":["keyhog:test"],"Layers":["blobs/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","blobs/sha256/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}]"#,
    )
    .expect("write manifest");

    let layers = TestApi.docker_manifest_layer_archives(&root).unwrap();
    assert_eq!(
        layers,
        vec![layer_a],
        "duplicate Docker layer archive content must be scanned once"
    );
}

#[cfg(all(feature = "docker", unix))]
#[test]
fn docker_fallback_layer_discovery_unreadable_entry_fails_loud() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let unreadable = root.join("blocked");
    std::fs::create_dir(&unreadable).expect("mkdir blocked");
    let original_permissions = std::fs::metadata(&unreadable)
        .expect("blocked metadata")
        .permissions();
    let mut blocked_permissions = original_permissions.clone();
    blocked_permissions.set_mode(0);
    std::fs::set_permissions(&unreadable, blocked_permissions).expect("chmod blocked");
    struct Restore {
        path: std::path::PathBuf,
        permissions: std::fs::Permissions,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.path, self.permissions.clone());
        }
    }
    let _restore = Restore {
        path: unreadable,
        permissions: original_permissions,
    };

    let err = TestApi.docker_manifest_layer_archives(root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("failed to inspect docker image archive")
            && msg.contains("docker image archive was not fully scanned"),
        "unreadable fallback layer-discovery entry must fail loud, got {msg}"
    );
}

#[cfg(any(not(feature = "docker"), not(unix)))]
#[test]
fn docker_fallback_layer_discovery_unreadable_entry_fails_loud() {
    assert!(cfg!(any(not(feature = "docker"), not(unix))));
}

#[cfg(feature = "docker")]
#[test]
fn docker_manifest_config_yields_metadata_chunks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("blobs").join("sha256")).expect("mkdir blobs");
    std::fs::write(
        root.join("blobs").join("sha256").join("config"),
        r#"{
          "config": {
            "Env": ["AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
            "Labels": {"com.example.token": "ghp_dockerMetadataToken000000000000000001"},
            "Cmd": ["node", "server.js"]
          },
          "history": [
            {"created_by": "/bin/sh -c export STRIPE_SECRET_KEY=sk_live_dockerHistory000000000000000000"}
          ]
        }"#,
    )
    .expect("write config");
    std::fs::write(
        root.join("manifest.json"),
        r#"[{"Config":"blobs/sha256/config","RepoTags":["keyhog:test"],"Layers":null}]"#,
    )
    .expect("write manifest");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "keyhog:test")
        .unwrap();
    assert_eq!(chunks.len(), 1);
    let chunk = &chunks[0];
    assert_eq!(chunk.metadata.source_type, "docker");
    assert!(
        chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.contains("keyhog:test:manifest[0]:blobs/sha256/config")),
        "metadata chunk path must identify the image and config source: {:?}",
        chunk.metadata.path
    );
    assert!(
        chunk.data.contains("AWS_SECRET_ACCESS_KEY")
            && chunk.data.contains("ghp_dockerMetadataToken")
            && chunk.data.contains("STRIPE_SECRET_KEY"),
        "Docker config ENV, labels, and history must be scanned as source text: {}",
        chunk.data
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_metadata_less_config_json_yields_metadata_chunks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("metadata")).expect("mkdir metadata");
    std::fs::write(
        root.join("metadata").join("config.json"),
        r#"{
          "config": {
            "Env": ["AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
            "Labels": {"com.example.token": "ghp_fallbackConfigToken00000000000001"}
          },
          "history": [
            {"created_by": "/bin/sh -c export STRIPE_SECRET_KEY=sk_live_fallbackHistory000000000000000"}
          ]
        }"#,
    )
    .expect("write metadata-less config");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "keyhog:test")
        .unwrap();
    assert_eq!(chunks.len(), 1);
    let chunk = &chunks[0];
    assert_eq!(chunk.metadata.source_type, "docker");
    assert!(
        chunk.metadata.path.as_deref().is_some_and(
            |path| path.contains("keyhog:test:fallback-config[0]:metadata/config.json")
        ),
        "fallback config chunk path must identify the image and config source: {:?}",
        chunk.metadata.path
    );
    assert!(
        chunk.data.contains("AWS_SECRET_ACCESS_KEY")
            && chunk.data.contains("ghp_fallbackConfigToken")
            && chunk.data.contains("STRIPE_SECRET_KEY"),
        "metadata-less Docker config ENV, labels, and history must be scanned as source text: {}",
        chunk.data
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_root_metadata_files_yield_scan_chunks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir root");
    std::fs::write(
        root.join("manifest.json"),
        r#"[{"Config":"config.json","RepoTags":["ghp_manifestMetadataToken000000000001"],"Layers":[]}]"#,
    )
    .expect("write manifest metadata");
    std::fs::write(
        root.join("index.json"),
        r#"{"schemaVersion":2,"annotations":{"com.example.token":"ghp_indexMetadataToken00000000000001"},"manifests":[]}"#,
    )
    .expect("write index metadata");
    std::fs::write(
        root.join("oci-layout"),
        r#"{"imageLayoutVersion":"1.0.0","com.example.token":"ghp_ociLayoutMetadataToken0000000001"}"#,
    )
    .expect("write oci layout metadata");

    let chunks = TestApi
        .docker_archive_metadata_chunks(&root, "keyhog:test")
        .unwrap();
    assert_eq!(chunks.len(), 3);
    let paths: Vec<_> = chunks
        .iter()
        .map(|chunk| chunk.metadata.path.as_deref().unwrap_or_default())
        .collect();
    assert_eq!(
        paths,
        vec![
            "keyhog:test:metadata:manifest.json",
            "keyhog:test:metadata:index.json",
            "keyhog:test:metadata:oci-layout",
        ],
        "Docker root metadata chunks must keep stable source labels"
    );
    assert!(
        chunks[0].data.contains("ghp_manifestMetadataToken")
            && chunks[1].data.contains("ghp_indexMetadataToken")
            && chunks[2].data.contains("ghp_ociLayoutMetadataToken"),
        "Docker root metadata file content must be scan-visible: {:?}",
        chunks.iter().map(|chunk| &chunk.data).collect::<Vec<_>>()
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_manifest_directory_fails_loud() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("manifest.json")).expect("mkdir manifest path");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("manifest.json")
            && msg.contains("not a regular file")
            && msg.contains("metadata was not scanned"),
        "manifest.json directory must fail loud, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_manifest_missing_config_fails_loud() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir root");
    std::fs::write(
        root.join("manifest.json"),
        r#"[{"RepoTags":["keyhog:test"],"Layers":[]}]"#,
    )
    .expect("write manifest");

    let err = TestApi
        .docker_manifest_config_chunks(&root, "keyhog:test")
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid docker manifest.json") && msg.contains("Config"),
        "missing Docker manifest Config must fail loud, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_manifest_missing_layers_fails_loud() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir root");
    std::fs::write(
        root.join("manifest.json"),
        r#"[{"Config":"config.json","RepoTags":["keyhog:test"]}]"#,
    )
    .expect("write manifest");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid docker manifest.json") && msg.contains("Layers"),
        "missing Docker manifest Layers must fail loud, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_manifest_empty_entries_fail_loud() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir root");
    std::fs::write(root.join("manifest.json"), "[]").expect("write manifest");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("manifest.json") && msg.contains("no image entries"),
        "empty Docker manifest entry list must fail loud, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn oci_image_layout_yields_config_and_layer_chunks() {
    use keyhog_core::Source;
    use keyhog_sources::FilesystemSource;
    use sha2::{Digest, Sha256};

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest: [u8; 32] = hasher.finalize().into();
        keyhog_core::hex_encode(&digest)
    }

    fn write_blob(root: &std::path::Path, bytes: &[u8]) -> (String, std::path::PathBuf) {
        let hex = sha256_hex(bytes);
        let path = root.join("blobs").join("sha256").join(&hex);
        std::fs::write(&path, bytes).expect("write OCI blob");
        (format!("sha256:{hex}"), path)
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("blobs").join("sha256")).expect("mkdir blobs");
    std::fs::write(root.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)
        .expect("write oci-layout");

    let config = br#"{
      "config": {
        "Env": ["AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
        "Labels": {"com.example.token": "ghp_ociConfigToken000000000000000001"}
      },
      "history": [
        {"created_by": "/bin/sh -c export STRIPE_SECRET_KEY=sk_live_ociHistory000000000000000000"}
      ]
    }"#;
    let (config_digest, _) = write_blob(&root, config);
    let layer_bytes = gzip_tar_layer_bytes("oci-secret.env", b"SECRET=AKIAOCIIMAGE7EXAMPLE\n");
    let (layer_digest, layer_path) = write_blob(&root, &layer_bytes);
    let manifest = format!(
        r#"{{
          "schemaVersion": 2,
          "config": {{
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "{config_digest}",
            "size": {}
          }},
          "layers": [{{
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": "{layer_digest}",
            "size": {}
          }}]
        }}"#,
        config.len(),
        layer_bytes.len()
    );
    let (manifest_digest, _) = write_blob(&root, manifest.as_bytes());
    std::fs::write(
        root.join("index.json"),
        format!(
            r#"{{
              "schemaVersion": 2,
              "manifests": [{{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "{manifest_digest}",
                "size": {},
                "annotations": {{"org.opencontainers.image.ref.name": "keyhog:oci"}}
              }}]
            }}"#,
            manifest.len()
        ),
    )
    .expect("write index");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "keyhog:test")
        .unwrap();
    assert_eq!(chunks.len(), 1);
    assert!(
        chunks[0]
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.contains("keyhog:test:oci[0]:keyhog:oci:config:")),
        "OCI config chunk path must identify index entry/ref/config digest: {:?}",
        chunks[0].metadata.path
    );
    assert!(
        chunks[0].data.contains("AWS_SECRET_ACCESS_KEY")
            && chunks[0].data.contains("ghp_ociConfigToken")
            && chunks[0].data.contains("STRIPE_SECRET_KEY"),
        "OCI config ENV, labels, and history must be scanned: {}",
        chunks[0].data
    );

    let layers = TestApi.docker_manifest_layer_archives(&root).unwrap();
    assert_eq!(layers, vec![layer_path]);

    let unpacked = dir.path().join("unpacked-oci");
    std::fs::create_dir(&unpacked).expect("mkdir unpacked");
    TestApi
        .unpack_docker_layer_archive(&layers[0], &unpacked)
        .unwrap();
    let layer_chunks: Vec<_> = FilesystemSource::new(unpacked)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("OCI layer filesystem chunks must drain without source errors");
    assert!(
        layer_chunks
            .iter()
            .any(|chunk| chunk.data.contains("AKIAOCIIMAGE7EXAMPLE")),
        "OCI layer payload must reach filesystem chunks; chunks={}",
        layer_chunks.len()
    );
}

#[cfg(feature = "docker")]
#[test]
fn oci_image_manifest_missing_config_fails_loud() {
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("blobs").join("sha256")).expect("mkdir blobs");
    std::fs::write(root.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)
        .expect("write oci-layout");

    let manifest = br#"{"schemaVersion":2,"layers":[]}"#;
    let mut hasher = Sha256::new();
    hasher.update(manifest);
    let manifest_digest: [u8; 32] = hasher.finalize().into();
    let manifest_hex = keyhog_core::hex_encode(&manifest_digest);
    std::fs::write(
        root.join("blobs").join("sha256").join(&manifest_hex),
        manifest,
    )
    .expect("write OCI manifest blob");

    std::fs::write(
        root.join("index.json"),
        format!(
            r#"{{
              "schemaVersion": 2,
              "manifests": [{{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:{manifest_hex}",
                "size": {}
              }}]
            }}"#,
            manifest.len()
        ),
    )
    .expect("write index");

    let err = TestApi
        .docker_manifest_config_chunks(&root, "keyhog:test")
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid OCI image manifest") && msg.contains("config"),
        "missing OCI image config must fail loud, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn oci_image_index_without_manifests_fails_loud() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("blobs").join("sha256")).expect("mkdir blobs");
    std::fs::write(root.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)
        .expect("write oci-layout");
    std::fs::write(root.join("index.json"), r#"{"schemaVersion":2}"#).expect("write index");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("OCI image index") && msg.contains("no manifests"),
        "OCI index without manifests must fail loud, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn oci_image_layout_rejects_unsafe_manifest_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("blobs").join("sha256")).expect("mkdir blobs");
    std::fs::write(root.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)
        .expect("write oci-layout");
    std::fs::write(
        root.join("index.json"),
        r#"{"schemaVersion":2,"manifests":[{"digest":"sha256:../escape"}]}"#,
    )
    .expect("write unsafe index");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unsafe digest"),
        "expected unsafe OCI digest rejection, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_manifest_rejects_parent_config_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir root");
    std::fs::write(
        root.join("manifest.json"),
        r#"[{"Config":"../escape/config.json","RepoTags":["keyhog:test"],"Layers":[]}]"#,
    )
    .expect("write manifest");

    let err = TestApi
        .docker_manifest_config_chunks(&root, "keyhog:test")
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unsafe config path"),
        "expected unsafe manifest config path rejection, got {msg:?}"
    );
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_manifest_gzip_layer_yields_chunks() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_fallback_layer_discovery_finds_compressed_layers() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_manifest_rejects_parent_layer_path() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_manifest_deduplicates_repeated_layer_content() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_manifest_config_yields_metadata_chunks() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_metadata_less_config_json_yields_metadata_chunks() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_root_metadata_files_yield_scan_chunks() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_manifest_directory_fails_loud() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_manifest_missing_config_fails_loud() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_manifest_missing_layers_fails_loud() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_manifest_empty_entries_fail_loud() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn oci_image_layout_yields_config_and_layer_chunks() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn oci_image_manifest_missing_config_fails_loud() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn oci_image_index_without_manifests_fails_loud() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn oci_image_layout_rejects_unsafe_manifest_digest() {
    assert!(!cfg!(feature = "docker"));
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_manifest_rejects_parent_config_path() {
    assert!(!cfg!(feature = "docker"));
}
