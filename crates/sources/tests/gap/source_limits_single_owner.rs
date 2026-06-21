//! Per-source operational byte/count caps must be owned by SourceLimits.

#[test]
fn source_byte_caps_have_single_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let old_private_caps = [
        "MAX_STDIN_BYTES",
        "MAX_RESPONSE_BYTES",
        "MAX_S3_OBJECT_BYTES",
        "MAX_GCS_OBJECT_BYTES",
        "MAX_AZURE_BLOB_BYTES",
        "MAX_TAR_ENTRY_BYTES",
        "MAX_IMAGE_CONFIG_BYTES",
        "MAX_TAR_TOTAL_BYTES",
        "MAX_GIT_TOTAL_BYTES",
        "MAX_GIT_BLOB_BYTES",
        "MAX_GIT_CHUNKS",
        "MAX_BINARY_READ_BYTES",
        "MAX_DECOMPILED_SIZE",
        "DEFAULT_MAX_OBJECTS",
        "MAX_PAGES",
    ];

    let mut stack = vec![root.clone()];
    let mut offenders = Vec::new();
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).expect("read src dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source readable");
            for cap in old_private_caps {
                if text.contains(cap) {
                    offenders.push(format!("{} contains {cap}", path.display()));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "old private source cap constants must not return; use SourceLimits:\n{}",
        offenders.join("\n")
    );

    let limits = std::fs::read_to_string(root.join("limits.rs")).expect("limits.rs");
    assert!(
        limits.contains("cloud_max_objects: 100_000") && limits.contains("hosted_git_pages: 1000"),
        "cloud object count and hosted-git page defaults must be owned by SourceLimits"
    );

    for rel in ["s3/mod.rs", "gcs.rs", "cloud/azure_blob.rs"] {
        let source = std::fs::read_to_string(root.join(rel)).expect("cloud source readable");
        assert!(
            source.contains("cloud_max_objects") && source.contains("with_max_objects"),
            "{rel} must resolve default object count from SourceLimits while preserving explicit overrides"
        );
    }

    for rel in ["github_org.rs", "gitlab_group.rs", "bitbucket_workspace.rs"] {
        let source = std::fs::read_to_string(root.join(rel)).expect("hosted-git source readable");
        assert!(
            source.contains("hosted_git_pages") && source.contains("with_limits"),
            "{rel} must resolve API pagination limits from SourceLimits"
        );
    }
}
