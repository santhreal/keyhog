//! Per-source operational byte caps must be owned by SourceLimits.

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
    ];

    let mut stack = vec![root];
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
}
