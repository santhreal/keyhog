//! Gate: ML training/probe scripts must use the Rust serve-path feature extractor.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(root: &Path, rel: &str) -> String {
    let path = root.join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn ml_training_uses_rust_serve_path_features() {
    let root = repo_root();
    let train = read(&root, "ml/train_classifier.py");
    let probe = read(&root, "ml/probe_entropy_separation.py");
    let rust_features = read(&root, "ml/rust_features.py");

    assert!(
        train.contains("import rust_features")
            && train.contains("rust_features.compute_feature_matrix"),
        "train_classifier.py must obtain training feature matrices from Rust dump_features"
    );
    assert!(
        probe.contains("import rust_features")
            && probe.contains("rust_features.compute_feature_matrix"),
        "probe_entropy_separation.py must score model probes with Rust dump_features features"
    );
    assert!(
        rust_features.contains("KEYHOG_DUMP_FEATURES")
            && rust_features.contains("--example")
            && rust_features.contains("dump_features"),
        "rust_features.py must own the dump_features invocation and prebuilt-binary path"
    );

    let mut offenders = Vec::new();
    let ml_dir = root.join("ml");
    for entry in std::fs::read_dir(&ml_dir).expect("read ml dir") {
        let entry = entry.expect("read ml entry");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("py") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("utf-8 file name");
        if matches!(name, "feature_parity.py" | "parity_check.py") {
            continue;
        }
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        if src.contains("import feature_parity")
            || src.contains("feature_parity.compute_features")
            || src.contains("featmod")
        {
            offenders.push(name.to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "only parity_check.py may use the Python feature parity port; training/probe scripts must call Rust dump_features: {offenders:?}"
    );
}
