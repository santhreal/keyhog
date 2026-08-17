//! WHY THIS TEST EXISTS:
//! Row 8 / Feature matrix contract:
//! Feature combinations (`portable`, `simd`, `gpu`, `ci-lean`, `ci`, `full`, `verify`,
//! `static-hyperscan`) must compose deterministically without undefined compilation states.
//!
//! WHAT IT DOES NOT CATCH:
//! Dynamic link failures against missing third-party native C-libraries on unequipped hosts.

use std::collections::BTreeMap;
use std::path::Path;
use toml::Value;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
}

fn load_features_from_manifest(manifest_path: &Path) -> BTreeMap<String, Vec<String>> {
    let content = std::fs::read_to_string(manifest_path)
        .unwrap_or_else(|e| panic!("Failed to read {manifest_path:?}: {e}"));
    let parsed: Value = toml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse TOML {manifest_path:?}: {e}"));

    let mut result = BTreeMap::new();
    if let Some(features_table) = parsed.get("features").and_then(|f| f.as_table()) {
        for (name, values) in features_table {
            let deps = values
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            result.insert(name.clone(), deps);
        }
    }
    result
}

#[test]
fn feature_manifests_declare_canonical_matrix_profiles() {
    let root = repo_root();
    let cli_manifest = root.join("crates/cli/Cargo.toml");
    let scanner_manifest = root.join("crates/scanner/Cargo.toml");

    let cli_features = load_features_from_manifest(&cli_manifest);
    let scanner_features = load_features_from_manifest(&scanner_manifest);

    // Assert canonical high-level profiles exist in CLI
    for profile in &["default", "portable", "full", "ci", "ci-lean"] {
        assert!(
            cli_features.contains_key(*profile),
            "CLI manifest must declare canonical profile '{profile}'"
        );
    }

    // Assert core capabilities exist in scanner
    for feature in &["ml", "entropy", "decode", "multiline", "simd", "gpu"] {
        assert!(
            scanner_features.contains_key(*feature),
            "Scanner manifest must declare engine feature '{feature}'"
        );
    }
}

#[test]
fn portable_profile_encompasses_all_offline_detection_capabilities() {
    let root = repo_root();
    let cli_manifest = root.join("crates/cli/Cargo.toml");
    let cli_features = load_features_from_manifest(&cli_manifest);

    let portable_deps = cli_features
        .get("portable")
        .expect("portable profile must be declared");

    for required_dep in &[
        "keyhog-scanner/ml",
        "keyhog-scanner/entropy",
        "keyhog-scanner/decode",
        "keyhog-scanner/multiline",
        "git",
        "web",
        "github",
        "gitlab",
        "bitbucket",
        "slack",
        "azure",
        "gcs",
        "s3",
        "docker",
        "binary",
        "verify",
    ] {
        assert!(
            portable_deps.contains(&required_dep.to_string()),
            "portable profile must enable '{required_dep}'"
        );
    }
}

#[test]
fn ci_profile_is_minimal_and_omits_heavy_source_backends() {
    let root = repo_root();
    let cli_manifest = root.join("crates/cli/Cargo.toml");
    let cli_features = load_features_from_manifest(&cli_manifest);

    let ci_deps = cli_features.get("ci").expect("ci profile must be declared");

    // CI profile should only include core detection features, shedding cloud/git/decompiler
    for heavy in &[
        "git",
        "github",
        "gitlab",
        "bitbucket",
        "slack",
        "azure",
        "gcs",
        "s3",
        "docker",
        "binary",
        "verify",
        "gpu",
        "simd",
    ] {
        assert!(
            !ci_deps.contains(&heavy.to_string()),
            "minimal ci profile must omit heavy backend '{heavy}'"
        );
    }
}
