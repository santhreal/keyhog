use std::path::Path;

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_manifest_path() -> std::path::PathBuf {
    manifest_dir().join("../../Cargo.toml")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{} not readable: {e}", path.display()))
}

fn features(manifest: &toml::Value) -> &toml::value::Table {
    manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .expect("manifest has [features]")
}

fn feature_list<'a>(features: &'a toml::value::Table, name: &str) -> Vec<&'a str> {
    features
        .get(name)
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("feature {name} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("feature {name} entries are strings"))
        })
        .collect()
}

fn nearby_default_comment(manifest: &str) -> String {
    let lines = manifest.lines().collect::<Vec<_>>();
    let default_line = lines
        .iter()
        .position(|line| line.trim_start().starts_with("default ="))
        .expect("CLI manifest declares default features");
    let start = default_line.saturating_sub(6);
    lines[start..=default_line].join("\n").to_ascii_lowercase()
}

/// A bare crates.io install must not acquire native accelerator build prerequisites.
#[test]
fn cli_default_is_the_portable_source_and_verification_surface() {
    let cli_toml = read(&manifest_dir().join("Cargo.toml"));
    let cli_manifest: toml::Value = toml::from_str(&cli_toml).expect("CLI Cargo.toml parses");
    let cli_default = feature_list(features(&cli_manifest), "default");

    assert_eq!(
        cli_default,
        vec!["portable"],
        "`cargo install keyhog` must use the no-system-library portable profile"
    );
    let default_comment = nearby_default_comment(&cli_toml);
    for required in ["portable", "hyperscan", "gpu", "clean rust host"] {
        assert!(
            default_comment.contains(required),
            "CLI default comment must explain {required:?}: {default_comment}"
        );
    }
}

/// Keeps native GPU releases independent from the optional Hyperscan system library.
#[test]
fn scanner_gpu_feature_does_not_pull_hyperscan_transitively() {
    let cli_toml = read(&manifest_dir().join("Cargo.toml"));
    let scanner_toml = read(&manifest_dir().join("../scanner/Cargo.toml"));
    let cli_manifest: toml::Value = toml::from_str(&cli_toml).expect("CLI Cargo.toml parses");
    let scanner_manifest: toml::Value =
        toml::from_str(&scanner_toml).expect("scanner Cargo.toml parses");
    let cli_features = features(&cli_manifest);
    let scanner_features = features(&scanner_manifest);
    let gpu = feature_list(scanner_features, "gpu");
    let scanner_defaults = feature_list(scanner_features, "default");

    assert_eq!(
        feature_list(cli_features, "gpu"),
        vec!["keyhog-scanner/gpu"],
        "CLI GPU opt-in must not acquire the scanner default feature bundle"
    );
    assert!(!gpu.contains(&"ml"), "GPU must remain detection-only");
    assert!(
        !gpu.contains(&"simd") && !gpu.contains(&"dep:hyperscan"),
        "native Metal/WGPU builds must not acquire Hyperscan through `gpu`"
    );
    assert!(
        scanner_defaults.contains(&"gpu") && scanner_defaults.contains(&"simd"),
        "the scanner library's explicit default bundle still contains both accelerators"
    );
}

#[test]
fn workspace_build_profile_comments_match_cli_feature_contract() {
    let workspace_toml = read(&workspace_manifest_path());
    let cli_toml = read(&manifest_dir().join("Cargo.toml"));
    let cli_manifest: toml::Value = toml::from_str(&cli_toml).expect("cli Cargo.toml parses");
    let cli_features = features(&cli_manifest);

    let default_features = feature_list(cli_features, "default");
    assert_eq!(
        default_features,
        vec!["portable"],
        "the workspace CLI default must remain installable without system accelerator libraries"
    );

    let full_features = feature_list(cli_features, "full");
    assert!(
        full_features.contains(&"binary")
            && full_features.contains(&"verify")
            && full_features.contains(&"git")
            && full_features.contains(&"web")
            && full_features.contains(&"github")
            && full_features.contains(&"gitlab")
            && full_features.contains(&"bitbucket")
            && full_features.contains(&"azure")
            && full_features.contains(&"gcs")
            && full_features.contains(&"s3")
            && full_features.contains(&"docker")
            && full_features.contains(&"keyhog-scanner/ml")
            && full_features.contains(&"keyhog-scanner/entropy")
            && full_features.contains(&"keyhog-scanner/decode")
            && full_features.contains(&"keyhog-scanner/multiline")
            && !full_features.iter().any(|feature| *feature == "keyhog-scanner/gpu"
                || *feature == "keyhog-scanner/simd"
                || *feature == "keyhog-scanner/default"),
        "CLI full feature is the source/decompiler surface and must not be documented as all scanner accelerators"
    );

    let portable_features = feature_list(cli_features, "portable");
    assert!(
        portable_features.contains(&"verify")
            && portable_features.contains(&"git")
            && portable_features.contains(&"web")
            && portable_features.contains(&"github")
            && portable_features.contains(&"gitlab")
            && portable_features.contains(&"bitbucket")
            && portable_features.contains(&"azure")
            && portable_features.contains(&"gcs")
            && portable_features.contains(&"s3")
            && portable_features.contains(&"docker")
            && portable_features.contains(&"binary")
            && portable_features.contains(&"keyhog-scanner/ml")
            && portable_features.contains(&"keyhog-scanner/entropy")
            && portable_features.contains(&"keyhog-scanner/decode")
            && portable_features.contains(&"keyhog-scanner/multiline")
            && !portable_features
                .iter()
                .any(|feature| *feature == "keyhog-scanner/gpu"
                    || *feature == "keyhog-scanner/simd"
                    || *feature == "keyhog-scanner/default"),
        "portable is the no-system-library source-backend feature set"
    );

    let build_profile_comments = workspace_toml
        .lines()
        .skip_while(|line| !line.contains("# Build Profiles"))
        .take_while(|line| line.starts_with('#') || line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();

    for stale_claim in [
        "default (ml + entropy + decode + multiline)",
        "wgpu compute shader batch moe inference",
        "all scanner features + live verification",
        "bare minimum (aho-corasick + regex only)",
        "combine freely",
        "everything",
    ] {
        assert!(
            !build_profile_comments.contains(stale_claim),
            "workspace build-profile comments still contain stale feature claim {stale_claim:?}: {build_profile_comments}"
        );
    }

    for required_claim in [
        "cli default: portable source/verification surface",
        "without hyperscan/gpu/cuda/ghidra",
        "opt-in gpu routes",
        "source/decompiler surface without accelerator/system-library features",
        "bare filesystem/stdin scanner surface",
        "portable source-backend build without hyperscan/gpu/cuda/ghidra",
        "lean ci/embeddable scanner",
        "default source/verification surface without gpu dispatch",
        "features are additive on the selected base",
    ] {
        assert!(
            build_profile_comments.contains(required_claim),
            "workspace build-profile comments must document {required_claim:?}: {build_profile_comments}"
        );
    }
}
