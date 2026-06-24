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

fn nearby_default_import_comment(manifest: &str) -> String {
    let lines = manifest.lines().collect::<Vec<_>>();
    let default_import_line = lines
        .iter()
        .position(|line| line.contains("\"keyhog-scanner/default\""))
        .expect("CLI default imports scanner default");
    let start = default_import_line.saturating_sub(6);
    lines[start..=default_import_line]
        .join("\n")
        .to_ascii_lowercase()
}

#[test]
fn cli_default_scanner_feature_comment_matches_manifest_contract() {
    let cli_toml = read(&manifest_dir().join("Cargo.toml"));
    let scanner_toml = read(&manifest_dir().join("../scanner/Cargo.toml"));
    let cli_manifest: toml::Value = toml::from_str(&cli_toml).expect("cli Cargo.toml parses");
    let scanner_manifest: toml::Value =
        toml::from_str(&scanner_toml).expect("scanner Cargo.toml parses");

    let cli_default = feature_list(features(&cli_manifest), "default");
    let scanner_default = feature_list(features(&scanner_manifest), "default");
    assert!(
        cli_default.contains(&"keyhog-scanner/default"),
        "this gate covers the CLI default importing the scanner default feature set"
    );
    assert!(
        scanner_default.contains(&"gpu") && scanner_default.contains(&"simd"),
        "scanner default currently includes accelerator features; update this gate if that contract changes"
    );

    let scanner_default_comment = nearby_default_import_comment(&cli_toml);
    assert!(
        scanner_default_comment.contains("gpu")
            && (scanner_default_comment.contains("hyperscan")
                || scanner_default_comment.contains("simd")),
        "`keyhog-scanner/default` nearby comments must say it imports accelerator features too: {scanner_default_comment}"
    );
    assert!(
        !scanner_default_comment.contains("ml, entropy, decode-through, multiline"),
        "`keyhog-scanner/default` comment must not list only data features while scanner/default also includes gpu/simd"
    );
}

#[test]
fn workspace_build_profile_comments_match_cli_feature_contract() {
    let workspace_toml = read(&workspace_manifest_path());
    let cli_toml = read(&manifest_dir().join("Cargo.toml"));
    let cli_manifest: toml::Value = toml::from_str(&cli_toml).expect("cli Cargo.toml parses");
    let cli_features = features(&cli_manifest);

    let default_features = feature_list(cli_features, "default");
    assert!(
        default_features.contains(&"keyhog-scanner/default"),
        "root build-profile comments cover the workspace CLI default feature contract"
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
                || *feature == "keyhog-scanner/cuda"
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
            && portable_features.contains(&"keyhog-scanner/ml")
            && portable_features.contains(&"keyhog-scanner/entropy")
            && portable_features.contains(&"keyhog-scanner/decode")
            && portable_features.contains(&"keyhog-scanner/multiline")
            && !portable_features.contains(&"binary")
            && !portable_features
                .iter()
                .any(|feature| *feature == "keyhog-scanner/gpu"
                    || *feature == "keyhog-scanner/simd"
                    || *feature == "keyhog-scanner/cuda"
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
    assert!(
        !build_profile_comments
            .lines()
            .any(|line| line.contains("cargo build --release -f gpu")),
        "workspace build-profile comments must not present `-F gpu` as its own build profile: {build_profile_comments}"
    );

    for required_claim in [
        "cli default: scanner full desktop stack",
        "gpu + hyperscan/simd + simdsieve",
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
