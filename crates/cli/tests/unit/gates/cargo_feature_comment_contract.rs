use std::path::Path;

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
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
