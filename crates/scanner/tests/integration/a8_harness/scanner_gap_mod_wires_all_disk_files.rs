//! LR2-A8 harness integration: gap/mod.rs matches disk

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[test]
fn gap_mod_covers_every_gap_rs_except_mod() {
    let gap_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gap");
    let mod_src = std::fs::read_to_string(gap_dir.join("mod.rs")).expect("mod.rs");
    for entry in std::fs::read_dir(&gap_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_str().unwrap();
        if stem == "mod" {
            continue;
        }
        assert!(
            mod_src.contains(&format!("pub mod {stem};")),
            "gap/mod.rs missing {stem}"
        );
    }
}

fn manifest_test_paths(manifest: &str) -> BTreeSet<String> {
    manifest
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            let (_, value) = line.split_once("path")?;
            let (_, value) = value.split_once('=')?;
            let value = value.trim();
            let value = value.strip_prefix('"')?;
            let (path, _) = value.split_once('"')?;
            Some(path.replace('\\', "/"))
        })
        .collect()
}

fn path_attrs_from_top_level_tests(tests_dir: &Path) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for entry in std::fs::read_dir(tests_dir).expect("tests dir readable") {
        let path = entry.expect("test dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} readable: {error}", path.display()));
        for line in src.lines().map(str::trim) {
            let Some(rest) = line.strip_prefix("#[path = \"") else {
                continue;
            };
            let Some((path_attr, _)) = rest.split_once('"') else {
                continue;
            };
            paths.insert(format!("tests/{}", path_attr.replace('\\', "/")));
        }
    }
    paths
}

fn gap_rs_files(gap_dir: &Path) -> BTreeSet<String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = BTreeSet::new();
    for entry in std::fs::read_dir(gap_dir).expect("gap dir readable") {
        let path = entry.expect("gap dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        if path.file_name().and_then(|s| s.to_str()) == Some("mod.rs") {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or_else(|error| panic!("{} under manifest dir: {error}", path.display()))
            .to_string_lossy()
            .replace('\\', "/");
        files.insert(rel);
    }
    files
}

#[test]
fn no_new_unreachable_gap_rs_files() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let tests_dir = root.join("tests");
    let gap_dir = tests_dir.join("gap");
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("scanner Cargo.toml");
    let mut executable = manifest_test_paths(&manifest);
    executable.extend(path_attrs_from_top_level_tests(&tests_dir));

    let allowed_unreachable: BTreeSet<&'static str> = BTreeSet::new();

    let unreachable: BTreeSet<String> = gap_rs_files(&gap_dir)
        .into_iter()
        .filter(|path| !executable.contains(path))
        .collect();
    let unexpected: Vec<_> = unreachable
        .iter()
        .filter(|path| !allowed_unreachable.contains(path.as_str()))
        .cloned()
        .collect();
    assert!(
        unexpected.is_empty(),
        "new tests/gap/*.rs files must be executable via Cargo.toml [[test]] or a top-level #[path] target; unexpected unreachable files: {unexpected:#?}"
    );
}

#[test]
fn decode_pipeline_layers_gap_has_cargo_target() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("scanner Cargo.toml");
    assert!(
        manifest.contains("name = \"gap_decode_pipeline_layers\"")
            && manifest.contains("path = \"tests/gap/decode_pipeline_layers.rs\""),
        "decode_pipeline_layers gap suite must be executable as a Cargo test target"
    );
}
