use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[test]
fn ci_scanner_test_targets_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo = root
        .parent()
        .and_then(Path::parent)
        .expect("scanner crate lives under crates/scanner");
    let workflow_path = repo.join(".github/workflows/ci.yml");
    let workflow = std::fs::read_to_string(&workflow_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", workflow_path.display()));

    let targets = scanner_ci_test_targets(&workflow);
    assert!(
        !targets.is_empty(),
        "{} must contain scanner cargo test --test targets",
        workflow_path.display()
    );

    let known = known_scanner_test_targets(root);
    let missing: Vec<_> = targets.difference(&known).map(String::as_str).collect();
    assert!(
        missing.is_empty(),
        "{} references keyhog-scanner --test targets that Cargo cannot execute: {missing:?}",
        workflow_path.display()
    );
}

#[test]
fn ci_scanner_property_fuzz_runs_as_library_target() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo = root
        .parent()
        .and_then(Path::parent)
        .expect("scanner crate lives under crates/scanner");
    let workflow_path = repo.join(".github/workflows/ci.yml");
    let workflow = std::fs::read_to_string(&workflow_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", workflow_path.display()));

    let command = workflow
        .lines()
        .find(|line| line.contains("property::scanner_fuzz"))
        .unwrap_or_else(|| {
            panic!(
                "{} must run the scanner property::scanner_fuzz gate",
                workflow_path.display()
            )
        });

    assert!(
        command.contains("cargo test -p keyhog-scanner --lib property::scanner_fuzz"),
        "{} must run property::scanner_fuzz through --lib so CI does not compile every scanner integration target before filtering one library property module: {command}",
        workflow_path.display()
    );
}

fn scanner_ci_test_targets(workflow: &str) -> BTreeSet<String> {
    workflow
        .lines()
        .filter(|line| line.contains("cargo test") && line.contains("-p keyhog-scanner"))
        .flat_map(test_targets_from_line)
        .collect()
}

fn test_targets_from_line(line: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if word == "--test" {
            if let Some(target) = words.next() {
                targets.push(target.to_string());
            }
        }
    }
    targets
}

fn known_scanner_test_targets(root: &Path) -> BTreeSet<String> {
    let tests_dir = root.join("tests");
    let mut targets = top_level_test_files(&tests_dir);
    targets.extend(explicit_cargo_test_targets(&root.join("Cargo.toml")));
    targets
}

fn top_level_test_files(tests_dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(tests_dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", tests_dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|e| panic!("read entry in {}: {e}", tests_dir.display()))
                .path()
        })
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .filter_map(file_stem)
        .collect()
}

fn explicit_cargo_test_targets(cargo_toml: &Path) -> BTreeSet<String> {
    let src = std::fs::read_to_string(cargo_toml)
        .unwrap_or_else(|e| panic!("read {}: {e}", cargo_toml.display()));
    let mut targets = BTreeSet::new();
    let mut in_test_section = false;

    for line in src.lines() {
        let line = line.trim();
        if line == "[[test]]" {
            in_test_section = true;
            continue;
        }
        if line.starts_with("[[") || (line.starts_with('[') && line.ends_with(']')) {
            in_test_section = false;
            continue;
        }
        if in_test_section {
            if let Some(name) = line.strip_prefix("name = ") {
                targets.insert(name.trim_matches('"').to_string());
            }
        }
    }

    targets
}

fn file_stem(path: PathBuf) -> Option<String> {
    path.file_stem()?.to_str().map(ToOwned::to_owned)
}
