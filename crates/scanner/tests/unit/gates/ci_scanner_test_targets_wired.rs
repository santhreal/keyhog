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
    logical_workflow_commands(workflow)
        .into_iter()
        .filter(|command| is_scanner_cargo_test_command(command))
        .flat_map(|command| test_targets_from_command(&command))
        .collect()
}

fn logical_workflow_commands(workflow: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut current = String::new();

    for raw_line in workflow.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let continued = line.ends_with('\\');
        let command_part = if continued {
            line.trim_end_matches('\\').trim_end()
        } else {
            line
        };

        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(command_part);

        if !continued {
            commands.push(std::mem::take(&mut current));
        }
    }

    if !current.is_empty() {
        commands.push(current);
    }

    commands
}

fn is_scanner_cargo_test_command(command: &str) -> bool {
    command.contains("cargo test")
        && (command.contains("-p keyhog-scanner")
            || command.contains("--package keyhog-scanner")
            || command.contains("--package=keyhog-scanner"))
}

fn test_targets_from_command(command: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut words = command.split_whitespace();
    while let Some(word) = words.next() {
        if let Some(target) = word.strip_prefix("--test=") {
            targets.push(target.to_string());
        } else if word == "--test" {
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

#[test]
fn scanner_ci_test_targets_parses_multiline_and_equals_forms() {
    let workflow = r#"
      - name: scanner shard
        run: |
          cargo test -p keyhog-scanner \
            --test all_tests \
            --test=unit_gates_live
    "#;

    let targets = scanner_ci_test_targets(workflow);
    assert!(targets.contains("all_tests"));
    assert!(targets.contains("unit_gates_live"));
}

#[test]
fn scanner_ci_test_targets_ignores_comments_and_accepts_package_form() {
    let workflow = r#"
      # cargo test -p keyhog-scanner --test commented_out
      - name: scanner package shard
        run: cargo test --package=keyhog-scanner --test gpu_literal_artifact_writer
    "#;

    let targets = scanner_ci_test_targets(workflow);
    assert!(targets.contains("gpu_literal_artifact_writer"));
    assert!(!targets.contains("commented_out"));
}
