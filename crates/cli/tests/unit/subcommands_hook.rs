use keyhog::testing::{CliTestApi as _, API};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use tempfile::TempDir;

#[test]
fn hook_template_embeds_canonical_scan_args() {
    let canonical = API.canonical_scan_args();
    let expected = format!("exec keyhog {canonical}\n");
    assert!(
        API.hook_content().contains(&expected),
        "API.hook_content() must invoke `{expected}` verbatim; the installed pre-commit hook diverged from API.canonical_scan_args()"
    );
    assert!(API.canonical_scan_args().contains("--git-staged"));
    assert!(API.canonical_scan_args().contains("--fast"));
    assert!(API.canonical_scan_args().contains("--backend cpu"));
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn pre_commit_hooks_yaml_matches_canonical_scan_args() {
    let path = repo_root().join(".pre-commit-hooks.yaml");
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));

    let canonical = API.canonical_scan_args();
    let expected_entry = format!("entry: keyhog {canonical}");
    assert!(
        yaml.contains(&expected_entry),
        ".pre-commit-hooks.yaml must contain `{expected_entry}` so the framework hook mirrors `hook install`; found:\n{yaml}"
    );
    assert!(
        yaml.contains("pass_filenames: false"),
        ".pre-commit-hooks.yaml must keep `pass_filenames: false`; a true value appends filenames and aborts every commit with clap exit 2"
    );
    assert!(
        yaml.contains("always_run: true"),
        ".pre-commit-hooks.yaml must run for binary-only change sets so the staged source can report unscanned blobs as coverage gaps"
    );

    let hooks: serde_yaml::Value = serde_yaml::from_str(&yaml)
        .unwrap_or_else(|err| panic!("parsing {}: {err}", path.display()));
    let hook = hooks
        .as_sequence()
        .and_then(|entries| entries.first())
        .and_then(serde_yaml::Value::as_mapping)
        .expect(".pre-commit-hooks.yaml must contain one hook mapping");
    assert!(
        !hook.contains_key(serde_yaml::Value::String("types".into())),
        ".pre-commit-hooks.yaml must not filter by pre-commit file type; archive-only and binary-only staged changes still require a scan"
    );
}

#[test]
fn scripts_pre_commit_matches_canonical_scan_args() {
    let path = repo_root().join("scripts").join("pre-commit");
    let script = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));

    let canonical = API.canonical_scan_args();
    let expected_exec = format!("exec keyhog {canonical}");
    assert!(
        script.contains(&expected_exec),
        "scripts/pre-commit must invoke `{expected_exec}` verbatim; found:\n{script}"
    );
    for forbidden in [
        "KEYHOG_",
        "--detectors",
        "--path",
        "git show",
        "git cat-file",
        "2>/dev/null",
        "grep -c",
    ] {
        assert!(
            !script.contains(forbidden),
            "scripts/pre-commit must not carry legacy staged-tree-copy behavior `{forbidden}`; found:\n{script}"
        );
    }
    assert!(
        script.contains("keyhog: not found on PATH - blocking commit"),
        "scripts/pre-commit must block when the scanner is missing; found:\n{script}"
    );
    assert!(
        !script.contains("skipping the pre-commit secret scan"),
        "scripts/pre-commit must not silently bypass the installed security control; found:\n{script}"
    );
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).expect("write executable");
    let mut perms = std::fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("chmod executable");
}

#[cfg(unix)]
#[test]
fn scripts_pre_commit_propagates_scanner_failure() {
    let dir = TempDir::new().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir(&bin_dir).expect("bin dir");
    let args_file = dir.path().join("args.txt");
    make_executable(
        &bin_dir.join("keyhog"),
        r#"#!/bin/sh
printf '%s\n' "$@" > "$KEYHOG_ARGS_FILE"
exit 2
"#,
    );

    let output = Command::new(repo_root().join("scripts").join("pre-commit"))
        .env("PATH", &bin_dir)
        .env("KEYHOG_ARGS_FILE", &args_file)
        .output()
        .expect("run scripts/pre-commit");

    assert_eq!(
        output.status.code(),
        Some(2),
        "scripts/pre-commit must propagate scanner failures; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&args_file).expect("read args"),
        "scan\n--fast\n--git-staged\n--backend\ncpu\n"
    );
}

#[cfg(unix)]
#[test]
fn scripts_pre_commit_missing_keyhog_blocks_loudly() {
    let dir = TempDir::new().expect("tempdir");
    let output = Command::new(repo_root().join("scripts").join("pre-commit"))
        .env("PATH", dir.path())
        .output()
        .expect("run scripts/pre-commit");

    assert_eq!(
        output.status.code(),
        Some(127),
        "missing keyhog must block instead of bypassing the hook; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("keyhog: not found on PATH - blocking commit because the pre-commit secret scan did not run."),
        "missing-binary block must stay operator-visible; stderr={stderr}"
    );
    assert!(
        stderr.contains("fix PATH"),
        "missing-binary block must tell the operator how to repair PATH; stderr={stderr}"
    );
}
