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
    assert!(API.canonical_scan_args().contains("--backend simd"));
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
        script.contains("keyhog: not found on PATH - skipping"),
        "scripts/pre-commit must preserve the operator-visible missing-binary skip; found:\n{script}"
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
        "scan\n--fast\n--git-staged\n--backend\nsimd\n"
    );
}

#[cfg(unix)]
#[test]
fn scripts_pre_commit_missing_keyhog_skips_loudly() {
    let dir = TempDir::new().expect("tempdir");
    let output = Command::new(repo_root().join("scripts").join("pre-commit"))
        .env("PATH", dir.path())
        .output()
        .expect("run scripts/pre-commit");

    assert!(
        output.status.success(),
        "missing keyhog remains a developer-convenience skip; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("keyhog: not found on PATH - skipping the pre-commit secret scan."),
        "missing-binary skip must stay operator-visible; stderr={stderr}"
    );
}
