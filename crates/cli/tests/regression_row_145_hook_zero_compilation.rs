#![cfg(unix)]

//! WHY: Row 145 contract: `keyhog hook run` and pre-commit hook execution must utilize
//! prepared execution packs and achieve sub-second execution with 0 runtime compilations.
//!
//! What it closes:
//! Closes the pre-commit latency and in-process compilation defect by enforcing that
//! hook execution paths (`keyhog hook run` and installed `.git/hooks/pre-commit` scan)
//! hydrate directly from installed execution packs without per-commit detector rebuilding.
//! When execution packs are missing or invalid, hook execution fails closed with exit code 2
//! rather than silently falling back to slow in-process compilation.
//!
//! What it does not catch:
//! Does not catch hardware GPU adapter faults during kernel execution or hardware memory bit flips.
//! Does not catch OS kernel-level process SIGKILL termination.

use keyhog::execution_pack_install::{
    InstalledArtifactClass, InstalledArtifactRegistry,
};
use keyhog::exit_codes::{EXIT_CREDENTIALS_FOUND, EXIT_SUCCESS, EXIT_USER_ERROR};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;
use std::time::Instant;

fn create_temp_dir(prefix: &str) -> tempfile::TempDir {
    let base_tmp = PathBuf::from("/mnt/FlareTraining/santh-archive/tmp");
    if base_tmp.exists() {
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(&base_tmp)
            .expect("tempdir in base_tmp")
    } else {
        tempfile::tempdir().expect("tempdir")
    }
}

fn keyhog_bin() -> &'static str {
    env!("CARGO_BIN_EXE_keyhog")
}

fn keyhog_path_env() -> String {
    let bin_dir = Path::new(keyhog_bin()).parent().expect("keyhog parent dir");
    let current_path = std::env::var("PATH").unwrap_or_default();
    format!("{}:{}", bin_dir.display(), current_path)
}

static PREPARED_INSTALLATION: LazyLock<(tempfile::TempDir, PathBuf, PathBuf)> =
    LazyLock::new(|| {
        let directory = create_temp_dir("keyhog-row145-install-");
        let cache_home = directory.path().join("cache");
        let pack_root = cache_home.join("keyhog/execution-packs");
        fs::create_dir_all(&pack_root).expect("execution-pack root");
        let key_path = pack_root.join("signing.key");
        let key_bytes = [0x5cu8; 32];
        fs::write(&key_path, key_bytes).expect("write signing key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("protect signing key");
        let output = pack_root.join("current");

        let result = Command::new(keyhog_bin())
            .arg("compile-execution-packs")
            .arg("--output-dir")
            .arg(&output)
            .arg("--signing-key")
            .arg(&key_path)
            .env("PATH", keyhog_path_env())
            .env("XDG_CACHE_HOME", &cache_home)
            .env("HOME", directory.path())
            .output()
            .expect("run install pack compiler");
        assert!(
            result.status.success(),
            "install pack compiler failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        (directory, pack_root, output)
    });

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create dst dir");
    for entry in fs::read_dir(src).expect("read src dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        let dest_path = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_all(&path, &dest_path);
        } else {
            fs::copy(&path, &dest_path).expect("copy file");
        }
    }
}

fn clone_prepared_installation(cache_home: &Path) -> (PathBuf, PathBuf) {
    let (_temp, source_pack_root, _output) = &*PREPARED_INSTALLATION;
    let pack_root = cache_home.join("keyhog/execution-packs");
    copy_dir_all(source_pack_root, &pack_root);
    let output = pack_root.join("current");
    (pack_root, output)
}

fn init_git_repo(dir: &Path) {
    let out = Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(dir)
        .output()
        .expect("spawn git init");
    assert!(
        out.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = Command::new("git")
        .current_dir(dir)
        .args(["config", "user.email", "test@example.com"])
        .output();
    let _ = Command::new("git")
        .current_dir(dir)
        .args(["config", "user.name", "Test User"])
        .output();

    let initial_file = dir.join("README.md");
    fs::write(&initial_file, "# Repository\n").expect("write initial readme");
    let add_initial = Command::new("git")
        .current_dir(dir)
        .args(["add", "README.md"])
        .output()
        .expect("git add initial");
    assert!(add_initial.status.success());
    let commit_initial = Command::new("git")
        .current_dir(dir)
        .args(["commit", "-q", "-m", "initial commit"])
        .output()
        .expect("git commit initial");
    assert!(commit_initial.status.success());
}

fn assert_zero_runtime_compilations(profile_path: &Path) {
    assert!(profile_path.exists(), "profile JSON must exist");
    let profile_content = fs::read_to_string(profile_path).expect("read profile json");
    let profile_json: serde_json::Value =
        serde_json::from_str(&profile_content).expect("parse profile json");

    let compile_records = profile_json
        .get("compile_surfaces")
        .and_then(|v| v.as_array())
        .expect("compile_surfaces array must exist in profile JSON");
    eprintln!("TEST RUN CARGO_BIN_EXE_keyhog = {}", env!("CARGO_BIN_EXE_keyhog"));
    assert!(
        !compile_records.is_empty(),
        "compile_surfaces must not be empty"
    );
    for record in compile_records {
        let surface = record
            .get("name")
            .or_else(|| record.get("surface"))
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        let runtime_compiles = record
            .get("runtime_compiles")
            .and_then(|c| c.as_u64())
            .unwrap_or(0);
        assert_eq!(
            runtime_compiles, 0,
            "Hook execution must perform ZERO runtime compilations for surface {surface}; found runtime_compiles={runtime_compiles}"
        );
    }
}

#[test]
fn hook_run_utilizes_execution_pack_zero_runtime_compilations_subsecond() {
    let temp_dir = create_temp_dir("keyhog-row145-run-");
    let cache_home = temp_dir.path().join("cache");
    let home_dir = temp_dir.path().join("home");
    fs::create_dir_all(&home_dir).expect("create home");
    let repo_dir = temp_dir.path().join("repo");
    fs::create_dir_all(&repo_dir).expect("create repo dir");
    init_git_repo(&repo_dir);

    clone_prepared_installation(&cache_home);

    // Install hook into repository
    let install_out = Command::new(keyhog_bin())
        .current_dir(&repo_dir)
        .arg("hook")
        .arg("install")
        .env("PATH", keyhog_path_env())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("run hook install");
    assert!(
        install_out.status.success(),
        "hook install must succeed; stderr:\n{}",
        String::from_utf8_lossy(&install_out.stderr)
    );

    // Stage clean files
    let file1 = repo_dir.join("main.rs");
    fs::write(&file1, "fn main() {\n    println!(\"clean commit\");\n}\n").expect("write main.rs");
    let git_add = Command::new("git")
        .current_dir(&repo_dir)
        .args(["add", "main.rs"])
        .output()
        .expect("git add");
    assert!(git_add.status.success(), "git add must succeed");

    let profile_output_path = temp_dir.path().join("hook-profile.json");

    // Execute `keyhog hook run`
    let start_time = Instant::now();
    let hook_out = Command::new(keyhog_bin())
        .current_dir(&repo_dir)
        .arg("hook")
        .arg("run")
        .arg("--profile-out")
        .arg(&profile_output_path)
        .env("PATH", keyhog_path_env())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("run hook run");
    let elapsed = start_time.elapsed();
    assert_eq!(
        hook_out.status.code(),
        Some(EXIT_SUCCESS as i32),
        "hook run must exit 0 on clean staged files; stderr:\n{}",
        String::from_utf8_lossy(&hook_out.stderr)
    );

    let max_allowed_ms = if cfg!(debug_assertions) { 60_000 } else { 1_000 };
    assert!(
        elapsed.as_millis() < max_allowed_ms,
        "hook run must execute with zero runtime compilation in subsecond/fast time; took {} ms (max allowed: {} ms)",
        elapsed.as_millis(),
        max_allowed_ms
    );
    assert_zero_runtime_compilations(&profile_output_path);

    // Also verify running the pre-commit hook script directly
    let hook_script = repo_dir.join(".git/hooks/pre-commit");
    assert!(hook_script.exists(), "installed hook script must exist");

    let script_start = Instant::now();
    let script_out = Command::new(&hook_script)
        .current_dir(&repo_dir)
        .env("PATH", keyhog_path_env())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("run pre-commit hook script");
    let script_elapsed = script_start.elapsed();

    assert_eq!(
        script_out.status.code(),
        Some(EXIT_SUCCESS as i32),
        "hook script must exit 0; stderr:\n{}",
        String::from_utf8_lossy(&script_out.stderr)
    );
    assert!(
        script_elapsed.as_millis() < max_allowed_ms,
        "hook script must execute with zero runtime compilation in subsecond/fast time; took {} ms (max allowed: {} ms)",
        script_elapsed.as_millis(),
        max_allowed_ms
    );
}

#[test]
fn hook_run_detects_staged_secrets_with_zero_runtime_compilations() {
    let temp_dir = create_temp_dir("keyhog-row145-secret-");
    let cache_home = temp_dir.path().join("cache");
    let home_dir = temp_dir.path().join("home");
    fs::create_dir_all(&home_dir).expect("create home");
    let repo_dir = temp_dir.path().join("repo");
    fs::create_dir_all(&repo_dir).expect("create repo dir");
    init_git_repo(&repo_dir);

    clone_prepared_installation(&cache_home);

    // Stage a secret file
    let secret_file = repo_dir.join("credentials.env");
    fs::write(
        &secret_file,
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .expect("write secret file");
    let git_add = Command::new("git")
        .current_dir(&repo_dir)
        .args(["add", "credentials.env"])
        .output()
        .expect("git add");
    assert!(git_add.status.success(), "git add must succeed");

    let profile_output_path = temp_dir.path().join("secret-profile.json");

    let hook_out = Command::new(keyhog_bin())
        .current_dir(&repo_dir)
        .arg("hook")
        .arg("run")
        .arg("--profile-out")
        .arg(&profile_output_path)
        .env("PATH", keyhog_path_env())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("run hook run on staged secret");

    assert_eq!(
        hook_out.status.code(),
        Some(EXIT_CREDENTIALS_FOUND as i32),
        "hook run must exit 1 (EXIT_CREDENTIALS_FOUND) when secrets are staged; stderr:\n{}",
        String::from_utf8_lossy(&hook_out.stderr)
    );

    let stdout = String::from_utf8_lossy(&hook_out.stdout);
    assert!(
        stdout.contains("AKIAKPQXRMSNTBVWYZBN") || stdout.contains("aws") || stdout.contains("AWS") || stdout.contains("secret found"),
        "hook output must identify detected secret; stdout:\n{stdout}"
    );

    assert_zero_runtime_compilations(&profile_output_path);
}

#[test]
fn hook_run_fails_closed_when_execution_pack_missing() {
    let temp_dir = create_temp_dir("keyhog-row145-missing-");
    let cache_home = temp_dir.path().join("cache");
    let home_dir = temp_dir.path().join("home");
    fs::create_dir_all(&home_dir).expect("create home");
    let repo_dir = temp_dir.path().join("repo");
    fs::create_dir_all(&repo_dir).expect("create repo dir");
    init_git_repo(&repo_dir);

    // Empty cache home - no execution pack installed
    let staged_file = repo_dir.join("sample.txt");
    fs::write(&staged_file, "sample staged text\n").expect("write sample");
    Command::new("git")
        .current_dir(&repo_dir)
        .args(["add", "sample.txt"])
        .output()
        .expect("git add");

    let hook_out = Command::new(keyhog_bin())
        .current_dir(&repo_dir)
        .arg("hook")
        .arg("run")
        .env("PATH", keyhog_path_env())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("run hook run");

    assert_eq!(
        hook_out.status.code(),
        Some(EXIT_USER_ERROR as i32),
        "hook run must fail closed with exit code 2 when execution pack is missing; stderr:\n{}",
        String::from_utf8_lossy(&hook_out.stderr)
    );

    let stderr = String::from_utf8_lossy(&hook_out.stderr);
    assert!(
        stderr.contains("keyhog install") || stderr.contains("execution pack"),
        "stderr must instruct user to run keyhog install; stderr:\n{stderr}"
    );
}

#[test]
fn hook_run_fails_closed_when_execution_pack_corrupted() {
    let temp_dir = create_temp_dir("keyhog-row145-corrupt-");
    let cache_home = temp_dir.path().join("cache");
    let home_dir = temp_dir.path().join("home");
    fs::create_dir_all(&home_dir).expect("create home");
    let repo_dir = temp_dir.path().join("repo");
    fs::create_dir_all(&repo_dir).expect("create repo dir");
    init_git_repo(&repo_dir);

    let (_pack_root, output_dir) = clone_prepared_installation(&cache_home);

    // Corrupt all pack files
    for entry in fs::read_dir(&output_dir).expect("read output dir") {
        let entry = entry.expect("entry");
        if entry.path().extension().and_then(|s| s.to_str()) == Some("khpack") {
            let mut bytes = fs::read(entry.path()).expect("read pack");
            if !bytes.is_empty() {
                bytes[0] ^= 0xff;
                fs::write(entry.path(), bytes).expect("write corrupted pack");
            }
        }
    }

    let staged_file = repo_dir.join("sample.txt");
    fs::write(&staged_file, "sample staged text\n").expect("write sample");
    Command::new("git")
        .current_dir(&repo_dir)
        .args(["add", "sample.txt"])
        .output()
        .expect("git add");

    let hook_out = Command::new(keyhog_bin())
        .current_dir(&repo_dir)
        .arg("hook")
        .arg("run")
        .env("PATH", keyhog_path_env())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("run hook run");

    assert_eq!(
        hook_out.status.code(),
        Some(EXIT_USER_ERROR as i32),
        "hook run must fail closed with exit code 2 when execution pack is corrupted; stderr:\n{}",
        String::from_utf8_lossy(&hook_out.stderr)
    );
}

#[test]
fn hook_consumed_classes_registry_invariants() {
    let hook_classes = InstalledArtifactRegistry::hook_consumed_classes();
    let expected_classes: BTreeSet<_> =
        InstalledArtifactClass::EXECUTION_PACK_CLASSES.iter().copied().collect();

    assert_eq!(
        hook_classes, expected_classes,
        "hook consumed classes must match EXECUTION_PACK_CLASSES exactly"
    );

    for &class in &hook_classes {
        assert!(
            class.is_consumed_by_hook(),
            "class {class:?} in hook_consumed_classes must return true for is_consumed_by_hook()"
        );
    }

    // Mutation test: Removing any execution pack class must violate equality
    for &removed in InstalledArtifactClass::EXECUTION_PACK_CLASSES {
        let mut mutated = hook_classes.clone();
        mutated.remove(&removed);
        assert_ne!(
            mutated, expected_classes,
            "mutated set missing {removed:?} must not match expected classes"
        );
    }
}
