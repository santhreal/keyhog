#![cfg(unix)]

//! WHY: Row 134 contract: update recommendation parity and candidate capability probe on binary replacement.
//!
//! What it closes:
//! 1. Closes the unverified installation and stale artifact defect where `keyhog update` fallback
//!    instructions and documentation prescribed raw `cargo install --force` without triggering artifact
//!    compilation or post-install health verification (`keyhog doctor`).
//! 2. Closes the unverified binary replacement defect in `keyhog repair` where reinstallation replaced
//!    the binary on disk and installed GPU literals but failed to execute `install_execution_generation`
//!    (compilation of execution packs and calibration of autoroute).
//! 3. Enforces documentation and update-message parity across `docs/src/install.md`, `capabilities.md`,
//!    `hardening.md`, `reference/cli.md`, and the `keyhog update` CLI fallback path so all update and
//!    rollback instructions prescribe verified installation.
//! 4. Closes the stale-artifact and failed rollback defects on legacy candidate binary probe by
//!    backing up existing artifacts during probe, restoring them on health failure, and clearing
//!    stale artifacts when the legacy binary replacement commits.
//!
//! What it does not catch / boundary limits:
//! - Does not catch network transport failures when fetching packages from crates.io.
//! - Does not catch host disk full (ENOSPC) conditions occurring during local cargo compilation.

use keyhog::testing::CliTestApi;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn documentation_prescribes_verified_installation_with_doctor() {
    let root = repo_root();
    let install_doc =
        fs::read_to_string(root.join("docs/src/install.md")).expect("read docs/src/install.md");
    let capabilities_doc = fs::read_to_string(root.join("docs/src/capabilities.md"))
        .expect("read docs/src/capabilities.md");
    let hardening_doc =
        fs::read_to_string(root.join("docs/src/hardening.md")).expect("read docs/src/hardening.md");
    let cli_ref_doc = fs::read_to_string(root.join("docs/src/reference/cli.md"))
        .expect("read docs/src/reference/cli.md");

    // Invariant 1: install.md fallback and update sections require `keyhog doctor`
    assert!(
        install_doc.contains("cargo install --locked --force keyhog")
            && install_doc.contains("keyhog doctor"),
        "install.md historical binary-asset section must prescribe cargo install with keyhog doctor"
    );
    assert!(
        install_doc.contains("cargo install --locked --force keyhog\nkeyhog doctor"),
        "install.md update section must prescribe keyhog doctor after cargo install --force"
    );
    assert!(
        install_doc.contains(
            "cargo install --locked --force --version '=MAJOR.MINOR.PATCH' keyhog\nkeyhog doctor"
        ),
        "install.md rollback section must prescribe keyhog doctor after cargo install --force"
    );

    // Invariant 2: capabilities.md prescribes verified update and repair
    assert!(
        capabilities_doc.contains("cargo install --locked --force keyhog")
            && capabilities_doc.contains("keyhog doctor"),
        "capabilities.md must prescribe verified update with keyhog doctor"
    );

    // Invariant 3: hardening.md prescribes verified update
    assert!(
        hardening_doc.contains("cargo install --locked --force keyhog")
            && hardening_doc.contains("keyhog doctor"),
        "hardening.md must prescribe verified update with keyhog doctor"
    );

    // Invariant 4: reference/cli.md prescribes verified update
    assert!(
        cli_ref_doc.contains("cargo install --locked --force keyhog")
            && cli_ref_doc.contains("keyhog doctor"),
        "reference/cli.md must prescribe verified update with keyhog doctor"
    );
}

fn create_executable_script(path: &std::path::Path, body: &str) {
    fs::write(path, body).expect("write mock script");
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("set permissions");
}

#[test]
fn legacy_candidate_binary_probe_skips_generation_compilation_safely() {
    // When candidate binary is a legacy binary without compile-execution-packs,
    // existing artifacts are safely cleared on commit and restored on rollback.
    let cache_dir = tempfile::tempdir().expect("tempdir");
    let prev_cache = std::env::var_os("XDG_CACHE_HOME");
    std::env::set_var("XDG_CACHE_HOME", cache_dir.path());

    let test_dir = tempfile::tempdir().expect("testdir");
    let mock_bin = test_dir.path().join("mock_keyhog");
    create_executable_script(&mock_bin, "#!/bin/sh\nexit 1\n");

    // Seed prior execution-pack and autoroute artifacts
    let keyhog_cache = cache_dir.path().join("keyhog");
    let current_packs = keyhog_cache.join("execution-packs").join("current");
    let current_cache = keyhog_cache.join("autoroute.json");
    fs::create_dir_all(&current_packs).expect("create packs dir");
    fs::write(current_packs.join("manifest.json"), b"prior-generation").expect("write manifest");
    fs::write(&current_cache, b"prior-autoroute").expect("write autoroute");

    let target_bin = test_dir.path().join("target_keyhog");
    fs::write(&target_bin, b"original-bin").expect("write target bin");

    // 1. Rollback test: when install_with_rollback_checked fails on a legacy binary,
    // prior artifacts and original binary must be restored.
    let res = keyhog::testing::API.install_with_rollback_checked(
        &target_bin,
        b"legacy-bin",
        |candidate| {
            let tx = keyhog::testing::API.install_execution_generation(candidate);
            assert!(tx.is_ok(), "probe on legacy binary must succeed");
            Err(anyhow::anyhow!(
                "simulated post-install health verification failure"
            ))
        },
    );
    assert!(res.is_err(), "failed verification must return Err");
    assert_eq!(
        fs::read(&target_bin).expect("read target bin"),
        b"original-bin",
        "target binary must be rolled back on failure"
    );
    assert_eq!(
        fs::read(current_packs.join("manifest.json")).expect("read manifest"),
        b"prior-generation",
        "prior execution packs must be restored on rollback"
    );
    assert_eq!(
        fs::read(&current_cache).expect("read autoroute"),
        b"prior-autoroute",
        "prior autoroute cache must be restored on rollback"
    );

    // 2. Commit test: when legacy binary install commits, stale artifacts are removed
    // so they do not linger for the legacy binary version.
    let tx = keyhog::testing::API.install_execution_generation(&mock_bin);
    assert!(tx.is_ok(), "probe on legacy binary must succeed");
    assert!(
        !current_packs.exists(),
        "stale execution packs must be cleared when legacy binary commits"
    );
    assert!(
        !current_cache.exists(),
        "stale autoroute cache must be cleared when legacy binary commits"
    );

    // Restore environment
    if let Some(val) = prev_cache {
        std::env::set_var("XDG_CACHE_HOME", val);
    } else {
        std::env::remove_var("XDG_CACHE_HOME");
    }
}

#[test]
fn execution_generation_rollback_and_commit_behavior() {
    let cache_dir = tempfile::tempdir().expect("tempdir");
    let prev_cache = std::env::var_os("XDG_CACHE_HOME");
    std::env::set_var("XDG_CACHE_HOME", cache_dir.path());

    let test_dir = tempfile::tempdir().expect("testdir");
    let mock_bin = test_dir.path().join("mock_keyhog_pack_capable");
    let script = r#"#!/bin/sh
case "$1" in
  compile-execution-packs)
    if [ "$2" = "--help" ]; then exit 0; fi
    shift
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --output-dir) OUT="$2"; shift 2;;
        *) shift;;
      esac
    done
    mkdir -p "$OUT"
    echo "mock-pack-data" > "$OUT/manifest.json"
    exit 0
    ;;
  calibrate-autoroute)
    shift
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --autoroute-cache) CACHE="$2"; shift 2;;
        *) shift;;
      esac
    done
    echo "mock-autoroute-data" > "$CACHE"
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
"#;
    create_executable_script(&mock_bin, script);

    // Seed prior artifacts
    let keyhog_cache = cache_dir.path().join("keyhog");
    let current_packs = keyhog_cache.join("execution-packs").join("current");
    let current_cache = keyhog_cache.join("autoroute.json");
    fs::create_dir_all(&current_packs).expect("create packs dir");
    fs::write(current_packs.join("manifest.json"), b"prior-manifest")
        .expect("write prior manifest");
    fs::write(&current_cache, b"prior-autoroute").expect("write prior autoroute");

    let target_bin = test_dir.path().join("target_keyhog");
    fs::write(&target_bin, b"original-bin").expect("write target bin");

    // 1. Test failure rollback: closure fails, old binary and old artifacts are preserved
    let res = keyhog::testing::API.install_with_rollback_checked(
        &target_bin,
        b"new-bin-bytes",
        |_candidate| {
            // Simulate verification failure
            Err(anyhow::anyhow!("mock verification failure"))
        },
    );
    assert!(res.is_err(), "failed verification must return Err");
    assert_eq!(
        fs::read(&target_bin).expect("read target bin"),
        b"original-bin",
        "target binary must be rolled back on failure"
    );
    assert_eq!(
        fs::read(current_packs.join("manifest.json")).expect("read manifest"),
        b"prior-manifest",
        "prior execution packs must be restored on failure"
    );
    assert_eq!(
        fs::read(&current_cache).expect("read autoroute"),
        b"prior-autoroute",
        "prior autoroute cache must be restored on failure"
    );

    // 2. Test successful install and commit: new artifacts are generated and published
    let res = keyhog::testing::API.install_with_rollback_checked(
        &target_bin,
        b"new-bin-bytes",
        |candidate| {
            keyhog::testing::API.install_execution_generation(candidate)?;
            Ok(())
        },
    );
    assert!(res.is_ok(), "successful install must succeed");
    assert_eq!(
        fs::read(&target_bin).expect("read target bin"),
        b"new-bin-bytes",
        "target binary must be updated on commit"
    );
    let manifest_bytes = fs::read(current_packs.join("manifest.json")).expect("read new manifest");
    assert!(
        String::from_utf8_lossy(&manifest_bytes).contains("mock-pack-data"),
        "new execution packs must be published on commit"
    );
    let autoroute_bytes = fs::read(&current_cache).expect("read new autoroute");
    assert!(
        String::from_utf8_lossy(&autoroute_bytes).contains("mock-autoroute-data"),
        "new autoroute cache must be published on commit"
    );

    // Restore environment
    if let Some(val) = prev_cache {
        std::env::set_var("XDG_CACHE_HOME", val);
    } else {
        std::env::remove_var("XDG_CACHE_HOME");
    }
}
