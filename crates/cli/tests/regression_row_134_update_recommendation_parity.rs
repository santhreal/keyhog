#![cfg(unix)]

//! WHY: Row 134 contract: update recommendation parity and candidate capability probe.
//!
//! What it closes:
//! 1. Closes the unverified installation defect where documentation prescribed raw
//!    `cargo install --force` without triggering artifact compilation or post-install
//!    health verification (`keyhog doctor`).
//! 2. Enforces documentation parity across `docs/src/install.md`, `capabilities.md`,
//!    `hardening.md`, and `reference/cli.md` so every update and rollback instruction
//!    prescribes verified installation.
//! 3. Closes the silent-fallback defect on the candidate capability probe: a candidate
//!    without `compile-execution-packs`, and one that fails compilation, both fail closed
//!    with the installed generation intact instead of publishing or clearing artifacts.
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

/// Both scenarios live in one test: they set `XDG_CACHE_HOME` for the whole
/// process, so running them as separate tests would race in the same binary.
#[test]
fn candidate_execution_generation_clears_stale_artifacts_and_fails_closed() {
    let cache_dir = tempfile::tempdir().expect("tempdir");
    let prev_cache = std::env::var_os("XDG_CACHE_HOME");
    std::env::set_var("XDG_CACHE_HOME", cache_dir.path());

    let test_dir = tempfile::tempdir().expect("testdir");
    let keyhog_cache = cache_dir.path().join("keyhog");
    let current_packs = keyhog_cache.join("execution-packs").join("current");
    let current_cache = keyhog_cache.join("autoroute.json");
    let seed_artifacts = || {
        fs::create_dir_all(&current_packs).expect("create packs dir");
        fs::write(current_packs.join("manifest.json"), b"prior-generation")
            .expect("write manifest");
        fs::write(&current_cache, b"prior-autoroute").expect("write autoroute");
    };

    // 1. A candidate without the compile-execution-packs subcommand cannot
    // publish a generation, so the install must fail closed and leave the
    // installed artifacts untouched.
    seed_artifacts();
    let legacy_bin = test_dir.path().join("legacy_keyhog");
    create_executable_script(&legacy_bin, "#!/bin/sh\nexit 1\n");
    let err = keyhog::testing::API
        .install_execution_generation(&legacy_bin)
        .expect_err("candidate without execution-pack support must fail closed");
    assert!(
        format!("{err:#}").contains("cannot compile execution packs"),
        "error must name the missing capability, got: {err:#}"
    );
    assert_eq!(
        fs::read(current_packs.join("manifest.json")).expect("installed manifest survives"),
        b"prior-generation",
        "a rejected candidate must leave the installed packs in place"
    );

    // 2. A candidate that advertises compile-execution-packs but fails to
    // compile them must fail closed and leave the installed generation intact.
    seed_artifacts();
    let broken_bin = test_dir.path().join("broken_keyhog");
    create_executable_script(
        &broken_bin,
        "#!/bin/sh\nif [ \"$1\" = compile-execution-packs ] && [ \"$2\" = --help ]; then exit 0; fi\nexit 1\n",
    );
    let err = keyhog::testing::API
        .install_execution_generation(&broken_bin)
        .expect_err("failed pack compilation must fail closed");
    assert!(
        format!("{err:#}").contains("execution-pack compilation"),
        "error must name the phase that failed, got: {err:#}"
    );
    assert_eq!(
        fs::read(current_packs.join("manifest.json")).expect("prior manifest survives"),
        b"prior-generation",
        "a failed generation must leave the installed packs in place"
    );
    assert_eq!(
        fs::read(&current_cache).expect("prior autoroute cache survives"),
        b"prior-autoroute",
        "a failed generation must leave the installed autoroute cache in place"
    );

    match prev_cache {
        Some(val) => std::env::set_var("XDG_CACHE_HOME", val),
        None => std::env::remove_var("XDG_CACHE_HOME"),
    }
}
