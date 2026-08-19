#![cfg(unix)]

//! WHY: Row 134 contract: update recommendation parity and complete artifact generation on binary replacement.
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
//!
//! What it does not catch / boundary limits:
//! - Does not catch network transport failures when fetching packages from crates.io.
//! - Does not catch host disk full (ENOSPC) conditions occurring during local cargo compilation.

use keyhog::testing::{CliTestApi as _, API};
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn update_fallback_instructions_prescribe_verified_installation() {
    let update_src = fs::read_to_string(repo_root().join("crates/cli/src/subcommands/update.rs"))
        .expect("read update.rs source");
    // Invariant: ChannelBehind fallback instructions MUST prescribe verified installation
    // with `cargo install --locked --force keyhog` and `keyhog doctor`.
    assert!(
        update_src.contains("cargo install --locked --force keyhog")
            && update_src.contains("keyhog doctor"),
        "keyhog update fallback instructions must prescribe verified install with doctor; got:\n{update_src}"
    );
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

#[test]
fn binary_replacement_paths_trigger_execution_generation_and_gpu_literals() {
    let update_src = fs::read_to_string(repo_root().join("crates/cli/src/subcommands/update.rs"))
        .expect("read update.rs source");
    let repair_src = fs::read_to_string(repo_root().join("crates/cli/src/subcommands/repair.rs"))
        .expect("read repair.rs source");

    for (name, src) in [("update.rs", &update_src), ("repair.rs", &repair_src)] {
        assert!(
            src.contains("installer::install_gpu_literal_files("),
            "{name} binary replacement path must trigger GPU literal installation"
        );
        assert!(
            src.contains("installer::install_execution_generation("),
            "{name} binary replacement path must trigger execution generation installation"
        );
        assert!(
            src.contains("execution_transaction.commit();"),
            "{name} binary replacement path must commit the execution generation transaction"
        );
        assert!(
            src.contains("gpu_transaction.commit();"),
            "{name} binary replacement path must commit the GPU literal transaction"
        );
    }
}

#[test]
fn candidate_binary_execution_generation_fails_closed_on_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mock_bin = dir.path().join("mock_keyhog");
    // Write a mock binary that exits 1 on compile-execution-packs
    fs::write(&mock_bin, "#!/bin/sh\nexit 1\n").expect("write mock");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&mock_bin).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&mock_bin, perms).expect("set permissions");
    }

    let result = API.install_execution_generation(&mock_bin);
    assert!(
        result.is_err(),
        "install_execution_generation on broken candidate must fail closed"
    );
}
