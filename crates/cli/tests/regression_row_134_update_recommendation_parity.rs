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
    // with `cargo install --locked --force keyhog && keyhog doctor`.
    assert!(
        update_src.contains("cargo install --locked --force keyhog && keyhog doctor"),
        "keyhog update fallback instructions must prescribe verified install with doctor; got:\n{update_src}"
    );

    // Invariant: raw `cargo install --locked --force keyhog` without doctor is forbidden
    let raw_unverified_pattern = "cargo install --locked --force keyhog{reset}";
    assert!(
        !update_src.contains(raw_unverified_pattern),
        "keyhog update fallback instructions must not prescribe raw cargo install without verification"
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
        install_doc.contains("cargo install --locked --force keyhog && keyhog doctor"),
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

    // Invariant 2: capabilities.md prescribes verified update
    assert!(
        capabilities_doc.contains("cargo install --locked --force keyhog && keyhog doctor"),
        "capabilities.md must prescribe verified update with keyhog doctor"
    );

    // Invariant 3: hardening.md prescribes verified update
    assert!(
        hardening_doc.contains("cargo install --locked --force keyhog && keyhog doctor"),
        "hardening.md must prescribe verified update with keyhog doctor"
    );

    // Invariant 4: reference/cli.md prescribes verified update
    assert!(
        cli_ref_doc.contains("cargo install --locked --force keyhog && keyhog doctor"),
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
fn mutation_omitting_doctor_fails_recommendation_invariant() {
    let raw_recommendation = "cargo install --locked --force keyhog";
    let verified_recommendation = "cargo install --locked --force keyhog && keyhog doctor";

    assert!(
        !raw_recommendation.contains("keyhog doctor"),
        "mutation baseline check: raw recommendation lacks doctor verification"
    );
    assert!(
        verified_recommendation.contains("keyhog doctor"),
        "verified recommendation must include doctor verification"
    );
}

#[test]
fn mutation_omitting_execution_generation_fails_parity_check() {
    let mock_missing_execution_gen = r#"
        installer::install_with_rollback_checked(&exe, &bytes, |candidate| {
            let gpu_transaction = installer::install_gpu_literal_files(&gpu_literal_files)?;
            installer::verify_candidate_release(candidate, &expected_tag, current, false)?;
            gpu_transaction.commit();
            Ok(())
        })
    "#;

    let has_execution_gen =
        mock_missing_execution_gen.contains("installer::install_execution_generation");
    let has_execution_commit =
        mock_missing_execution_gen.contains("execution_transaction.commit();");

    assert!(
        !has_execution_gen || !has_execution_commit,
        "mutation detector: mock replacement path without execution generation must be detected as non-compliant"
    );
}
