//! Install integrity bypasses must be explicit flags, never ambient env.

use keyhog::testing::{API, CliTestApi as _};
use std::collections::BTreeSet;

fn keyhog_env_tokens(script: &str) -> BTreeSet<&str> {
    let mut tokens = BTreeSet::new();
    for (start, _) in script.match_indices("KEYHOG_") {
        let tail = &script[start..];
        let end = tail
            .find(|ch: char| !(ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_'))
            .unwrap_or(tail.len());
        tokens.insert(&tail[..end]);
    }
    tokens
}

#[test]
fn installer_keyhog_env_surface_is_exactly_the_install_pin() {
    let allowed = BTreeSet::from(["KEYHOG_VERSION"]);
    for (name, script) in [
        ("install.sh", include_str!("../../../install.sh")),
        ("install.ps1", include_str!("../../../install.ps1")),
    ] {
        let actual = keyhog_env_tokens(script);
        assert_eq!(
            actual, allowed,
            "{name} must not grow ambient KEYHOG_* installer configuration. \
             The only surviving installer env is KEYHOG_VERSION as the release pin; \
             local files, destination, variant, insecure mode, calibration, and behavior use explicit flags."
        );
    }
}

#[test]
fn install_scripts_do_not_accept_insecure_env_override() {
    for (name, script) in [
        ("install.sh", include_str!("../../../install.sh")),
        ("install.ps1", include_str!("../../../install.ps1")),
    ] {
        assert!(
            !script.contains("KEYHOG_INSECURE_INSTALL"),
            "{name} must not accept an ambient env var that weakens checksum verification"
        );
    }
}

#[test]
fn install_from_file_is_explicit_flag_not_env() {
    for (name, script) in [
        ("install.sh", include_str!("../../../install.sh")),
        ("install.ps1", include_str!("../../../install.ps1")),
    ] {
        assert!(
            !script.contains("KEYHOG_FROM_FILE"),
            "{name} must not accept KEYHOG_FROM_FILE; local/offline installs use --from-file/-FromFile explicitly"
        );
    }
}

#[test]
fn installer_destination_and_variant_are_explicit_flags_not_env() {
    for (name, script, forbidden) in [
        (
            "install.sh",
            include_str!("../../../install.sh"),
            &["KEYHOG_INSTALL", "KEYHOG_VARIANT"][..],
        ),
        (
            "install.ps1",
            include_str!("../../../install.ps1"),
            &["KEYHOG_INSTALL", "KEYHOG_VARIANT"][..],
        ),
    ] {
        for token in forbidden {
            assert!(
                !script.contains(token),
                "{name} must not accept {token}; installer destination and variant use explicit flags"
            );
        }
    }
}

#[test]
fn install_scripts_keep_explicit_insecure_flags() {
    let sh = include_str!("../../../install.sh");
    assert!(
        sh.contains("--insecure"),
        "POSIX installer still needs the explicit emergency bypass flag"
    );
    assert!(
        sh.contains("INSECURE_INSTALL=0"),
        "POSIX installer default must remain fail-closed"
    );

    let ps1 = include_str!("../../../install.ps1");
    assert!(
        ps1.contains("-Insecure"),
        "PowerShell installer still needs the explicit emergency bypass flag"
    );
    assert!(
        ps1.contains("$Script:InsecureInstall = [bool]$Insecure"),
        "PowerShell installer must derive bypass state only from the explicit flag"
    );
}

#[test]
fn bootstrap_installers_verify_release_minisig_with_updater_key() {
    let public_key = API.release_public_key();
    for (name, script) in [
        ("install.sh", include_str!("../../../install.sh")),
        ("install.ps1", include_str!("../../../install.ps1")),
    ] {
        assert!(
            script.contains(public_key),
            "{name} must embed the same minisign release public key as the Rust updater"
        );
        assert!(
            script.contains(".minisig"),
            "{name} must download and verify release .minisig sidecars"
        );
        assert!(
            script.contains("minisign"),
            "{name} must invoke minisign for bootstrap release authenticity"
        );
        assert!(
            script.contains("Minisign signature verification failed"),
            "{name} must fail closed on invalid release signatures"
        );
        assert!(
            script.contains("Refusing to install an unverified keyhog binary."),
            "{name} must refuse unsigned/unverified bootstrap assets by default"
        );
    }
}

#[test]
fn bootstrap_installers_verify_gpu_literal_sidecars_before_installing_cache_artifacts() {
    let sh = include_str!("../../../install.sh");
    assert!(
        sh.contains("verify_release_signature \"$sidecar_tmp\" \"$sidecar_name\"")
            && sh.contains("verify_checksum \"$sidecar_tmp\" \"$sidecar_name\"")
            && sh.contains("stage_local_gpu_literal_sidecar")
            && sh.contains("--from-file requires a sibling GPU literal sidecar")
            && sh.contains("validate_gpu_literal_sidecar_archive")
            && sh.contains("GPU literal artifact sidecar contains link entries.")
            && sh.contains("backup_gpu_programs_cache_for_install")
            && sh.contains("restore_gpu_programs_cache_backup")
            && sh.contains("clear_gpu_programs_cache_backup")
            && !sh.contains("[ -z \"$FROM_FILE\" ] || return 0"),
        "install.sh must verify and inspect GPU literal sidecar archives before extraction"
    );

    let ps1 = include_str!("../../../install.ps1");
    assert!(
        ps1.contains("Verify-ReleaseSignature -BinaryPath $sidecarPath -AssetName $sidecarName")
            && ps1.contains("Verify-Checksum -BinaryPath $sidecarPath -AssetName $sidecarName")
            && ps1.contains("-FromFile requires a sibling GPU literal sidecar")
            && ps1.contains("Test-GpuLiteralSidecarArchive")
            && ps1.contains("GPU literal artifact sidecar contains a link entry")
            && ps1.contains("Backup-GpuProgramsCacheForInstall")
            && ps1.contains("Restore-GpuProgramsCacheBackup")
            && ps1.contains("Clear-GpuProgramsCacheBackup")
            && !ps1.contains("if ($FromFile) { return $true }"),
        "install.ps1 must verify and inspect GPU literal sidecar archives before extraction"
    );
}

#[test]
fn bootstrap_installers_reject_binary_release_tag_mismatch() {
    let sh = include_str!("../../../install.sh");
    assert!(
        sh.contains("observed_tag=$(version_tag_from_text \"$verify_out\")")
            && sh.contains("[ \"$observed_tag\" != \"$TAG\" ]")
            && sh.contains("Candidate binary version does not match release tag")
            && sh.contains("possible substitution or downgrade attack"),
        "install.sh must verify the installed binary version against the resolved release tag"
    );

    let ps1 = include_str!("../../../install.ps1");
    assert!(
        ps1.contains("$observedTag = Get-VersionTagFromText -Text ($out | Out-String)")
            && ps1.contains("$observedTag -ne $Script:Tag")
            && ps1.contains("Candidate binary version does not match release tag")
            && ps1.contains("possible substitution or downgrade attack"),
        "install.ps1 must verify the installed binary version against the resolved release tag"
    );
}
