//! Install integrity bypasses must be explicit flags, never ambient env.

use keyhog::testing::{CliTestApi as _, API};

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
