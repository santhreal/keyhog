//! Install integrity bypasses must be explicit flags, never ambient env.

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
