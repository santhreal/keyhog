//! Windows installs should clear Mark-of-the-Web after staging keyhog.exe.

#[test]
fn powershell_installer_unblocks_staged_binary() {
    let script = include_str!("../../../install.ps1");
    assert!(
        script.contains("function Clear-MarkOfTheWeb"),
        "install.ps1 must define a single Mark-of-the-Web cleanup helper"
    );
    assert!(
        script.contains("Get-Command Unblock-File"),
        "cleanup helper must use PowerShell's Unblock-File when available"
    );
    assert!(
        script.contains("Clear-MarkOfTheWeb -Path $dest"),
        "Stage-Install must unblock the final keyhog.exe path after Move-Item"
    );
}

#[test]
fn powershell_installer_explains_smartscreen_if_unblock_fails() {
    let script = include_str!("../../../install.ps1");
    assert!(
        script.contains("SmartScreen prompts"),
        "install.ps1 must explain what to do if Windows still shows SmartScreen"
    );
    assert!(
        script.contains("verify the SHA256 above"),
        "SmartScreen guidance must tie the operator back to the checksum proof"
    );
}
