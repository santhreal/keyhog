//! Packaging contract for the two shipped installer entry points.
//!
//! Autoroute behavior itself is exercised through the real binary in
//! `regression_cli_calibrate_autoroute_e2e.rs` and the backend persistence
//! suite. This file checks only the installer bytes that expose that workflow.

#[test]
fn installers_delegate_to_the_canonical_autoroute_commands() {
    let install_sh = include_str!("../../../../../install.sh");
    let install_ps1 = include_str!("../../../../../install.ps1");

    assert!(
        install_sh.contains("\"$bin\" calibrate-autoroute $core_no_config --quiet")
            && install_ps1.contains("& $BinPath @coreCalibrateArgs"),
        "both installers must invoke the production core calibration command"
    );
    // An install runs from an arbitrary directory. Calibration measures under
    // the resolved scan configuration, so a `.keyhog.toml` on that directory's
    // walk-up would bind the whole host baseline to a repository policy the
    // installed binary is not being primed for. Both installers decline it,
    // and both probe for the flag first so a binary that predates it still
    // calibrates.
    assert!(
        install_sh.contains("calibrate-autoroute --help")
            && install_sh.contains("core_no_config=\"--no-config\""),
        "install.sh must probe for --no-config and pass it when the binary has it"
    );
    assert!(
        install_ps1.contains("calibrate-autoroute --help")
            && install_ps1.contains("$coreCalibrateArgs += '--no-config'"),
        "install.ps1 must probe for --no-config and pass it when the binary has it"
    );
    assert!(
        install_sh.contains("scan --autoroute-calibrate --autoroute-gpu")
            && install_ps1.contains("@('--autoroute-calibrate', '--autoroute-gpu')"),
        "both installers must use the explicit external-source calibration path"
    );
    assert!(
        !install_sh.contains("KEYHOG_AUTOROUTE_CALIBRATE")
            && !install_ps1.contains("KEYHOG_AUTOROUTE_CALIBRATE")
            && !install_sh.contains("KEYHOG_GPU_AUTOROUTE")
            && !install_ps1.contains("KEYHOG_GPU_AUTOROUTE"),
        "installer behavior must not depend on retired hidden environment shims"
    );
}
