#[test]
fn install_static_analysis_gate_requires_real_linters_in_ci() {
    let gate = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/gates/install_static_analysis.sh"
    ))
    .expect("install static-analysis gate readable");
    assert!(gate.contains("shellcheck -x"), "gate must run ShellCheck");
    assert!(gate.contains("shfmt -d"), "gate must run shfmt in diff mode");
    assert!(
        gate.contains("Invoke-ScriptAnalyzer"),
        "gate must run PSScriptAnalyzer for install.ps1"
    );
    assert!(
        gate.contains("REQUIRE_INSTALL_LINTERS"),
        "gate must fail CI when a linter is missing"
    );
}

#[test]
fn ci_install_scripts_job_runs_static_analysis_in_required_mode() {
    let workflow = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/workflows/ci.yml"
    ))
    .expect("ci workflow readable");
    assert!(
        workflow.contains("shellcheck shfmt"),
        "install-scripts job must install shellcheck and shfmt"
    );
    assert!(
        workflow.contains("Install-Module -Name PSScriptAnalyzer"),
        "install-scripts job must install PSScriptAnalyzer"
    );
    assert!(
        workflow.contains("REQUIRE_INSTALL_LINTERS: '1'")
            && workflow.contains("bash scripts/gates/install_static_analysis.sh"),
        "install-scripts job must run the static-analysis gate in required mode"
    );
}
