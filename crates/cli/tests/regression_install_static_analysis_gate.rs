#[test]
fn install_static_analysis_gate_requires_real_linters_in_ci() {
    let gate = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/gates/install_static_analysis.sh"
    ))
    .expect("install static-analysis gate readable");
    assert!(gate.contains("shellcheck -x"), "gate must run ShellCheck");
    assert!(
        gate.contains("shfmt -d"),
        "gate must run shfmt in diff mode"
    );
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

fn normalize_doc_text(text: &str) -> String {
    text.replace("<code>", " ")
        .replace("</code>", " ")
        .replace('`', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

#[test]
fn install_docs_scope_cuda_fallback_to_auto_selected_variant() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root exists");
    let docs = [
        repo.join("README.md"),
        repo.join("docs/src/install.md"),
        repo.join("site/pages/install.html"),
        repo.join("site/install.html"),
    ];

    for path in docs {
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let normalized = normalize_doc_text(&raw);
        assert!(
            !normalized.contains(
                "you can rerun with --variant=cuda once a tag with the cuda variant lands"
            ),
            "{} still documents explicit CUDA as a retry-after-fallback path",
            path.display()
        );
        assert!(
            normalized.contains("explicit")
                && normalized.contains("cuda")
                && normalized.contains("fail")
                && normalized.contains("closed"),
            "{} must state that explicit CUDA asset misses fail closed",
            path.display()
        );
        assert!(
            normalized.contains("auto-selected cuda")
                || normalized.contains("auto-selected cuda hosts"),
            "{} must scope portable CUDA fallback to installer auto-selection",
            path.display()
        );
    }
}

#[test]
fn unix_installer_explicit_cuda_has_no_portable_asset_fallback() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.sh"))
        .expect("install.sh readable");
    assert!(
        script.contains(
            "cuda)\n            ASSET=\"keyhog-linux-x86_64-cuda\"\n            ASSET_FALLBACK=\"\""
        ),
        "explicit --variant=cuda must require the CUDA asset without a portable fallback"
    );
    assert!(
        script.contains(
            "yes)\n                ASSET=\"keyhog-linux-x86_64-cuda\"\n                ASSET_FALLBACK=\"keyhog-linux-x86_64\""
        ),
        "auto-selected CUDA may use the portable fallback because the installer made the variant choice"
    );
}
