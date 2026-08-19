//! WHY: Row 149 structural gate consolidation contract.
//!
//! Asserts single authoritative ownership per structural rule across the entire workspace:
//! 1. `scripts/gates/no_inline_tests_in_src.py` is the single authoritative owner for forbidding
//!    inline test modules across all workspace crates.
//! 2. `scripts/gates/no_cwd_relative_source_reads.py` is the single authoritative owner for forbidding
//!    CWD-relative crate source reads in tests.
//! 3. Both gates are wired into `scripts/gates/run_all.sh`.
//! 4. Legacy per-crate duplicate/divergent gap test files are eliminated and cannot reappear.
//!
//! What it does not catch: Dynamic runtime failures inside test execution or semantic test assertions
//! outside structural module layout and file read patterns.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

#[test]
fn single_structural_gate_scripts_exist_and_pass() {
    let root = repo_root();

    let inline_gate = root.join("scripts/gates/no_inline_tests_in_src.py");
    assert!(
        inline_gate.is_file(),
        "scripts/gates/no_inline_tests_in_src.py must exist as single authoritative owner"
    );

    let cwd_read_gate = root.join("scripts/gates/no_cwd_relative_source_reads.py");
    assert!(
        cwd_read_gate.is_file(),
        "scripts/gates/no_cwd_relative_source_reads.py must exist as single authoritative owner"
    );

    let status = Command::new("python3")
        .arg("-B")
        .arg(&inline_gate)
        .arg("--self-test")
        .current_dir(&root)
        .status()
        .expect("run no_inline_tests_in_src.py --self-test");
    assert!(
        status.success(),
        "no_inline_tests_in_src.py --self-test must succeed"
    );

    let status = Command::new("python3")
        .arg("-B")
        .arg(&cwd_read_gate)
        .arg("--self-test")
        .current_dir(&root)
        .status()
        .expect("run no_cwd_relative_source_reads.py --self-test");
    assert!(
        status.success(),
        "no_cwd_relative_source_reads.py --self-test must succeed"
    );
}

#[test]
fn gates_wired_into_run_all_sh() {
    let root = repo_root();
    let run_all = root.join("scripts/gates/run_all.sh");
    assert!(run_all.is_file(), "scripts/gates/run_all.sh must exist");

    let content = std::fs::read_to_string(&run_all).expect("read run_all.sh");
    assert!(
        content.contains("no_inline_tests_in_src.py"),
        "run_all.sh must wire no_inline_tests_in_src.py"
    );
    assert!(
        content.contains("no_cwd_relative_source_reads.py"),
        "run_all.sh must wire no_cwd_relative_source_reads.py"
    );
}

#[test]
fn redundant_per_crate_duplicate_gap_tests_eliminated() {
    let root = repo_root();

    let legacy_paths = [
        "crates/core/tests/gap/no_cwd_relative_source_reads.rs",
        "crates/core/tests/gap/no_inline_tests_in_src.rs",
        "crates/verifier/tests/gap/no_inline_tests_in_src.rs",
        "crates/scanner/tests/gap/no_cwd_relative_source_reads.rs",
        "crates/scanner/tests/gap/no_inline_tests_in_src.rs",
        "crates/scanner/tests/gap/no_inline_tests_in_a3_slice.rs",
        "crates/scanner/tests/gap/compiler_inline_tests_in_src.rs",
        "crates/scanner/tests/gap/compiler_prefix_inline_tests_in_src.rs",
        "crates/scanner/tests/gap/context_false_positive_inline_tests_in_src.rs",
        "crates/scanner/tests/gap/entropy_keywords_inline_tests_in_src.rs",
        "crates/scanner/tests/gap/inline_gate.rs",
        "crates/cli/tests/gap/no_inline_tests_in_src.rs",
        "crates/cli/tests/unit/gates/no_inline_tests_in_src.rs",
    ];

    for path_str in legacy_paths {
        let p = root.join(path_str);
        assert!(
            !p.exists(),
            "Legacy duplicate per-crate gap test must remain deleted: {path_str}"
        );
    }
}
