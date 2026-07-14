//! FILE_GATE_MATRIX row-count contract for the current module inventory.

#[test]
fn file_gate_matrix_has_current_rows() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let raw = std::fs::read_to_string(repo.join("tests/FILE_GATE_MATRIX.toml")).expect("matrix");
    let rows = raw.lines().filter(|l| l.starts_with("[[module]]")).count();
    let paths = raw.lines().filter(|l| l.starts_with("path = ")).count();
    assert_eq!(
        rows, paths,
        "every FILE_GATE_MATRIX path row must be inside an explicit [[module]] table"
    );
    // 443 = the current module inventory. The count had drifted stale (docker
    // and other module rows were added without bumping this contract), and the
    // orchestrator inline-test migration adds five sibling `tests.rs` rows
    // `orchestrator/tests.rs`, `orchestrator/dispatch/tests.rs`,
    // `orchestrator/reporting/tests.rs`, `subcommands/backend/tests.rs`, and
    // `subcommands/watch/tests.rs`, each a real cli/src file that
    // `file_gate_matrix_lists_every_cli_src_module` requires be listed.
    // Reconcile to the true total so the force-awareness contract is accurate.
    assert_eq!(rows, 443, "expected 443 module rows, got {rows}");
}
