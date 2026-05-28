//! KH-GAP-135: FILE_GATE_MATRIX marks all CLI modules boundary/adversarial/e2e=false.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn file_gate_matrix_cli_rows_mark_hostile_coverage() {
    let raw = std::fs::read_to_string(repo_root().join("tests/FILE_GATE_MATRIX.toml"))
        .expect("FILE_GATE_MATRIX.toml");
    let mut in_cli = false;
    let mut cli_rows = 0usize;
    let mut unmarked = 0usize;
    for line in raw.lines() {
        if line.starts_with("path = \"crates/cli/") {
            in_cli = true;
            cli_rows += 1;
            continue;
        }
        if in_cli && line.starts_with("path = \"") && !line.contains("crates/cli/") {
            in_cli = false;
        }
        if in_cli
            && (line.starts_with("boundary = false")
                || line.starts_with("adversarial = false")
                || line.starts_with("e2e_linked = false"))
        {
            unmarked += 1;
        }
    }
    assert!(cli_rows >= 31, "expected >=31 CLI matrix rows, got {cli_rows}");
    assert_eq!(
        unmarked, 0,
        "CLI matrix rows must not leave boundary/adversarial/e2e_linked false when suites exist; unmarked={unmarked}"
    );
}
