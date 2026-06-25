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

    #[derive(Default)]
    struct Row {
        path: String,
        boundary: bool,
        error: bool,
        adversarial: bool,
        e2e_linked: bool,
    }

    fn finish(row: Option<Row>, unmarked: &mut Vec<String>) {
        if let Some(row) = row {
            if !row.boundary {
                unmarked.push(format!("{}: missing boundary=true", row.path));
            }
            if !row.error {
                unmarked.push(format!("{}: missing error=true", row.path));
            }
            if !row.adversarial {
                unmarked.push(format!("{}: missing adversarial=true", row.path));
            }
            if !row.e2e_linked {
                unmarked.push(format!("{}: missing e2e_linked=true", row.path));
            }
        }
    }

    let mut current: Option<Row> = None;
    let mut cli_rows = 0usize;
    let mut unmarked = Vec::new();
    for line in raw.lines() {
        if line.trim().starts_with("[[module]]") {
            finish(current.take(), &mut unmarked);
            continue;
        }
        if let Some(path) = line
            .strip_prefix("path = \"")
            .and_then(|p| p.strip_suffix('"'))
        {
            current = path.starts_with("crates/cli/src/").then(|| {
                cli_rows += 1;
                Row {
                    path: path.to_string(),
                    ..Default::default()
                }
            });
        }
        if let Some(row) = current.as_mut() {
            match line.trim() {
                "boundary = true" => row.boundary = true,
                "error = true" => row.error = true,
                "adversarial = true" => row.adversarial = true,
                "e2e_linked = true" => row.e2e_linked = true,
                "boundary = false"
                | "error = false"
                | "adversarial = false"
                | "e2e_linked = false" => unmarked.push(format!("{}: {}", row.path, line.trim())),
                _ => {}
            }
        }
    }
    finish(current.take(), &mut unmarked);
    assert!(
        cli_rows >= 31,
        "expected >=31 CLI matrix rows, got {cli_rows}"
    );
    assert!(
        unmarked.is_empty(),
        "CLI matrix rows must explicitly mark boundary/error/adversarial/e2e_linked=true when hostile suites exist; unmarked={unmarked:?}"
    );
}
