//! FILE_GATE_MATRIX must mark verifier hostile coverage columns explicitly.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn file_gate_matrix_verifier_rows_mark_hostile_coverage() {
    let raw = std::fs::read_to_string(repo_root().join("tests/FILE_GATE_MATRIX.toml"))
        .expect("FILE_GATE_MATRIX.toml");

    #[derive(Default)]
    struct Row {
        path: String,
        boundary: bool,
        error: bool,
        adversarial: bool,
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
        }
    }

    let mut current: Option<Row> = None;
    let mut verifier_rows = 0usize;
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
            current = path.starts_with("crates/verifier/src/").then(|| {
                verifier_rows += 1;
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
                "boundary = false" | "error = false" | "adversarial = false" => {
                    unmarked.push(format!("{}: {}", row.path, line.trim()));
                }
                _ => {}
            }
        }
    }
    finish(current.take(), &mut unmarked);

    assert!(
        verifier_rows >= 19,
        "expected verifier source matrix rows, got {verifier_rows}"
    );
    assert!(
        unmarked.is_empty(),
        "verifier matrix rows must explicitly mark boundary/error/adversarial=true when hostile suites exist; unmarked={unmarked:?}"
    );
}
