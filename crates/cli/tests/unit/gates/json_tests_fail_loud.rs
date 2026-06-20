use std::fs;
use std::path::PathBuf;

#[test]
fn cli_json_tests_do_not_drop_parse_errors() {
    let tests_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let from_str_call = ["serde_json::from_str::<serde_json::Value>", "("].concat();
    let ok_call = [").", "ok()"].concat();
    let mut stack = vec![tests_root.clone()];
    let mut offenders = Vec::new();

    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("read test directory {}: {error}", dir.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| {
                panic!("read test directory entry under {}: {error}", dir.display())
            });
            let path = entry.path();
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("read file type for {}: {error}", path.display()));
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }

            let source = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read test source {}: {error}", path.display()));
            let lines: Vec<_> = source.lines().collect();
            for index in 0..lines.len() {
                let end = (index + 3).min(lines.len());
                let compact_window: String = lines[index..end]
                    .join("")
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect();
                if compact_window.contains(&from_str_call) && compact_window.contains(&ok_call) {
                    let relative = path
                        .strip_prefix(&tests_root)
                        .unwrap_or(&path)
                        .to_string_lossy();
                    offenders.push(format!("{}:{}", relative, index + 1));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "CLI JSON tests must fail loud on malformed output instead of hiding parse errors with .ok(): {offenders:?}"
    );
}
