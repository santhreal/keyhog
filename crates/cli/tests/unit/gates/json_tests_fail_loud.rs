use std::fs;
use std::path::PathBuf;

#[test]
fn cli_json_tests_do_not_drop_parse_errors() {
    let tests_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let from_str_call = ["serde_json::from_str::<serde_json::Value>", "("].concat();
    let from_slice_call = ["serde_json::from_slice", "("].concat();
    let json_empty_fallback = ["serde_json::", "json!([])"].concat();
    let ok_call = [").", "ok()"].concat();
    let cloned_array_default = ["as_array()", ".cloned()", ".unwrap_or_default()"].concat();
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
                let drops_parse_error = (compact_window.contains(&from_str_call)
                    || compact_window.contains(&from_slice_call))
                    && (compact_window.contains(&ok_call)
                        || compact_window.contains(&json_empty_fallback));
                let drops_non_array_shape = compact_window.contains(&cloned_array_default);
                if drops_parse_error || drops_non_array_shape {
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
        "CLI JSON tests must fail loud on malformed output and non-array JSON instead of hiding them with .ok(), json!([]), or unwrap_or_default(): {offenders:?}"
    );
}
