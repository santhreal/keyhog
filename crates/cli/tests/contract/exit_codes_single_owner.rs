//! Contract: exit-code numbers have one owner and scan-reachable outcomes do
//! not collide.

use keyhog::exit_codes::{
    DEFINITIONS, EXIT_REQUIRE_GPU_UNMET, EXIT_SOURCE_FAILED, EXIT_USER_ERROR, HELP,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn scan_reachable_exit_codes_are_unique() {
    let mut seen = BTreeMap::new();
    for definition in DEFINITIONS.iter().filter(|d| d.scan_reachable) {
        if let Some(previous) = seen.insert(definition.code, definition.label) {
            panic!(
                "scan-reachable exit code {} is reused by both {:?} and {:?}",
                definition.code, previous, definition.label
            );
        }
    }
}

#[test]
fn user_gpu_and_source_failures_have_distinct_codes() {
    assert_ne!(EXIT_USER_ERROR, EXIT_REQUIRE_GPU_UNMET);
    assert_ne!(EXIT_USER_ERROR, EXIT_SOURCE_FAILED);
    assert_ne!(EXIT_REQUIRE_GPU_UNMET, EXIT_SOURCE_FAILED);
}

#[test]
fn help_text_names_every_owned_exit_code() {
    for definition in DEFINITIONS {
        assert!(
            HELP.contains(&definition.code.to_string()),
            "exit help omits owned code {} ({})",
            definition.code,
            definition.label
        );
    }
}

#[test]
fn production_code_does_not_construct_numeric_exit_codes_inline() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let roots = [manifest.join("src"), manifest.join("../scanner/src")];
    let mut violations = Vec::new();
    for src_root in roots {
        for path in rust_sources(&src_root) {
            let rel = path.strip_prefix(manifest).unwrap_or(&path);
            let text = fs::read_to_string(&path).unwrap_or_else(|err| {
                panic!("read {} for exit-code owner check: {err}", path.display())
            });
            for (line_idx, line) in text.lines().enumerate() {
                if contains_inline_numeric_exit_code(line) {
                    violations.push(format!("{}:{}", rel.display(), line_idx + 1));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "production code constructs numeric exit codes outside exit_codes.rs: {}",
        violations.join(", ")
    );
}

#[test]
fn scanner_require_gpu_hard_exit_matches_cli_exit_contract() {
    let scanner_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scanner/src");
    let helper_path = scanner_src.join("process_exit.rs");
    let helper = fs::read_to_string(&helper_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", helper_path.display()));
    assert!(
        helper.contains(&format!(
            "REQUIRE_GPU_UNMET_EXIT_CODE: i32 = {}",
            EXIT_REQUIRE_GPU_UNMET
        )),
        "scanner require-GPU hard exit must match keyhog::exit_codes::EXIT_REQUIRE_GPU_UNMET"
    );

    let mut offenders = Vec::new();
    for path in rust_sources(&scanner_src) {
        if path == helper_path {
            continue;
        }
        let rel = path.strip_prefix(&scanner_src).unwrap_or(&path);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read scanner source {}: {err}", path.display()));
        for (line_idx, line) in text.lines().enumerate() {
            if line.contains("std::process::exit(") || line.contains("process::exit(") {
                offenders.push(format!("{}:{}", rel.display(), line_idx + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "scanner hard exits must go through process_exit.rs: {}",
        offenders.join(", ")
    );
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = fs::read_dir(&path)
            .unwrap_or_else(|err| panic!("read source directory {}: {err}", path.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|err| panic!("read source entry: {err}"));
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn contains_inline_numeric_exit_code(line: &str) -> bool {
    numeric_call_arg_starts_with_digit(line, "ExitCode::from(")
        || numeric_call_arg_starts_with_digit(line, "std::process::exit(")
        || numeric_call_arg_starts_with_digit(line, "process::exit(")
}

fn numeric_call_arg_starts_with_digit(line: &str, call: &str) -> bool {
    let mut tail = line;
    while let Some(idx) = tail.find(call) {
        let after_call = &tail[idx + call.len()..];
        let first = after_call.trim_start().chars().next();
        if first.is_some_and(|ch| ch.is_ascii_digit()) {
            return true;
        }
        tail = after_call;
    }
    false
}
