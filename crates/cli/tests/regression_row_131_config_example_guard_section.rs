//! WHY: Closes the defect class where .keyhog.toml.example lacked a [guard] section
//! and example guard configuration keys could drift from the schema or fail to parse (Row 131).
//! Without example guard configuration and schema parity tests, operators have no
//! template for configuring daemon-resident perpetual guard parameters, and schema
//! changes can silently break configuration examples.
//!
//! What this does NOT catch: runtime daemon socket transport and filesystem watcher I/O errors.

use keyhog::testing::{CliTestApi as _, API};
use std::path::Path;

fn example_config_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.keyhog.toml.example")
        .canonicalize()
        .expect("canonicalize .keyhog.toml.example path")
}

fn read_example_config() -> String {
    std::fs::read_to_string(example_config_path())
        .expect("read .keyhog.toml.example")
}

#[test]
fn example_config_contains_guard_section() {
    let content = read_example_config();
    assert!(
        content.contains("[guard]"),
        ".keyhog.toml.example must contain a [guard] section header"
    );
    assert!(
        content.contains("scrub_interval"),
        ".keyhog.toml.example [guard] must document scrub_interval"
    );
    assert!(
        content.contains("state_path"),
        ".keyhog.toml.example [guard] must document state_path"
    );
    assert!(
        content.contains("hot_index_memory"),
        ".keyhog.toml.example [guard] must document hot_index_memory"
    );
    assert!(
        content.contains("max_pending_events_per_root"),
        ".keyhog.toml.example [guard] must document max_pending_events_per_root"
    );
    assert!(
        content.contains("coalesce_window"),
        ".keyhog.toml.example [guard] must document coalesce_window"
    );
    assert!(
        content.contains("scanner_idle_timeout"),
        ".keyhog.toml.example [guard] must document scanner_idle_timeout"
    );
    assert!(
        content.contains("subtree_max_files"),
        ".keyhog.toml.example [guard] must document subtree_max_files"
    );
    assert!(
        content.contains("subtree_max_depth"),
        ".keyhog.toml.example [guard] must document subtree_max_depth"
    );
}

#[test]
fn example_config_file_parses_against_schema() {
    let content = read_example_config();
    let result = API.parse_config_file_from_str(&content);
    assert!(
        result.is_ok(),
        ".keyhog.toml.example must parse cleanly against ConfigFile schema: {:?}",
        result.err()
    );
}

#[test]
fn fully_populated_guard_section_parses_cleanly() {
    let populated_toml = r#"
[guard]
scrub_interval = "5m"
state_path = "~/.local/state/keyhog/guard.redb"
hot_index_memory = "64MB"
max_pending_events_per_root = 8192
max_pending_events_total = 65536
coalesce_window = "100ms"
scanner_residency = "warm"
scanner_idle_timeout = "5m"
subtree_max_files = 10000
subtree_max_depth = 64
"#;

    let result = API.parse_config_file_from_str(populated_toml);
    assert!(
        result.is_ok(),
        "fully populated [guard] section must parse against ConfigFile schema: {:?}",
        result.err()
    );

    let inner_kv = populated_toml
        .trim()
        .strip_prefix("[guard]")
        .expect("starts with [guard]")
        .trim();
    let guard_result = API.parse_guard_section_from_str(inner_kv);
    assert!(
        guard_result.is_ok(),
        "fully populated [guard] section must parse against GuardSection schema: {:?}",
        guard_result.err()
    );
}

#[test]
fn guard_section_rejects_unknown_fields() {
    let invalid_toml = r#"
[guard]
scrub_interval = "5m"
invalid_unknown_guard_key = "should_fail"
"#;

    let result = API.parse_config_file_from_str(invalid_toml);
    assert!(
        result.is_err(),
        "[guard] with unknown fields must fail closed under deny_unknown_fields"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("unknown field `invalid_unknown_guard_key`"),
        "error must name the unknown field, got: {err}"
    );
}

#[test]
fn guard_section_uncommented_example_keys_parse() {
    let content = read_example_config();
    let guard_section = content
        .split("[guard]")
        .nth(1)
        .expect("[guard] section exists")
        .split("\n# ==")
        .next()
        .expect("guard section body");

    // Uncomment all lines that look like `# key = value` where key is an identifier
    let mut uncommented = String::from("[guard]\n");
    for line in guard_section.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('#') {
            let rest_trimmed = rest.trim();
            if let Some((k, _v)) = rest_trimmed.split_once('=') {
                let key = k.trim();
                if !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    uncommented.push_str(rest_trimmed);
                    uncommented.push('\n');
                }
            }
        } else if !trimmed.is_empty() {
            uncommented.push_str(trimmed);
            uncommented.push('\n');
        }
    }

    let result = API.parse_config_file_from_str(&uncommented);
    assert!(
        result.is_ok(),
        "uncommented example [guard] keys must parse cleanly: {:?}",
        result.err()
    );
}

#[test]
fn guard_docs_and_example_keys_coherence() {
    let docs = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/src/workflows/guard.md"),
    )
    .expect("read docs/src/workflows/guard.md");

    let example = read_example_config();

    let expected_keys = [
        "scrub_interval",
        "state_path",
        "hot_index_memory",
        "max_pending_events_per_root",
        "coalesce_window",
        "scanner_idle_timeout",
        "subtree_max_files",
        "subtree_max_depth",
    ];

    for key in expected_keys {
        assert!(
            docs.contains(key),
            "docs/src/workflows/guard.md must document `{key}`"
        );
        assert!(
            example.contains(key),
            ".keyhog.toml.example must document `{key}`"
        );
    }
}
