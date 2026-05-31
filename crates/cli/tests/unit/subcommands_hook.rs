use keyhog::subcommands::hook::{CANONICAL_SCAN_ARGS, HOOK_CONTENT};
use std::path::PathBuf;

#[test]
fn hook_template_embeds_canonical_scan_args() {
    let expected = format!("exec keyhog {CANONICAL_SCAN_ARGS}\n");
    assert!(
        HOOK_CONTENT.contains(&expected),
        "HOOK_CONTENT must invoke `{expected}` verbatim; the installed pre-commit hook diverged from CANONICAL_SCAN_ARGS"
    );
    assert!(CANONICAL_SCAN_ARGS.contains("--git-staged"));
    assert!(CANONICAL_SCAN_ARGS.contains("--fast"));
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn pre_commit_hooks_yaml_matches_canonical_scan_args() {
    let path = repo_root().join(".pre-commit-hooks.yaml");
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));

    let expected_entry = format!("entry: keyhog {CANONICAL_SCAN_ARGS}");
    assert!(
        yaml.contains(&expected_entry),
        ".pre-commit-hooks.yaml must contain `{expected_entry}` so the framework hook mirrors `hook install`; found:\n{yaml}"
    );
    assert!(
        yaml.contains("pass_filenames: false"),
        ".pre-commit-hooks.yaml must keep `pass_filenames: false`; a true value appends filenames and aborts every commit with clap exit 2"
    );
}

#[test]
fn scripts_pre_commit_divergence_is_pinned() {
    let path = repo_root().join("scripts").join("pre-commit");
    let script = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));

    let uses_canonical = script.contains(CANONICAL_SCAN_ARGS);
    let uses_path_detectors = script.contains("--detectors") && script.contains("--path");
    assert!(
        uses_canonical || uses_path_detectors,
        "scripts/pre-commit must either invoke the canonical `keyhog {CANONICAL_SCAN_ARGS}` or keep its documented `--path`/`--detectors` staged-tree-copy form"
    );
}
