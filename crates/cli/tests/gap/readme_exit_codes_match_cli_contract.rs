//! KH-GAP-095: README exit-code table must match `Cli::after_help` and orchestrator constants.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

/// Every exit code the binary can return must have its own row in the README
/// table. Derived from `exit_codes::DEFINITIONS` at run time, so adding a code
/// turns this RED until the README documents it. The previous version pinned
/// five hand-picked prose fragments, which could not see a new code at all and
/// broke on any rewording of the ones it did pin.
#[test]
fn readme_documents_full_exit_code_contract() {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    let table: String = readme
        .lines()
        .skip_while(|l| !l.starts_with("| Exit | Meaning |"))
        .take_while(|l| l.starts_with('|'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !table.is_empty(),
        "README must contain the `| Exit | Meaning |` exit-code table"
    );

    let missing: Vec<u8> = keyhog::exit_codes::DEFINITIONS
        .iter()
        .map(|d| d.code)
        .filter(|code| !table.contains(&format!("| `{code}` ")))
        .collect();
    assert!(
        missing.is_empty(),
        "README exit-code table is missing a row for exit code(s) {missing:?}; table:\n{table}"
    );

    // The table must not invent codes the binary cannot return.
    let documented: Vec<u8> = table
        .lines()
        .filter_map(|l| l.split('`').nth(1))
        .filter_map(|c| c.parse::<u8>().ok())
        .collect();
    let undefined: Vec<u8> = documented
        .iter()
        .copied()
        .filter(|c| !keyhog::exit_codes::DEFINITIONS.iter().any(|d| d.code == *c))
        .collect();
    assert!(
        undefined.is_empty(),
        "README documents exit code(s) {undefined:?} that no `DEFINITIONS` entry defines"
    );
}
