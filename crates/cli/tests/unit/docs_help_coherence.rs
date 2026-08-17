//! KH-087: docs/help coherence test suite.
//!
//! These tests drive the live `clap::Command` model exposed by
//! `keyhog::args::command()` and prove that `docs/src/reference/cli.md` stays
//! in sync. The reference keeps curated prose for semantics, precedence, and
//! workflow guidance; the command/flag tables inside the marked regions are
//! generated from the real model so they cannot drift.

use clap::{Arg, Command};
use std::path::PathBuf;

fn root_command() -> clap::Command {
    keyhog::args::command()
}

fn reference_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/src/reference/cli.md")
}

fn reference_source() -> String {
    std::fs::read_to_string(reference_path()).expect("cli.md should be readable")
}

fn generated_commands(source: &str) -> Vec<&str> {
    source
        .lines()
        .filter_map(|line| {
            line.strip_prefix(keyhog::cli_reference::MARKER_OPEN)?
                .strip_suffix(keyhog::cli_reference::MARKER_CLOSE)
        })
        .collect()
}

fn table_row<'a>(rendered: &'a str, argument: &str) -> &'a str {
    let prefix = format!("| {argument} |");
    rendered
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("generated table is missing row for {argument}"))
}

fn table_columns<'a>(rendered: &'a str, argument: &str) -> Vec<&'a str> {
    table_row(rendered, argument)
        .strip_prefix("| ")
        .expect("table row should start with a column delimiter")
        .strip_suffix(" |")
        .expect("table row should end with a column delimiter")
        .split(" | ")
        .collect()
}

/// CI drift gate: the committed `cli.md` must match the regenerated output.
///
/// Run with `UPDATE_CLI_REFERENCE=1` and the focused library test to refresh
/// generated blocks after an intentional command-model change.
#[test]
fn cli_reference_renders_without_drift() {
    let source = reference_source();
    let regenerated = keyhog::cli_reference::regenerate(&source, &root_command());

    if std::env::var("UPDATE_CLI_REFERENCE").as_deref() == Ok("1") {
        std::fs::write(reference_path(), &regenerated).expect("cli.md should be writable");
    }

    let committed = reference_source();
    assert_eq!(
        committed, regenerated,
        "docs/src/reference/cli.md is out of sync with the live clap command model. \
         Run `UPDATE_CLI_REFERENCE=1 cargo test -p keyhog --lib \
         cli_reference_renders_without_drift` to regenerate."
    );
}

/// Regeneration must be byte-identical: running it on already-generated output
/// should not change anything.
#[test]
fn cli_reference_regeneration_is_deterministic() {
    let source = reference_source();
    let once = keyhog::cli_reference::regenerate(&source, &root_command());
    let twice = keyhog::cli_reference::regenerate(&once, &root_command());
    assert_eq!(once, twice, "regeneration is not idempotent");
}

/// The document must contain exactly one block for the root and every visible
/// top-level command. This catches missing, duplicate, and orphaned sections.
#[test]
fn cli_reference_has_markers_for_all_commands() {
    let source = reference_source();
    let root = root_command();

    let mut expected = vec![""];
    expected.extend(
        root.get_subcommands()
            .filter(|command| !command.is_hide_set())
            .map(Command::get_name),
    );
    expected.sort_unstable();

    let mut actual = generated_commands(&source);
    actual.sort_unstable();

    assert_eq!(
        actual, expected,
        "generated block commands must exactly match the live visible command inventory"
    );
}

/// Nested subcommands (daemon start/stop/status, hook install/uninstall) are
/// rendered with both a summary table and per-subcommand flag tables.
#[test]
fn nested_subcommands_are_covered() {
    let daemon = keyhog::cli_reference::generate_for(&root_command(), "daemon");
    for sub in ["start", "stop", "status"] {
        assert!(
            daemon.contains(&format!("keyhog daemon {sub}")),
            "daemon subcommand `{sub}` missing from generated reference"
        );
    }
    assert!(
        daemon.contains("`--socket`"),
        "daemon start --socket missing"
    );
    assert!(
        daemon.contains("`--request-timeout-secs`"),
        "daemon start --request-timeout-secs missing"
    );

    let hook = keyhog::cli_reference::generate_for(&root_command(), "hook");
    assert!(hook.contains("keyhog hook install"), "hook install missing");
    assert!(
        hook.contains("keyhog hook uninstall"),
        "hook uninstall missing"
    );
    assert!(hook.contains("`--force`"), "hook install --force missing");

    let guard = keyhog::cli_reference::generate_for(&root_command(), "guard");
    for sub in [
        "add",
        "down",
        "list",
        "rebuild",
        "reconcile",
        "remove",
        "status",
        "up",
    ] {
        assert!(
            guard.contains(&format!("keyhog guard {sub}")),
            "guard subcommand `{sub}` missing from generated reference"
        );
    }
    assert!(guard.contains("`--socket`"), "guard add --socket missing");
    assert!(guard.contains("`--no-hook`"), "guard add --no-hook missing");
    assert!(
        guard.contains("`--keep-hook`"),
        "guard remove --keep-hook missing"
    );
}

/// Defaults, value arities, and possible-value lists must come from the built
/// command model. This prevents plausible-looking values elsewhere in the page
/// from satisfying the test for the wrong flag.
#[test]
fn defaults_value_enums_and_possible_values_are_documented() {
    let root = root_command();
    let scan = keyhog::cli_reference::generate_for(&root, "scan");

    let format = table_columns(&scan, "`--format`");
    assert_eq!(&format[..3], ["`--format`", "`FORMAT`", "`text`"]);
    assert_eq!(
        format[3],
        "Output format. `json` is a bare findings array for pipelines; prefer \
         `json-envelope` for scan status, coverage gaps, and backend recoveries \
         in one document (KH-1435 / KH-1474) Possible values: `text`, `json`, \
         `json-envelope`, `jsonl`, `jsonl-envelope`, `sarif`, `csv`, \
         `github-annotations`, `gitlab-sast`, `html`, `junit`."
    );

    let dedup = table_columns(&scan, "`--dedup`");
    assert_eq!(&dedup[..3], ["`--dedup`", "`DEDUP`", "`credential`"]);
    assert_eq!(
        dedup[3],
        "Deduplication scope for findings Possible values: `credential`, `file`, `none`."
    );

    let detectors_mode = table_columns(&scan, "`--detectors-mode`");
    assert_eq!(&detectors_mode[..3], ["`--detectors-mode`", "`MODE`", ""]);
    assert_eq!(
        detectors_mode[3],
        "How an explicitly selected custom corpus participates in the embedded \
         corpus. Omitted preserves the established replace behavior Possible \
         values: `replace`, `overlay`."
    );

    let config = keyhog::cli_reference::generate_for(&root, "config");
    assert_eq!(
        table_row(&config, "`--detectors-mode`"),
        table_row(&scan, "`--detectors-mode`"),
        "`config --effective` must document the same detector-mode contract as `scan`"
    );

    let daemon = table_columns(&scan, "`--daemon`");
    assert_eq!(
        &daemon[..3],
        ["`--daemon`", "`[auto\\|on\\|mass\\|off]`", ""]
    );

    let verify_rate = table_columns(&scan, "`--verify-rate`");
    assert_eq!(&verify_rate[..3], ["`--verify-rate`", "`RPS`", "`5.0`"]);

    let scan_system = keyhog::cli_reference::generate_for(&root, "scan-system");
    let space = table_columns(&scan_system, "`--space`");
    assert_eq!(&space[..3], ["`--space`", "`SPACE`", "`50G`"]);
}

/// Hidden flags must remain in the generated inventory and be marked. An exact
/// synthetic table guards both ordering and the visible hidden annotation.
#[test]
fn hidden_flags_are_covered() {
    let cmd = Command::new("test")
        .disable_help_flag(true)
        .arg(Arg::new("visible").long("visible").help("A visible flag"))
        .arg(
            Arg::new("hidden")
                .long("hidden")
                .help("A hidden flag")
                .hide(true),
        );

    let generated = keyhog::cli_reference::generate_for(&cmd, "");
    assert_eq!(
        generated,
        "| Argument | Value | Default | Description |\n\
         |----------|-------|---------|-------------|\n\
         | `--hidden` *(hidden)* | `HIDDEN` |  | A hidden flag |\n\
         | `--visible` | `VISIBLE` |  | A visible flag |\n"
    );
}

/// Markdown-special characters in help text must be escaped so generated
/// tables remain valid mdBook tables. The exact fragment guards every column.
#[test]
fn markdown_special_characters_are_escaped() {
    let cmd = Command::new("test").disable_help_flag(true).arg(
        Arg::new("x")
            .long("x")
            .help("Use A | B <C> & D and `left|right`"),
    );

    let generated = keyhog::cli_reference::generate_for(&cmd, "");
    assert_eq!(
        generated,
        "| Argument | Value | Default | Description |\n\
         |----------|-------|---------|-------------|\n\
         | `--x` | `X` |  | Use A \\| B &lt;C&gt; &amp; D and `left\\|right` |\n"
    );
}

/// Command and argument aliases must appear exactly as operators can type
/// them; this prevents a long alias from being mislabeled as a short option.
#[test]
fn aliases_are_covered() {
    let args = Command::new("test").disable_help_flag(true).arg(
        Arg::new("fast")
            .long("fast")
            .visible_short_alias('f')
            .help("Fast"),
    );
    assert_eq!(
        keyhog::cli_reference::generate_for(&args, ""),
        "| Argument | Value | Default | Description |\n\
         |----------|-------|---------|-------------|\n\
         | `--fast`, `-f` | `FAST` |  | Fast |\n"
    );

    let commands = Command::new("test").subcommand(
        Command::new("group")
            .disable_help_subcommand(true)
            .subcommand(Command::new("start").visible_alias("go").about("Start")),
    );
    assert_eq!(
        keyhog::cli_reference::generate_for(&commands, "group"),
        "| Subcommand | Aliases | Description |\n\
         |------------|---------|-------------|\n\
         | `start` | `go` | Start |\n\n\
         ### `keyhog group start`\n\n\
         *No arguments.*\n\n"
    );
}

/// A synthetic hidden flag must alter the regenerated bytes and surface as an
/// exact row, proving the drift gate observes the built clap model itself.
#[test]
fn stale_help_model_is_caught() {
    let source = reference_source();
    let baseline = keyhog::cli_reference::regenerate(&source, &root_command());

    let stale = root_command().mut_subcommand("scan", |sub| {
        sub.arg(
            Arg::new("stale-test-flag")
                .long("stale-test-flag")
                .hide(true),
        )
    });

    let stale_doc = keyhog::cli_reference::regenerate(&source, &stale);
    assert_ne!(
        baseline, stale_doc,
        "an extra hidden flag must change the regenerated reference"
    );
    assert_eq!(
        table_row(&stale_doc, "`--stale-test-flag` *(hidden)*"),
        "| `--stale-test-flag` *(hidden)* | `STALE-TEST-FLAG` |  | *No description.* |"
    );
}
