//! CLI-08 surface gate: pin the CLI's two bloat-prone axes — the top-level
//! subcommand set and the `scan` long-flag set — so neither can grow (or
//! silently churn via rename) without a deliberate edit to this file.
//!
//! The backlog (cli-surface-bloat.md) flags the concern directly: "scan carries
//! 68 flags; the binary exposes 18 subcommands. Surface this large is hard to
//! keep coherent, document, and test." This gate makes every addition show up
//! as a failing test that names exactly what was added/removed, forcing the
//! author to (a) confirm the new surface is intentional and (b) update the
//! pinned list — which is the audit trail.
//!
//! It introspects the SAME canonical `clap::Command` the binary runs
//! (`keyhog::args::command()`), not rendered `--help` text, so it can't be
//! fooled by help-formatting changes and never spawns a process.

use std::collections::BTreeSet;

use keyhog::args::command;

/// Top-level subcommands that are ALWAYS compiled in (no feature gate). The one
/// feature-gated verb, `tui` (`#[cfg(feature = "tui")]` on `Command::Tui`), is
/// added conditionally in [`expected_subcommands`] so this gate matches the
/// compiled surface under ANY feature selection — `default`, `full`, `ci`, or a
/// custom mix — instead of only passing under the feature set the test happened
/// to be built with. Adding a subcommand is a deliberate surface-growth
/// decision: update the right list (base here, or the matching `#[cfg]` block in
/// [`expected_subcommands`]) in the same change and justify the new verb.
const BASE_SUBCOMMANDS: &[&str] = &[
    "backend",
    "calibrate",
    "completion",
    "daemon",
    "detectors",
    "diff",
    "doctor",
    "explain",
    "hook",
    "repair",
    "scan",
    "scan-system",
    "uninstall",
    "update",
    "watch",
];

/// Build the expected top-level subcommand set for the CURRENTLY-COMPILED
/// feature selection: the unconditional [`BASE_SUBCOMMANDS`] plus any
/// feature-gated verb whose `#[cfg]` is active in this build. The gates here
/// MUST mirror the `#[cfg(feature = ...)]` attributes on the `Command` variants
/// in `args.rs`, so the snapshot is feature-robust (Law 10: no silent surface
/// drift hidden behind a feature flag).
fn expected_subcommands() -> BTreeSet<String> {
    let mut set: BTreeSet<String> = BASE_SUBCOMMANDS.iter().map(|s| s.to_string()).collect();
    // `Command::Tui` is `#[cfg(feature = "tui")]` (default-on, off under `ci`).
    #[cfg(feature = "tui")]
    set.insert("tui".to_string());
    set
}

/// `scan` long-flags that are ALWAYS compiled in (no feature gate). This is the
/// 68-flag monster the backlog calls out; the feature-gated source/verify/binary
/// flags are layered on in [`expected_scan_long_flags`] under the SAME `#[cfg]`
/// gates the real args carry, so a new flag fails this gate until it is added
/// here (or in the matching cfg block) on purpose. A rename shows up as one
/// removal + one addition, so churn is caught too.
const BASE_SCAN_LONG_FLAGS: &[&str] = &[
    "backend",
    "baseline",
    "benchmark",
    "config",
    "create-baseline",
    "daemon",
    "decode-depth",
    "decode-size-limit",
    "dedup",
    "deep",
    "detectors",
    "dogfood",
    "entropy-source-files",
    "entropy-threshold",
    "exclude-paths",
    "fast",
    "format",
    "hide-client-safe",
    "incremental",
    "incremental-cache",
    "lockdown",
    "max-file-size",
    "min-confidence",
    "ml-threshold",
    "ml-weight",
    // `--no-config`: hermetic run on the compiled-in Tier-A shipped defaults,
    // rejecting ambient `.keyhog.toml` discovery (conflicts_with = "config";
    // backlog MC-07). Unconditional — not feature-gated.
    "no-config",
    "no-daemon",
    "no-decode",
    "no-default-excludes",
    "no-entropy",
    "no-entropy-ml-scoring",
    "no-keyword-low-entropy",
    "no-ml",
    "no-suppress-test-fixtures",
    "no-unicode-norm",
    "output",
    "path",
    "precision",
    "progress",
    "rate",
    "regex-dfa-limit",
    "scan-comments",
    "severity",
    "show-secrets",
    "source",
    "stdin",
    "stream",
    "threads",
    "timeout",
    "update-baseline",
];

/// Build the expected `scan` long-flag set for the CURRENTLY-COMPILED feature
/// selection. Mirrors every `#[cfg(feature = ...)]` on a `ScanArgs` field
/// (`args/scan.rs`): `git`/`github`/`s3`/`docker`/`web` source flags, the
/// `any(web,github,s3)` network knobs (`proxy`/`insecure`), the `verify` cluster,
/// and the opt-in `binary` (Ghidra) flag. Keeping these gates in lockstep with
/// the args is what makes the snapshot pass under `default`, `full`, AND `ci`.
fn expected_scan_long_flags() -> BTreeSet<String> {
    let mut set: BTreeSet<String> = BASE_SCAN_LONG_FLAGS.iter().map(|s| s.to_string()).collect();
    let mut add = |f: &str| {
        set.insert(f.to_string());
    };
    #[cfg(feature = "git")]
    {
        add("git-blobs");
        add("git-diff");
        add("git-diff-path");
        add("git-history");
        add("git-staged");
        add("max-commits");
    }
    #[cfg(feature = "github")]
    {
        add("github-org");
        add("github-token");
    }
    #[cfg(feature = "s3")]
    {
        add("s3-bucket");
        add("s3-endpoint");
        add("s3-prefix");
    }
    #[cfg(feature = "docker")]
    add("docker-image");
    #[cfg(feature = "web")]
    add("url");
    #[cfg(any(feature = "web", feature = "github", feature = "s3"))]
    {
        add("proxy");
        add("insecure");
    }
    #[cfg(feature = "verify")]
    {
        add("verify");
        add("verify-batch");
        add("verify-oob");
        add("verify-rate");
        add("oob-server");
        add("oob-timeout");
    }
    #[cfg(feature = "binary")]
    add("binary");
    // Silence the unused-closure warning when no source/verify feature is on
    // (e.g. `--features ci`): `add` is only invoked inside cfg blocks.
    let _ = &mut add;
    set
}

/// Format the symmetric difference between expected and actual surfaces so a
/// failure tells the maintainer EXACTLY what changed and which way.
fn diff_message(kind: &str, expected: &BTreeSet<String>, actual: &BTreeSet<String>) -> String {
    let added: Vec<&String> = actual.difference(expected).collect();
    let removed: Vec<&String> = expected.difference(actual).collect();
    format!(
        "{kind} surface drifted from the pinned snapshot (CLI-08).\n  \
         ADDED (present in binary, missing from snapshot): {added:?}\n  \
         REMOVED (in snapshot, gone from binary): {removed:?}\n  \
         If this change is intentional, update {} in \
         crates/cli/tests/gate/cli_surface_snapshot.rs in the SAME commit \
         (a feature-gated flag goes in the matching `#[cfg]` block of the \
         builder, NOT the base list).",
        if kind == "subcommand" {
            "BASE_SUBCOMMANDS / expected_subcommands()"
        } else {
            "BASE_SCAN_LONG_FLAGS / expected_scan_long_flags()"
        },
    )
}

#[test]
fn top_level_subcommand_set_matches_pinned_snapshot() {
    let cmd = command();
    let actual: BTreeSet<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .filter(|name| name != "help")
        .collect();
    let expected = expected_subcommands();
    assert_eq!(actual, expected, "{}", diff_message("subcommand", &expected, &actual));
}

#[test]
fn scan_long_flag_set_matches_pinned_snapshot() {
    let cmd = command();
    let scan = cmd
        .get_subcommands()
        .find(|s| s.get_name() == "scan")
        .expect("scan subcommand must exist");
    let actual: BTreeSet<String> = scan
        .get_arguments()
        .filter_map(|a| a.get_long())
        .map(str::to_string)
        .filter(|long| long != "help")
        .collect();
    let expected = expected_scan_long_flags();
    assert_eq!(actual, expected, "{}", diff_message("scan flag", &expected, &actual));
}
