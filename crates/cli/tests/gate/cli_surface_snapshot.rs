//! CLI-08 surface gate: pin the CLI's two bloat-prone axes — the top-level
//! subcommand set and the `scan` long-flag set — so neither can grow (or
//! silently churn via rename) without a deliberate edit to this file.
//!
//! This snapshot flags the concern directly: "scan carries
//! 73 unconditional flags; the binary exposes 17 subcommands. Surface this large is hard to
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

/// Top-level subcommands that are ALWAYS compiled in (no feature gate). Every
/// verb is currently unconditional, so [`expected_subcommands`] is just this
/// list — but the helper stays a function so a future feature-gated verb is
/// added under the SAME `#[cfg]` the `Command` variant carries, keeping the
/// gate feature-robust. Adding a subcommand is a deliberate surface-growth
/// decision: update this list in the same change and justify the new verb.
const BASE_SUBCOMMANDS: &[&str] = &[
    "backend",
    "calibrate",
    "calibrate-autoroute",
    "completion",
    "config",
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
    BASE_SUBCOMMANDS.iter().map(|s| s.to_string()).collect()
}

/// `scan` long-flags that are ALWAYS compiled in (no feature gate). This is the
/// 73-flag base this snapshot protects; the feature-gated source/verify/binary
/// flags are layered on in [`expected_scan_long_flags`] under the SAME `#[cfg]`
/// gates the real args carry, so a new flag fails this gate until it is added
/// here (or in the matching cfg block) on purpose. A rename shows up as one
/// removal + one addition, so churn is caught too.
const BASE_SCAN_LONG_FLAGS: &[&str] = &[
    "autoroute-cache",
    "autoroute-calibrate",
    "autoroute-gpu",
    "backend",
    "baseline",
    "batch-pipeline",
    "benchmark",
    "cache-dir",
    "calibration-cache",
    "config",
    "create-baseline",
    "daemon",
    "daemon-socket",
    "decode-depth",
    "decode-size-limit",
    "dedup",
    "deep",
    "detectors",
    "dogfood",
    "entropy-bpe-max-bytes-per-token",
    "entropy-source-files",
    "entropy-threshold",
    "exclude-paths",
    "fast",
    "format",
    "fused-batch",
    "fused-depth",
    "hide-client-safe",
    "incremental",
    "incremental-cache",
    "limit-stdin-bytes",
    "lockdown",
    "max-file-size",
    "gpu-batch-input-limit",
    "min-confidence",
    "min-secret-len",
    "ml-threshold",
    "ml-weight",
    // `--no-config`: hermetic run on the compiled-in Tier-A shipped defaults,
    // rejecting ambient `.keyhog.toml` discovery (conflicts_with = "config";
    // hermetic config enforcement). Unconditional — not feature-gated.
    "no-config",
    "no-autoroute-gpu",
    "no-batch-pipeline",
    "no-daemon",
    "no-decode",
    "no-default-excludes",
    "no-entropy",
    "no-entropy-ml-scoring",
    "no-keyword-low-entropy",
    "no-ml",
    "no-gpu",
    "no-color",
    "no-suppress-test-fixtures",
    "no-unicode-norm",
    "output",
    "path",
    "per-chunk-timeout-ms",
    "perf-trace",
    "precision",
    "profile",
    "progress",
    "quiet",
    "rate",
    "regex-dfa-limit",
    "reader-threads",
    "require-gpu",
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
/// (`args/scan.rs`): `git`/`github`/`s3`/`gcs`/`azure`/`docker`/`web` source flags, the
/// network knobs (`proxy`/`insecure`), the `verify` cluster,
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
        add("limit-git-blob-bytes");
        add("limit-git-chunks");
        add("limit-git-line-bytes");
        add("limit-git-total-bytes");
        add("max-commits");
    }
    #[cfg(feature = "github")]
    {
        add("github-org");
        add("github-token");
    }
    #[cfg(feature = "gitlab")]
    {
        add("gitlab-endpoint");
        add("gitlab-group");
        add("gitlab-token");
    }
    #[cfg(feature = "bitbucket")]
    {
        add("bitbucket-endpoint");
        add("bitbucket-token");
        add("bitbucket-username");
        add("bitbucket-workspace");
    }
    #[cfg(feature = "gcs")]
    {
        add("allow-gcs-token-forward");
        add("gcs-bucket");
        add("gcs-endpoint");
        add("gcs-prefix");
        add("limit-gcs-object-bytes");
    }
    #[cfg(feature = "azure")]
    {
        add("azure-container-url");
        add("azure-prefix");
        add("limit-azure-blob-bytes");
    }
    #[cfg(feature = "s3")]
    {
        add("allow-s3-credential-forward");
        add("limit-s3-object-bytes");
        add("s3-bucket");
        add("s3-endpoint");
        add("s3-prefix");
    }
    // `--limit-cloud-max-objects` caps object enumeration across ALL cloud
    // object stores, so it compiles in whenever ANY of s3/gcs/azure is active
    // (mirrors the `#[cfg(any(...))]` on the `limit_cloud_max_objects` arg).
    #[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
    {
        add("allow-private-cloud-endpoint");
        add("limit-cloud-max-objects");
    }
    // `--limit-hosted-git-pages` caps API pagination across ALL hosted-git
    // providers, compiled in whenever ANY of github/gitlab/bitbucket is active.
    #[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
    {
        add("limit-hosted-git-pages");
    }
    #[cfg(feature = "docker")]
    {
        add("docker-image");
        add("limit-docker-image-config-bytes");
        add("limit-docker-tar-entry-bytes");
        add("limit-docker-tar-total-bytes");
    }
    #[cfg(feature = "web")]
    {
        add("limit-web-response-bytes");
        add("url");
    }
    #[cfg(feature = "binary")]
    {
        add("binary");
        add("limit-binary-decompiled-bytes");
        add("limit-binary-read-bytes");
    }
    #[cfg(any(
        feature = "web",
        feature = "github",
        feature = "gitlab",
        feature = "bitbucket",
        feature = "s3",
        feature = "gcs",
        feature = "azure"
    ))]
    {
        add("proxy");
        add("insecure");
    }
    #[cfg(feature = "verify")]
    {
        add("allow-script-verify");
        add("verify");
        add("verify-batch");
        add("verify-oob");
        add("verify-rate");
        add("oob-server");
        add("oob-timeout");
    }
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
    assert_eq!(
        actual,
        expected,
        "{}",
        diff_message("subcommand", &expected, &actual)
    );
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
    assert_eq!(
        actual,
        expected,
        "{}",
        diff_message("scan flag", &expected, &actual)
    );
}
