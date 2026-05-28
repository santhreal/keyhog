use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
pub struct DetectorArgs {
    /// Detector TOML directory
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    /// Filter detectors by substring match (case-insensitive) against id,
    /// name, service, and keywords. Useful for finding detectors in the
    /// 891-strong corpus (e.g. `keyhog detectors --search aws`).
    #[arg(short, long)]
    pub search: Option<String>,
    /// Print full detector spec (regex, prefixes, keywords) instead of
    /// the grouped service summary. Pairs naturally with `--search`.
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
    /// Audit detectors against the quality gate (`keyhog_core::validate_detector`).
    /// Prints every issue grouped by detector and exits non-zero (3) if any
    /// `Error`-severity issue was found. Warnings are reported but do not
    /// fail the run. Pairs with `--detectors <DIR>` for CI gating.
    #[arg(long, conflicts_with = "fix")]
    pub audit: bool,
    /// Apply safe automated fixes to the detector TOMLs in `--detectors`.
    /// Currently rewrites single-brace template references (`{name}`) to
    /// the double-brace form (`{{name}}`) within `[detector.verify*]`
    /// blocks — the one fix the interpolator's contract makes safe to
    /// perform mechanically. Other validator findings are left alone
    /// (they need human judgement). Use `--dry-run` to preview rewrites
    /// without touching the filesystem.
    #[arg(long, conflicts_with = "audit")]
    pub fix: bool,
    /// Show the rewrites `--fix` *would* make without writing them. No-op
    /// unless `--fix` is also set.
    #[arg(long, requires = "fix")]
    pub dry_run: bool,
    /// Emit the detector listing as a JSON array on stdout instead of the
    /// human-readable grouped summary. Pairs with `--search` for filtered
    /// programmatic discovery (CI gates, bench harnesses, IDE plugins).
    /// Mutually exclusive with `--audit` / `--fix` since those emit their
    /// own structured output formats. JSON shape mirrors the human surface:
    /// `[{ "id", "name", "service", "severity", "keywords": [..],
    /// "patterns": [{ "regex", "description", "group" }, ..],
    /// "companions": [{ "name", "regex", "within_lines", "required" }, ..],
    /// "verify": <bool> }, ..]`.
    #[arg(long, conflicts_with_all = ["audit", "fix"])]
    pub json: bool,
}
