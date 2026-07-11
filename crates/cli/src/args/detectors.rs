use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser)]
pub struct DetectorArgs {
    /// Detector TOML directory
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    /// Filter detectors by substring match (case-insensitive) against id,
    /// name, service, and keywords (e.g. `keyhog detectors --search aws`).
    ///
    /// The short `--help` line is intentionally count-free; the long `--help`
    /// (rendered via [`crate::args::command`]) injects the live embedded
    /// detector count so the cited corpus size can never drift from the
    /// detectors actually compiled into this binary.
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
    /// blocks: the one fix the interpolator's contract makes safe to
    /// perform mechanically. Other validator findings are left alone
    /// (they need human judgement). Use `--dry-run` to preview rewrites
    /// without touching the filesystem.
    #[arg(long, conflicts_with = "audit")]
    pub fix: bool,
    /// Show the rewrites `--fix` *would* make without writing them. No-op
    /// unless `--fix` is also set.
    #[arg(long, requires = "fix")]
    pub dry_run: bool,
    /// Output format for the detector listing. `text` (default) is the grouped,
    /// human-readable summary; `json` emits the structured detector array. This
    /// is the canonical flag — it matches `scan --format` so the
    /// two surfaces share one convention (CLI-01). Only `text`/`json` apply to a
    /// detector listing, so the format set is intentionally narrower than
    /// `scan`'s. Mutually exclusive with `--audit` / `--fix` (they emit their own
    /// structured formats).
    #[arg(long, value_enum, conflicts_with_all = ["audit", "fix", "json"])]
    pub format: Option<DetectorFormat>,
    /// Compatibility spelling for `--format json`. It remains accepted with a
    /// visible migration warning but is hidden from the canonical help surface.
    #[arg(long, hide = true, conflicts_with_all = ["audit", "fix"])]
    pub json: bool,
}

/// Output formats valid for the `detectors` listing. Deliberately a narrow
/// pair (not the full [`super::OutputFormat`]): a detector listing has exactly
/// one structured form (JSON) and one human form (text); SARIF/JUnit/CSV/HTML
/// are findings-report shapes with no meaning here, so offering them would be
/// an incoherent surface. Shares the `--format` flag *name* with `scan` for
/// convention parity (CLI-01) without sharing the irrelevant variants.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DetectorFormat {
    Text,
    Json,
}
