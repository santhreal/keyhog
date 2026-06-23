use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct DiffArgs {
    /// Baseline file A (the "before" / older state).
    pub before: PathBuf,
    /// Baseline file B (the "after" / newer state).
    pub after: PathBuf,
    /// Suppress the `UNCHANGED` section (default: shown).
    #[arg(long)]
    pub hide_unchanged: bool,
    /// Emit results as JSON instead of human-readable text. Useful for CI
    /// that wants to gate merges on regressions programmatically.
    #[arg(long)]
    pub json: bool,
}
