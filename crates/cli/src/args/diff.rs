use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct DiffArgs {
    /// Baseline file A, or the older artifact when --artifacts is set.
    pub before: PathBuf,
    /// Baseline file B, or the newer artifact when --artifacts is set.
    pub after: PathBuf,
    /// Scan the two inputs as artifacts instead of loading baseline JSON.
    #[arg(long)]
    pub artifacts: bool,
    /// Verify credentials found only in the older artifact.
    #[arg(long, requires = "artifacts")]
    pub verify_removed: bool,
    /// Detector TOML directory used by --artifacts (default: auto-discover).
    #[arg(long, requires = "artifacts")]
    pub detectors: Option<PathBuf>,
    /// Maximum bytes read from each artifact (default: 67108864).
    #[arg(long, requires = "artifacts")]
    pub max_artifact_bytes: Option<u64>,
    /// Per-credential verification timeout in seconds (default: 5).
    #[arg(long, requires = "verify_removed")]
    pub verify_timeout: Option<u64>,
    /// Suppress the `UNCHANGED` section (default: shown).
    #[arg(long)]
    pub hide_unchanged: bool,
    /// Emit results as JSON instead of human-readable text. Useful for CI
    /// that wants to gate merges on regressions programmatically.
    #[arg(long)]
    pub json: bool,
}
