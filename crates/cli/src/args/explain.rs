use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct ExplainArgs {
    /// Detector ID to explain (e.g. `aws-access-key`, `github-pat`).
    /// Use `keyhog detectors` to list available IDs.
    pub detector_id: String,

    /// Detector TOML directory; falls back to the embedded corpus when
    /// missing. Same semantics as `keyhog detectors --detectors`.
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
}
