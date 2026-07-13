use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct ExplainArgs {
    /// Detector ID to explain (e.g. `aws-access-key`, `github-pat`).
    /// Use `keyhog detectors` to list available IDs.
    pub detector_id: String,

    /// Detector TOML directory. When omitted, KeyHog discovers an installed
    /// corpus or uses the embedded corpus. An explicitly named missing path is
    /// an error.
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,

    #[arg(skip)]
    pub(crate) detectors_cli_explicit: bool,
}
