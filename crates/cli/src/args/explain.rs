use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct ExplainArgs {
    /// Detector ID to explain (e.g. `aws-access-key`, `github-pat-fine-grained`).
    /// Use `keyhog detectors` to list available IDs.
    pub detector_id: String,

    /// Detector TOML directory. When omitted, KeyHog discovers an installed
    /// corpus or uses the embedded corpus. An explicitly named missing path is
    /// an error.
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,

    /// Read a `bloom-evidence-v1` receipt produced by `keyhog bloom-diagnostic`.
    /// The receipt must match the selected detector corpus and prove exact
    /// enabled-versus-bypassed finding parity.
    #[arg(long, value_name = "PATH")]
    pub bloom_evidence: Option<PathBuf>,

    /// Print the detector's compiled evidence plan, including resolved capture
    /// groups, direction, structural scope, and admission semantics.
    #[arg(long)]
    pub compiled_plan: bool,

    #[arg(skip)]
    pub(crate) detectors_cli_explicit: bool,
}
