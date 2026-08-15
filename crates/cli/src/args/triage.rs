use clap::Parser;
use std::path::PathBuf;

/// Import redacted findings and emit separate suppression and training artifacts.
#[derive(Debug, Parser)]
pub struct TriageArgs {
    /// Current versioned redacted finding envelope
    #[arg(long, value_name = "PATH")]
    pub input: PathBuf,

    /// New file for immediate scoped runtime suppressions
    #[arg(long, value_name = "PATH")]
    pub suppressions: PathBuf,

    /// New file for pattern-training feedback
    #[arg(long, value_name = "PATH")]
    pub pattern_feedback: PathBuf,
}
