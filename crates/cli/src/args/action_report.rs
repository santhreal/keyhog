//! Hidden arguments for the composite Action's bound report receipt.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct ActionReportArgs {
    #[command(subcommand)]
    pub command: ActionReportCommand,
}

#[derive(Debug, Subcommand)]
pub enum ActionReportCommand {
    /// Verify a bounded scan receipt against the exact report bytes
    Verify(ActionReportVerifyArgs),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ActionReportFormat {
    Sarif,
    Json,
    Jsonl,
    Text,
}

impl std::fmt::Display for ActionReportFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Sarif => "sarif",
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Text => "text",
        })
    }
}

#[derive(Debug, Parser)]
pub struct ActionReportVerifyArgs {
    #[arg(long)]
    pub receipt: PathBuf,
    #[arg(long)]
    pub report: PathBuf,
    #[arg(long, value_enum)]
    pub format: ActionReportFormat,
    #[arg(long, value_name = "CODE")]
    pub exit_code: u8,
}
