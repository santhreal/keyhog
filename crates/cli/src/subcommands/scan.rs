//! Logic for the `scan` subcommand.

use crate::args::ScanArgs;
use crate::orchestrator::ScanOrchestrator;
use anyhow::Result;
use std::process::ExitCode;

pub async fn run(args: ScanArgs) -> Result<ExitCode> {
    let orchestrator = ScanOrchestrator::new(args)?;
    orchestrator.run().await
}
