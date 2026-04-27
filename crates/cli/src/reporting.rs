//! Report formatting and delivery for the KeyHog CLI.

use crate::args::{OutputFormat, ScanArgs};
use anyhow::{Context, Result};
use keyhog_core::{
    JsonReporter, JsonlReporter, Reporter, SarifReporter, TextReporter, VerifiedFinding,
};
use std::io::{self, IsTerminal};

pub fn report_findings(findings: &[VerifiedFinding], args: &ScanArgs) -> Result<()> {
    if let Some(ref path) = args.output {
        let file = std::fs::File::create(path)
            .with_context(|| format!("creating output file {}", path.display()))?;
        let w = io::BufWriter::new(file);
        report_with(w, &args.format, false, findings)
    } else {
        let w = io::BufWriter::new(io::stdout());
        report_with(w, &args.format, io::stdout().is_terminal(), findings)
    }
}

fn report_with<W: std::io::Write + 'static + Send>(
    w: W,
    format: &OutputFormat,
    color: bool,
    findings: &[VerifiedFinding],
) -> Result<()> {
    match format {
        OutputFormat::Text => finish_reporter(TextReporter::with_color(w, color), findings),
        OutputFormat::Json => finish_reporter(JsonReporter::new(w)?, findings),
        OutputFormat::Jsonl => finish_reporter(JsonlReporter::new(w), findings),
        OutputFormat::Sarif => finish_reporter(SarifReporter::new(w), findings),
    }
}

fn finish_reporter<R: Reporter>(mut reporter: R, findings: &[VerifiedFinding]) -> Result<()> {
    for finding in findings {
        reporter.report(finding)?;
    }
    reporter.finish()?;
    Ok(())
}
