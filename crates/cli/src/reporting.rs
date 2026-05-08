//! Report formatting and delivery for the KeyHog CLI.

use crate::args::{OutputFormat, ScanArgs};
use anyhow::{Context, Result};
use keyhog_core::{
    JsonReporter, JsonlReporter, Reporter, SarifReporter, TextReporter, VerifiedFinding,
};
use std::io::{self, IsTerminal};

pub fn report_findings(findings: &[VerifiedFinding], args: &ScanArgs) -> Result<()> {
    if let Some(ref path) = args.output {
        // Atomic-write the report file. A partial SARIF/JSON output
        // breaks downstream tooling (GitHub code scanning rejects
        // malformed SARIF; CI gates fail to parse JSON). Write to
        // a NamedTempFile in the target directory, let the reporter
        // flush + finish, then atomic-rename. If keyhog crashes
        // mid-report (panic, OOM, kill), the user's previous
        // report file is untouched and the tmp gets reaped by Drop.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating output parent dir {}", parent.display()))?;
        let tmp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("creating output tmp in {}", parent.display()))?;
        let writer_handle = tmp.reopen().with_context(|| {
            format!("reopening output tmp for write of {}", path.display())
        })?;
        let w = io::BufWriter::new(writer_handle);
        report_with(w, &args.format, false, findings)?;
        // BufWriter is dropped inside report_with's flush path;
        // sync the tempfile's backing file before atomic rename so
        // a crash between persist and the next fsync of the parent
        // dir doesn't lose data on filesystems with delayed
        // metadata writeback.
        tmp.as_file().sync_all().with_context(|| {
            format!("fsyncing output tmp for {}", path.display())
        })?;
        tmp.persist(path)
            .map_err(|e| e.error)
            .with_context(|| format!("renaming output tmp onto {}", path.display()))?;
        Ok(())
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
