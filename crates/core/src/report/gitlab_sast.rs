//! GitLab SAST security-report JSON reporter.

use std::io::Write;

use crate::{Severity, VerifiedFinding};

use super::{ReportError, Reporter, WriterBackedReporter};

const SCHEMA_VERSION: &str = "15.2.4";
const SCHEMA_URL: &str = "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/sast-report-format.json";

/// GitLab SAST security-report JSON reporter.
pub(crate) struct GitlabSastReporter<W: Write + Send> {
    writer: W,
    scan_started_at: String,
    scan_finished_at: String,
    prefix_written: bool,
    first_vulnerability: bool,
}

impl<W: Write + Send> GitlabSastReporter<W> {
    /// Create a GitLab SAST reporter.
    pub(crate) fn new(writer: W, scan_started_at: String, scan_finished_at: String) -> Self {
        Self {
            writer,
            scan_started_at,
            scan_finished_at,
            prefix_written: false,
            first_vulnerability: true,
        }
    }

    fn ensure_prefix(&mut self) -> Result<(), ReportError> {
        if self.prefix_written {
            return Ok(());
        }
        write!(self.writer, "{{\"version\":")?;
        serde_json::to_writer(&mut self.writer, SCHEMA_VERSION)?;
        write!(self.writer, ",\"schema\":")?;
        serde_json::to_writer(&mut self.writer, SCHEMA_URL)?;
        write!(self.writer, ",\"scan\":")?;
        serde_json::to_writer(
            &mut self.writer,
            &scan_object(&self.scan_started_at, &self.scan_finished_at),
        )?;
        write!(self.writer, ",\"vulnerabilities\":[")?;
        self.prefix_written = true;
        Ok(())
    }
}

impl<W: Write + Send> Reporter for GitlabSastReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        let vulnerability = vulnerability_object(finding)?;
        self.ensure_prefix()?;
        if self.first_vulnerability {
            self.first_vulnerability = false;
        } else {
            write!(self.writer, ",")?;
        }
        serde_json::to_writer(&mut self.writer, &vulnerability)?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.ensure_prefix()?;
        write!(self.writer, "],\"remediations\":[]}}")?;
        self.flush_writer()
    }
}

impl<W: Write + Send> WriterBackedReporter for GitlabSastReporter<W> {
    type Writer = W;

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }
}

fn scan_object(scan_started_at: &str, scan_finished_at: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "sast",
        "status": "success",
        "start_time": scan_started_at,
        "end_time": scan_finished_at,
        "analyzer": analyzer_object(),
        "scanner": scanner_object(),
    })
}

fn analyzer_object() -> serde_json::Value {
    serde_json::json!({
        "id": "keyhog",
        "name": "KeyHog",
        "version": env!("CARGO_PKG_VERSION"),
        "vendor": {
            "name": "Santh Security"
        },
        "url": "https://github.com/santhsecurity/keyhog"
    })
}

fn scanner_object() -> serde_json::Value {
    serde_json::json!({
        "id": "keyhog",
        "name": "KeyHog",
        "version": env!("CARGO_PKG_VERSION"),
        "vendor": {
            "name": "Santh Security"
        },
        "url": "https://github.com/santhsecurity/keyhog"
    })
}

fn vulnerability_object(finding: &VerifiedFinding) -> Result<serde_json::Value, ReportError> {
    let file = gitlab_file(finding)?;
    let start_line = gitlab_start_line(finding)?;
    let credential_hash = crate::hex_encode(&finding.credential_hash);
    let id = format!(
        "keyhog:{}:{}:{}:{}",
        finding.detector_id, credential_hash, file, start_line
    );
    let name = format!("{} credential detected", finding.service);
    let message = format!(
        "{} found by {} at {}:{}",
        finding.detector_name, finding.detector_id, file, start_line
    );

    Ok(serde_json::json!({
        "id": id,
        "category": "sast",
        "name": name,
        "message": message,
        "description": format!(
            "KeyHog detected a redacted {} credential. Rotate the credential and remove it from source control.",
            finding.service
        ),
        "severity": gitlab_severity(finding.severity),
        "solution": "Rotate this credential, revoke the exposed value, and load the replacement from a secret manager or CI secret variable.",
        "scanner": scanner_object(),
        "identifiers": [
            {
                "type": "keyhog_rule",
                "name": finding.detector_name.as_ref(),
                "value": finding.detector_id.as_ref()
            }
        ],
        "location": {
            "file": file,
            "start_line": start_line
        },
        "details": {
            "credential": {
                "name": "Redacted credential",
                "type": "text",
                "value": finding.credential_redacted.as_ref()
            },
            "service": {
                "name": "Service",
                "type": "text",
                "value": finding.service.as_ref()
            },
            "credential_hash": {
                "name": "Credential hash",
                "type": "text",
                "value": credential_hash
            }
        }
    }))
}

fn gitlab_file(finding: &VerifiedFinding) -> Result<&str, ReportError> {
    match finding.location.file_path.as_deref() {
        Some(path) if !path.is_empty() => Ok(path),
        _ => anyhow::bail!(
            "GitLab SAST output requires a non-empty file path for every finding; \
             finding {} from source {} has no file path. Use --format json or --format sarif for non-file sources.",
            finding.detector_id,
            finding.location.source
        ),
    }
}

fn gitlab_start_line(finding: &VerifiedFinding) -> Result<usize, ReportError> {
    match finding.location.line {
        Some(line) if line > 0 => Ok(line),
        _ => anyhow::bail!(
            "GitLab SAST output requires a one-based line number for every finding; \
             finding {} in {} has no line. Use --format json or --format sarif for non-line sources.",
            finding.detector_id,
            finding.location.source
        ),
    }
}

fn gitlab_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::ClientSafe | Severity::Info => "Info",
    }
}
