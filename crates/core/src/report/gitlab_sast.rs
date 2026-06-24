//! GitLab SAST security-report JSON reporter.

use std::borrow::Cow;
use std::io::Write;

use crate::{Severity, VerifiedFinding};
use serde::Serialize;

use super::{impl_writer_backed, ReportError, Reporter, WriterBackedReporter};

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

impl_writer_backed!(GitlabSastReporter);

#[derive(Serialize)]
struct GitlabScan<'a> {
    #[serde(rename = "type")]
    scan_type: &'static str,
    status: &'static str,
    start_time: &'a str,
    end_time: &'a str,
    analyzer: GitlabTool,
    scanner: GitlabTool,
}

#[derive(Clone, Copy, Serialize)]
struct GitlabTool {
    id: &'static str,
    name: &'static str,
    version: &'static str,
    vendor: GitlabVendor,
    url: &'static str,
}

#[derive(Clone, Copy, Serialize)]
struct GitlabVendor {
    name: &'static str,
}

#[derive(Serialize)]
struct GitlabVulnerability<'a> {
    id: String,
    category: &'static str,
    name: String,
    message: String,
    description: String,
    severity: &'static str,
    solution: &'static str,
    scanner: GitlabTool,
    identifiers: [GitlabIdentifier<'a>; 1],
    location: GitlabLocation<'a>,
    details: GitlabDetails<'a>,
}

#[derive(Serialize)]
struct GitlabIdentifier<'a> {
    #[serde(rename = "type")]
    identifier_type: &'static str,
    name: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct GitlabLocation<'a> {
    file: &'a str,
    start_line: usize,
}

#[derive(Serialize)]
struct GitlabDetails<'a> {
    credential: GitlabTextDetail<'a>,
    service: GitlabTextDetail<'a>,
    credential_hash: GitlabTextDetail<'a>,
}

#[derive(Serialize)]
struct GitlabTextDetail<'a> {
    name: &'static str,
    #[serde(rename = "type")]
    detail_type: &'static str,
    value: Cow<'a, str>,
}

fn scan_object<'a>(scan_started_at: &'a str, scan_finished_at: &'a str) -> GitlabScan<'a> {
    GitlabScan {
        scan_type: "sast",
        status: "success",
        start_time: scan_started_at,
        end_time: scan_finished_at,
        analyzer: keyhog_tool(),
        scanner: keyhog_tool(),
    }
}

fn keyhog_tool() -> GitlabTool {
    GitlabTool {
        id: "keyhog",
        name: "KeyHog",
        version: env!("CARGO_PKG_VERSION"),
        vendor: GitlabVendor {
            name: "Santh Security",
        },
        url: env!("CARGO_PKG_REPOSITORY"),
    }
}

fn vulnerability_object(finding: &VerifiedFinding) -> Result<GitlabVulnerability<'_>, ReportError> {
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

    Ok(GitlabVulnerability {
        id,
        category: "sast",
        name,
        message,
        description: format!(
            "KeyHog detected a redacted {} credential. Rotate the credential and remove it from source control.",
            finding.service
        ),
        severity: gitlab_severity(finding.severity),
        solution: "Rotate this credential, revoke the exposed value, and load the replacement from a secret manager or CI secret variable.",
        scanner: keyhog_tool(),
        identifiers: [GitlabIdentifier {
            identifier_type: "keyhog_rule",
            name: finding.detector_name.as_ref(),
            value: finding.detector_id.as_ref(),
        }],
        location: GitlabLocation { file, start_line },
        details: GitlabDetails {
            credential: GitlabTextDetail {
                name: "Redacted credential",
                detail_type: "text",
                value: Cow::Borrowed(finding.credential_redacted.as_ref()),
            },
            service: GitlabTextDetail {
                name: "Service",
                detail_type: "text",
                value: Cow::Borrowed(finding.service.as_ref()),
            },
            credential_hash: GitlabTextDetail {
                name: "Credential hash",
                detail_type: "text",
                value: Cow::Owned(credential_hash),
            },
        },
    })
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
