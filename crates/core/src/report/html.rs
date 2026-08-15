//! Dynamic themed HTML findings reporter.

use std::collections::BTreeMap;
use std::io::{self, Write};

use serde::ser::{SerializeStruct, Serializer};

use crate::{VerificationResult, VerifiedFinding};

use super::{impl_writer_backed, HtmlScanMetadata, ReportError, Reporter, WriterBackedReporter};

/// Streaming writer that keeps JSON safe inside an HTML script raw-text node.
///
/// It escapes tag delimiters, `/`, and the two JavaScript line separators
/// without materializing the serialized JSON document.
struct ScriptSafeWriter<'a, W: Write> {
    inner: &'a mut W,
    pending_e2: [u8; 3],
    pending_len: usize,
}

impl<'a, W: Write> ScriptSafeWriter<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            pending_e2: [0; 3],
            pending_len: 0,
        }
    }

    fn finish(self) -> io::Result<()> {
        if self.pending_len != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "JSON serializer ended inside a UTF-8 code point",
            ));
        }
        self.inner.flush()
    }

    fn write_escaped(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut run_start = 0usize;
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            let escaped = match bytes[cursor] {
                b'<' => Some(b"\\u003c".as_slice()),
                b'>' => Some(b"\\u003e".as_slice()),
                b'/' => Some(b"\\u002f".as_slice()),
                0xe2 if cursor + 2 < bytes.len()
                    && bytes[cursor + 1] == 0x80
                    && bytes[cursor + 2] == 0xa8 =>
                {
                    Some(b"\\u2028".as_slice())
                }
                0xe2 if cursor + 2 < bytes.len()
                    && bytes[cursor + 1] == 0x80
                    && bytes[cursor + 2] == 0xa9 =>
                {
                    Some(b"\\u2029".as_slice())
                }
                0xe2 if cursor + 2 >= bytes.len() => {
                    self.inner.write_all(&bytes[run_start..cursor])?;
                    let remaining = &bytes[cursor..];
                    self.pending_e2[..remaining.len()].copy_from_slice(remaining);
                    self.pending_len = remaining.len();
                    return Ok(());
                }
                _ => None,
            };
            if let Some(escaped) = escaped {
                self.inner.write_all(&bytes[run_start..cursor])?;
                self.inner.write_all(escaped)?;
                cursor += if bytes[cursor] == 0xe2 { 3 } else { 1 };
                run_start = cursor;
            } else {
                cursor += 1;
            }
        }
        self.inner.write_all(&bytes[run_start..])
    }
}

impl<W: Write> Write for ScriptSafeWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut consumed = 0usize;
        if self.pending_len != 0 {
            let needed = 3usize.saturating_sub(self.pending_len);
            let take = needed.min(bytes.len());
            self.pending_e2[self.pending_len..self.pending_len + take]
                .copy_from_slice(&bytes[..take]);
            self.pending_len += take;
            consumed += take;
            if self.pending_len < 3 {
                return Ok(bytes.len());
            }
            let prefix = [0xe2, self.pending_e2[1], self.pending_e2[2]];
            self.pending_len = 0;
            self.write_escaped(&prefix)?;
        }
        self.write_escaped(&bytes[consumed..])?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn write_script_json<W: Write, T: serde::Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), ReportError> {
    let mut safe = ScriptSafeWriter::new(writer);
    serde_json::to_writer(&mut safe, value)?;
    safe.finish()?;
    Ok(())
}

struct HtmlVerification<'a>(&'a VerificationResult);

impl serde::Serialize for HtmlVerification<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            VerificationResult::Error(_) => serializer.serialize_str("error"),
            verification => verification.serialize(serializer),
        }
    }
}

struct HtmlFinding<'a>(&'a VerifiedFinding);

impl serde::Serialize for HtmlFinding<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let finding = self.0;
        let remediation = crate::auto_fix::remediation_for(
            &finding.detector_id,
            &finding.service,
            finding.severity,
        );
        let mut field_count = 13;
        field_count += usize::from(finding.entropy.is_some());
        field_count += usize::from(finding.evidence_score.is_some());
        let mut state = serializer.serialize_struct("VerifiedFinding", field_count)?;
        state.serialize_field("detector_id", finding.detector_id.as_ref())?;
        state.serialize_field("detector_name", finding.detector_name.as_ref())?;
        state.serialize_field("service", finding.service.as_ref())?;
        state.serialize_field("severity", &finding.severity)?;
        state.serialize_field("credential_redacted", finding.credential_redacted.as_ref())?;
        state.serialize_field(
            "credential_hash",
            &crate::finding::hex_encode(finding.credential_hash),
        )?;
        let sorted_companions: BTreeMap<&str, &str> = finding
            .companions_redacted
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        state.serialize_field("companions_redacted", &sorted_companions)?;
        state.serialize_field("location", &finding.location)?;
        state.serialize_field("verification", &HtmlVerification(&finding.verification))?;
        state.serialize_field("evidence", &finding.evidence)?;
        let sorted_metadata: BTreeMap<&str, &str> = finding
            .metadata
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        state.serialize_field("metadata", &sorted_metadata)?;
        state.serialize_field("additional_locations", &finding.additional_locations)?;
        if let Some(entropy) = finding.entropy {
            state.serialize_field("entropy", &entropy)?;
        }
        if let Some(evidence_score) = finding.evidence_score {
            state.serialize_field("evidence_score", &evidence_score)?;
        }
        state.serialize_field("remediation", &remediation)?;
        state.end()
    }
}

/// Dynamic themed HTML findings reporter.
pub(crate) struct HtmlReporter<W: Write + Send> {
    writer: W,
    started: bool,
    first_finding: bool,
    skip_summary: Vec<(String, usize)>,
    metadata: Option<HtmlScanMetadata>,
}

impl<W: Write + Send> HtmlReporter<W> {
    /// Create a new HTML reporter.
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer,
            started: false,
            first_finding: true,
            skip_summary: Vec::new(),
            metadata: None,
        }
    }

    /// Attach the scan coverage-gap summary. Zero-count entries are dropped so
    /// the panel only lists categories that actually reduced coverage.
    pub(crate) fn with_skip_summary(mut self, skip_summary: Vec<(String, usize)>) -> Self {
        self.skip_summary = skip_summary.into_iter().filter(|(_, n)| *n > 0).collect();
        self
    }

    /// Attach scan metadata rendered in the report header.
    pub(crate) fn with_metadata(mut self, metadata: Option<HtmlScanMetadata>) -> Self {
        self.metadata = metadata;
        self
    }

    fn start(&mut self) -> Result<(), ReportError> {
        if self.started {
            return Ok(());
        }
        writeln!(self.writer, "<!DOCTYPE html>")?;
        writeln!(self.writer, "<html lang=\"en\" data-theme=\"keyhog\">")?;
        writeln!(self.writer, "<head>")?;
        writeln!(self.writer, "  <meta charset=\"UTF-8\">")?;
        writeln!(
            self.writer,
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        )?;
        writeln!(self.writer, "  <title>KeyHog Secret Scan Report</title>")?;
        writeln!(self.writer, "  <style>")?;
        writeln!(self.writer, "{}", include_str!("html_styles.css"))?;
        writeln!(self.writer, "  </style>")?;
        writeln!(self.writer, "</head>")?;
        writeln!(self.writer, "<body>")?;
        writeln!(self.writer, "{}", include_str!("html_body.html"))?;
        writeln!(self.writer, "  <script>")?;
        write!(self.writer, "    const rawFindings = [")?;
        self.started = true;
        Ok(())
    }
}

impl<W: Write + Send> Reporter for HtmlReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.start()?;
        if !self.first_finding {
            write!(self.writer, ",")?;
        }
        write_script_json(&mut self.writer, &HtmlFinding(finding))?;
        self.first_finding = false;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.start()?;
        writeln!(self.writer, "];")?;
        write!(self.writer, "    const coverageGaps = [")?;
        let mut first = true;
        for (reason, count) in &self.skip_summary {
            if !first {
                write!(self.writer, ",")?;
            }
            write_script_json(
                &mut self.writer,
                &serde_json::json!({ "reason": reason, "count": count }),
            )?;
            first = false;
        }
        writeln!(self.writer, "];")?;
        write!(self.writer, "    const scanMetadata = ")?;
        write_script_json(&mut self.writer, &self.metadata)?;
        writeln!(self.writer, ";")?;
        writeln!(self.writer, "{}", include_str!("html_script.js"))?;
        writeln!(self.writer, "  </script>")?;
        writeln!(self.writer, "</body>")?;
        writeln!(self.writer, "</html>")?;
        self.flush_writer()
    }
}

impl_writer_backed!(HtmlReporter);
