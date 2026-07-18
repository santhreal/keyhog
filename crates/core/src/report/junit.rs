//! Structured JUnit XML findings reporter.

use std::io::Write;

use crate::{ScanBackendRecoverySummary, ScanCompletionStatus, VerifiedFinding};

use super::{
    escape::{escape_cdata, escape_xml_attr},
    impl_writer_backed, ReportError, Reporter, WriterBackedReporter,
};

/// Structured JUnit XML findings reporter.
pub(crate) struct JunitReporter<W: Write + Send> {
    writer: W,
    testcases: Vec<u8>,
    tests_count: usize,
    skip_summary: Vec<(String, usize)>,
    scan_status: ScanCompletionStatus,
    backend_recoveries: Vec<ScanBackendRecoverySummary>,
}

impl<W: Write + Send> JunitReporter<W> {
    /// Create a new JUnit reporter.
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer,
            testcases: Vec::new(),
            tests_count: 0,
            skip_summary: Vec::new(),
            scan_status: ScanCompletionStatus::Success,
            backend_recoveries: Vec::new(),
        }
    }

    /// Attach deterministic suite properties for source coverage gaps.
    pub(crate) fn with_skip_summary(mut self, summary: Vec<(String, usize)>) -> Self {
        self.skip_summary = summary
            .into_iter()
            .filter(|(_, count)| *count > 0)
            .collect();
        self.scan_status =
            ScanCompletionStatus::resolve(Some(self.scan_status), !self.skip_summary.is_empty());
        self
    }

    /// Attach the explicit terminal state from the shared scan metadata.
    pub(crate) fn with_scan_status(mut self, status: ScanCompletionStatus) -> Self {
        self.scan_status = status;
        self
    }

    pub(crate) fn with_backend_recoveries(
        mut self,
        recoveries: Vec<ScanBackendRecoverySummary>,
    ) -> Self {
        self.backend_recoveries = recoveries;
        self
    }
}

impl<W: Write + Send> Reporter for JunitReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        write_testcase(&mut self.testcases, finding)?;
        self.tests_count += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        writeln!(self.writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
        writeln!(self.writer, "<testsuites>")?;

        writeln!(
            self.writer,
            "  <testsuite name=\"keyhog\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"0.0\">",
            self.tests_count, self.tests_count
        )?;

        writeln!(self.writer, "    <properties>")?;
        writeln!(
            self.writer,
            "      <property name=\"keyhog.scan.status\" value=\"{}\"/>",
            serde_json::to_string(&self.scan_status)?.trim_matches('"')
        )?;
        for (reason, count) in &self.skip_summary {
            writeln!(
                self.writer,
                "      <property name=\"keyhog.coverage_gap\" value=\"{}={}\"/>",
                escape_xml_attr(reason),
                count
            )?;
        }
        for recovery in &self.backend_recoveries {
            writeln!(
                self.writer,
                "      <property name=\"keyhog.backend.recovery\" value=\"{}\"/>",
                escape_xml_attr(&serde_json::to_string(recovery)?)
            )?;
        }
        writeln!(self.writer, "    </properties>")?;

        self.writer.write_all(&self.testcases)?;

        writeln!(self.writer, "  </testsuite>")?;
        writeln!(self.writer, "</testsuites>")?;

        self.flush_writer()
    }
}

fn write_testcase<W: Write>(writer: &mut W, finding: &VerifiedFinding) -> Result<(), ReportError> {
    // LAW10 (both below): recall-safe, formatting OPTIONAL location fields of
    // an already-detected finding into JUnit XML. A `None` becomes an empty
    // string handled by the `case_name` branches below; the finding is still
    // emitted. No detection happens here.
    let line_str = finding
        .location
        .line
        .map(|l| l.to_string())
        .unwrap_or_default(); // LAW10: optional field -> empty, finding still emitted
    let file_path_str = finding
        .location
        .file_path
        .as_ref()
        .map(|f| f.as_ref())
        .unwrap_or_default(); // LAW10: optional field -> empty, finding still emitted
    let case_name = if file_path_str.is_empty() {
        format!("{}:{}", finding.detector_id, line_str)
    } else if line_str.is_empty() {
        format!("{}:{}", file_path_str, finding.detector_id)
    } else {
        format!("{}:{}:{}", file_path_str, line_str, finding.detector_id)
    };

    let confidence_str = finding
        .confidence
        .map(|c| c.to_string())
        .unwrap_or_default(); // LAW10: optional confidence -> empty cell; finding still emitted
    let verification_str = super::style::verification_token(&finding.verification).into_owned();

    writeln!(
        writer,
        "    <testcase name=\"{}\" classname=\"keyhog.findings\" time=\"0.0\">",
        escape_xml_attr(&case_name)
    )?;

    let failure_msg = format!(
        "Secret detected: {} (id: {})",
        finding.detector_name, finding.detector_id
    );
    writeln!(
        writer,
        "      <failure message=\"{}\" type=\"{}\">",
        escape_xml_attr(&failure_msg),
        escape_xml_attr(finding.severity.as_str())
    )?;

    writeln!(writer, "        <![CDATA[")?;
    writeln!(
        writer,
        "Detector Name: {}",
        escape_cdata(&finding.detector_name)
    )?;
    writeln!(
        writer,
        "Detector ID:   {}",
        escape_cdata(&finding.detector_id)
    )?;
    writeln!(writer, "Service:       {}", escape_cdata(&finding.service))?;
    writeln!(writer, "Severity:      {}", finding.severity)?;
    writeln!(
        writer,
        "Source:        {}",
        escape_cdata(&finding.location.source)
    )?;
    if !file_path_str.is_empty() {
        writeln!(writer, "File Path:     {}", escape_cdata(file_path_str))?;
    }
    if !line_str.is_empty() {
        writeln!(writer, "Line:          {}", line_str)?;
    }
    writeln!(writer, "Offset:        {}", finding.location.offset)?;
    if let Some(c) = &finding.location.commit {
        writeln!(writer, "Commit:        {}", escape_cdata(c))?;
    }
    if let Some(a) = &finding.location.author {
        writeln!(writer, "Author:        {}", escape_cdata(a))?;
    }
    if let Some(d) = &finding.location.date {
        writeln!(writer, "Date:          {}", escape_cdata(d))?;
    }
    writeln!(
        writer,
        "Redacted:      {}",
        escape_cdata(&finding.credential_redacted)
    )?;
    writeln!(
        writer,
        "Hash:          {}",
        crate::hex_encode(&finding.credential_hash)
    )?;
    writeln!(writer, "Verification:  {}", escape_cdata(&verification_str))?;
    if !finding.companions_redacted.is_empty() {
        writeln!(
            writer,
            "Companions:    {}",
            escape_cdata(&super::companions_json(finding)?)
        )?;
    }
    if !confidence_str.is_empty() {
        writeln!(writer, "Confidence:    {}", confidence_str)?;
    }
    if let Some(entropy) = finding.entropy.filter(|entropy| entropy.is_finite()) {
        writeln!(writer, "Entropy:       {:.3} bits/byte", entropy)?;
    }
    writeln!(writer, "        ]]>")?;
    writeln!(writer, "      </failure>")?;
    writeln!(writer, "    </testcase>")?;
    Ok(())
}

impl_writer_backed!(JunitReporter);
