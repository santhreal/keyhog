use std::io::Write;

use keyhog_core::{write_report, ReportError, ReportFormat, VerifiedFinding};

pub trait Reporter {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError>;
    fn finish(&mut self) -> Result<(), ReportError>;
}

macro_rules! buffered_reporter {
    ($name:ident, $format:expr) => {
        pub struct $name<W: Write + Send> {
            writer: Option<W>,
            findings: Vec<VerifiedFinding>,
        }

        impl<W: Write + Send> $name<W> {
            pub fn new(writer: W) -> Self {
                Self {
                    writer: Some(writer),
                    findings: Vec::new(),
                }
            }

            pub fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
                self.findings.push(finding.clone());
                Ok(())
            }

            pub fn finish(&mut self) -> Result<(), ReportError> {
                let writer = self.writer.take().ok_or_else(|| {
                    ReportError::msg("test reporter was already finished; construct a new reporter")
                })?;
                write_report(writer, $format, &self.findings)
            }
        }

        impl<W: Write + Send> Reporter for $name<W> {
            fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
                self.report(finding)
            }

            fn finish(&mut self) -> Result<(), ReportError> {
                self.finish()
            }
        }
    };
}

pub struct TextReporter<W: Write + Send> {
    writer: Option<W>,
    findings: Vec<VerifiedFinding>,
    example_suppressions: usize,
    dogfood_active: bool,
    color: bool,
}

impl<W: Write + Send> TextReporter<W> {
    pub fn with_color(writer: W, color: bool) -> Self {
        Self {
            writer: Some(writer),
            findings: Vec::new(),
            example_suppressions: 0,
            dogfood_active: false,
            color,
        }
    }

    pub fn set_example_suppressions(&mut self, count: usize) {
        self.example_suppressions = count;
    }

    pub fn set_dogfood_active(&mut self, active: bool) {
        self.dogfood_active = active;
    }

    pub fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.findings.push(finding.clone());
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), ReportError> {
        let writer = self.writer.take().ok_or_else(|| {
            ReportError::msg("test reporter was already finished; construct a new reporter")
        })?;
        write_report(
            writer,
            ReportFormat::Text {
                color: self.color,
                example_suppressions: self.example_suppressions,
                dogfood_active: self.dogfood_active,
            },
            &self.findings,
        )
    }
}

impl<W: Write + Send> Reporter for TextReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.report(finding)
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.finish()
    }
}

buffered_reporter!(JsonlReporter, ReportFormat::Jsonl);
buffered_reporter!(
    HtmlReporter,
    ReportFormat::Html {
        skip_summary: Vec::new(),
        metadata: None
    }
);
buffered_reporter!(JunitReporter, ReportFormat::Junit);

pub struct JsonArrayReporter<W: Write + Send> {
    writer: Option<W>,
    findings: Vec<VerifiedFinding>,
}

impl<W: Write + Send> JsonArrayReporter<W> {
    pub fn new(writer: W) -> Result<Self, ReportError> {
        Ok(Self {
            writer: Some(writer),
            findings: Vec::new(),
        })
    }

    pub fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.findings.push(finding.clone());
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), ReportError> {
        let writer = self.writer.take().ok_or_else(|| {
            ReportError::msg("test reporter was already finished; construct a new reporter")
        })?;
        write_report(writer, ReportFormat::Json, &self.findings)
    }
}

impl<W: Write + Send> Reporter for JsonArrayReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.report(finding)
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.finish()
    }
}

pub type JsonReporter<W> = JsonArrayReporter<W>;

pub struct SarifReporter<W: Write + Send> {
    writer: Option<W>,
    findings: Vec<VerifiedFinding>,
    skip_summary: Vec<(String, usize)>,
}

impl<W: Write + Send> SarifReporter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: Some(writer),
            findings: Vec::new(),
            skip_summary: Vec::new(),
        }
    }

    pub fn with_skip_summary(mut self, skip_summary: Vec<(String, usize)>) -> Self {
        self.skip_summary = skip_summary;
        self
    }

    pub fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.findings.push(finding.clone());
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), ReportError> {
        let writer = self.writer.take().ok_or_else(|| {
            ReportError::msg("test reporter was already finished; construct a new reporter")
        })?;
        write_report(
            writer,
            ReportFormat::Sarif {
                skip_summary: std::mem::take(&mut self.skip_summary),
            },
            &self.findings,
        )
    }
}

impl<W: Write + Send> Reporter for SarifReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.report(finding)
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.finish()
    }
}

pub struct CsvReporter<W: Write + Send> {
    writer: Option<W>,
    findings: Vec<VerifiedFinding>,
}

impl<W: Write + Send> CsvReporter<W> {
    pub fn new(writer: W) -> Result<Self, ReportError> {
        Ok(Self {
            writer: Some(writer),
            findings: Vec::new(),
        })
    }

    pub fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.findings.push(finding.clone());
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), ReportError> {
        let writer = self.writer.take().ok_or_else(|| {
            ReportError::msg("test reporter was already finished; construct a new reporter")
        })?;
        write_report(writer, ReportFormat::Csv, &self.findings)
    }
}

impl<W: Write + Send> Reporter for CsvReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.report(finding)
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.finish()
    }
}
