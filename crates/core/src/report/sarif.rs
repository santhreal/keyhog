//! SARIF reporter for code-scanning platforms such as GitHub code scanning,
//! Azure DevOps, and IDE integrations.

use std::collections::HashMap;
use std::io::Write;

use crate::{MatchLocation, Severity, VerifiedFinding};

use super::{ReportError, Reporter, WriterBackedReporter};

#[path = "sarif_taxonomies.rs"]
mod sarif_taxonomies;
use sarif_taxonomies::sarif_taxonomies_json;

/// SARIF v2.1.0 reporter - STREAMING.
///
/// Writes the SARIF document skeleton on construction and emits each
/// `runs[0].results[]` entry directly to the writer as `report()` is called.
/// Rules accumulate in a small `HashMap` (one entry per unique detector_id,
/// at most a few hundred), and are flushed in `finish()`. Peak memory is
/// O(rules × ~500B) regardless of finding count, replacing the previous
/// O(N findings × ~500B) buffer that audited as the SARIF OOM wall at 1M+
/// findings.
///
/// SARIF spec is order-agnostic on object keys; we emit `runs[0].results`
/// before `runs[0].tool` so the streaming write order is legal.
pub struct SarifReporter<W: Write + Send> {
    writer: W,
    rules: HashMap<String, SarifRule>,
    /// Tracks whether the prefix has been emitted; lazy so the writer can
    /// fail before we touch it.
    prefix_written: bool,
    /// Tracks whether at least one result has been emitted (for comma logic).
    any_result: bool,
}

#[path = "sarif_types.rs"]
mod sarif_types;
use sarif_types::*;

impl<W: Write + Send> SarifReporter<W> {
    /// Construct a streaming SARIF reporter that writes its document to
    /// `writer`. The SARIF prefix is emitted lazily on the first finding.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            rules: HashMap::new(),
            prefix_written: false,
            any_result: false,
        }
    }

    /// Lazily emit the SARIF document skeleton up to the start of the
    /// `results` array. Idempotent.
    fn ensure_prefix(&mut self) -> Result<(), ReportError> {
        if self.prefix_written {
            return Ok(());
        }
        // Manual JSON: serde won't help us here because we want to write
        // results streamed BEFORE we know the rule set. We use
        // `serde_json::to_string` for value escaping.
        let version = env!("CARGO_PKG_VERSION");
        write!(
            self.writer,
            r#"{{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json","runs":[{{"results":["#
        )?;
        let _ = version;
        self.prefix_written = true;
        Ok(())
    }

    fn build_sarif_result(finding: &VerifiedFinding) -> SarifResult {
        let locations = vec![Self::location_to_sarif(&finding.location)];
        // GitHub Code Scanning rejects SARIF whose `relatedLocations`
        // contains duplicate items. Some detector pipelines emit the
        // same location twice (e.g. a credential found via two rules
        // pointing at the same span). Dedup by the canonical
        // (file_path, line, offset) tuple - that's what makes two
        // locations "the same finding" for UI purposes.
        let mut seen_related: std::collections::HashSet<(String, Option<usize>, usize)> =
            std::collections::HashSet::new();
        let related_locations: Vec<SarifLocation> = finding
            .additional_locations
            .iter()
            .filter(|loc| {
                let key = (
                    loc.file_path.clone().unwrap_or_default().to_string(),
                    loc.line,
                    loc.offset,
                );
                seen_related.insert(key)
            })
            .map(Self::location_to_sarif)
            .collect();

        let mut properties = serde_json::Map::new();
        properties.insert(
            "verification".to_string(),
            serde_json::Value::String(format!("{:?}", finding.verification).to_lowercase()),
        );
        if let Some(confidence) = finding.confidence {
            properties.insert(
                "confidence".to_string(),
                serde_json::Value::Number(
                    serde_json::Number::from_f64(confidence).unwrap_or_else(|| 0.into()),
                ),
            );
        }
        // CWE / OWASP taxonomy. CWE-798 ("Use of Hard-coded Credentials") and
        // OWASP A07:2021 ("Identification and Authentication Failures") apply
        // to every secret-scanning finding by definition. Compliance dashboards
        // consume `properties.cwe` + `properties.owasp` directly. Tier-B #16.
        properties.insert(
            "cwe".to_string(),
            serde_json::Value::String("CWE-798".to_string()),
        );
        properties.insert(
            "owasp".to_string(),
            serde_json::Value::String("A07:2021".to_string()),
        );
        for (key, value) in &finding.metadata {
            properties.insert(
                format!("metadata.{}", key),
                serde_json::Value::String(value.to_string()),
            );
        }

        // Auto-fix suggestion: replace the leaked credential with a
        // ${ENV_VAR_NAME} reference at the same physical location. We emit
        // this only when we have a file_path (no fix possible for stdin /
        // git-history-only findings) AND a line number.
        let fixes = if let (Some(_), Some(line)) =
            (finding.location.file_path.as_ref(), finding.location.line)
        {
            let replacement = crate::auto_fix::fix_replacement_text(&finding.service);
            let env_name = crate::auto_fix::env_var_name_for_service(&finding.service);
            Some(vec![SarifFix {
                description: SarifMessage {
                    text: format!(
                        "Replace the leaked credential with `{replacement}` and load `{env_name}` from your secret manager."
                    ),
                },
                artifact_changes: vec![SarifArtifactChange {
                    artifact_location: SarifArtifactLocation {
                        uri: finding
                            .location
                            .file_path
                            .as_deref()
                            .map(super::sarif_uri::file_path_to_sarif_uri)
                            .unwrap_or_default(),
                        uri_base_id: None,
                    },
                    replacements: vec![SarifReplacement {
                        deleted_region: SarifRegion {
                            start_line: Some(line),
                            start_column: None,
                            end_line: None,
                            end_column: None,
                            char_offset: None,
                            snippet: None,
                        },
                        inserted_content: SarifSnippet { text: replacement },
                    }],
                }],
            }])
        } else {
            None
        };

        SarifResult {
            rule_id: finding.detector_id.to_string(),
            level: Self::severity_to_level(finding.severity).to_string(),
            message: SarifMessage {
                text: format!(
                    "{} secret detected: {}",
                    finding.service, finding.credential_redacted
                ),
            },
            locations,
            properties: Some(properties),
            related_locations: if related_locations.is_empty() {
                None
            } else {
                Some(related_locations)
            },
            fixes,
            partial_fingerprints: super::sarif_uri::credential_fingerprints(
                &finding.credential_hash,
            ),
        }
    }

    fn severity_to_level(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "error",
            Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
            Severity::ClientSafe => "note",
            Severity::Info => "note",
        }
    }

    fn build_rule(finding: &VerifiedFinding) -> SarifRule {
        SarifRule {
            id: finding.detector_id.to_string(),
            name: finding.detector_name.to_string(),
            short_description: Some(SarifMessage {
                text: format!("{} secret detected", finding.service),
            }),
            full_description: Some(SarifMessage {
                text: format!(
                    "A {} secret was detected by the {} detector",
                    finding.service, finding.detector_name
                ),
            }),
            help: Some(SarifMessage {
                text: format!(
                    "Review and rotate the exposed {} credential.",
                    finding.service
                ),
            }),
            properties: Some({
                let mut props = serde_json::Map::new();
                props.insert(
                    "service".to_string(),
                    serde_json::Value::String(finding.service.to_string()),
                );
                props.insert(
                    "severity".to_string(),
                    serde_json::Value::String(format!("{:?}", finding.severity).to_lowercase()),
                );
                super::sarif_uri::apply_code_scanning_props(&mut props, finding.severity);
                props
            }),
        }
    }

    fn location_to_sarif(loc: &MatchLocation) -> SarifLocation {
        let uri = loc
            .file_path
            .as_ref()
            .map(|p| super::sarif_uri::file_path_to_sarif_uri(p.as_ref()))
            .unwrap_or_else(|| "stdin".to_string());

        let artifact_location = Some(SarifArtifactLocation {
            uri,
            uri_base_id: None,
        });

        let region = if loc.line.is_some() || loc.offset != 0 {
            Some(SarifRegion {
                start_line: loc.line,
                start_column: None,
                end_line: None,
                end_column: None,
                char_offset: if loc.offset != 0 {
                    Some(loc.offset)
                } else {
                    None
                },
                snippet: None,
            })
        } else {
            None
        };

        let mut logical_locations = Vec::new();

        if let Some(commit) = &loc.commit {
            logical_locations.push(SarifLogicalLocation {
                name: commit.to_string(),
                kind: "commit".to_string(),
            });
        }

        if let Some(author) = &loc.author {
            logical_locations.push(SarifLogicalLocation {
                name: author.to_string(),
                kind: "author".to_string(),
            });
        }

        if let Some(date) = &loc.date {
            logical_locations.push(SarifLogicalLocation {
                name: date.to_string(),
                kind: "date".to_string(),
            });
        }

        SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location,
                region,
            },
            logical_locations: if logical_locations.is_empty() {
                None
            } else {
                Some(logical_locations)
            },
        }
    }
}

impl<W: Write + Send> Reporter for SarifReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.ensure_prefix()?;

        let detector_id = finding.detector_id.as_ref();
        if !self.rules.contains_key(detector_id) {
            let rule = Self::build_rule(finding);
            self.rules.insert(detector_id.to_string(), rule);
        }

        // Stream this result directly to the writer. No per-finding buffer.
        if self.any_result {
            self.writer.write_all(b",")?;
        }
        let result = Self::build_sarif_result(finding);
        serde_json::to_writer(&mut self.writer, &result)?;
        self.any_result = true;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        // If `report()` was never called we still need a valid SARIF doc.
        self.ensure_prefix()?;

        // Close the results array; emit tool.driver with the accumulated
        // rules; emit taxonomies (CWE + OWASP) so consumers can resolve
        // `properties.cwe` references; close runs[0], runs[], and the doc.
        write!(self.writer, "],\"tool\":")?;

        let mut rules: Vec<SarifRule> = self.rules.values().cloned().collect();
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        let tool = SarifTool {
            driver: SarifToolDriver {
                name: "keyhog".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                // Sourced from the crate's `repository` field (Cargo sets
                // CARGO_PKG_REPOSITORY) so the SARIF `informationUri` always
                // points at the canonical repo and can never drift from the
                // published manifest. Previously hardcoded to the wrong
                // `github.com/keyhog/keyhog` org.
                information_uri: Some(env!("CARGO_PKG_REPOSITORY").to_string()),
                rules,
            },
        };
        serde_json::to_writer(&mut self.writer, &tool)?;

        // SARIF taxonomies block - each entry references a canonical entry in
        // CWE / OWASP. Compliance dashboards (e.g. SonarQube, GitHub Code
        // Scanning, Splunk) resolve `result.properties.cwe = "CWE-798"`
        // against this block. Tier-B #16 from audits/legendary-2026-04-26.
        write!(self.writer, ",\"taxonomies\":")?;
        serde_json::to_writer(&mut self.writer, &sarif_taxonomies_json())?;

        write!(self.writer, "}}]}}")?;
        writeln!(self.writer)?;
        self.flush_writer()
    }
}

impl<W: Write + Send> WriterBackedReporter for SarifReporter<W> {
    type Writer = W;

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }
}
