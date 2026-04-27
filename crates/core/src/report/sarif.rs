//! SARIF reporter for code-scanning platforms such as GitHub code scanning,
//! Azure DevOps, and IDE integrations.

use std::collections::HashMap;
use std::io::Write;

use crate::{MatchLocation, Severity, VerifiedFinding};

use super::{ReportError, Reporter, WriterBackedReporter};

/// SARIF v2.1.0 reporter — STREAMING.
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

/// A SARIF rule (tool component rule).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    short_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    help: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifMessage {
    text: String,
}

// Note: `SarifRun` and `SarifLog` are no longer constructed since the
// streaming reporter writes the document skeleton manually. They remain as
// schema documentation for readers; mark `#[allow(dead_code)]` so the
// compiler warns us if a non-streaming consumer reuses them.
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool {
    driver: SarifToolDriver,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifToolDriver {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    information_uri: Option<String>,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    related_locations: Option<Vec<SarifLocation>>,
    /// SARIF v2.2.0 `fixes[]` — auto-rotation suggestions. Each entry
    /// proposes replacing the leaked credential with a `${ENV_VAR_NAME}`
    /// shell-interpolation reference. Tier-B #15 + #17.
    #[serde(skip_serializing_if = "Option::is_none")]
    fixes: Option<Vec<SarifFix>>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifFix {
    description: SarifMessage,
    artifact_changes: Vec<SarifArtifactChange>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactChange {
    artifact_location: SarifArtifactLocation,
    replacements: Vec<SarifReplacement>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifReplacement {
    deleted_region: SarifRegion,
    inserted_content: SarifSnippet,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    logical_locations: Option<Vec<SarifLogicalLocation>>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_location: Option<SarifArtifactLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri_base_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    #[serde(skip_serializing_if = "Option::is_none")]
    start_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<SarifSnippet>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifSnippet {
    text: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLogicalLocation {
    name: String,
    kind: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<SarifRun>,
}

impl<W: Write + Send> SarifReporter<W> {
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
        let related_locations: Vec<SarifLocation> = finding
            .additional_locations
            .iter()
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
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                        uri_base_id: None,
                    },
                    replacements: vec![SarifReplacement {
                        deleted_region: SarifRegion {
                            start_line: Some(line),
                            start_column: None,
                            end_line: None,
                            end_column: None,
                            snippet: None,
                        },
                        inserted_content: SarifSnippet {
                            text: replacement,
                        },
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
        }
    }

    fn severity_to_level(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "error",
            Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
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
                props
            }),
        }
    }

    fn location_to_sarif(loc: &MatchLocation) -> SarifLocation {
        let uri = loc
            .file_path
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "stdin".to_string());

        let artifact_location = Some(SarifArtifactLocation {
            uri,
            uri_base_id: None,
        });

        let region = loc.line.map(|line| SarifRegion {
            start_line: Some(line),
            start_column: None,
            end_line: None,
            end_column: None,
            snippet: None,
        });

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
                information_uri: Some("https://github.com/keyhog/keyhog".to_string()),
                rules,
            },
        };
        serde_json::to_writer(&mut self.writer, &tool)?;

        // SARIF taxonomies block — each entry references a canonical entry in
        // CWE / OWASP. Compliance dashboards (e.g. SonarQube, GitHub Code
        // Scanning, Splunk) resolve `result.properties.cwe = "CWE-798"`
        // against this block. Tier-B #16 from audits/legendary-2026-04-26.
        write!(self.writer, ",\"taxonomies\":")?;
        let taxonomies = serde_json::json!([
            {
                "name": "CWE",
                "version": "4.13",
                "informationUri": "https://cwe.mitre.org/data/definitions/798.html",
                "shortDescription": { "text": "Common Weakness Enumeration" },
                "taxa": [{
                    "id": "CWE-798",
                    "name": "Use of Hard-coded Credentials",
                    "shortDescription": {
                        "text": "The product contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data."
                    },
                    "helpUri": "https://cwe.mitre.org/data/definitions/798.html"
                }]
            },
            {
                "name": "OWASP",
                "version": "2021",
                "informationUri": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                "shortDescription": { "text": "OWASP Top 10:2021" },
                "taxa": [{
                    "id": "A07:2021",
                    "name": "Identification and Authentication Failures",
                    "shortDescription": {
                        "text": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks."
                    },
                    "helpUri": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
                }]
            }
        ]);
        serde_json::to_writer(&mut self.writer, &taxonomies)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MatchLocation, VerificationResult};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn synthetic_finding() -> VerifiedFinding {
        VerifiedFinding {
            detector_id: Arc::from("test-detector"),
            detector_name: Arc::from("Test Detector"),
            service: Arc::from("test"),
            severity: Severity::High,
            credential_redacted: std::borrow::Cow::Borrowed("****redacted"),
            credential_hash: "abcdefabcdefabcdef".into(),
            location: MatchLocation {
                source: Arc::from("filesystem"),
                file_path: Some(Arc::from("config.env")),
                line: Some(42),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            verification: VerificationResult::Unverifiable,
            metadata: HashMap::new(),
            additional_locations: vec![],
            confidence: Some(0.9),
        }
    }

    #[test]
    fn sarif_output_is_valid_json_with_cwe_owasp_taxa() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut r = SarifReporter::new(&mut buf);
            r.report(&synthetic_finding()).unwrap();
            r.finish().unwrap();
        }
        let json: serde_json::Value =
            serde_json::from_slice(&buf).expect("SARIF output must parse as JSON");

        // Per-result properties carry CWE and OWASP refs.
        let cwe = json["runs"][0]["results"][0]["properties"]["cwe"].as_str();
        assert_eq!(cwe, Some("CWE-798"));
        let owasp = json["runs"][0]["results"][0]["properties"]["owasp"].as_str();
        assert_eq!(owasp, Some("A07:2021"));

        // runs[0].taxonomies block resolves the CWE/OWASP references.
        let tax_name = json["runs"][0]["taxonomies"][0]["name"].as_str();
        assert_eq!(tax_name, Some("CWE"));
        let cwe_taxa_id = json["runs"][0]["taxonomies"][0]["taxa"][0]["id"].as_str();
        assert_eq!(cwe_taxa_id, Some("CWE-798"));
        let owasp_name = json["runs"][0]["taxonomies"][1]["name"].as_str();
        assert_eq!(owasp_name, Some("OWASP"));

        // SARIF v2.2 fixes[]: a replacement suggestion for the leaked
        // credential. With service="test" we expect ${TEST_KEY} fallback.
        let fix_replacement = json["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]
            ["replacements"][0]["insertedContent"]["text"]
            .as_str();
        assert_eq!(fix_replacement, Some("${TEST_KEY}"));
        let fix_uri = json["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]
            ["artifactLocation"]["uri"]
            .as_str();
        assert_eq!(fix_uri, Some("config.env"));
    }

    #[test]
    fn empty_run_still_produces_valid_sarif() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut r = SarifReporter::new(&mut buf);
            r.finish().unwrap();
        }
        let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid JSON");
        assert_eq!(json["version"].as_str(), Some("2.1.0"));
        let results = json["runs"][0]["results"]
            .as_array()
            .expect("results array");
        assert!(results.is_empty());
    }
}
