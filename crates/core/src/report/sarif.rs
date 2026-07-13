//! SARIF reporter for code-scanning platforms such as GitHub code scanning,
//! Azure DevOps, and IDE integrations.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;

use crate::{MatchLocation, Severity, VerifiedFinding};

use super::{impl_writer_backed, ReportError, Reporter, WriterBackedReporter};

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
pub(crate) struct SarifReporter<W: Write + Send> {
    writer: W,
    rules: HashMap<String, SarifRule>,
    /// Tracks whether the prefix has been emitted; lazy so the writer can
    /// fail before we touch it.
    prefix_written: bool,
    /// Tracks whether at least one result has been emitted (for comma logic).
    any_result: bool,
    /// `(reason, count)` pairs of scan coverage gaps: whole-file skips
    /// (oversize, binary, default-excluded, unreadable) and partial-coverage
    /// degradations (truncated source scans, structured parse fallbacks, binary
    /// deep-analysis degradation). Surfaced as SARIF
    /// `invocations[].toolExecutionNotifications` so a consuming platform can
    /// interpret coverage correctly. Empty = no notifications block. Set by the
    /// caller (which owns the source-layer counters) via [`Self::with_skip_summary`];
    /// kept as plain `(String, usize)` so `core` takes no dependency on the
    /// sources crate.
    skip_summary: Vec<(String, usize)>,
}

#[path = "sarif_types.rs"]
mod sarif_types;
use sarif_types::*;

/// SINGLE OWNER for the taxonomy identifiers keyhog attaches to every finding.
///
/// Each string appears in TWO SARIF positions that a consuming dashboard
/// cross-references: the per-result `properties.cwe` / `properties.owasp`
/// (built in [`SarifReporter::result_properties`]) and the `taxonomies[].taxa[].id`
/// (built in `sarif_taxonomies::sarif_taxonomies_json`). If those two drift, the
/// reference silently fails to resolve. Owning the id once here, consumed by
/// both sites (makes that drift impossible).
pub(super) const CWE_HARDCODED_CREDENTIALS_ID: &str = "CWE-798";
pub(super) const OWASP_AUTH_FAILURES_ID: &str = "A07:2021";

impl<W: Write + Send> SarifReporter<W> {
    /// Construct a streaming SARIF reporter that writes its document to
    /// `writer`. The SARIF prefix is emitted lazily on the first finding.
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer,
            rules: HashMap::new(),
            prefix_written: false,
            any_result: false,
            skip_summary: Vec::new(),
        }
    }

    /// Attach scan coverage-gap summary entries, surfaced as SARIF
    /// `invocations[].toolExecutionNotifications`. Each `(reason, count)` with a
    /// non-zero count becomes one `note`-level notification. No-op for empty
    /// input. See [`Self::skip_summary`].
    #[must_use]
    pub(crate) fn with_skip_summary(mut self, summary: Vec<(String, usize)>) -> Self {
        self.skip_summary = summary.into_iter().filter(|(_, n)| *n > 0).collect();
        self
    }

    /// Lazily emit the SARIF document skeleton up to the start of the
    /// `results` array. Idempotent.
    fn ensure_prefix(&mut self) -> Result<(), ReportError> {
        if self.prefix_written {
            return Ok(());
        }
        // Manual JSON: serde won't help us here because we want to write
        // results streamed BEFORE we know the rule set. The tool version is
        // emitted separately in `finish` via `tool.driver.version`.
        write!(
            self.writer,
            r#"{{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json","runs":[{{"results":["#
        )?;
        self.prefix_written = true;
        Ok(())
    }

    fn build_sarif_result(finding: &VerifiedFinding) -> SarifResult {
        let locations = vec![Self::location_to_sarif(&finding.location)];
        let related_locations = Self::related_locations(finding);
        let properties = Self::result_properties(finding);
        let fixes = Self::result_fixes(finding);

        SarifResult {
            rule_id: finding.detector_id.to_string(),
            level: Self::severity_to_level(finding.severity),
            message: SarifMessage {
                text: format!(
                    "{} secret detected: {}",
                    finding.service, finding.credential_redacted
                ),
                markdown: None,
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
                finding.credential_hash,
            ),
        }
    }

    fn related_locations(finding: &VerifiedFinding) -> Vec<SarifLocation> {
        // GitHub Code Scanning rejects SARIF whose `relatedLocations`
        // contains duplicate items. Some detector pipelines emit the
        // same location twice (e.g. a credential found via two rules
        // pointing at the same span). Dedup by the canonical
        // (file_path, line, offset) tuple - that's what makes two
        // locations "the same finding" for UI purposes.
        // Key on a cloned `Arc<str>` (a pointer/refcount bump, not a fresh
        // allocation) rather than `to_string()`; `Arc<str>` hashes/compares by
        // content, so dedup is unchanged while the per-location String alloc is
        // gone.
        let mut seen_related: std::collections::HashSet<(
            Option<std::sync::Arc<str>>,
            Option<usize>,
            usize,
        )> = std::collections::HashSet::new();
        finding
            .additional_locations
            .iter()
            .filter(|loc| seen_related.insert((loc.file_path.clone(), loc.line, loc.offset)))
            .map(Self::location_to_sarif)
            .collect()
    }

    fn result_properties(finding: &VerifiedFinding) -> SarifResultProperties {
        // CWE / OWASP taxonomy. CWE-798 ("Use of Hard-coded Credentials") and
        // OWASP A07:2021 ("Identification and Authentication Failures") apply
        // to every secret-scanning finding by definition. Compliance dashboards
        // consume `properties.cwe` + `properties.owasp` directly. Tier-B #16.
        let remediation = crate::auto_fix::remediation_for(
            &finding.detector_id,
            &finding.service,
            finding.severity,
        );
        SarifResultProperties {
            verification: super::style::verification_token(&finding.verification).into_owned(),
            confidence: finding.confidence.map(|confidence| {
                if confidence.is_finite() {
                    confidence
                } else {
                    0.0
                }
            }),
            cwe: CWE_HARDCODED_CREDENTIALS_ID,
            owasp: OWASP_AUTH_FAILURES_ID,
            remediation_action: remediation.action.clone(),
            remediation_revoke_url: remediation.revoke_url.clone(),
            remediation_docs_url: remediation.docs_url.clone(),
            remediation_revoke_command: remediation.revoke_command.clone(),
            metadata: finding
                .metadata
                .iter()
                .map(|(key, value)| (format!("metadata.{key}"), value.to_string()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    fn result_fixes(finding: &VerifiedFinding) -> Option<Vec<SarifFix>> {
        // Auto-fix suggestion: replace the leaked credential with a
        // ${ENV_VAR_NAME} reference at the same physical location. We emit
        // this only when we have a file_path (no fix possible for stdin /
        // git-history-only findings) AND a line number.
        if let (Some(_), Some(line)) = (finding.location.file_path.as_ref(), finding.location.line)
        {
            let replacement = crate::auto_fix::fix_replacement_text(&finding.service);
            let env_name = crate::auto_fix::env_var_name_for_service(&finding.service);
            Some(vec![SarifFix {
                description: SarifMessage {
                    text: format!(
                        "Replace the leaked credential with `{replacement}` and load `{env_name}` from your secret manager."
                    ),
                    markdown: None,
                },
                artifact_changes: vec![SarifArtifactChange {
                    artifact_location: SarifArtifactLocation {
                        uri: finding
                            .location
                            .file_path
                            .as_deref()
                            .map(super::sarif_uri::file_path_to_sarif_uri)
                            .unwrap_or_default(), // LAW10: empty URI for a path-less finding; finding still emitted
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
        }
    }

    fn severity_to_level(severity: Severity) -> SarifLevel {
        match severity {
            Severity::Critical => SarifLevel::Error,
            Severity::High => SarifLevel::Error,
            Severity::Medium => SarifLevel::Warning,
            Severity::Low => SarifLevel::Note,
            Severity::ClientSafe => SarifLevel::Note,
            Severity::Info => SarifLevel::Note,
        }
    }

    fn build_rule(finding: &VerifiedFinding) -> SarifRule {
        let remediation = crate::auto_fix::remediation_for(
            &finding.detector_id,
            &finding.service,
            finding.severity,
        );
        let help_uri = remediation
            .revoke_url
            .clone()
            .or_else(|| remediation.docs_url.clone());
        SarifRule {
            id: finding.detector_id.to_string(),
            name: finding.detector_name.to_string(),
            short_description: Some(SarifMessage {
                text: format!("{} secret detected", finding.service),
                markdown: None,
            }),
            full_description: Some(SarifMessage {
                text: format!(
                    "A {} secret was detected by the {} detector",
                    finding.service, finding.detector_name
                ),
                markdown: None,
            }),
            help: Some(SarifMessage {
                text: remediation.action.clone(),
                markdown: Some(remediation.markdown()),
            }),
            help_uri,
            properties: Some(SarifRuleProperties {
                service: finding.service.to_string(),
                severity: finding.severity.as_str().to_string(),
                security_severity: super::sarif_uri::code_scanning_security_severity(
                    finding.severity,
                ),
                tags: [super::sarif_uri::CODE_SCANNING_SECURITY_TAG],
            }),
        }
    }

    fn location_to_sarif(loc: &MatchLocation) -> SarifLocation {
        let uri = loc
            .file_path
            .as_ref()
            .map(|p| super::sarif_uri::file_path_to_sarif_uri(p.as_ref()))
            .unwrap_or_else(|| "stdin".to_string()); // LAW10: path-less finding labels as "stdin"; finding still emitted

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
                kind: SarifLogicalLocationKind::Commit,
            });
        }

        if let Some(author) = &loc.author {
            logical_locations.push(SarifLogicalLocation {
                name: author.to_string(),
                kind: SarifLogicalLocationKind::Author,
            });
        }

        if let Some(date) = &loc.date {
            logical_locations.push(SarifLogicalLocation {
                name: date.to_string(),
                kind: SarifLogicalLocationKind::Date,
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
        // against this block. Tier-B #16 from the internal design notes.
        write!(self.writer, ",\"taxonomies\":")?;
        serde_json::to_writer(&mut self.writer, &sarif_taxonomies_json())?;

        // Coverage transparency: report whole-file skips and partial scan
        // degradations as SARIF tool-execution notifications, so a platform
        // consuming the run knows the tree was not fully covered. A "no results"
        // run with coverage gaps is not a clean bill of health.
        // `executionSuccessful` stays true: these notifications describe scan
        // coverage, not a reporter failure.
        if !self.skip_summary.is_empty() {
            let notifications = self
                .skip_summary
                .iter()
                .map(|(reason, count)| SarifNotification {
                    level: SarifLevel::Note,
                    message: SarifMessage {
                        text: format!("{count} coverage gap(s): {reason}"),
                        markdown: None,
                    },
                    descriptor: SarifNotificationDescriptor {
                        id: "keyhog/coverage-gap",
                    },
                    properties: SarifNotificationProperties {
                        count: *count,
                        reason: reason.clone(),
                    },
                })
                .collect::<Vec<_>>();
            let invocations = [SarifInvocation {
                execution_successful: true,
                tool_execution_notifications: notifications,
            }];
            write!(self.writer, ",\"invocations\":")?;
            serde_json::to_writer(&mut self.writer, &invocations)?;
        }

        write!(self.writer, "}}]}}")?;
        writeln!(self.writer)?;
        self.flush_writer()
    }
}

impl_writer_backed!(SarifReporter);
