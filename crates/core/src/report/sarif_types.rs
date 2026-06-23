//! SARIF serialization structs used by the streaming reporter.

/// A SARIF rule (tool component rule).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifRule {
    pub(super) id: String,
    pub(super) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) short_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) full_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) help: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) help_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) properties: Option<SarifRuleProperties>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifMessage {
    pub(super) text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) markdown: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifTool {
    pub(super) driver: SarifToolDriver,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifToolDriver {
    pub(super) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) information_uri: Option<String>,
    pub(super) rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifResult {
    pub(super) rule_id: String,
    pub(super) level: SarifLevel,
    pub(super) message: SarifMessage,
    pub(super) locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) properties: Option<SarifResultProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) related_locations: Option<Vec<SarifLocation>>,
    /// SARIF v2.2.0 `fixes[]` - auto-rotation suggestions. Each entry
    /// proposes replacing the leaked credential with a `${ENV_VAR_NAME}`
    /// shell-interpolation reference. Tier-B #15 + #17.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) fixes: Option<Vec<SarifFix>>,
    /// SARIF `partialFingerprints` - stable per-finding identity (the
    /// credential hash) so GitHub code-scanning dedups alerts across runs
    /// instead of re-opening the same leak every scan. See `sarif_uri`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) partial_fingerprints: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifFix {
    pub(super) description: SarifMessage,
    pub(super) artifact_changes: Vec<SarifArtifactChange>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifArtifactChange {
    pub(super) artifact_location: SarifArtifactLocation,
    pub(super) replacements: Vec<SarifReplacement>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifReplacement {
    pub(super) deleted_region: SarifRegion,
    pub(super) inserted_content: SarifSnippet,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifLocation {
    pub(super) physical_location: SarifPhysicalLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) logical_locations: Option<Vec<SarifLogicalLocation>>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifPhysicalLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) artifact_location: Option<SarifArtifactLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) region: Option<SarifRegion>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifArtifactLocation {
    pub(super) uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) uri_base_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifRegion {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) start_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) start_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) end_column: Option<usize>,
    #[serde(rename = "charOffset", skip_serializing_if = "Option::is_none")]
    pub(super) char_offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) snippet: Option<SarifSnippet>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifSnippet {
    pub(super) text: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifLogicalLocation {
    pub(super) name: String,
    pub(super) kind: SarifLogicalLocationKind,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum SarifLevel {
    Error,
    Warning,
    Note,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum SarifLogicalLocationKind {
    Commit,
    Author,
    Date,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct SarifResultProperties {
    pub(super) verification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) confidence: Option<f64>,
    pub(super) cwe: &'static str,
    pub(super) owasp: &'static str,
    #[serde(rename = "remediation.action")]
    pub(super) remediation_action: String,
    #[serde(
        rename = "remediation.revoke_url",
        skip_serializing_if = "Option::is_none"
    )]
    pub(super) remediation_revoke_url: Option<String>,
    #[serde(
        rename = "remediation.docs_url",
        skip_serializing_if = "Option::is_none"
    )]
    pub(super) remediation_docs_url: Option<String>,
    #[serde(
        rename = "remediation.revoke_command",
        skip_serializing_if = "Option::is_none"
    )]
    pub(super) remediation_revoke_command: Option<String>,
    #[serde(flatten)]
    pub(super) metadata: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct SarifRuleProperties {
    pub(super) service: String,
    pub(super) severity: String,
    #[serde(rename = "security-severity")]
    pub(super) security_severity: &'static str,
    pub(super) tags: [&'static str; 1],
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifInvocation {
    pub(super) execution_successful: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) tool_execution_notifications: Vec<SarifNotification>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifNotification {
    pub(super) level: SarifLevel,
    pub(super) message: SarifMessage,
    pub(super) descriptor: SarifNotificationDescriptor,
    pub(super) properties: SarifNotificationProperties,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct SarifNotificationDescriptor {
    pub(super) id: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct SarifNotificationProperties {
    pub(super) count: usize,
    pub(super) reason: String,
}
