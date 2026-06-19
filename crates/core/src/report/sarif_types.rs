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
    pub(super) properties: Option<serde_json::Map<String, serde_json::Value>>,
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
    pub(super) level: String,
    pub(super) message: SarifMessage,
    pub(super) locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) properties: Option<serde_json::Map<String, serde_json::Value>>,
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
    pub(super) kind: String,
}
