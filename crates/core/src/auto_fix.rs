//! Auto-fix suggestions: turn each finding into "replace this credential
//! with `${ENV_VAR_NAME}`" advice.
//!
//! Tier-B moat innovation #15 + #17 from the internal design notes:
//! moves keyhog from "find" to "fix." We surface the suggestion in SARIF
//! `result.fixes[]` per the v2.2.0 spec; CLI consumers can apply the edit
//! interactively or in a pre-commit hook.
//!
//! This module provides only the SUGGESTION step (deterministic env-var
//! name from service + the `${VAR}` replacement string). Actually rewriting
//! files belongs in the CLI, where we can prompt the user before clobbering
//! their working tree.
//!
//! The curated `service -> env var` mappings are **Tier-B data**, compiled in
//! from `data/service-env-vars.toml`. They are NOT a hardcoded `match` arm and
//! are not extended by ambient process environment; changing the shipped map is
//! a data-file edit, reviewable in the same diff as the detector corpus.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use crate::Severity;

/// One curated `service -> env var` mapping, deserialized from the Tier-B
/// `[[service]]` tables in `data/service-env-vars.toml`.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceEnvEntry {
    /// ASCII-case-insensitive needle tested against the service string.
    #[serde(rename = "match")]
    needle: String,
    /// The environment-variable name emitted verbatim when the needle matches.
    env: String,
    /// When `true`, require the service to START with `needle`; otherwise it is
    /// a substring test.
    #[serde(default)]
    prefix: bool,
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ServiceEnvFile {
    #[serde(default)]
    service: Vec<ServiceEnvEntry>,
}

/// The compiled-in service map. Ordering within the file is preserved; because
/// matching takes the first hit, the data file must list more-specific needles
/// before broader substrings they could otherwise shadow.
///
/// A corrupt baseline is a build-time-embedded constant, so a parse failure
/// there is a hard programming error and we surface it LOUDLY (unconditional
/// `eprintln!`) and fall back to the screaming-snake derivation rather than
/// silently producing wrong fix advice.
static SERVICE_ENV_MAP: LazyLock<Vec<ServiceEnvEntry>> = LazyLock::new(|| {
    parse_service_env_file(
        include_str!("../data/service-env-vars.toml"),
        "<embedded data/service-env-vars.toml>",
    )
});

/// Provider-specific remediation advice emitted by text, JSON, SARIF, and HTML
/// reporters. The values come from Tier-B data, never reporter-side match arms.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct Remediation {
    pub(crate) action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) revoke_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) docs_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) revoke_command: Option<String>,
}

impl Remediation {
    pub(crate) fn markdown(&self) -> String {
        let mut out = self.action.clone();
        if let Some(command) = &self.revoke_command {
            out.push_str("\n\nRevoke command:\n\n```sh\n");
            out.push_str(command);
            out.push_str("\n```");
        }
        if let Some(url) = self.revoke_url.as_ref().or(self.docs_url.as_ref()) {
            out.push_str("\n\nReference: ");
            out.push_str(url);
        }
        out
    }
}

#[derive(Clone, serde::Deserialize)]
struct RemediationFields {
    action: String,
    #[serde(default)]
    revoke_url: Option<String>,
    #[serde(default)]
    docs_url: Option<String>,
    #[serde(default)]
    revoke_command: Option<String>,
}

impl From<&RemediationFields> for Remediation {
    fn from(fields: &RemediationFields) -> Self {
        Self {
            action: fields.action.clone(),
            revoke_url: fields.revoke_url.clone(),
            docs_url: fields.docs_url.clone(),
            revoke_command: fields.revoke_command.clone(),
        }
    }
}

#[derive(serde::Deserialize)]
struct DetectorRemediationEntry {
    id: String,
    #[serde(flatten)]
    fields: RemediationFields,
}

#[derive(serde::Deserialize)]
struct ServiceRemediationEntry {
    #[serde(rename = "match")]
    needle: String,
    #[serde(default)]
    prefix: bool,
    #[serde(flatten)]
    fields: RemediationFields,
}

#[derive(serde::Deserialize)]
struct SeverityRemediationEntry {
    severity: String,
    #[serde(flatten)]
    fields: RemediationFields,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RemediationFile {
    #[serde(default)]
    detector: Vec<DetectorRemediationEntry>,
    #[serde(default)]
    service: Vec<ServiceRemediationEntry>,
    #[serde(default)]
    severity: Vec<SeverityRemediationEntry>,
}

static REMEDIATION_MAP: LazyLock<RemediationFile> =
    LazyLock::new(|| {
        match parse_remediation_file(
            include_str!("../data/remediation.toml"),
            "<embedded data/remediation.toml>",
        ) {
            Ok(parsed) => parsed,
            Err(error) => {
                panic!(
            "keyhog: remediation map '<embedded data/remediation.toml>' is invalid: {error}. \
                 Fix: correct crates/core/data/remediation.toml and rebuild"
        );
            }
        }
    });

/// Parse one `service-env-vars.toml` document into its entries. On a parse
/// error we surface the failure LOUDLY (Law 10: no silent fallback) and return
/// an empty list so the caller degrades to the deterministic screaming-snake
/// derivation rather than silently dropping curated advice.
fn parse_service_env_file(raw: &str, origin: &str) -> Vec<ServiceEnvEntry> {
    match toml::from_str::<ServiceEnvFile>(raw) {
        Ok(parsed) => parsed.service,
        Err(e) => {
            eprintln!(
                "keyhog: service-env map '{origin}' failed to parse: {e}; \
                 falling back to <SERVICE>_KEY derivation for all services"
            );
            Vec::new()
        }
    }
}

pub(crate) fn validate_remediation_file_for_test(raw: &str) -> Result<(), String> {
    parse_remediation_file(raw, "<test remediation.toml>").map(|_| ())
}

fn parse_remediation_file(raw: &str, origin: &str) -> Result<RemediationFile, String> {
    validate_remediation_keys(raw, origin)?;
    let parsed = toml::from_str::<RemediationFile>(raw)
        .map_err(|error| format!("failed to parse {origin}: {error}"))?;
    validate_remediation_file(&parsed, origin)?;
    Ok(parsed)
}

fn validate_remediation_keys(raw: &str, origin: &str) -> Result<(), String> {
    let value = toml::from_str::<toml::Value>(raw)
        .map_err(|error| format!("failed to parse {origin}: {error}"))?;
    let table = value
        .as_table()
        .ok_or_else(|| format!("{origin} must be a TOML table"))?;

    for key in table.keys() {
        if !matches!(key.as_str(), "detector" | "service" | "severity") {
            return Err(format!("{origin} contains unknown top-level table {key:?}"));
        }
    }

    validate_array_table_keys(
        table,
        "detector",
        &["id", "action", "revoke_url", "docs_url", "revoke_command"],
        origin,
    )?;
    validate_array_table_keys(
        table,
        "service",
        &[
            "match",
            "prefix",
            "action",
            "revoke_url",
            "docs_url",
            "revoke_command",
        ],
        origin,
    )?;
    validate_array_table_keys(
        table,
        "severity",
        &[
            "severity",
            "action",
            "revoke_url",
            "docs_url",
            "revoke_command",
        ],
        origin,
    )?;
    Ok(())
}

fn validate_array_table_keys(
    table: &toml::map::Map<String, toml::Value>,
    section: &str,
    allowed: &[&str],
    origin: &str,
) -> Result<(), String> {
    let Some(value) = table.get(section) else {
        return Ok(());
    };
    let rows = value
        .as_array()
        .ok_or_else(|| format!("{origin} [{section}] must be an array of tables"))?;
    for (index, row) in rows.iter().enumerate() {
        let row = row
            .as_table()
            .ok_or_else(|| format!("{origin} [[{section}]] row {index} must be a table"))?;
        for key in row.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(format!(
                    "{origin} [[{section}]] row {index} contains unknown field {key:?}"
                ));
            }
        }
    }
    Ok(())
}

fn validate_remediation_file(file: &RemediationFile, origin: &str) -> Result<(), String> {
    validate_detector_remediation(file, origin)?;
    validate_service_remediation(file, origin)?;
    validate_severity_remediation(file, origin)?;
    Ok(())
}

fn validate_detector_remediation(file: &RemediationFile, origin: &str) -> Result<(), String> {
    let detectors = crate::load_embedded_detectors_or_fail()
        .map_err(|error| format!("{origin} could not validate detector ids: {error}"))?;
    let detector_ids = detectors
        .iter()
        .map(|detector| detector.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for (index, entry) in file.detector.iter().enumerate() {
        validate_non_empty("detector", index, "id", &entry.id, origin)?;
        validate_fields("detector", index, &entry.fields, origin)?;
        if !detector_ids.contains(entry.id.as_str()) {
            return Err(format!(
                "{origin} [[detector]] row {index} references unknown detector id {:?}",
                entry.id
            ));
        }
        if !seen.insert(entry.id.as_str()) {
            return Err(format!(
                "{origin} [[detector]] contains duplicate detector id {:?}",
                entry.id
            ));
        }
    }
    Ok(())
}

fn validate_service_remediation(file: &RemediationFile, origin: &str) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for (index, entry) in file.service.iter().enumerate() {
        validate_non_empty("service", index, "match", &entry.needle, origin)?;
        validate_fields("service", index, &entry.fields, origin)?;
        let key = (entry.needle.as_str(), entry.prefix);
        if !seen.insert(key) {
            return Err(format!(
                "{origin} [[service]] contains duplicate match {:?} with prefix={}",
                entry.needle, entry.prefix
            ));
        }
    }
    Ok(())
}

fn validate_severity_remediation(file: &RemediationFile, origin: &str) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for (index, entry) in file.severity.iter().enumerate() {
        validate_non_empty("severity", index, "severity", &entry.severity, origin)?;
        validate_fields("severity", index, &entry.fields, origin)?;
        let severity = Severity::from_filter_label(&entry.severity).ok_or_else(|| {
            format!(
                "{origin} [[severity]] row {index} uses unknown severity {:?}; expected {}",
                entry.severity,
                Severity::FILTER_EXPECTED_LABELS
            )
        })?;
        if entry.severity.as_str() != severity.as_str() {
            return Err(format!(
                "{origin} [[severity]] row {index} must use canonical severity {:?}, got {:?}",
                severity.as_str(),
                entry.severity
            ));
        }
        if !seen.insert(severity) {
            return Err(format!(
                "{origin} [[severity]] contains duplicate severity {:?}",
                severity.as_str()
            ));
        }
    }
    for severity in Severity::ORDERED {
        if !seen.contains(&severity) {
            return Err(format!(
                "{origin} is missing [[severity]] fallback for {:?}",
                severity.as_str()
            ));
        }
    }
    Ok(())
}

fn validate_fields(
    section: &str,
    index: usize,
    fields: &RemediationFields,
    origin: &str,
) -> Result<(), String> {
    validate_non_empty(section, index, "action", &fields.action, origin)?;
    if let Some(url) = &fields.revoke_url {
        validate_non_empty(section, index, "revoke_url", url, origin)?;
    }
    if let Some(url) = &fields.docs_url {
        validate_non_empty(section, index, "docs_url", url, origin)?;
    }
    if let Some(command) = &fields.revoke_command {
        validate_non_empty(section, index, "revoke_command", command, origin)?;
    }
    Ok(())
}

fn validate_non_empty(
    section: &str,
    index: usize,
    field: &str,
    value: &str,
    origin: &str,
) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!(
            "{origin} [[{section}]] row {index} has empty {field}"
        ));
    }
    Ok(())
}

/// Map a detector's `service` string to a conventional environment-variable
/// name. Falls back to `<UPPER_SERVICE>_KEY` when the service isn't in the
/// curated [Tier-B map](../data/service-env-vars.toml).
///
/// The curated mappings follow community conventions (12-factor, common SDKs);
/// see `data/service-env-vars.toml` for the authoritative list.
pub(crate) fn env_var_name_for_service(service: &str) -> String {
    SERVICE_ENV_MAP
        .iter()
        .find(|entry| service_entry_matches(service, &entry.needle, entry.prefix))
        .map(|entry| entry.env.clone())
        // The default below is not an error fallback — it is the documented
        // `<SERVICE>_KEY` mapping for any service the curated Tier-B map does not
        // cover, always producing a deterministic, correct suggestion.
        .unwrap_or_else(|| service_to_screaming_snake(service)) // LAW10: documented default, not a failure path
}

fn service_to_screaming_snake(service: &str) -> String {
    let mut out = String::with_capacity(service.len() + 4);
    for ch in service.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string() + "_KEY"
}

/// Render the `${ENV_VAR_NAME}` shell-interpolation replacement string for
/// a detector. Reporters embed this in their `fixes[]` output.
/// Return the recommended replacement text for a leaked credential (e.g., "${STRIPE_KEY}").
pub(crate) fn fix_replacement_text(service: &str) -> String {
    format!("${{{}}}", env_var_name_for_service(service))
}

pub(crate) fn remediation_for(detector_id: &str, service: &str, severity: Severity) -> Remediation {
    let data = &*REMEDIATION_MAP;
    if let Some(entry) = data
        .detector
        .iter()
        .find(|entry| entry.id.as_str() == detector_id)
    {
        return Remediation::from(&entry.fields);
    }

    if let Some(entry) = data
        .service
        .iter()
        .find(|entry| service_entry_matches(service, &entry.needle, entry.prefix))
    {
        return Remediation::from(&entry.fields);
    }

    if let Some(entry) = data
        .severity
        .iter()
        .find(|entry| entry.severity == severity.as_str())
    {
        return Remediation::from(&entry.fields);
    }

    Remediation {
        action: "Remove the exposed credential from the codebase and rotate it at the provider."
            .to_string(),
        revoke_url: None,
        docs_url: None,
        revoke_command: None,
    }
}

fn service_entry_matches(service: &str, needle: &str, prefix: bool) -> bool {
    if prefix {
        crate::starts_with_ignore_ascii_case(service, needle)
    } else {
        crate::contains_ignore_ascii_case(service, needle)
    }
}
