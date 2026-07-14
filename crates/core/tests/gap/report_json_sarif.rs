//! Gap-coverage integration tests for the JSON, JSONL, and SARIF reporters.
//!
//! Every expected value here is derived from the real implementation under
//! `crates/core/src/report/{json,sarif,sarif_uri,sarif_types,sarif_taxonomies}.rs`
//! and `crates/core/src/{finding,auto_fix,spec,lib}.rs`. Assertions check
//! concrete strings/numbers/bytes, never just non-emptiness.
//!
//! Written as a plain module body (no `fn main`, no wrapping `mod`) for
//! inclusion via `mod report_json_sarif;` in the `tests/gaps.rs` aggregator.

use crate::support::reporters::{JsonArrayReporter, JsonReporter, JsonlReporter, SarifReporter};
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/// A minimal, deterministic finding. `service="test"`, `severity=High`,
/// file `config.env` at line 42, offset 0, all-zero credential hash.
fn finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("test-detector"),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("****redacted"),
        credential_hash: [0u8; 32].into(),
        companions_redacted: std::collections::HashMap::new(),
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
        entropy: None,
        confidence: Some(0.9),
    }
}

/// Run findings through the SARIF reporter and parse the document.
fn sarif_of(findings: &[VerifiedFinding]) -> serde_json::Value {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        for f in findings {
            r.report(f).unwrap();
        }
        r.finish().unwrap();
    }
    serde_json::from_slice(&buf).expect("SARIF must parse as JSON")
}

/// Run a single finding through SARIF and return the parsed document plus the
/// raw bytes (for byte-level/structural assertions).
fn sarif_bytes(findings: &[VerifiedFinding]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        for f in findings {
            r.report(f).unwrap();
        }
        r.finish().unwrap();
    }
    buf
}

/// Run findings through the JSON array reporter; return raw UTF-8 string.
fn json_array_str(findings: &[VerifiedFinding]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = JsonArrayReporter::new(&mut buf).unwrap();
        for f in findings {
            r.report(f).unwrap();
        }
        r.finish().unwrap();
    }
    String::from_utf8(buf).expect("utf8")
}

/// Run findings through the JSONL reporter; return raw UTF-8 string.
fn jsonl_str(findings: &[VerifiedFinding]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = JsonlReporter::new(&mut buf);
        for f in findings {
            r.report(f).unwrap();
        }
        r.finish().unwrap();
    }
    String::from_utf8(buf).expect("utf8")
}

// ============================================================================
// JSONL reporter
// ============================================================================

#[test]
fn jsonl_single_finding_is_one_line_ending_in_newline() {
    let out = jsonl_str(&[finding()]);
    // serde object then `writeln!` -> exactly one trailing '\n'.
    assert!(out.ends_with('\n'), "JSONL line must end with newline");
    assert_eq!(out.matches('\n').count(), 1, "one finding -> one newline");
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(parsed["detector_id"], "test-detector");
}

#[test]
fn jsonl_emits_one_object_per_line_for_n_findings() {
    let f = finding();
    let mut f2 = finding();
    f2.detector_id = Arc::from("second");
    let mut f3 = finding();
    f3.detector_id = Arc::from("third");
    let out = jsonl_str(&[f, f2, f3]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "three findings -> three lines");
    let ids: Vec<String> = lines
        .iter()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["detector_id"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(ids, vec!["test-detector", "second", "third"]);
}

#[test]
fn jsonl_empty_run_produces_no_bytes() {
    // No `report()` calls; `finish()` only flushes. JSONL has no skeleton.
    let out = jsonl_str(&[]);
    assert_eq!(out, "", "empty JSONL run writes nothing");
}

#[test]
fn jsonl_required_fields_present_and_correct() {
    let out = jsonl_str(&[finding()]);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["detector_id"], "test-detector");
    assert_eq!(v["detector_name"], "Test Detector");
    assert_eq!(v["service"], "test");
    // Severity serializes kebab-case; High -> "high".
    assert_eq!(v["severity"], "high");
    assert_eq!(v["credential_redacted"], "****redacted");
    // Raw [u8;32] hex-encoded at the serde boundary: 64 zero-hex chars.
    assert_eq!(
        v["credential_hash"],
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    // verification is snake_case; Unverifiable -> "unverifiable".
    assert_eq!(v["verification"], "unverifiable");
    assert_eq!(v["confidence"], 0.9);
}

#[test]
fn jsonl_location_nested_object_fields() {
    let out = jsonl_str(&[finding()]);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["location"]["source"], "filesystem");
    assert_eq!(v["location"]["file_path"], "config.env");
    assert_eq!(v["location"]["line"], 42);
    assert_eq!(v["location"]["offset"], 0);
    // None optionals serialize as null (serde_arc_str_opt -> Option<&str>).
    assert!(v["location"]["commit"].is_null());
    assert!(v["location"]["author"].is_null());
    assert!(v["location"]["date"].is_null());
}

#[test]
fn jsonl_confidence_omitted_when_none() {
    // VerifiedFinding.confidence has skip_serializing_if = Option::is_none.
    let mut f = finding();
    f.confidence = None;
    let out = jsonl_str(&[f]);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert!(
        v.get("confidence").is_none(),
        "confidence:None must be omitted from JSON, not null"
    );
}

#[test]
fn jsonl_severity_kebab_case_client_safe() {
    // ClientSafe must render kebab-case "client-safe", not "clientsafe".
    let mut f = finding();
    f.severity = Severity::ClientSafe;
    let out = jsonl_str(&[f]);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["severity"], "client-safe");
}

#[test]
fn jsonl_verification_error_variant_serializes_with_payload() {
    // VerificationResult::Error(String) -> {"error": "..."} (snake_case adjacent).
    let mut f = finding();
    f.verification = VerificationResult::Error("timeout".to_string());
    let out = jsonl_str(&[f]);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["verification"]["error"], "timeout");
}

#[test]
fn jsonl_metadata_map_roundtrips() {
    let mut f = finding();
    f.metadata = HashMap::from([("team".to_string(), "acme".to_string())]);
    let out = jsonl_str(&[f]);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["metadata"]["team"], "acme");
}

#[test]
fn jsonl_additional_locations_array_present() {
    let mut f = finding();
    f.additional_locations = vec![MatchLocation {
        source: Arc::from("filesystem"),
        file_path: Some(Arc::from("backup.env")),
        line: Some(7),
        offset: 3,
        commit: None,
        author: None,
        date: None,
    }];
    let out = jsonl_str(&[f]);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    let adds = v["additional_locations"].as_array().unwrap();
    assert_eq!(adds.len(), 1);
    assert_eq!(adds[0]["file_path"], "backup.env");
    assert_eq!(adds[0]["line"], 7);
    assert_eq!(adds[0]["offset"], 3);
}

#[test]
fn jsonl_credential_hash_hex_encodes_nonzero_bytes() {
    let mut f = finding();
    let mut h = [0u8; 32];
    h[0] = 0xde;
    h[1] = 0xad;
    h[31] = 0xff;
    f.credential_hash = h.into();
    let out = jsonl_str(&[f]);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    let hex = v["credential_hash"].as_str().unwrap();
    assert_eq!(hex.len(), 64, "32 bytes -> 64 hex chars");
    assert!(hex.starts_with("dead"), "first two bytes 0xde 0xad");
    assert!(hex.ends_with("ff"), "last byte 0xff");
}

// ============================================================================
// JSON array reporter
// ============================================================================

#[test]
fn json_array_empty_run_is_empty_brackets() {
    // new() writes "[", finish() writes "]" with no findings between.
    let out = json_array_str(&[]);
    assert_eq!(out, "[]", "empty array reporter -> exactly []");
}

#[test]
fn json_array_single_finding_no_leading_comma() {
    let out = json_array_str(&[finding()]);
    assert!(out.starts_with('['));
    assert!(out.ends_with(']'));
    // No comma directly after the opening bracket for the first element.
    assert!(
        !out.starts_with("[,"),
        "first element must not be comma-prefixed"
    );
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["detector_id"], "test-detector");
}

#[test]
fn json_array_comma_separates_multiple_findings() {
    let f = finding();
    let mut f2 = finding();
    f2.detector_id = Arc::from("two");
    let mut f3 = finding();
    f3.detector_id = Arc::from("three");
    let out = json_array_str(&[f, f2, f3]);
    // Two separators for three elements.
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["detector_id"], "test-detector");
    assert_eq!(arr[1]["detector_id"], "two");
    assert_eq!(arr[2]["detector_id"], "three");
}

#[test]
fn json_array_no_trailing_newline() {
    // JsonArrayReporter::finish writes "]" with NO writeln (unlike SARIF/JSONL).
    let out = json_array_str(&[finding()]);
    assert!(
        !out.ends_with('\n'),
        "JSON array must not append a trailing newline"
    );
    assert!(out.ends_with(']'));
}

#[test]
fn json_array_required_fields_match_jsonl() {
    let out = json_array_str(&[finding()]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let obj = &v[0];
    assert_eq!(obj["detector_id"], "test-detector");
    assert_eq!(obj["detector_name"], "Test Detector");
    assert_eq!(obj["service"], "test");
    assert_eq!(obj["severity"], "high");
    assert_eq!(obj["verification"], "unverifiable");
    assert_eq!(obj["confidence"], 0.9);
}

#[test]
fn json_reporter_alias_behaves_as_array_reporter() {
    // JsonReporter is a type alias for JsonArrayReporter.
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = JsonReporter::new(&mut buf).unwrap();
        r.report(&finding()).unwrap();
        r.finish().unwrap();
    }
    let out = String::from_utf8(buf).unwrap();
    assert!(out.starts_with('[') && out.ends_with(']'));
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v[0]["detector_id"], "test-detector");
}

// ============================================================================
// SARIF: top-level skeleton + required fields
// ============================================================================

#[test]
fn sarif_top_level_version_and_schema() {
    let json = sarif_of(&[finding()]);
    assert_eq!(json["version"], "2.1.0");
    let schema = json["$schema"].as_str().unwrap();
    assert_eq!(
        schema,
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json"
    );
}

#[test]
fn sarif_exactly_one_run() {
    let json = sarif_of(&[finding()]);
    let runs = json["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1, "keyhog always emits exactly one run");
}

#[test]
fn sarif_tool_driver_name_version_information_uri() {
    let json = sarif_of(&[finding()]);
    let driver = &json["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "keyhog");
    // informationUri == env!("CARGO_PKG_REPOSITORY") (set in sarif.rs finish()).
    assert_eq!(
        driver["informationUri"],
        env!("CARGO_PKG_REPOSITORY"),
        "informationUri must point at the keyhog repository"
    );
    // version == CARGO_PKG_VERSION; the test crate shares the workspace version.
    let driver_version = driver["version"].as_str().unwrap();
    assert_eq!(
        driver_version,
        env!("CARGO_PKG_VERSION"),
        "SARIF driver.version must equal the crate package version"
    );
    // Sanity: it is a dotted semver, not empty.
    assert!(
        driver_version.split('.').count() >= 2,
        "version should be dotted semver, got {driver_version}"
    );
}

#[test]
fn sarif_empty_run_still_valid_document() {
    // finish() with no report() still emits a full, parseable SARIF doc.
    let json = sarif_of(&[]);
    assert_eq!(json["version"], "2.1.0");
    let runs = json["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    let results = runs[0]["results"].as_array().unwrap();
    assert!(results.is_empty(), "no findings -> empty results array");
    let rules = runs[0]["tool"]["driver"]["rules"].as_array().unwrap();
    assert!(rules.is_empty(), "no findings -> empty rules array");
    // Taxonomies are static and always present.
    let taxa = runs[0]["taxonomies"].as_array().unwrap();
    assert_eq!(taxa.len(), 2);
}

#[test]
fn sarif_document_ends_with_newline() {
    // finish() ends with writeln! after the closing braces.
    let bytes = sarif_bytes(&[finding()]);
    assert_eq!(*bytes.last().unwrap(), b'\n', "SARIF doc ends with newline");
}

// ============================================================================
// SARIF: results required fields
// ============================================================================

#[test]
fn sarif_result_rule_id_matches_detector_id() {
    let json = sarif_of(&[finding()]);
    assert_eq!(json["runs"][0]["results"][0]["ruleId"], "test-detector");
}

#[test]
fn sarif_result_message_text_format() {
    // build_sarif_result: "{service} secret detected: {credential_redacted}".
    let json = sarif_of(&[finding()]);
    let text = json["runs"][0]["results"][0]["message"]["text"]
        .as_str()
        .unwrap();
    assert_eq!(text, "test secret detected: ****redacted");
}

#[test]
fn sarif_result_level_high_is_error() {
    let json = sarif_of(&[finding()]);
    assert_eq!(json["runs"][0]["results"][0]["level"], "error");
}

#[test]
fn sarif_severity_to_level_full_mapping() {
    // severity_to_level: Critical/High -> error; Medium -> warning;
    // Low/ClientSafe/Info -> note. Use distinct detector_ids so rules don't merge.
    let cases = [
        (Severity::Critical, "error"),
        (Severity::High, "error"),
        (Severity::Medium, "warning"),
        (Severity::Low, "note"),
        (Severity::ClientSafe, "note"),
        (Severity::Info, "note"),
    ];
    for (sev, expected) in cases {
        let mut f = finding();
        f.severity = sev;
        f.detector_id = Arc::from(format!("det-{expected}-{sev:?}"));
        let json = sarif_of(&[f]);
        assert_eq!(
            json["runs"][0]["results"][0]["level"], expected,
            "severity {sev:?} -> level {expected}"
        );
    }
}

#[test]
fn sarif_result_region_start_line_and_no_columns() {
    // line=42, offset=0 -> region has startLine, no charOffset.
    let json = sarif_of(&[finding()]);
    let region = &json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
    assert_eq!(region["startLine"], 42);
    assert!(
        region.get("charOffset").is_none(),
        "offset 0 omits charOffset"
    );
    assert!(region.get("startColumn").is_none());
    assert!(region.get("endLine").is_none());
    assert!(region.get("snippet").is_none());
}

#[test]
fn sarif_region_charoffset_emitted_when_offset_nonzero() {
    // location_to_sarif: offset != 0 -> charOffset = Some(offset).
    let mut f = finding();
    f.location.line = None;
    f.location.offset = 128;
    let json = sarif_of(&[f]);
    let region = &json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
    assert_eq!(region["charOffset"], 128);
    assert!(
        region.get("startLine").is_none(),
        "line None omits startLine"
    );
}

#[test]
fn sarif_region_absent_when_no_line_and_zero_offset() {
    // line None + offset 0 -> region is None entirely.
    let mut f = finding();
    f.location.line = None;
    f.location.offset = 0;
    let json = sarif_of(&[f]);
    let phys = &json["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
    assert!(
        phys.get("region").is_none(),
        "no line + zero offset -> no region key"
    );
}

#[test]
fn sarif_result_artifact_location_relative_uri() {
    // config.env is already relative; file_path_to_sarif_uri keeps it.
    let json = sarif_of(&[finding()]);
    let uri = json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        ["uri"]
        .as_str();
    assert_eq!(uri, Some("config.env"));
}

#[test]
fn sarif_result_properties_verification_lowercased() {
    // properties.verification comes from the canonical `style::verification_token`
    // (snake_case, matching the JSON serde representation). NOT the old
    // `format!("{:?}", v).to_lowercase()`, which emitted `ratelimited`/`error("..")`.
    let json = sarif_of(&[finding()]);
    assert_eq!(
        json["runs"][0]["results"][0]["properties"]["verification"],
        "unverifiable"
    );
}

#[test]
fn sarif_verification_token_is_snake_case_consistent_with_json() {
    // Regression: SARIF previously derived `verification` from Debug formatting,
    // so RateLimited became "ratelimited" (no underscore) and Error became
    // `error("msg")`: diverging from JSON's serde snake_case and from the
    // junit/csv/github mappings. The canonical token fixes both.
    let mut rl = finding();
    rl.verification = VerificationResult::RateLimited;
    let json = sarif_of(&[rl]);
    assert_eq!(
        json["runs"][0]["results"][0]["properties"]["verification"], "rate_limited",
        "RateLimited must be snake_case `rate_limited`, never Debug `ratelimited`"
    );

    let mut err = finding();
    err.verification = VerificationResult::Error("timeout".to_string());
    let json = sarif_of(&[err]);
    assert_eq!(
        json["runs"][0]["results"][0]["properties"]["verification"], "error: timeout",
        "Error must render as `error: <msg>`, never the Debug form `error(\"..\")`"
    );
}

#[test]
fn sarif_result_properties_verification_live() {
    let mut f = finding();
    f.verification = VerificationResult::Live;
    let json = sarif_of(&[f]);
    assert_eq!(
        json["runs"][0]["results"][0]["properties"]["verification"],
        "live"
    );
}

#[test]
fn sarif_result_properties_confidence_number() {
    let json = sarif_of(&[finding()]);
    assert_eq!(
        json["runs"][0]["results"][0]["properties"]["confidence"],
        0.9
    );
}

#[test]
fn sarif_result_properties_confidence_omitted_when_none() {
    let mut f = finding();
    f.confidence = None;
    let json = sarif_of(&[f]);
    let props = &json["runs"][0]["results"][0]["properties"];
    assert!(
        props.get("confidence").is_none(),
        "confidence None -> no properties.confidence"
    );
}

#[test]
fn sarif_result_cwe_and_owasp_always_present() {
    // CWE-798 + A07:2021 are inserted for every finding.
    let json = sarif_of(&[finding()]);
    let props = &json["runs"][0]["results"][0]["properties"];
    assert_eq!(props["cwe"], "CWE-798");
    assert_eq!(props["owasp"], "A07:2021");
}

#[test]
fn sarif_result_metadata_keys_prefixed() {
    // metadata.{key} = value for each metadata entry.
    let mut f = finding();
    f.metadata = HashMap::from([("account_id".to_string(), "AKIA123".to_string())]);
    let json = sarif_of(&[f]);
    assert_eq!(
        json["runs"][0]["results"][0]["properties"]["metadata.account_id"],
        "AKIA123"
    );
}

#[test]
fn sarif_partial_fingerprints_present_for_nonzero_hash() {
    // credential_fingerprints: non-zero hash -> keyhog/credentialHash/v1 entry.
    let mut f = finding();
    let mut h = [0u8; 32];
    h[0] = 0x01;
    f.credential_hash = h.into();
    let json = sarif_of(&[f]);
    let fp = &json["runs"][0]["results"][0]["partialFingerprints"]["keyhog/credentialHash/v1"];
    let hex = fp.as_str().unwrap();
    assert_eq!(hex.len(), 64);
    assert!(hex.starts_with("01"));
    assert!(hex.ends_with("00"), "only first byte set -> trailing zeros");
}

#[test]
fn sarif_partial_fingerprints_absent_for_zero_hash() {
    // All-zero hash is the "no identity" sentinel -> None -> field omitted.
    let json = sarif_of(&[finding()]); // default hash is [0;32]
    let result = &json["runs"][0]["results"][0];
    assert!(
        result.get("partialFingerprints").is_none(),
        "all-zero hash must omit partialFingerprints"
    );
}

// ============================================================================
// SARIF: rules indexing + dedup
// ============================================================================

#[test]
fn sarif_single_rule_built_from_finding() {
    let json = sarif_of(&[finding()]);
    let rules = json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 1);
    let rule = &rules[0];
    assert_eq!(rule["id"], "test-detector");
    assert_eq!(rule["name"], "Test Detector");
    assert_eq!(rule["shortDescription"]["text"], "test secret detected");
    assert_eq!(
        rule["fullDescription"]["text"],
        "A test secret was detected by the Test Detector detector"
    );
    assert_eq!(
        rule["help"]["text"],
        "Revoke and rotate the exposed credential, then remove it from the codebase."
    );
    assert_eq!(
        rule["help"]["markdown"],
        "Revoke and rotate the exposed credential, then remove it from the codebase."
    );
    assert!(
        rule.get("helpUri").is_none(),
        "synthetic test service should use the Tier-B severity fallback without provider URL"
    );
}

#[test]
fn sarif_rule_properties_service_and_severity() {
    let json = sarif_of(&[finding()]);
    let props = &json["runs"][0]["tool"]["driver"]["rules"][0]["properties"];
    assert_eq!(props["service"], "test");
    // build_rule uses the canonical structured severity token, not Debug casing.
    assert_eq!(props["severity"], "high");
}

#[test]
fn sarif_rule_properties_severity_uses_kebab_case_token() {
    let mut f = finding();
    f.severity = Severity::ClientSafe;
    f.detector_id = Arc::from("client-safe-detector");
    f.detector_name = Arc::from("Client Safe Detector");
    let json = sarif_of(&[f]);
    let props = &json["runs"][0]["tool"]["driver"]["rules"][0]["properties"];
    assert_eq!(
        props["severity"], "client-safe",
        "SARIF severity must match JSON's kebab-case token, never Debug `clientsafe`"
    );
}

#[test]
fn sarif_rule_code_scanning_security_severity_and_tags() {
    // apply_code_scanning_props: High -> "8.0", tags=["security"].
    let json = sarif_of(&[finding()]);
    let props = &json["runs"][0]["tool"]["driver"]["rules"][0]["properties"];
    assert_eq!(props["security-severity"], "8.0");
    let tags = props["tags"].as_array().unwrap();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0], "security");
}

#[test]
fn sarif_code_scanning_severity_band_full_mapping() {
    // Critical 9.5, High 8.0, Medium 5.0, Low 2.0, ClientSafe 1.0, Info 0.0.
    let cases = [
        (Severity::Critical, "9.5"),
        (Severity::High, "8.0"),
        (Severity::Medium, "5.0"),
        (Severity::Low, "2.0"),
        (Severity::ClientSafe, "1.0"),
        (Severity::Info, "0.0"),
    ];
    for (sev, expected) in cases {
        let mut f = finding();
        f.severity = sev;
        f.detector_id = Arc::from(format!("ss-{sev:?}"));
        f.detector_name = Arc::from(format!("ss {sev:?}"));
        let json = sarif_of(&[f]);
        let props = &json["runs"][0]["tool"]["driver"]["rules"][0]["properties"];
        assert_eq!(
            props["security-severity"], expected,
            "severity {sev:?} -> security-severity {expected}"
        );
    }
}

#[test]
fn sarif_rules_deduped_by_detector_id() {
    // Two findings, same detector_id -> one rule.
    let f1 = finding();
    let mut f2 = finding();
    f2.location.line = Some(99);
    f2.location.file_path = Some(Arc::from("other.env"));
    let json = sarif_of(&[f1, f2]);
    let rules = json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 1, "same detector_id -> single rule");
    let results = json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2, "still two results");
}

#[test]
fn sarif_distinct_detectors_produce_distinct_rules_sorted() {
    // finish() sorts rules by id ascending. Feed out of order: zeta then alpha.
    let mut fz = finding();
    fz.detector_id = Arc::from("zeta");
    fz.detector_name = Arc::from("Zeta");
    fz.service = Arc::from("zeta-svc");
    let mut fa = finding();
    fa.detector_id = Arc::from("alpha");
    fa.detector_name = Arc::from("Alpha");
    fa.service = Arc::from("alpha-svc");
    let json = sarif_of(&[fz, fa]);
    let rules = json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["id"], "alpha", "rules sorted by id ascending");
    assert_eq!(rules[1]["id"], "zeta");
}

#[test]
fn sarif_rule_id_indexes_into_results() {
    // Every result.ruleId must have a matching rule.id in the driver.
    let mut f1 = finding();
    f1.detector_id = Arc::from("aws-access-key");
    f1.detector_name = Arc::from("AWS Access Key");
    f1.service = Arc::from("aws");
    let mut f2 = finding();
    f2.detector_id = Arc::from("github-pat");
    f2.detector_name = Arc::from("GitHub PAT");
    f2.service = Arc::from("github");
    let json = sarif_of(&[f1, f2]);
    let rule_ids: Vec<String> = json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect();
    let result_ids: Vec<String> = json["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap().to_string())
        .collect();
    for rid in &result_ids {
        assert!(
            rule_ids.contains(rid),
            "result ruleId {rid} must index into driver.rules"
        );
    }
    assert!(rule_ids.contains(&"aws-access-key".to_string()));
    assert!(rule_ids.contains(&"github-pat".to_string()));
}

// ============================================================================
// SARIF: locations, logical locations, related locations
// ============================================================================

#[test]
fn sarif_stdin_uri_when_no_file_path() {
    // location_to_sarif: file_path None -> uri "stdin".
    let mut f = finding();
    f.location.file_path = None;
    let json = sarif_of(&[f]);
    let uri = json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        ["uri"]
        .as_str();
    assert_eq!(uri, Some("stdin"));
}

#[test]
fn sarif_logical_locations_commit_author_date_ordered() {
    let mut f = finding();
    f.location.commit = Some(Arc::from("abc123"));
    f.location.author = Some(Arc::from("dev@example.com"));
    f.location.date = Some(Arc::from("2026-03-20T12:00:00Z"));
    let json = sarif_of(&[f]);
    let logical = json["runs"][0]["results"][0]["locations"][0]["logicalLocations"]
        .as_array()
        .unwrap();
    assert_eq!(logical.len(), 3);
    assert_eq!(logical[0]["kind"], "commit");
    assert_eq!(logical[0]["name"], "abc123");
    assert_eq!(logical[1]["kind"], "author");
    assert_eq!(logical[1]["name"], "dev@example.com");
    assert_eq!(logical[2]["kind"], "date");
    assert_eq!(logical[2]["name"], "2026-03-20T12:00:00Z");
}

#[test]
fn sarif_logical_locations_absent_when_no_git_metadata() {
    let json = sarif_of(&[finding()]);
    let loc = &json["runs"][0]["results"][0]["locations"][0];
    assert!(
        loc.get("logicalLocations").is_none(),
        "no commit/author/date -> no logicalLocations"
    );
}

#[test]
fn sarif_related_locations_emitted_from_additional() {
    let mut f = finding();
    f.additional_locations = vec![MatchLocation {
        source: Arc::from("filesystem"),
        file_path: Some(Arc::from("backup.env")),
        line: Some(100),
        offset: 0,
        commit: None,
        author: None,
        date: None,
    }];
    let json = sarif_of(&[f]);
    let related = json["runs"][0]["results"][0]["relatedLocations"]
        .as_array()
        .unwrap();
    assert_eq!(related.len(), 1);
    assert_eq!(
        related[0]["physicalLocation"]["artifactLocation"]["uri"],
        "backup.env"
    );
    assert_eq!(related[0]["physicalLocation"]["region"]["startLine"], 100);
}

#[test]
fn sarif_related_locations_absent_when_no_additional() {
    let json = sarif_of(&[finding()]);
    assert!(
        json["runs"][0]["results"][0]
            .get("relatedLocations")
            .is_none(),
        "no additional_locations -> no relatedLocations key"
    );
}

#[test]
fn sarif_related_locations_deduped_by_canonical_tuple() {
    // build_sarif_result dedups additional_locations by (path, line, offset).
    let dup = MatchLocation {
        source: Arc::from("filesystem"),
        file_path: Some(Arc::from("dup.env")),
        line: Some(5),
        offset: 0,
        commit: None,
        author: None,
        date: None,
    };
    let mut f = finding();
    f.additional_locations = vec![dup.clone(), dup.clone(), dup];
    let json = sarif_of(&[f]);
    let related = json["runs"][0]["results"][0]["relatedLocations"]
        .as_array()
        .unwrap();
    assert_eq!(
        related.len(),
        1,
        "three identical related locations collapse to one"
    );
}

#[test]
fn sarif_related_locations_distinct_lines_kept() {
    let base = |line: usize| MatchLocation {
        source: Arc::from("filesystem"),
        file_path: Some(Arc::from("multi.env")),
        line: Some(line),
        offset: 0,
        commit: None,
        author: None,
        date: None,
    };
    let mut f = finding();
    f.additional_locations = vec![base(1), base(2), base(1)]; // 1 dup, 2 distinct
    let json = sarif_of(&[f]);
    let related = json["runs"][0]["results"][0]["relatedLocations"]
        .as_array()
        .unwrap();
    assert_eq!(related.len(), 2, "distinct lines kept, duplicate dropped");
    assert_eq!(related[0]["physicalLocation"]["region"]["startLine"], 1);
    assert_eq!(related[1]["physicalLocation"]["region"]["startLine"], 2);
}

// ============================================================================
// SARIF: fixes (auto-fix)
// ============================================================================

#[test]
fn sarif_fix_present_with_file_path_and_line() {
    let json = sarif_of(&[finding()]);
    let fixes = json["runs"][0]["results"][0]["fixes"].as_array().unwrap();
    assert_eq!(fixes.len(), 1);
    // service "test" is not curated -> service_to_screaming_snake -> "TEST_KEY".
    let replacement =
        fixes[0]["artifactChanges"][0]["replacements"][0]["insertedContent"]["text"].as_str();
    assert_eq!(replacement, Some("${TEST_KEY}"));
}

#[test]
fn sarif_fix_description_text_format() {
    let json = sarif_of(&[finding()]);
    let desc = json["runs"][0]["results"][0]["fixes"][0]["description"]["text"]
        .as_str()
        .unwrap();
    assert_eq!(
        desc,
        "Replace the leaked credential with `${TEST_KEY}` and load `TEST_KEY` from your secret manager."
    );
}

#[test]
fn sarif_fix_deleted_region_uses_finding_line() {
    let json = sarif_of(&[finding()]);
    let region = &json["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]["replacements"]
        [0]["deletedRegion"];
    assert_eq!(region["startLine"], 42);
    assert!(region.get("startColumn").is_none());
    assert!(region.get("endLine").is_none());
}

#[test]
fn sarif_fix_artifact_uri_matches_finding_path() {
    let json = sarif_of(&[finding()]);
    let uri = json["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]["artifactLocation"]
        ["uri"]
        .as_str();
    assert_eq!(uri, Some("config.env"));
}

#[test]
fn sarif_fix_curated_env_var_for_aws() {
    // keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(&keyhog_core::testing::TestApi, "aws") -> AWS_ACCESS_KEY_ID.
    let mut f = finding();
    f.service = Arc::from("aws");
    f.detector_id = Arc::from("aws-key");
    let json = sarif_of(&[f]);
    let replacement = json["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]
        ["replacements"][0]["insertedContent"]["text"]
        .as_str();
    assert_eq!(replacement, Some("${AWS_ACCESS_KEY_ID}"));
}

#[test]
fn sarif_fix_curated_env_var_for_stripe() {
    let mut f = finding();
    f.service = Arc::from("stripe");
    f.detector_id = Arc::from("stripe-key");
    let json = sarif_of(&[f]);
    let replacement = json["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]
        ["replacements"][0]["insertedContent"]["text"]
        .as_str();
    assert_eq!(replacement, Some("${STRIPE_SECRET_KEY}"));
}

#[test]
fn sarif_fix_absent_when_no_file_path() {
    // fixes built only when (file_path, line) both Some.
    let mut f = finding();
    f.location.file_path = None;
    let json = sarif_of(&[f]);
    assert!(
        json["runs"][0]["results"][0].get("fixes").is_none(),
        "no file_path -> no fixes"
    );
}

#[test]
fn sarif_fix_absent_when_no_line() {
    let mut f = finding();
    f.location.line = None;
    let json = sarif_of(&[f]);
    assert!(
        json["runs"][0]["results"][0].get("fixes").is_none(),
        "no line -> no fixes"
    );
}

// ============================================================================
// SARIF: taxonomies block + informationUri targets
// ============================================================================

#[test]
fn sarif_taxonomies_cwe_block() {
    let json = sarif_of(&[finding()]);
    let cwe = &json["runs"][0]["taxonomies"][0];
    assert_eq!(cwe["name"], "CWE");
    assert_eq!(cwe["version"], "4.13");
    assert_eq!(
        cwe["informationUri"],
        "https://cwe.mitre.org/data/definitions/798.html"
    );
    assert_eq!(cwe["taxa"][0]["id"], "CWE-798");
    assert_eq!(cwe["taxa"][0]["name"], "Use of Hard-coded Credentials");
    assert_eq!(
        cwe["taxa"][0]["helpUri"],
        "https://cwe.mitre.org/data/definitions/798.html"
    );
}

#[test]
fn sarif_taxonomies_owasp_block() {
    let json = sarif_of(&[finding()]);
    let owasp = &json["runs"][0]["taxonomies"][1];
    assert_eq!(owasp["name"], "OWASP");
    assert_eq!(owasp["version"], "2021");
    assert_eq!(
        owasp["informationUri"],
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
    );
    assert_eq!(owasp["taxa"][0]["id"], "A07:2021");
    assert_eq!(
        owasp["taxa"][0]["name"],
        "Identification and Authentication Failures"
    );
}

#[test]
fn sarif_taxonomies_always_two_entries_even_empty_run() {
    let json = sarif_of(&[]);
    let taxa = json["runs"][0]["taxonomies"].as_array().unwrap();
    assert_eq!(taxa.len(), 2);
    assert_eq!(taxa[0]["name"], "CWE");
    assert_eq!(taxa[1]["name"], "OWASP");
}

// ============================================================================
// SARIF: URI rendering (file_path_to_sarif_uri)
// ============================================================================

#[test]
fn sarif_uri_posix_absolute_outside_root_gets_file_scheme() {
    // Absolute path not under scan root -> "file://" + percent-encoded path.
    // /etc/... is reliably outside any test CWD under the repo tree.
    let mut f = finding();
    f.location.file_path = Some(Arc::from("/etc/keys/aws.env"));
    let json = sarif_of(&[f]);
    let uri = json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        ["uri"]
        .as_str();
    assert_eq!(uri, Some("file:///etc/keys/aws.env"));
}

#[test]
fn sarif_uri_relative_path_percent_encoded() {
    // A relative path with a space must be percent-encoded (space -> %20).
    let mut f = finding();
    f.location.file_path = Some(Arc::from("dir with space/secret.env"));
    let json = sarif_of(&[f]);
    let uri = json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        ["uri"]
        .as_str();
    assert_eq!(uri, Some("dir%20with%20space/secret.env"));
}

#[test]
fn sarif_uri_relative_safe_chars_preserved() {
    // Alphanumerics, '-', '_', '.', '~', '/', ':' stay unescaped.
    let mut f = finding();
    f.location.file_path = Some(Arc::from("src/a-b_c.d~e/f.env"));
    let json = sarif_of(&[f]);
    let uri = json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        ["uri"]
        .as_str();
    assert_eq!(uri, Some("src/a-b_c.d~e/f.env"));
}

#[test]
fn sarif_uri_unicode_path_percent_encoded() {
    // Non-ASCII bytes percent-encoded as uppercase hex of each UTF-8 byte.
    // 'é' = U+00E9 = UTF-8 0xC3 0xA9 -> "%C3%A9".
    let mut f = finding();
    f.location.file_path = Some(Arc::from("café.env"));
    let json = sarif_of(&[f]);
    let uri = json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        ["uri"]
        .as_str();
    assert_eq!(uri, Some("caf%C3%A9.env"));
}

#[test]
fn sarif_uri_windows_absolute_gets_triple_slash_file_scheme() {
    // is_windows_absolute path (not under POSIX scan root) -> file:/// + fwd slashes.
    let mut f = finding();
    f.location.file_path = Some(Arc::from("C:\\secrets\\key.env"));
    let json = sarif_of(&[f]);
    let uri = json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        ["uri"]
        .as_str();
    // ':' is in the safe set; backslashes normalized to '/'.
    assert_eq!(uri, Some("file:///C:/secrets/key.env"));
}

// ============================================================================
// SARIF: structural / streaming integrity (multi-finding byte shape)
// ============================================================================

#[test]
fn sarif_results_comma_separated_streaming() {
    // Streaming reporter inserts a comma before every result after the first.
    let mut f1 = finding();
    f1.detector_id = Arc::from("d1");
    let mut f2 = finding();
    f2.detector_id = Arc::from("d2");
    let mut f3 = finding();
    f3.detector_id = Arc::from("d3");
    let json = sarif_of(&[f1, f2, f3]);
    let results = json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["ruleId"], "d1");
    assert_eq!(results[1]["ruleId"], "d2");
    assert_eq!(results[2]["ruleId"], "d3");
}

#[test]
fn sarif_prefix_emitted_exactly_once_for_many_findings() {
    // ensure_prefix is idempotent: the skeleton/version string appears once.
    let mut f1 = finding();
    f1.detector_id = Arc::from("p1");
    let mut f2 = finding();
    f2.detector_id = Arc::from("p2");
    let bytes = sarif_bytes(&[f1, f2]);
    let s = String::from_utf8(bytes).unwrap();
    assert_eq!(
        s.matches(r#""version":"2.1.0""#).count(),
        1,
        "SARIF version prefix must be written exactly once"
    );
    assert_eq!(
        s.matches(r#""results":["#).count(),
        1,
        "results array opener written exactly once"
    );
}

#[test]
fn sarif_full_document_is_strict_json_object() {
    // Whole document must parse as a JSON object with exactly the top keys.
    let json = sarif_of(&[finding()]);
    assert!(json.is_object());
    assert!(json.get("version").is_some());
    assert!(json.get("$schema").is_some());
    assert!(json.get("runs").is_some());
    // runs[0] has results, tool, taxonomies.
    let run = &json["runs"][0];
    assert!(run.get("results").is_some());
    assert!(run.get("tool").is_some());
    assert!(run.get("taxonomies").is_some());
}

#[test]
fn sarif_message_text_uses_redacted_not_plaintext() {
    // The message must carry credential_redacted, never any raw secret.
    let mut f = finding();
    f.credential_redacted = Cow::Owned("AKIA...WXYZ".to_string());
    let json = sarif_of(&[f]);
    let text = json["runs"][0]["results"][0]["message"]["text"]
        .as_str()
        .unwrap();
    assert_eq!(text, "test secret detected: AKIA...WXYZ");
}

// ============================================================================
// Property-style loops over pure mapping functions (via reporter output)
// ============================================================================

#[test]
fn sarif_property_level_only_error_warning_note() {
    // Across all severities, level is one of exactly three legal SARIF values.
    let all = [
        Severity::Info,
        Severity::ClientSafe,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    for (i, sev) in all.iter().enumerate() {
        let mut f = finding();
        f.severity = *sev;
        f.detector_id = Arc::from(format!("lvl-{i}"));
        let json = sarif_of(&[f]);
        let level = json["runs"][0]["results"][0]["level"].as_str().unwrap();
        assert!(
            matches!(level, "error" | "warning" | "note"),
            "level {level} for {sev:?} must be a legal SARIF level"
        );
    }
}

#[test]
fn sarif_property_security_severity_is_parseable_float_in_range() {
    // security-severity strings must parse to 0.0..=10.0 for every severity.
    let all = [
        Severity::Info,
        Severity::ClientSafe,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    for (i, sev) in all.iter().enumerate() {
        let mut f = finding();
        f.severity = *sev;
        f.detector_id = Arc::from(format!("score-{i}"));
        f.detector_name = Arc::from(format!("Score {i}"));
        let json = sarif_of(&[f]);
        let s = json["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
            .as_str()
            .unwrap();
        let score: f64 = s.parse().expect("security-severity must be a float string");
        assert!(
            (0.0..=10.0).contains(&score),
            "security-severity {score} out of GitHub band range for {sev:?}"
        );
    }
}

#[test]
fn sarif_property_credential_redacted_in_message_for_varied_inputs() {
    // For a range of redacted strings, the message text is exactly
    // "{service} secret detected: {redacted}".
    let samples = ["****", "abcd...wxyz", "ghp_...1234", "****redacted"];
    for (i, red) in samples.iter().enumerate() {
        let mut f = finding();
        f.detector_id = Arc::from(format!("msg-{i}"));
        f.service = Arc::from("svc");
        f.credential_redacted = Cow::Owned((*red).to_string());
        let json = sarif_of(&[f]);
        let text = json["runs"][0]["results"][0]["message"]["text"]
            .as_str()
            .unwrap();
        assert_eq!(text, format!("svc secret detected: {red}"));
    }
}

#[test]
fn sarif_property_every_result_has_required_keys() {
    // Each result must carry ruleId, level, message, locations, properties.
    let svcs = ["aws", "github", "stripe", "gcp", "azure"];
    let findings: Vec<VerifiedFinding> = svcs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut f = finding();
            f.detector_id = Arc::from(format!("req-{i}"));
            f.service = Arc::from(*s);
            f
        })
        .collect();
    let json = sarif_of(&findings);
    let results = json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 5);
    for r in results {
        assert!(r.get("ruleId").is_some(), "ruleId required");
        assert!(r.get("level").is_some(), "level required");
        assert!(r["message"].get("text").is_some(), "message.text required");
        assert!(
            r["locations"].as_array().is_some_and(|a| !a.is_empty()),
            "at least one location required"
        );
        assert_eq!(r["properties"]["cwe"], "CWE-798");
    }
}
