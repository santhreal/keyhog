//! Regression: `keyhog scan --format json-envelope` emits a machine-parseable report
//! whose SHAPE is pinned field-by-field against the REAL shipped binary.
//!
//! The CLI JSON reporter writes a versioned object with a `findings` array.
//! Each element is a serialized `VerifiedFinding` whose custom `Serialize` impl
//! (finding.rs) emits, in this exact set:
//!   detector_id, detector_name, service, severity, credential_redacted,
//!   credential_hash, location{source,file_path,line,offset,commit,author,date},
//!   verification, metadata, additional_locations, (confidence if Some),
//!   remediation.
//!
//! One secret is planted: a GitHub classic PAT (`ghp_` + 36 alnum) that fires
//! the `github-classic-pat` detector (critical / github). Every assertion pins
//! a CONCRETE value observed from the binary:
//!   * detector_id  = "github-classic-pat"
//!   * severity     = "critical"           (Severity kebab-case)
//!   * service      = "github"
//!   * credential_redacted = "ghp_...DSiF" (masked, never the raw token)
//!   * credential_hash = sha256 of the token (deterministic, host-independent)
//!   * location.source="filesystem", .line=1, .offset=0, .file_path ends dump.txt
//!   * verification = "skipped"            (VerificationResult snake_case)
//!   * metadata = {} ; additional_locations = []
//!
//! HOST-INDEPENDENT: runs `--backend cpu`, so the CPU path is exercised on every
//! host regardless of GPU/Hyperscan presence. `confidence` is an ML score that
//! legitimately varies by build, so it is range-checked (0,1], never pinned;
//! `credential_hash` is a pure sha256 and IS pinned exactly.
//!
//! Negative twin: a clean file exits 0 and the report contains an empty
//! versioned `findings` array.
//! Adversarial: the raw plaintext token must NEVER appear anywhere in the JSON.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// A planted GitHub classic PAT: `ghp_` + 36 alphanumerics, clean right
/// boundary. Fires `github-classic-pat` on its own bytes, carries no keyword
/// context, so exactly one finding is produced.
const PLANTED: &str = "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";
const DETECTOR_ID: &str = "github-classic-pat";
const DETECTOR_NAME: &str = "GitHub Classic PAT";
const SERVICE: &str = "github";
const SEVERITY: &str = "critical";
/// The redacted (first4...last4) form the reporter emits for the planted token.
const REDACTED: &str = "ghp_...DSiF";
/// Deterministic sha256 of the planted token (host-independent: pure hashing).
const CRED_HASH: &str = "7b85310a29300230c865bc48ca1836f15b81bd50ac85e8c0785e8145e98ff175";

/// The complete set of top-level keys a finding object may carry. `confidence`
/// is optional (skipped when the ML score is None on ML-less builds); every
/// other key is required.
const REQUIRED_KEYS: [&str; 11] = [
    "detector_id",
    "detector_name",
    "service",
    "severity",
    "credential_redacted",
    "credential_hash",
    "location",
    "verification",
    "metadata",
    "additional_locations",
    "remediation",
];
const OPTIONAL_KEYS: [&str; 1] = ["confidence"];

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Plant the PAT alone on one line inside `dump.txt` in a fresh tempdir.
fn leak_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("dump.txt");
    std::fs::write(&path, format!("{PLANTED}\n")).expect("write leak fixture");
    (dir, path)
}

/// A file with no credential-shaped content and no bridge keywords.
fn clean_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("notes.txt");
    std::fs::write(
        &path,
        "just ordinary prose with plain everyday words here\n",
    )
    .expect("write clean fixture");
    (dir, path)
}

/// Run `keyhog scan --daemon=off --backend cpu --format json <path>`.
fn run_json(path: &PathBuf) -> (Option<i32>, String, String) {
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--no-suppress-test-fixtures",
            "--format",
            "json-envelope",
        ])
        .arg(path)
        .output()
        .expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Parse the versioned envelope and return its findings array.
fn findings_array(out: &str) -> Vec<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(out).expect("json stdout must parse");
    assert_eq!(value["schema_version"]["major"], 1);
    value["findings"]
        .as_array()
        .expect("findings must be an array")
        .clone()
}

/// Parse stdout and return the single finding object.
fn single_finding(out: &str) -> serde_json::Value {
    let arr = findings_array(out);
    assert_eq!(arr.len(), 1, "exactly one secret planted -> one element");
    arr[0].clone()
}

// ---------------------------------------------------------------------------
// Top-level container shape
// ---------------------------------------------------------------------------

/// The report is a versioned object with exactly one finding for one planted
/// secret, and the run exits 1.
#[test]
fn top_level_is_json_array_of_one_and_exits_one() {
    let (_dir, path) = leak_fixture();
    let (code, out, err) = run_json(&path);
    assert_eq!(code, Some(1), "a finding must exit 1; stderr={err}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("json must parse");
    let arr = findings_array(&out);
    assert_eq!(arr.len(), 1, "one planted secret -> one array element");
    assert!(
        v["metadata"].is_object(),
        "CLI envelope carries scan metadata"
    );
}

/// Every REQUIRED top-level key is present on the finding object, and NO key
/// outside the required+optional allow-set appears (guards silent field drift).
#[test]
fn finding_object_has_exact_top_level_key_set() {
    let (_dir, path) = leak_fixture();
    let (_c, out, _e) = run_json(&path);
    let obj = single_finding(&out);
    let map = obj.as_object().expect("finding must be a json object");

    for key in REQUIRED_KEYS {
        assert!(
            map.contains_key(key),
            "finding object missing required key `{key}`; keys present: {:?}",
            map.keys().collect::<Vec<_>>()
        );
    }
    for key in map.keys() {
        let allowed =
            REQUIRED_KEYS.contains(&key.as_str()) || OPTIONAL_KEYS.contains(&key.as_str());
        assert!(
            allowed,
            "unexpected top-level key `{key}` in finding object"
        );
    }
}

// ---------------------------------------------------------------------------
// Scalar identity fields
// ---------------------------------------------------------------------------

/// detector_id / detector_name / service carry the exact planted-detector
/// identity strings.
#[test]
fn detector_identity_fields_exact() {
    let (_dir, path) = leak_fixture();
    let (_c, out, _e) = run_json(&path);
    let obj = single_finding(&out);
    assert_eq!(
        obj.get("detector_id").and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "detector_id"
    );
    assert_eq!(
        obj.get("detector_name").and_then(|x| x.as_str()),
        Some(DETECTOR_NAME),
        "detector_name"
    );
    assert_eq!(
        obj.get("service").and_then(|x| x.as_str()),
        Some(SERVICE),
        "service"
    );
}

/// severity is the kebab-case token `critical` (Severity::Critical), rendered
/// as a JSON string (not a number or an object).
#[test]
fn severity_field_is_kebab_critical_string() {
    let (_dir, path) = leak_fixture();
    let (_c, out, _e) = run_json(&path);
    let obj = single_finding(&out);
    let sev = obj.get("severity").expect("severity key present");
    assert!(
        sev.is_string(),
        "severity must be a JSON string, got {sev:?}"
    );
    assert_eq!(sev.as_str(), Some(SEVERITY), "severity must be `critical`");
}

// ---------------------------------------------------------------------------
// Credential redaction / hashing
// ---------------------------------------------------------------------------

/// credential_redacted is the masked first4...last4 form and is NOT the raw
/// token.
#[test]
fn credential_redacted_is_masked_form() {
    let (_dir, path) = leak_fixture();
    let (_c, out, _e) = run_json(&path);
    let obj = single_finding(&out);
    let redacted = obj
        .get("credential_redacted")
        .and_then(|x| x.as_str())
        .expect("credential_redacted must be a string");
    assert_eq!(redacted, REDACTED, "exact masked form");
    assert_ne!(redacted, PLANTED, "must not be the raw token");
}

/// credential_hash is the deterministic 64-char lowercase-hex sha256 of the
/// planted token (a value that is identical on every host (pure hashing)).
#[test]
fn credential_hash_is_deterministic_sha256_hex() {
    let (_dir, path) = leak_fixture();
    let (_c, out, _e) = run_json(&path);
    let obj = single_finding(&out);
    let hash = obj
        .get("credential_hash")
        .and_then(|x| x.as_str())
        .expect("credential_hash must be a string");
    assert_eq!(hash.len(), 64, "sha256 hex is 64 chars, got {}", hash.len());
    assert!(
        hash.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "hash must be lowercase hex, got {hash}"
    );
    assert_eq!(hash, CRED_HASH, "exact sha256 of the planted token");
}

/// ADVERSARIAL / anti-exfil: the raw plaintext token must NEVER appear anywhere
/// in the JSON output. A serializer that leaked the secret would fail here.
#[test]
fn raw_plaintext_token_absent_from_json_output() {
    let (_dir, path) = leak_fixture();
    let (_c, out, _e) = run_json(&path);
    assert!(
        !out.contains(PLANTED),
        "the raw credential must not appear in the JSON report"
    );
    // The redacted head/tail fragments are fine, but the middle body of the
    // token must be gone: assert the long alnum run is absent.
    assert!(
        !out.contains("1234567890123456789012345678902"),
        "the token body must be redacted out of the JSON report"
    );
}

// ---------------------------------------------------------------------------
// Nested location object
// ---------------------------------------------------------------------------

/// location is a nested object whose fields carry the exact filesystem-scan
/// coordinates: source `filesystem`, line 1, offset 0, file_path ending in the
/// planted file, and null git fields for a non-history scan.
#[test]
fn location_object_fields_exact() {
    let (_dir, path) = leak_fixture();
    let (_c, out, _e) = run_json(&path);
    let obj = single_finding(&out);
    let loc = obj
        .get("location")
        .and_then(|l| l.as_object())
        .expect("location must be a json object");

    assert_eq!(
        loc.get("source").and_then(|x| x.as_str()),
        Some("filesystem"),
        "location.source"
    );
    assert_eq!(
        loc.get("line").and_then(|x| x.as_u64()),
        Some(1),
        "location.line must be 1 (token on line 1)"
    );
    assert_eq!(
        loc.get("offset").and_then(|x| x.as_u64()),
        Some(0),
        "location.offset must be 0"
    );
    let file_path = loc
        .get("file_path")
        .and_then(|x| x.as_str())
        .expect("location.file_path must be a string");
    assert!(
        file_path.ends_with("dump.txt"),
        "file_path must be the planted file, got {file_path}"
    );
    for git_field in ["commit", "author", "date"] {
        assert!(
            loc.get(git_field).map(|v| v.is_null()).unwrap_or(false),
            "location.{git_field} must be null for a filesystem scan"
        );
    }
}

// ---------------------------------------------------------------------------
// verification / metadata / additional_locations / confidence / remediation
// ---------------------------------------------------------------------------

/// verification is the snake_case token `skipped` (VerificationResult::Skipped)
/// when no live verification runs.
#[test]
fn verification_field_is_skipped() {
    let (_dir, path) = leak_fixture();
    let (_c, out, _e) = run_json(&path);
    let obj = single_finding(&out);
    assert_eq!(
        obj.get("verification").and_then(|x| x.as_str()),
        Some("skipped"),
        "verification must be `skipped` (no --verify)"
    );
}

/// metadata is an empty JSON object and additional_locations is an empty JSON
/// array for a single-location filesystem finding.
#[test]
fn metadata_empty_object_and_additional_locations_empty_array() {
    let (_dir, path) = leak_fixture();
    let (_c, out, _e) = run_json(&path);
    let obj = single_finding(&out);
    let meta = obj
        .get("metadata")
        .and_then(|m| m.as_object())
        .expect("metadata must be a json object");
    assert_eq!(meta.len(), 0, "metadata must be empty, got {meta:?}");
    let extra = obj
        .get("additional_locations")
        .and_then(|a| a.as_array())
        .expect("additional_locations must be a json array");
    assert_eq!(extra.len(), 0, "additional_locations must be empty");
}

/// confidence, when present, is a JSON number in the unit interval (0, 1].
/// It is an ML score that varies by build, so it is range-checked rather than
/// pinned (keeping the test host-independent).
#[test]
fn confidence_when_present_is_in_unit_interval() {
    let (_dir, path) = leak_fixture();
    let (_c, out, _e) = run_json(&path);
    let obj = single_finding(&out);
    if let Some(conf) = obj.get("confidence") {
        let c = conf
            .as_f64()
            .expect("confidence must be a JSON number when present");
        assert!(
            c > 0.0 && c <= 1.0,
            "confidence must lie in (0, 1], got {c}"
        );
    }
}

/// remediation is a nested object whose `action` string tells the operator to
/// revoke the exposed credential (actionable guidance, not a bare code).
#[test]
fn remediation_object_carries_revoke_action() {
    let (_dir, path) = leak_fixture();
    let (_c, out, _e) = run_json(&path);
    let obj = single_finding(&out);
    let rem = obj
        .get("remediation")
        .and_then(|r| r.as_object())
        .expect("remediation must be a json object");
    let action = rem
        .get("action")
        .and_then(|x| x.as_str())
        .expect("remediation.action must be a string");
    assert!(
        action.contains("Revoke"),
        "remediation.action must instruct a revoke, got {action}"
    );
}

// ---------------------------------------------------------------------------
// Negative twin
// ---------------------------------------------------------------------------

/// A clean file exits 0 and the JSON report carries an empty findings array.
#[test]
fn clean_scan_is_exactly_empty_array_exit_zero() {
    let (_dir, path) = clean_fixture();
    let (code, out, err) = run_json(&path);
    assert_eq!(code, Some(0), "clean scan must exit 0; stderr={err}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("empty json parses");
    assert_eq!(v["schema_version"]["major"], 1);
    assert!(v["findings"].as_array().is_some_and(Vec::is_empty));
}
