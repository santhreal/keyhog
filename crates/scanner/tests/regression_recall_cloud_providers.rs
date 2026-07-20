//! Recall lock: the five canonical cloud-provider credential shapes must each
//! surface through the on-disk `CompiledScanner` with their EXACT detector id,
//! their EXACT captured credential bytes, and the EXACT 1-based line number the
//! secret sits on, never a bare `!is_empty`. Every positive is paired with a
//! negative twin (wrong case, over-/under-length, or a documentation `EXAMPLE`
//! token) that must NOT surface under the same detector, proving the recall is
//! shape-anchored rather than a blanket "anything of this length" catch.
//!
//!   - AWS access key id  → `aws-access-key`            (whole `AKIA…`/`ASIA…`)
//!   - AWS secret key     → `aws-secret-access-key`     (40-char group-1 body)
//!   - GCP API key        → `google-api-key`            (whole `AIza…`)
//!   - GCP service acct   → `vertexai-service-account`  (JSON `type…BEGIN KEY`)
//!   - Azure storage key  → `azure-storage-account-key` (88-char group-1 body)
//!
//! None of these five prefixes is checksum-validated (the checksum registry
//! only claims github/gitlab/npm/pypi/slack/stripe), so the fabricated tokens
//! below pass through `ChecksumResult::NotApplicable` and are judged purely on
//! shape + anchor + entropy, exactly the production path. The only tokens that
//! must be dropped are the doc-marker `EXAMPLE` twins and the shape misses.

mod support;

use keyhog_core::{Chunk, RawMatch};
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;
use support::contracts::{make_chunk, scanner};

/// One compiled scanner for the whole file. `scanner()` recompiles every on-disk
/// detector per call, so the `OnceLock` keeps the suite fast; the scanner is
/// `Send + Sync` and the harness runs these `#[test]`s serially, so the
/// per-scan fragment-cache clear never races (mirrors the sibling
/// `regression_cloud_credential_recall.rs` harness).
fn shared() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(scanner)
}

/// Scan `text` as a filesystem chunk and return every raw match.
fn matches_for(text: &str) -> Vec<RawMatch> {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", "cloud.conf");
    s.scan(&chunk)
}

/// The matches attributed to exactly `detector_id`.
fn by_detector(text: &str, detector_id: &str) -> Vec<RawMatch> {
    matches_for(text)
        .into_iter()
        .filter(|m| m.detector_id.as_ref() == detector_id)
        .collect()
}

/// The single match attributed to `detector_id`, asserting exactly one exists.
/// A count of anything but 1 names the offending detector and the whole match
/// set, so a miss or a duplicate is a concrete, debuggable failure.
fn only(text: &str, detector_id: &str) -> RawMatch {
    let mut hits = by_detector(text, detector_id);
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one `{detector_id}` match, got {}: {:?}",
        hits.len(),
        hits.iter()
            .map(|m| (
                m.detector_id.as_ref(),
                m.credential.as_ref(),
                m.location.line
            ))
            .collect::<Vec<_>>()
    );
    hits.pop().unwrap()
}

// Fabricated, distinct, high-entropy tokens (deterministic, no repeats, no
// `EXAMPLE` marker). Generated once so every assertion is against a literal
// known value rather than a runtime-derived one.
const AKID: &str = "AKIAZ7QH4XNB2WKLP3RV"; // AKIA + 16 upper alnum = 20
const ASIA: &str = "ASIA5TKD9WBN3FYQ8MJV"; // ASIA session id
const AWS_SECRET: &str = "nvFR5lDXjH7z3z7HjXDl5RFvnhdbbdhnvFR5lDXj"; // 40 base62
const AWS_SECRET2: &str = "qyIU8oG0mKaC6CaKm0Go8UIyqkgeegkqyIU8oG0m"; // 40 base62
const GCP_KEY: &str = "AIzazHR3hxP9vTjLfLjTv9Pxh3RHztpnnptzHR3"; // AIza + 35 = 39
const AZURE_KEY: &str =
    "tBLXbrJ3pNdF9FdNp3JrbXLBtnjhhjntBLXbrJ3pNdF9FdNp3JrbXLBtnjhhjntBLXbrJ3pNdF9FdNp3JrbXLB==";

// ── AWS access key id (aws-access-key) ───────────────────────────────────────

#[test]
fn aws_access_key_akia_exact_id_credential_and_line() {
    // Key sits on physical line 3 (comment, section header, then the key line).
    let text = format!("# ~/.aws/credentials\n[default]\naws_access_key_id = {AKID}\n");
    let m = only(&text, "aws-access-key");
    assert_eq!(
        m.credential.as_ref(),
        AKID,
        "whole AKIA id is the credential"
    );
    assert_eq!(
        m.location.line,
        Some(3),
        "key is on the third physical line"
    );
    assert_eq!(m.service.as_ref(), "aws");
}

#[test]
fn aws_access_key_asia_session_exact_id_and_line() {
    // ASIA session ids share the aws-access-key detector; key on line 2.
    let text = format!("[profile ci]\naws_access_key_id={ASIA}\n");
    let m = only(&text, "aws-access-key");
    assert_eq!(m.credential.as_ref(), ASIA);
    assert_eq!(m.location.line, Some(2));
}

#[test]
fn aws_access_key_lowercase_lookalike_not_found() {
    // `(?-i)` in the pattern forces case-sensitivity: the lowercase doc/test
    // look-alike must NOT surface as aws-access-key (negative twin).
    let lower = AKID.to_ascii_lowercase();
    let text = format!("key = {lower}\n");
    assert_eq!(
        by_detector(&text, "aws-access-key").len(),
        0,
        "lowercase AKIA look-alike must not attribute to aws-access-key"
    );
}

#[test]
fn aws_access_key_overlong_run_not_found() {
    // An AWS access key id is EXACTLY 20 chars; the trailing `\b` fails closed on
    // a 21-char contiguous upper-alnum run, so it is not a valid key (boundary).
    let overlong = format!("{AKID}X"); // 21 chars
    let text = format!("token = {overlong}\n");
    assert_eq!(
        by_detector(&text, "aws-access-key").len(),
        0,
        "a 21-char AKIA run is not a valid access key id"
    );
}

#[test]
fn aws_access_key_documentation_example_suppressed() {
    // The canonical AWS docs id ends in `EXAMPLE`; the doc-marker suppression
    // must drop it even though it is shape-valid (adversarial negative).
    let text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n";
    assert_eq!(
        by_detector(text, "aws-access-key").len(),
        0,
        "AKIAIOSFODNN7EXAMPLE is a documentation placeholder, not a leak"
    );
}

// ── AWS secret access key (aws-secret-access-key) ────────────────────────────

#[test]
fn aws_secret_access_key_exact_group_value_and_line() {
    // The detector captures GROUP 1 (the 40-char body), not the anchor. Key on
    // line 2.
    let text = format!("# env\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\n");
    let m = only(&text, "aws-secret-access-key");
    assert_eq!(
        m.credential.as_ref(),
        AWS_SECRET,
        "only the 40-char group-1 body is the credential, not the anchor"
    );
    assert_eq!(m.location.line, Some(2));
    assert_eq!(m.service.as_ref(), "aws");
}

#[test]
fn aws_secret_access_key_too_short_body_not_found() {
    // A 39-char body is one short of the required `{40}`; the anchored pattern
    // must not fire (boundary negative).
    let short = "NV5hvL3nJ7xZtZx7Jn3Lvh5VNHDBBDHNV5hvL3n"; // 39 chars
    let text = format!("AWS_SECRET_ACCESS_KEY={short}\n");
    assert_eq!(
        by_detector(&text, "aws-secret-access-key").len(),
        0,
        "a 39-char body is below the 40-char secret-key window"
    );
}

#[test]
fn aws_secret_access_key_canonical_example_suppressed() {
    // AWS's canonical example secret ends in `EXAMPLEKEY`; doc-marker
    // suppression drops it despite matching the anchored 40-char shape.
    let text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
    assert_eq!(
        by_detector(text, "aws-secret-access-key").len(),
        0,
        "the wJalr…EXAMPLEKEY docs secret is a placeholder"
    );
}

// ── AWS shared-credentials file: both keys, distinct lines ───────────────────

#[test]
fn aws_shared_credentials_file_both_keys_correct_lines() {
    // The real `~/.aws/credentials` INI: id on line 2, secret on line 3.
    let file =
        format!("[default]\naws_access_key_id = {AKID}\naws_secret_access_key = {AWS_SECRET2}\n");
    let id = only(&file, "aws-access-key");
    assert_eq!(id.credential.as_ref(), AKID);
    assert_eq!(id.location.line, Some(2), "access key id is on line 2");

    let secret = only(&file, "aws-secret-access-key");
    assert_eq!(secret.credential.as_ref(), AWS_SECRET2);
    assert_eq!(secret.location.line, Some(3), "secret key is on line 3");
}

// ── GCP API key (google-api-key) ─────────────────────────────────────────────

#[test]
fn google_api_key_aiza_exact_id_credential_and_line() {
    // `AIza` + 35 chars; the whole token is the credential. On line 2.
    let text = format!("# config\nGOOGLE_API_KEY = \"{GCP_KEY}\"\n");
    let m = only(&text, "google-api-key");
    assert_eq!(
        m.credential.as_ref(),
        GCP_KEY,
        "whole AIza token is captured"
    );
    assert_eq!(m.location.line, Some(2));
    assert_eq!(m.service.as_ref(), "google");
}

#[test]
fn google_api_key_too_short_not_found() {
    // `AIza` + only 20 chars is below the `{35}` body; the quote terminates the
    // run so no valid key exists (boundary negative).
    let short = "AIzadlvHVbtN9xXpTpXx9Ntb"; // AIza + 20 = 24
    let text = format!("GOOGLE_API_KEY = \"{short}\"\n");
    assert_eq!(
        by_detector(&text, "google-api-key").len(),
        0,
        "a 24-char AIza token is below the 39-char API-key length"
    );
}

// ── GCP service-account JSON (vertexai-service-account) ───────────────────────

#[test]
fn gcp_service_account_pretty_json_exact_id_span_and_line() {
    // The canonical downloaded key file (pretty-printed): the newline-crossing
    // bridge must match from the `type` field (line 2) through the PEM header.
    let priv_key =
        "-----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqhkiG\\n-----END PRIVATE KEY-----\\n";
    let json = format!(
        "{{\n  \"type\": \"service_account\",\n  \"project_id\": \"demo-proj-7788\",\n  \
         \"private_key_id\": \"0123456789abcdef0123456789abcdef01234567\",\n  \
         \"private_key\": \"{priv_key}\",\n  \
         \"client_email\": \"svc@demo-proj-7788.iam.gserviceaccount.com\"\n}}"
    );
    let m = only(&json, "vertexai-service-account");
    let cred = m.credential.as_str().to_string();
    assert!(
        cred.starts_with("type"),
        "match span starts at the `type` anchor field, got {cred:?}"
    );
    assert!(
        cred.contains("service_account"),
        "span must carry the service_account marker, got {cred:?}"
    );
    assert!(
        cred.ends_with("-----BEGIN PRIVATE KEY-----"),
        "the pattern terminates exactly at the PEM header, got {cred:?}"
    );
    assert_eq!(
        m.location.line,
        Some(2),
        "the `type` field is on the second physical line of the pretty JSON"
    );
    assert_eq!(m.service.as_ref(), "vertexai");
}

#[test]
fn gcp_service_account_env_var_reference_not_found() {
    // A source file that merely READS the credential-path env var carries no
    // secret; the v0.5.19 dogfood FP must stay dead (negative twin).
    let src = "const credPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;\n\
               const projectId = process.env.GOOGLE_CLOUD_PROJECT;\n";
    assert_eq!(
        by_detector(src, "vertexai-service-account").len(),
        0,
        "env-var references are not service-account credentials"
    );
}

// ── Azure storage account key (azure-storage-account-key) ────────────────────

#[test]
fn azure_storage_connection_string_accountkey_exact_value_and_line() {
    // Connection-string `AccountKey=<88 b64>;` form (most common in code). The
    // detector captures GROUP 1, the 88-char key only, not the surrounding
    // connection string. On line 2.
    let conn = format!(
        "# azure\nDefaultEndpointsProtocol=https;AccountName=demostorage;AccountKey={AZURE_KEY};\
         EndpointSuffix=core.windows.net\n"
    );
    let m = only(&conn, "azure-storage-account-key");
    assert_eq!(
        m.credential.as_ref(),
        AZURE_KEY,
        "only the 88-char AccountKey body is the credential"
    );
    assert_eq!(m.location.line, Some(2));
    assert_eq!(m.service.as_ref(), "azure");
}

#[test]
fn azure_storage_env_key_exact_value_and_line() {
    // `AZURE_STORAGE_KEY=<88 b64>` env/properties anchor; key on line 2.
    let key =
        "GOYaoEWgC0qSmSq0CgWEoaYOGAwuuwAGOYaoEWgC0qSmSq0CgWEoaYOGAwuuwAGOYaoEWgC0qSmSq0CgWEoaYO==";
    let text = format!("# secrets\nAZURE_STORAGE_KEY={key}\n");
    let m = only(&text, "azure-storage-account-key");
    assert_eq!(m.credential.as_ref(), key);
    assert_eq!(m.location.line, Some(2));
}

#[test]
fn azure_storage_key_too_short_body_not_found() {
    // The Azure key body is EXACTLY 86 base64 chars + `=` padding. An 80-char
    // body is below the `{86}` window, so `AccountKey=` must not fire (boundary).
    let short =
        "08iuIYgAWkKcGcKkWAgYIui80UQOOQU08iuIYgAWkKcGcKkWAgYIui80UQOOQU08iuIYgAWkKcGcKkWA==";
    let conn = format!("AccountName=x;AccountKey={short};EndpointSuffix=core.windows.net\n");
    assert_eq!(
        by_detector(&conn, "azure-storage-account-key").len(),
        0,
        "an 80-char AccountKey body is below the 86-char Azure key window"
    );
}
