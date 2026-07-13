//! Regression: the `keyhog scan` credential-redaction contract, driven end to
//! end over the SHIPPED binary (`--daemon=off`, `--backend cpu` so the assertions
//! are host-independent (no accelerator is ever assumed)).
//!
//! A single checksum-valid GitHub classic PAT is planted in a temp file. It
//! fires `github-classic-pat` on its own bytes with a passing CRC tail, so it
//! survives the confidence floor on the plain CPU path deterministically.
//!
//! The contract pinned here, on EXACT bytes (never a shape / `!is_empty`):
//!
//!   * DEFAULT REDACTS, every structured format (json, jsonl, csv, sarif) and
//!     the human text report emit the masked `first4…last4` form `ghp_...DSiF`
//!     and NEVER the 40-byte plaintext token nor its unique middle run.
//!   * `--show-secrets` REVEALS, the same run with `--show-secrets` puts the
//!     full plaintext token back into `credential_redacted` / the CSV cell /
//!     the text line, while the detector id and the sha256 credential hash are
//!     byte-for-byte identical to the redacted run (only the credential text
//!     differs (masking is display-only, it does not change identity)).
//!   * FAIL CLOSED: `--lockdown --show-secrets` is refused (exit 2) with an
//!     actionable message, so plaintext can never reach stdout under lockdown.
//!
//! There is NO `--no-redact` flag in the shipped CLI; the reveal flag is
//! `--show-secrets` (default: redacted). Confirmed by reading
//! `crates/cli/src/args/scan.rs` (`pub show_secrets: bool`, `#[arg(long)]`).

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// A planted GitHub classic PAT with a VALID CRC32 tail, the exact token used
/// across the scanner boundary/parity suites. Split-literal so THIS test file is
/// not itself a planted-secret tripwire for keyhog's own self-scan.
const PLANTED: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");
/// The detector this token fires (severity `critical`, service `github`).
const DETECTOR_ID: &str = "github-classic-pat";
/// The default-redaction form: `first4…last4` with a literal `...` separator.
/// `redact()` uses `edge = clamp(len/8, 1, 4)`; len 40 -> edge 4.
const REDACTED: &str = "ghp_...DSiF";
/// The 32-char middle run masked away by default. Its presence in a "redacted"
/// report would prove the mask leaks the interior bytes.
const SECRET_MIDDLE: &str = "1234567890123456789012345678902P";
/// sha256 of the exact plaintext token bytes (`credential_hash` is unaffected by
/// redaction). Computed out-of-band: `printf '%s' <PLANTED> | sha256sum`.
const PLANTED_SHA256: &str = "7b85310a29300230c865bc48ca1836f15b81bd50ac85e8c0785e8145e98ff175";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Plant the PAT in a temp `.env` file and return (dir, path). The `TempDir`
/// guard must stay bound in the caller so the file outlives the scan.
fn planted_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("leak.env");
    std::fs::write(&path, format!("GITHUB_TOKEN={PLANTED}\n")).expect("write fixture");
    (dir, path)
}

/// Run `keyhog scan --daemon=off --backend cpu <extra…> <path>` hermetically and
/// return (exit-code, stdout, stderr). CPU backend keeps the run host-independent.
fn scan(path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off", "--backend", "cpu"]);
    cmd.args(extra);
    cmd.arg(path);
    cmd.env_remove("KEYHOG_BACKEND");
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Parse a `--format json` array report and return its single finding object.
fn single_json_finding(stdout: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("json report must parse ({e}):\n{stdout}"));
    let arr = v.as_array().expect("json report is a top-level array");
    assert_eq!(
        arr.len(),
        1,
        "exactly one planted secret -> one finding: {arr:?}"
    );
    arr[0].clone()
}

// ---------------------------------------------------------------------------
// DEFAULT REDACTION, json
// ---------------------------------------------------------------------------

/// Default json: `credential_redacted` is EXACTLY the masked `ghp_...DSiF`, and
/// the finding surfaces (exit 1).
#[test]
fn default_json_redacts_credential_to_masked_form() {
    let (_dir, path) = planted_fixture();
    let (code, out, err) = scan(&path, &["--format", "json"]);
    assert_eq!(code, Some(1), "a finding must exit 1; stderr={err}");
    let obj = single_json_finding(&out);
    assert_eq!(
        obj.get("credential_redacted").and_then(|x| x.as_str()),
        Some(REDACTED),
        "default json must mask the token to `{REDACTED}`; got {out}"
    );
    assert_eq!(
        obj.get("detector_id").and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "the planted token must fire `{DETECTOR_ID}`"
    );
}

/// Default json: the 40-byte plaintext token and its unique 32-char middle run
/// are BOTH absent from the entire stdout (the mask does not leak the interior).
#[test]
fn default_json_output_contains_no_plaintext_token() {
    let (_dir, path) = planted_fixture();
    let (_code, out, _err) = scan(&path, &["--format", "json"]);
    assert!(
        !out.contains(PLANTED),
        "default json must NOT leak the full plaintext token; got {out}"
    );
    assert!(
        !out.contains(SECRET_MIDDLE),
        "default json must NOT leak the masked middle run `{SECRET_MIDDLE}`; got {out}"
    );
}

/// Boundary: the masked field is strictly shorter than the plaintext, is exactly
/// 11 bytes, and carries the `...` separator at byte offset 4 (prefix len).
#[test]
fn default_masked_field_has_exact_shape_and_length() {
    let (_dir, path) = planted_fixture();
    let (_code, out, _err) = scan(&path, &["--format", "json"]);
    let obj = single_json_finding(&out);
    let masked = obj
        .get("credential_redacted")
        .and_then(|x| x.as_str())
        .expect("credential_redacted present");
    assert_eq!(masked.len(), 11, "masked form is exactly 11 bytes");
    assert_eq!(PLANTED.len(), 40, "plaintext token is exactly 40 bytes");
    assert!(
        masked.len() < PLANTED.len(),
        "mask must be shorter than plaintext"
    );
    assert_eq!(
        &masked[4..7],
        "...",
        "separator `...` sits after the 4-char prefix"
    );
    assert_eq!(
        &masked[..4],
        "ghp_",
        "masked prefix is the token's first 4 bytes"
    );
    assert_eq!(
        &masked[7..],
        "DSiF",
        "masked suffix is the token's last 4 bytes"
    );
}

// ---------------------------------------------------------------------------
// --show-secrets REVEALS, json
// ---------------------------------------------------------------------------

/// `--show-secrets` puts the FULL plaintext token back into `credential_redacted`.
#[test]
fn show_secrets_reveals_full_plaintext_in_json() {
    let (_dir, path) = planted_fixture();
    let (code, out, err) = scan(&path, &["--format", "json", "--show-secrets"]);
    assert_eq!(code, Some(1), "a finding must exit 1; stderr={err}");
    let obj = single_json_finding(&out);
    assert_eq!(
        obj.get("credential_redacted").and_then(|x| x.as_str()),
        Some(PLANTED),
        "--show-secrets must reveal the full token verbatim; got {out}"
    );
}

/// Masking is display-only: the `credential_hash` is byte-identical with and
/// without `--show-secrets`, and equals sha256 of the exact plaintext, so the
/// redacted report still traces to the same secret identity.
#[test]
fn hash_is_identical_and_is_sha256_of_plaintext_regardless_of_masking() {
    let (_dir, path) = planted_fixture();
    let masked = single_json_finding(&scan(&path, &["--format", "json"]).1);
    let shown = single_json_finding(&scan(&path, &["--format", "json", "--show-secrets"]).1);
    let masked_hash = masked.get("credential_hash").and_then(|x| x.as_str());
    let shown_hash = shown.get("credential_hash").and_then(|x| x.as_str());
    assert_eq!(
        masked_hash,
        Some(PLANTED_SHA256),
        "redacted-run hash must be sha256 of the plaintext token"
    );
    assert_eq!(
        shown_hash, masked_hash,
        "--show-secrets must not change the credential hash (masking is display-only)"
    );
}

/// Cross-check: the masked run and the shown run agree on detector id AND hash;
/// ONLY the `credential_redacted` text differs. A single scan-config knob flips
/// display without touching identity.
#[test]
fn masked_and_shown_differ_only_in_credential_text() {
    let (_dir, path) = planted_fixture();
    let masked = single_json_finding(&scan(&path, &["--format", "json"]).1);
    let shown = single_json_finding(&scan(&path, &["--format", "json", "--show-secrets"]).1);
    assert_eq!(
        masked.get("detector_id"),
        shown.get("detector_id"),
        "detector id must be identical across masking modes"
    );
    assert_eq!(
        masked.get("credential_hash"),
        shown.get("credential_hash"),
        "credential hash must be identical across masking modes"
    );
    assert_ne!(
        masked.get("credential_redacted"),
        shown.get("credential_redacted"),
        "only the credential text differs: masked `{REDACTED}` vs full plaintext"
    );
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// Default csv: the sole data row's 5th cell (`credential_redacted`) is the
/// masked form, and neither the plaintext nor its middle run appears anywhere.
#[test]
fn default_csv_masks_credential_cell_and_hides_plaintext() {
    let (_dir, path) = planted_fixture();
    let (code, out, err) = scan(&path, &["--format", "csv"]);
    assert_eq!(code, Some(1), "a finding must exit 1; stderr={err}");
    let rows: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(rows.len(), 2, "header + exactly one data row: {rows:?}");
    let cells: Vec<&str> = rows[1].split(',').collect();
    assert_eq!(
        cells.get(4).copied(),
        Some(REDACTED),
        "csv column 5 (credential_redacted) must be the masked form; row={}",
        rows[1]
    );
    assert!(
        !out.contains(PLANTED) && !out.contains(SECRET_MIDDLE),
        "default csv must not leak the plaintext token or its middle; got {out}"
    );
}

/// `--show-secrets` csv: the 5th cell is the full plaintext token.
#[test]
fn show_secrets_csv_cell_is_full_plaintext() {
    let (_dir, path) = planted_fixture();
    let (_code, out, _err) = scan(&path, &["--format", "csv", "--show-secrets"]);
    let rows: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(rows.len(), 2, "header + one data row: {rows:?}");
    let cells: Vec<&str> = rows[1].split(',').collect();
    assert_eq!(
        cells.get(4).copied(),
        Some(PLANTED),
        "--show-secrets csv column 5 must be the full plaintext token; row={}",
        rows[1]
    );
}

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

/// Default sarif: exactly one result whose ruleId is the detector, and the full
/// plaintext token never appears anywhere in the SARIF document.
#[test]
fn default_sarif_hides_plaintext_and_names_detector() {
    let (_dir, path) = planted_fixture();
    let (code, out, err) = scan(&path, &["--format", "sarif"]);
    assert_eq!(code, Some(1), "a finding must exit 1; stderr={err}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("sarif must parse as json");
    let results = v
        .pointer("/runs/0/results")
        .and_then(|r| r.as_array())
        .expect("sarif runs[0].results must be an array");
    assert_eq!(results.len(), 1, "one planted secret -> one sarif result");
    assert_eq!(
        results[0].get("ruleId").and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "sarif ruleId must be the detector id"
    );
    assert!(
        !out.contains(PLANTED) && !out.contains(SECRET_MIDDLE),
        "default sarif must not leak the plaintext token; got {out}"
    );
}

// ---------------------------------------------------------------------------
// JSONL
// ---------------------------------------------------------------------------

/// Default jsonl: the single object line masks the credential and hides the
/// plaintext.
#[test]
fn default_jsonl_masks_credential_and_hides_plaintext() {
    let (_dir, path) = planted_fixture();
    let (code, out, err) = scan(&path, &["--format", "jsonl"]);
    assert_eq!(code, Some(1), "a finding must exit 1; stderr={err}");
    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "one finding -> one jsonl object line: {lines:?}"
    );
    let obj: serde_json::Value =
        serde_json::from_str(lines[0]).expect("jsonl line must be a json object");
    assert_eq!(
        obj.get("credential_redacted").and_then(|x| x.as_str()),
        Some(REDACTED),
        "jsonl credential_redacted must be the masked form; got {}",
        lines[0]
    );
    assert!(
        !out.contains(PLANTED),
        "default jsonl must not leak the plaintext token; got {out}"
    );
}

// ---------------------------------------------------------------------------
// TEXT (human report)
// ---------------------------------------------------------------------------

/// Default text report: the masked credential is printed and the plaintext is
/// absent from both stdout and stderr.
#[test]
fn default_text_shows_masked_not_plaintext() {
    let (_dir, path) = planted_fixture();
    let (code, out, err) = scan(&path, &["--format", "text"]);
    assert_eq!(code, Some(1), "a finding must exit 1; stderr={err}");
    let combined = format!("{out}\n{err}");
    assert!(
        combined.contains(REDACTED),
        "default text report must print the masked `{REDACTED}`; got:\n{combined}"
    );
    assert!(
        !combined.contains(PLANTED) && !combined.contains(SECRET_MIDDLE),
        "default text report must NOT print the plaintext token; got:\n{combined}"
    );
}

/// `--show-secrets` text report: the full plaintext token is printed.
#[test]
fn show_secrets_text_prints_full_plaintext() {
    let (_dir, path) = planted_fixture();
    let (_code, out, err) = scan(&path, &["--format", "text", "--show-secrets"]);
    let combined = format!("{out}\n{err}");
    assert!(
        combined.contains(PLANTED),
        "--show-secrets text report must reveal the plaintext token; got:\n{combined}"
    );
}

// ---------------------------------------------------------------------------
// FAIL CLOSED, lockdown refuses reveal
// ---------------------------------------------------------------------------

/// Adversarial: `--lockdown --show-secrets` is refused (exit 2, a user error)
/// with an actionable message, and NO plaintext token reaches stdout. Lockdown
/// must never let plaintext escape.
#[test]
fn lockdown_with_show_secrets_fails_closed_exit_2() {
    let (_dir, path) = planted_fixture();
    let (code, out, err) = scan(&path, &["--format", "json", "--lockdown", "--show-secrets"]);
    assert_eq!(
        code,
        Some(2),
        "lockdown + --show-secrets must fail closed with exit 2; stdout={out} stderr={err}"
    );
    assert!(
        err.contains("lockdown mode forbids --show-secrets"),
        "the refusal must be an actionable message; got stderr:\n{err}"
    );
    assert!(
        !out.contains(PLANTED) && !err.contains(PLANTED),
        "no plaintext token may reach stdout/stderr on the refused run"
    );
}

/// `--show-secrets` sarif: the reveal flag applies uniformly across formats 
/// the full plaintext token appears in the SARIF document, and it is the SAME
/// single result (ruleId unchanged) as the redacted run.
#[test]
fn show_secrets_sarif_reveals_plaintext_same_result() {
    let (_dir, path) = planted_fixture();
    let (code, out, err) = scan(&path, &["--format", "sarif", "--show-secrets"]);
    assert_eq!(code, Some(1), "a finding must exit 1; stderr={err}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("sarif must parse as json");
    let results = v
        .pointer("/runs/0/results")
        .and_then(|r| r.as_array())
        .expect("sarif runs[0].results array");
    assert_eq!(results.len(), 1, "one planted secret -> one sarif result");
    assert_eq!(
        results[0].get("ruleId").and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "--show-secrets sarif ruleId must still be the detector id"
    );
    assert!(
        out.contains(PLANTED),
        "--show-secrets sarif must reveal the plaintext token; got {out}"
    );
}

/// Cross-format redaction invariant: the DEFAULT (redacted) json, jsonl, csv,
/// sarif, and text reports NONE leak the plaintext token, a per-format
/// redaction hole (one serializer forgetting to use `credential_redacted`) is
/// caught here even if the other formats are clean.
#[test]
fn no_default_format_leaks_the_plaintext_token() {
    let (_dir, path) = planted_fixture();
    for fmt in ["json", "jsonl", "csv", "sarif", "text"] {
        let (_code, out, err) = scan(&path, &["--format", fmt]);
        let combined = format!("{out}\n{err}");
        assert!(
            !combined.contains(PLANTED),
            "default `{fmt}` report leaked the plaintext token; got:\n{combined}"
        );
        assert!(
            !combined.contains(SECRET_MIDDLE),
            "default `{fmt}` report leaked the masked middle run; got:\n{combined}"
        );
    }
}
