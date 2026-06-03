//! Adversarial audit — VECTOR 2 (RESEARCH) + VECTOR 4 (INNOVATION).
//!
//! These are **failing** tests that document categorical capability gaps versus
//! frontier secret scanners (trufflehog, kingfisher). Each test fails today and
//! is expected to PASS once the matching capability is implemented. They are
//! black-box: they spawn the keyhog binary and assert on its JSON output, so they
//! couple to observable behavior, not to private internals.
//!
//! Binary resolution: prefer the prebuilt release-fast binary the audit harness
//! ships; fall back to the cargo-built CLI binary (`CARGO_BIN_EXE_keyhog`) so the
//! test is runnable on any machine.
//!
//! ─────────────────────────────────────────────────────────────────────────────
//! FINDINGS
//!
//! AUD-research_innovation-1  Offline AWS account-ID decode is missing.
//!   The AWS account number is mathematically embedded in every modern AKIA/ASIA
//!   access-key ID and is recoverable with a pure base32-decode + bit-shift — NO
//!   network call, NO `--verify`. trufflehog reports this account ID for every AWS
//!   key (live OR revoked). keyhog only obtains `account_id` from a live STS
//!   `GetCallerIdentity` response (crates/verifier/src/verify/aws.rs:196-198),
//!   which requires `--verify`, network egress, AND a live key. A plain
//!   `keyhog scan` of `ASIAY34FZKBOKMUTVV7A` therefore surfaces `metadata: {}`
//!   instead of the documented, derivable account `609629065308`.
//!   Reference: trufflesecurity.com/blog/research-uncovers-aws-account-numbers-hidden-in-access-keys
//!   Expected fix: add an offline AWS-account decoder (in keyhog-scanner, e.g.
//!   `aws_account_from_key_id`) and attach `account_id` to the AWS access-key
//!   finding's metadata during scanning (no verify required).
//!
//! AUD-research_innovation-2  AWS canary-token (Thinkst / canarytokens.org)
//!   awareness is absent. Building on the offline decode above, frontier scanners
//!   recognise AWS keys whose decoded account ID belongs to a known canary issuer
//!   and flag them so the operator does NOT verify them (verifying trips the
//!   attacker's tripwire). keyhog has zero canary signatures: scanning a key that
//!   decodes to the confirmed canarytokens.org account `052310077262` yields a
//!   generic `aws-access-key` finding with empty metadata and no `is_canary`
//!   marker — and on the `--verify` path keyhog would send the request that sets
//!   the canary off. Reference: trufflesecurity.com/blog/canaries
//!   Expected fix: ship a Tier-B canary account-ID list (e.g.
//!   `rules/aws-canary-accounts.toml`), and when a detected AWS key decodes to a
//!   listed account, add `is_canary=true` metadata and suppress live verification.
//!
//! AUD-research_innovation-3  JWT structural analysis is built but never wired
//!   into output. crates/scanner/src/jwt.rs is a complete, fully-public analyzer
//!   whose own module doc promises to "Surface metadata: alg, iss, sub, aud, exp
//!   as evidence in the finding output" and to "Flag alg=none JWTs as a SECURITY
//!   ANOMALY". `jwt::analyze` / `jwt::anomalies_to_metadata` correctly return
//!   `JwtAnomaly::AlgNone` for a forged unsigned token, but a repo-wide search
//!   shows NO non-test caller (`grep -rn 'jwt::analyze' crates/` outside
//!   tests/jwt.rs is empty). Consequently a real `alg=none` forgery is detected
//!   as a secret yet ships with `metadata: {}` — none of the alg/issuer/expiry
//!   evidence, and no anomaly flag, ever reaches the operator. This is dead
//!   frontier capability (Vector 4 innovation + Vector 11 utilization).
//!   Expected fix: invoke `jwt::analyze` on JWT-shaped matches in the scan
//!   pipeline and merge `anomalies_to_metadata` + claim fields into the finding
//!   metadata so `jwt.alg_none` / `jwt.alg` / `jwt.iss` appear in output.

use std::path::PathBuf;
use std::process::Command;

/// Resolve the keyhog binary. Prefer the prebuilt release-fast artifact the
/// audit harness ships; fall back to the cargo test binary env var.
fn binary() -> PathBuf {
    let prebuilt =
        PathBuf::from("/mnt/FlareTraining/santh-archive/cargo-target/release-fast/keyhog");
    if prebuilt.is_file() {
        return prebuilt;
    }
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Write `contents` to a fresh temp file under a unique dir and return the path.
fn write_fixture(name: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keyhog_audit_ri_{}_{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    let file = dir.join(format!("{name}.txt"));
    std::fs::write(&file, contents).expect("write fixture");
    file
}

/// Run `keyhog scan <path> --format json` and parse the JSON array.
fn scan_json(path: &PathBuf) -> serde_json::Value {
    let output = Command::new(binary())
        .arg("scan")
        .arg(path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("spawn keyhog scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str::<serde_json::Value>(&stdout).unwrap_or_else(|e| {
        panic!(
            "keyhog scan must emit valid JSON; parse error: {e}; stdout={stdout}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Find the first finding whose metadata we care about (the array is small here).
fn first_finding(json: &serde_json::Value) -> &serde_json::Value {
    let arr = json.as_array().expect("scan output is a JSON array");
    assert!(
        !arr.is_empty(),
        "expected at least one finding in scan output, got empty array"
    );
    &arr[0]
}

/// AUD-research_innovation-1
///
/// `keyhog scan` of the canonical AWS sample key `ASIAY34FZKBOKMUTVV7A` (used in
/// trufflehog's own write-up) must surface the offline-derivable account ID
/// `609629065308` in the finding metadata WITHOUT `--verify` and without any
/// network access. Today metadata is empty, so this fails.
#[test]
fn aws_access_key_finding_carries_offline_decoded_account_id() {
    // ASIAY34FZKBOKMUTVV7A -> account 609629065308 (base32 decode + >>7).
    let path = write_fixture(
        "aws_offline_account",
        "aws_access_key_id = ASIAY34FZKBOKMUTVV7A\n",
    );
    let json = scan_json(&path);
    let finding = first_finding(&json);

    assert_eq!(
        finding["detector_id"].as_str(),
        Some("aws-access-key"),
        "the AWS key must be attributed to aws-access-key; got {finding}"
    );

    let account_id = finding["metadata"]["account_id"].as_str();
    assert_eq!(
        account_id,
        Some("609629065308"),
        "keyhog should decode the AWS account ID offline (base32 + bit-shift) and \
         attach it as metadata.account_id without --verify, matching trufflehog. \
         Got metadata = {}",
        finding["metadata"]
    );
}

/// AUD-research_innovation-2
///
/// An AWS key that decodes to the confirmed canarytokens.org account
/// `052310077262` must be flagged as a canary so the operator knows NOT to verify
/// it (verifying a canary alerts the attacker). `AKIAAYLPMN5HAAAAAAAA` decodes to
/// `052310077262`. keyhog currently emits a generic finding with empty metadata
/// and no canary marker, so this fails.
#[test]
fn aws_canary_token_is_flagged_so_it_is_not_verified() {
    // AKIAAYLPMN5HAAAAAAAA -> account 052310077262 (Thinkst/canarytokens.org).
    let path = write_fixture("aws_canary", "aws_access_key_id = AKIAAYLPMN5HAAAAAAAA\n");
    let json = scan_json(&path);
    let finding = first_finding(&json);

    assert_eq!(
        finding["detector_id"].as_str(),
        Some("aws-access-key"),
        "the canary AWS key must still be detected as aws-access-key; got {finding}"
    );

    let is_canary = finding["metadata"]["is_canary"].as_str();
    assert_eq!(
        is_canary,
        Some("true"),
        "keyhog should recognise AWS keys whose decoded account belongs to a known \
         canary issuer (canarytokens.org account 052310077262) and mark \
         metadata.is_canary=true so live verification is suppressed. Got metadata = {}",
        finding["metadata"]
    );
}

/// AUD-research_innovation-3
///
/// A forged `alg=none` JWT (unsigned, trivially forgeable — the classic JWT
/// vulnerability) must, when detected as a secret, carry the JWT analysis the
/// fully-built-but-unwired `keyhog_scanner::jwt` module already produces:
/// specifically the `alg_none` security anomaly. Today the token is detected but
/// metadata is empty, so this fails.
///
/// Token below = base64url({"alg":"none","typ":"JWT"}).{payload}.{dummy-sig}, a
/// realistic forged unsigned JWT.
#[test]
fn forged_alg_none_jwt_surfaces_security_anomaly_metadata() {
    // header {"alg":"none","typ":"JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
    // payload {"sub":"admin","name":"attacker","iss":"https://accounts.example.com","exp":9999999999}
    let token = concat!(
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
        ".eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJhdHRhY2tlciIsImlzcyI6Imh0dHBzOi8v",
        "YWNjb3VudHMuZXhhbXBsZS5jb20iLCJleHAiOjk5OTk5OTk5OTl9",
        ".aaaaaaaaaaXXXXXXXXXX"
    );
    let path = write_fixture("jwt_alg_none", &format!("Authorization: Bearer {token}\n"));
    let json = scan_json(&path);
    let finding = first_finding(&json);

    // The metadata must carry the JWT alg-none anomaly. The exact key name is
    // contractually `jwt.alg_none` per anomalies_to_metadata() in
    // crates/scanner/src/jwt.rs. Either the structured anomaly key OR an
    // explicit alg field exposing "none" satisfies "the analysis reached output";
    // we assert the strong, documented signal: the alg_none anomaly flag.
    let meta = &finding["metadata"];
    let has_alg_none_anomaly = meta
        .get("jwt.alg_none")
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_lowercase().contains("true"))
        .unwrap_or(false);
    let alg_reports_none = meta
        .get("jwt.alg")
        .and_then(|v| v.as_str())
        .map(|s| s.eq_ignore_ascii_case("none"))
        .unwrap_or(false);

    assert!(
        has_alg_none_anomaly || alg_reports_none,
        "keyhog_scanner::jwt::analyze flags this forged token with \
         JwtAnomaly::AlgNone, but that analysis is never wired into the scan \
         output, so the operator never learns the token is an unsigned forgery. \
         Expected metadata to contain jwt.alg_none=true (or jwt.alg=none). \
         Got metadata = {meta}"
    );
}
