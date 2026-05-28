//! Live-verify smoke test against real third-party APIs.
//!
//! This test is **gated on `KEYHOG_LIVE_VERIFY=1`** so it never runs in
//! normal CI. When enabled, it plants a credential read from one of the
//! recognized env-var pairs into a temp file, runs `keyhog scan
//! --verify --no-daemon` against that file, and asserts the binary
//! exits with code 10 - the `EXIT_LIVE_CREDENTIALS` contract from
//! `crates/cli/src/orchestrator.rs:45`.
//!
//! Why this exists: every other test in the tree uses synthesized
//! fixtures (`AKIAIOSFODNN7EXAMPLE`, well-known dummy GitHub PATs)
//! that the verifier short-circuits before any real network call. That
//! leaves the actual auth-signing + network-roundtrip path of the
//! verifier untested end-to-end. A regression in the SigV4 signer
//! (`crates/verifier/src/verify/aws.rs`) or the GitHub PAT request
//! builder would land green in CI and break only at runtime against
//! real customer credentials. This test is the canary on that path.
//!
//! Supported credential pairs (any one is enough to enable the test):
//!
//! | Env vars | Detector exercised |
//! | -------- | ------------------ |
//! | `KEYHOG_LIVE_AWS_ACCESS_KEY_ID`<br>`KEYHOG_LIVE_AWS_SECRET_ACCESS_KEY` | `aws-credentials` |
//! | `KEYHOG_LIVE_GITHUB_PAT` | `github-personal-access-token` |
//!
//! The two-prefixed scheme (`KEYHOG_LIVE_*`) is deliberate: it stays
//! distinct from any ambient `AWS_ACCESS_KEY_ID` / `GITHUB_TOKEN` the
//! developer may have exported for their own work, so the test only
//! fires when the developer explicitly opts in by re-exporting the
//! creds under `KEYHOG_LIVE_*`.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn live_verify_enabled() -> bool {
    std::env::var("KEYHOG_LIVE_VERIFY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// The exit-code contract from `crates/cli/src/orchestrator.rs:45`.
/// Duplicated here intentionally: if the orchestrator changes 10 to
/// something else, this test must fail loudly so the docs + downstream
/// CI consumers can be updated in lockstep.
const EXIT_LIVE_CREDENTIALS: i32 = 10;

#[derive(Debug, Clone)]
struct LiveCredential {
    label: &'static str,
    file_name: &'static str,
    contents: String,
}

fn collect_live_credentials() -> Vec<LiveCredential> {
    let mut out = Vec::new();

    let aws_id = std::env::var("KEYHOG_LIVE_AWS_ACCESS_KEY_ID").ok();
    let aws_secret = std::env::var("KEYHOG_LIVE_AWS_SECRET_ACCESS_KEY").ok();
    if let (Some(id), Some(secret)) = (aws_id, aws_secret) {
        if !id.trim().is_empty() && !secret.trim().is_empty() {
            // Two-line .env shape: the AWS verifier needs the secret
            // to be reachable from the access-key match site via the
            // companion-extraction window.
            out.push(LiveCredential {
                label: "aws-credentials",
                file_name: "live.env",
                contents: format!(
                    "AWS_ACCESS_KEY_ID={}\nAWS_SECRET_ACCESS_KEY={}\n",
                    id.trim(),
                    secret.trim()
                ),
            });
        }
    }

    if let Ok(pat) = std::env::var("KEYHOG_LIVE_GITHUB_PAT") {
        if !pat.trim().is_empty() {
            out.push(LiveCredential {
                label: "github-personal-access-token",
                file_name: "live-gh.env",
                contents: format!("GITHUB_TOKEN={}\n", pat.trim()),
            });
        }
    }

    out
}

#[test]
fn live_verify_smoke_real_credentials_yield_exit_10() {
    if !live_verify_enabled() {
        eprintln!(
            "live_verify_smoke: skipped - set KEYHOG_LIVE_VERIFY=1 and \
             at least one of KEYHOG_LIVE_AWS_ACCESS_KEY_ID/SECRET, \
             KEYHOG_LIVE_GITHUB_PAT to run the live-verify smoke."
        );
        return;
    }

    let creds = collect_live_credentials();
    if creds.is_empty() {
        // The opt-in env var was set but no credentials were supplied.
        // That's a user error - surface it loudly so the CI run that
        // enabled the gate doesn't silently pass without proving anything.
        panic!(
            "KEYHOG_LIVE_VERIFY=1 but no credentials supplied. Set at \
             least one of: (KEYHOG_LIVE_AWS_ACCESS_KEY_ID + \
             KEYHOG_LIVE_AWS_SECRET_ACCESS_KEY) or KEYHOG_LIVE_GITHUB_PAT."
        );
    }

    for cred in &creds {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join(cred.file_name);
        std::fs::write(&path, &cred.contents).expect("write planted credential");

        let out = Command::new(binary())
            .arg("scan")
            .arg("--no-daemon")
            .arg("--verify")
            .arg("--format")
            .arg("json")
            .arg(&path)
            .output()
            .expect("spawn keyhog scan --verify");

        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let code = out.status.code();

        // The hard contract: a real, live credential must produce
        // exit 10. Exit 1 means the detector fired but the verifier
        // classified it as Dead / Unverifiable / Unknown - that is
        // a regression in the verifier's auth-signing or response-
        // parsing path, NOT a configuration issue, because the
        // developer is telling us with KEYHOG_LIVE_VERIFY=1 that
        // these creds are valid right now.
        assert_eq!(
            code,
            Some(EXIT_LIVE_CREDENTIALS),
            "{label}: expected exit {expected} (EXIT_LIVE_CREDENTIALS) \
             but got {code:?}. The verifier's network roundtrip for \
             this credential class is broken - investigate {verifier_module}.\n\
             stdout:\n{stdout}\nstderr:\n{stderr}",
            label = cred.label,
            expected = EXIT_LIVE_CREDENTIALS,
            verifier_module = match cred.label {
                "aws-credentials" => "crates/verifier/src/verify/aws.rs",
                "github-personal-access-token" => "crates/verifier/src/verify/mod.rs",
                _ => "crates/verifier/src/verify/",
            },
        );

        // Belt-and-suspenders: the JSON report must also self-identify
        // the verification as Live. If the exit code matched 10 but the
        // JSON disagrees, the orchestrator's classification logic
        // (orchestrator.rs:439) has drifted from the report writer.
        assert!(
            stdout.contains("\"Live\"") || stdout.contains("\"live\""),
            "{label}: exit was 10 but JSON did not surface a Live \
             classification. orchestrator.rs and the report writer \
             are out of sync.\nstdout:\n{stdout}",
            label = cred.label,
        );
    }
}
