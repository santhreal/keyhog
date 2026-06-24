//! Contract test for issue #4: S3 source MUST NOT forward ambient
//! `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` to non-AWS endpoints
//! unless the operator explicitly opts in via a caller-supplied flag.
//!
//! The negative property: "for any S3 endpoint outside `*.amazonaws.com`,
//! no SigV4 `Authorization` header is attached." This is the kind of
//! test that catches an entire CLASS of credential-leak regressions
//! rather than one path. Any future change that re-adds env-cred lookup
//! to a custom-endpoint code path will fail this test.
//!
//! We test the `endpoint_is_aws` + `credential_forward_allowed` policy
//! gates directly rather than spinning up a mock HTTP server because:
//!   1. Spinning a real listener doesn't add coverage for the policy
//!      decision; only for the wire format afterward.
//!   2. The policy gates are the EXTERNAL CONTRACT - "for these inputs,
//!      ambient creds are or are not loaded." The wire-format check is
//!      an implementation detail of `AwsSigV4Config::sign`.
//!
//! Wire-format verification lives in unit tests under
//! `crates/sources/src/s3/auth.rs`.

use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// AWS-owned endpoints: every shape `aws s3 endpoint-url` documents.
/// Pre-fix: trivially true (everything got creds). Post-fix: these stay
/// permissive, third-party stays restrictive.
#[test]
fn aws_owned_endpoints_are_recognized_as_aws() {
    for endpoint in [
        "https://s3.amazonaws.com",
        "https://s3.us-east-1.amazonaws.com",
        "https://s3.eu-west-2.amazonaws.com",
        "https://s3.dualstack.us-east-1.amazonaws.com",
        "https://mybucket.s3.us-east-1.amazonaws.com",
        "https://S3.US-EAST-1.AMAZONAWS.COM",
        "https://s3.cn-north-1.amazonaws.com.cn",
        "https://s3.us-gov-east-1.amazonaws.com",
    ] {
        assert!(
            TestApi.s3_endpoint_is_aws(endpoint),
            "AWS-owned endpoint {endpoint} must be recognized as AWS",
        );
    }
}

/// Non-AWS hosts that LOOK plausible: MinIO defaults, generic S3-API
/// vendors, typo'd AWS hostnames, IP literals, and attacker-controlled
/// domains. None of these should receive ambient AWS credentials.
///
/// Issue #4: pre-fix, `--s3-endpoint=https://attacker.example` with
/// `AWS_ACCESS_KEY_ID` present in the environment caused KeyHog to
/// transmit a SigV4-signed `Authorization` header (plus
/// `x-amz-security-token`) to `attacker.example`. That's an ambient-
/// credential exfiltration channel created from a read-only scan
/// feature. The endpoint policy below is the only correct default.
#[test]
fn non_aws_endpoints_do_not_pass_aws_gate() {
    for endpoint in [
        "https://minio.example.test",
        "https://minio.local:9000",
        "https://s3.example.test",                // generic S3-API vendor
        "https://attacker.example",               // attacker-controlled
        "https://amazonaws.com.attacker.example", // suffix-confusion attack
        "https://AMAZONAWS.COM.attacker.example", // case variant suffix-confusion
        "https://s3.amazonaws.co",                // typo'd TLD
        "https://s3-amazonaws.com",               // missing dot
        "http://127.0.0.1:9000",                  // IP literal
        "http://10.0.0.5:9000",
        "https://ceph.internal.corp",
        "https://garage.internal",
        "https://wasabisys.com", // S3-compatible commercial
        "https://eu-central-1.linodeobjects.com",
    ] {
        assert!(
            !TestApi.s3_endpoint_is_aws(endpoint),
            "non-AWS endpoint {endpoint} must NOT be recognized as AWS \
             (would forward AWS_ACCESS_KEY_ID + AWS_SESSION_TOKEN to a \
             third party). Issue #4.",
        );
    }
}

/// Opt-in policy: forwarding must be explicit caller state, never ambient env.
/// Without this test a refactor could reintroduce an env knob and silently flip
/// the default to "forward."
#[test]
fn credential_forward_opt_in_ignores_ambient_env() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let saved = std::env::var("KEYHOG_S3_ALLOW_CREDENTIAL_FORWARD").ok();
    struct Restore(Option<String>);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: env::set_var/remove_var require unsafe in 2024 edition.
            unsafe {
                match &self.0 {
                    Some(v) => std::env::set_var("KEYHOG_S3_ALLOW_CREDENTIAL_FORWARD", v),
                    None => std::env::remove_var("KEYHOG_S3_ALLOW_CREDENTIAL_FORWARD"),
                }
            }
        }
    }
    let _restore = Restore(saved);

    unsafe {
        std::env::set_var("KEYHOG_S3_ALLOW_CREDENTIAL_FORWARD", "1");
    }

    assert!(
        !TestApi.s3_credential_forward_allowed(false),
        "ambient KEYHOG_S3_ALLOW_CREDENTIAL_FORWARD must not enable forwarding"
    );
    assert!(
        TestApi.s3_credential_forward_allowed(true),
        "explicit caller opt-in must enable forwarding"
    );
}
