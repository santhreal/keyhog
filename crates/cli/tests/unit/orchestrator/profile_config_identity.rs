use super::support::ENV_LOCK;
use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

fn scan_args(args: &[&str]) -> ScanArgs {
    ScanArgs::try_parse_from(args).expect("parse scan args")
}

fn digests(args: &[&str]) -> ([u8; 32], [u8; 32]) {
    let mut args = scan_args(args);
    API.profiling_config_digests_for_args(&mut args)
        .expect("resolve profiling config digests")
}

/// Repeated resolution of the same operator configuration must produce identical comparison keys.
#[test]
fn profiling_config_identity_is_deterministic() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let first = digests(&["scan", "--no-config", "--stdin", "--deep"]);
    let second = digests(&["scan", "--no-config", "--stdin", "--deep"]);

    assert_eq!(first, second);
    assert_ne!(first.0, [0; 32]);
    assert_ne!(first.1, [0; 32]);
}

/// A scanner policy override must invalidate both full configuration and performance-policy identity.
#[test]
fn profiling_policy_digest_tracks_detection_policy() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let baseline = digests(&["scan", "--no-config", "--stdin"]);
    let strict = digests(&["scan", "--no-config", "--stdin", "--min-confidence", "0.91"]);

    assert_ne!(baseline.0, strict.0);
    assert_ne!(baseline.1, strict.1);
}

/// Output encoding changes must invalidate the full config without falsifying scanner-cost policy.
#[test]
fn resolved_config_digest_separates_reporting_from_scan_policy() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let json = digests(&["scan", "--no-config", "--stdin", "--format", "json"]);
    let sarif = digests(&["scan", "--no-config", "--stdin", "--format", "sarif"]);

    assert_ne!(json.0, sarif.0);
    assert_eq!(json.1, sarif.1);
}

/// Verifier transport boundaries must participate in full config identity even before live use.
#[test]
fn resolved_config_digest_tracks_verifier_timeout_boundary() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let short = digests(&[
        "scan",
        "--no-config",
        "--stdin",
        "--verify",
        "--timeout",
        "1",
    ]);
    let long = digests(&[
        "scan",
        "--no-config",
        "--stdin",
        "--verify",
        "--timeout",
        "3600",
    ]);

    assert_ne!(short.0, long.0);
    assert_eq!(short.1, long.1);
}
