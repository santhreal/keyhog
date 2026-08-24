//! The exit-code contract is a PROMISE: scripts and CI branch on it. These
//! tests drive the real binary and assert the documented table
//! (`keyhog --help` EXIT CODES) actually holds, and that the exit code is
//! independent of output format (a format flag must never change the verdict).

use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

use crate::reliability::harness::binary;

/// A planted GitHub classic PAT with a valid embedded checksum. It reaches the
/// `confirmed` evidence tier, which blocks under the default policy, so the
/// verdict is "secret found" without --verify. The former AWS-key fixture
/// (`AKIAQYLPMN5HFIQR7XYA` alone in a text file) now lands at review tier
/// (unsupported context), and review-tier findings are documented as visible
/// under exit 0, so it can no longer stand in for a blocking finding.
const PLANTED_TOKEN: &str = "GITHUB_TOKEN = \"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\"\n";

fn scan_file(content: &str, extra: &[&str]) -> (Option<i32>, String, String) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, content).unwrap();
    run_scan(&path, extra)
}

fn run_scan(path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    // `cpu` is the scalar route every build ships. Pinning `simd` here made
    // the whole suite fail closed on a default (portable, Hyperscan-free)
    // build, which is the build most contributors and `cargo install` users
    // have. Backend behaviour is not what these contracts measure.
    let mut args: Vec<String> = vec![
        "scan".into(),
        "--daemon=off".into(),
        "--backend".into(),
        "cpu".into(),
    ];
    for e in extra {
        args.push((*e).into());
    }
    args.push(path.to_string_lossy().into_owned());
    let out = Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn clean_file_exits_zero() {
    let (code, _o, _e) = scan_file("nothing to see here, just prose\n", &["--format", "json"]);
    assert_eq!(
        code,
        Some(0),
        "a clean file must exit 0 (documented: 0=success)"
    );
}

#[test]
fn planted_secret_exits_one() {
    let (code, _o, _e) = scan_file(PLANTED_TOKEN, &["--format", "json"]);
    assert_eq!(
        code,
        Some(1),
        "an unverified finding must exit 1 (documented: 1=secrets found)"
    );
}

#[test]
fn missing_path_exits_two() {
    let (code, _o, _e) = run_scan(
        Path::new("/no/such/keyhog/path/xyz123"),
        &["--format", "json"],
    );
    assert_eq!(
        code,
        Some(2),
        "a missing path must exit 2 (documented: 2=user error / unreadable path)"
    );
}

#[test]
fn exit_code_is_independent_of_output_format() {
    // The verdict (found vs clean) must not depend on how it's rendered. A
    // format flag changing the exit code would silently break CI gating.
    let mut codes = vec![];
    for fmt in ["text", "json", "jsonl", "sarif"] {
        let (code, _o, _e) = scan_file(PLANTED_TOKEN, &["--format", fmt]);
        codes.push((fmt, code));
    }
    for (fmt, code) in &codes {
        assert_eq!(
            *code,
            Some(1),
            "format {fmt}: planted secret must still exit 1 (got {code:?}); exit code must be format-independent"
        );
    }
}

#[test]
fn clean_exit_is_independent_of_output_format() {
    for fmt in ["text", "json", "jsonl", "sarif"] {
        let (code, _o, _e) = scan_file("clean prose, no secrets\n", &["--format", fmt]);
        assert_eq!(
            code,
            Some(0),
            "format {fmt}: clean file must exit 0; exit code must be format-independent"
        );
    }
}

#[test]
fn help_documents_every_exit_code_it_can_return() {
    let out = Command::new(binary()).arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    for code in keyhog::exit_codes::DEFINITIONS
        .iter()
        .map(|definition| definition.code.to_string())
    {
        assert!(
            help.contains(&code),
            "`keyhog --help` EXIT CODES section omits documented code {code}:\n{help}"
        );
    }
}

#[test]
fn repeated_identical_scans_return_the_same_exit_code() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, PLANTED_TOKEN).unwrap();
    let (c1, _, _) = run_scan(&path, &["--format", "json"]);
    let (c2, _, _) = run_scan(&path, &["--format", "json"]);
    let (c3, _, _) = run_scan(&path, &["--format", "json"]);
    assert_eq!(
        (c1, c2),
        (c2, c3),
        "the same scan returned different exit codes across runs: {c1:?} {c2:?} {c3:?}"
    );
}
