//! Invariant: a machine output format stays machine-readable under EVERY
//! hostile profile.
//!
//! `output_format.rs` proves the formats are well-formed in a clean
//! environment. That is the easy half. The half that actually breaks a SIEM
//! ingest is the ugly one: HOME unset, an unwritable cwd, a `TMPDIR` that does
//! not exist, `CLICOLOR_FORCE=1`, a rejected `KEYHOG_BACKEND`, or a 4096-thread
//! request. Each of those flips a different runtime branch that can print a
//! plain-text warning, a colored banner, or half a document into the same
//! stream a parser is reading.
//!
//! Every cell asserts, for one `(format × profile)` pair:
//!   * no signal death, no escaped panic, a documented exit code;
//!   * stdout is either empty or completely parseable in that format, never a
//!     truncated or prose-contaminated document;
//!   * zero ANSI on stdout, including under `CLICOLOR_FORCE`, because forcing
//!     color is a request about the human surface and must never reach a
//!     machine stream.
//!
//! 3 formats x 16 profiles = 48 distinct cases.

use crate::reliability::harness::{
    assert_clean_exit, assert_documented_exit, assert_no_panic, assert_valid_json_if_nonempty, run,
    Outcome, Profile,
};
use tempfile::TempDir;

/// A real AWS access-key shape, so every cell scans a finding-producing input
/// rather than the trivial empty-report path.
const PLANTED_AWS: &str = "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n";

/// ANSI on a machine stream is never correct, so this is stricter than
/// `assert_no_ansi`: it holds even for `Profile::ClicolorForce`, where colored
/// stderr is the requested behavior.
fn assert_machine_stdout_has_no_ansi(o: &Outcome) {
    assert!(
        !o.stdout_raw.contains(&0x1b),
        "{}: ANSI escape reached a machine-format stdout stream:\n{}",
        o.what,
        o.stdout.chars().take(300).collect::<String>()
    );
}

/// Every non-blank JSONL line must be a complete JSON object on its own line,
/// which is the entire contract streaming consumers rely on.
fn assert_valid_jsonl(o: &Outcome) {
    for (index, line) in o.stdout.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|error| {
            panic!(
                "{}: jsonl line {index} is not valid JSON: {error}\n{line}",
                o.what
            )
        });
        assert!(
            value.is_object(),
            "{}: jsonl line {index} is not a JSON object: {line}",
            o.what
        );
    }
}

pub fn machine_format_invariant(profile: Profile, format: &str) {
    let dir = TempDir::new().expect("tempdir for planted secret");
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, PLANTED_AWS).expect("write planted secret");
    let path = path.to_string_lossy().into_owned();

    let outcome = run(
        profile,
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            format,
            &path,
        ],
    );

    assert_clean_exit(&outcome);
    assert_no_panic(&outcome);
    assert_documented_exit(&outcome);
    assert_machine_stdout_has_no_ansi(&outcome);

    match format {
        "jsonl" => assert_valid_jsonl(&outcome),
        // SARIF is a JSON dialect; validity as JSON is the parse contract a
        // code-scanning upload needs before any schema check runs.
        _ => assert_valid_json_if_nonempty(&outcome),
    }
}

crate::kh_matrix!(
    crate::reliability::machine_format::machine_format_invariant,
    json => "json",
    jsonl => "jsonl",
    sarif => "sarif",
);
