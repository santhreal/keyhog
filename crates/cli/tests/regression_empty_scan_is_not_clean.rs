//! Regression: a scan that read ZERO bytes must not read as a clean bill of
//! health.
//!
//! Before this lane, a `.keyhogignore` containing `path:**` produced exit 0,
//! `scan_status` "success", `source_bytes_scanned` 0, `source_chunks_scanned`
//! 0, an EMPTY `coverage_gap_summary`, and the stdout line "No secrets detected
//! in the scanned files." Every signal a consumer has said the tree was clean,
//! and the scan had examined nothing at all. `--exclude-paths '**'` and an
//! empty directory produced the same shape.
//!
//! `scan_status` alone cannot carry this: an ordinary git working-tree scan is
//! already "partial" from its default-exclusion rows, so consumers cannot
//! reject on "partial". The usable distinction is the FAIL/WARN class of the
//! coverage gaps, which is what exit 13 already encodes: WARN-only gaps
//! (exclusion policy, binary, oversize) keep exit 0, so "looked and found
//! nothing" stays exit 0, while "did not look" is exit 13 with a row naming
//! the reason.

use std::{path::Path, path::PathBuf, process::Command, process::Stdio};

/// `EXIT_SOURCE_FAILED`: the scan did not cover the requested input.
const EXIT_INCOMPLETE: i32 = 13;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// The target goes BEFORE the extra flags: `--exclude-paths` takes `num_args =
/// 1..`, so a trailing positional would be swallowed as another exclude
/// pattern and the scan would have no target at all.
fn scan(args: &[&str], target: &Path) -> Run {
    let output = Command::new(binary())
        .args(["scan", "--backend", "cpu", "--daemon=off", "--no-config"])
        .arg(target)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn keyhog");
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).expect("json-envelope stdout must be JSON")
}

fn gap_reasons(envelope: &serde_json::Value) -> Vec<String> {
    envelope["coverage_gap_summary"]
        .as_array()
        .expect("coverage_gap_summary must be an array")
        .iter()
        .filter_map(|row| row["reason"].as_str().map(str::to_owned))
        .collect()
}

/// A tree with real content, entirely removed by a `.keyhogignore`. Zero bytes
/// reach the scanner, so the result carries no information about the tree.
#[test]
fn keyhogignore_that_matches_everything_does_not_report_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("creds.env"), "AWS=AKIAJP3GG7XYRIBQXOLA\n")
        .expect("write creds");
    std::fs::write(dir.path().join(".keyhogignore"), "path:**\n").expect("write ignore file");

    let run = scan(&["--format", "json-envelope"], dir.path());
    let envelope = envelope(&run.stdout);

    assert_eq!(
        envelope["metadata"]["source_bytes_scanned"].as_u64(),
        Some(0),
        "the fixture must actually scan nothing, or this test proves nothing"
    );
    assert_eq!(
        run.code,
        Some(EXIT_INCOMPLETE),
        "scanning nothing is not success; stdout={} stderr={}",
        run.stdout,
        run.stderr
    );
    assert_ne!(
        envelope["scan_status"].as_str(),
        Some("success"),
        "a scan that examined nothing must not report success"
    );

    let reasons = gap_reasons(&envelope);
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("scan covered nothing")),
        "an empty scan must carry a gap row explaining why; reasons={reasons:?}"
    );
    assert!(
        !run.stdout.contains("No secrets detected"),
        "the clean-bill line must not appear for a scan that read no bytes"
    );
}

/// `--exclude-paths '**'` is the same defect through the flag instead of the
/// ignore file.
#[test]
fn exclude_paths_that_match_everything_does_not_report_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("creds.env"), "AWS=AKIAJP3GG7XYRIBQXOLA\n")
        .expect("write creds");

    let run = scan(
        &["--format", "json-envelope", "--exclude-paths", "**"],
        dir.path(),
    );
    let envelope = envelope(&run.stdout);

    assert_eq!(
        envelope["metadata"]["source_bytes_scanned"].as_u64(),
        Some(0),
        "the fixture must actually scan nothing, or this test proves nothing"
    );
    assert_eq!(
        run.code,
        Some(EXIT_INCOMPLETE),
        "an all-excluding --exclude-paths is not a clean scan; stderr={}",
        run.stderr
    );
    assert!(
        gap_reasons(&envelope)
            .iter()
            .any(|reason| reason.contains("scan covered nothing")),
        "stdout={}",
        run.stdout
    );
}

/// An empty directory reads nothing for a different reason, and gets a
/// different row. The remedies differ, so the rows differ.
#[test]
fn empty_directory_reports_the_no_input_row_not_the_all_skipped_row() {
    let dir = tempfile::tempdir().expect("tempdir");

    let run = scan(&["--format", "json-envelope"], dir.path());
    let reasons = gap_reasons(&envelope(&run.stdout));

    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("no skip was counted")),
        "an empty tree must say nothing was there, not that policy hid it; reasons={reasons:?}"
    );
    assert!(
        !reasons
            .iter()
            .any(|reason| reason.contains("every candidate was skipped")),
        "the two nothing-scanned causes must never both fire; reasons={reasons:?}"
    );
    assert_eq!(run.code, Some(EXIT_INCOMPLETE), "stderr={}", run.stderr);
}

/// A directory whose only entry is a symlink. Symlinks are deliberately never
/// followed, and before this lane that refusal was completely silent: the
/// planted credential behind the link produced exit 0 and "success".
#[cfg(unix)]
#[test]
fn directory_of_only_symlinks_does_not_report_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = dir.path().join("outside.env");
    std::fs::write(&outside, "AWS=AKIAJP3GG7XYRIBQXOLA\n").expect("write link target");
    let root = dir.path().join("root");
    std::fs::create_dir(&root).expect("create scan root");
    std::os::unix::fs::symlink(&outside, root.join(".env.config")).expect("create symlink");

    let run = scan(&["--format", "json-envelope"], &root);
    let envelope = envelope(&run.stdout);

    assert_eq!(
        envelope["metadata"]["source_bytes_scanned"].as_u64(),
        Some(0),
        "symlinks are not followed, so this root reads nothing"
    );
    assert_eq!(
        run.code,
        Some(EXIT_INCOMPLETE),
        "a root whose only entry is an unfollowed symlink is not a clean scan; stderr={}",
        run.stderr
    );
    assert!(
        gap_reasons(&envelope)
            .iter()
            .any(|reason| reason.contains("scan covered nothing")),
        "stdout={}",
        run.stdout
    );
}

/// The load-bearing negative. An ordinary scan that reads bytes and finds
/// nothing must stay exit 0 with no "covered nothing" row, even though its
/// default-exclusion rows already make `scan_status` "partial". Without this,
/// the fix above would just be a new false alarm.
#[test]
fn ordinary_clean_scan_still_exits_zero_and_reports_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("main.rs"),
        "fn main() { println!(\"hello\"); }\n",
    )
    .expect("write source file");
    // A default-excluded directory alongside real content: the scan reads
    // bytes AND records exclusion skips, which must remain WARN class.
    let excluded = dir.path().join("node_modules");
    std::fs::create_dir(&excluded).expect("create node_modules");
    std::fs::write(excluded.join("index.js"), "module.exports = 1;\n").expect("write vendored js");

    let run = scan(&["--format", "json-envelope"], dir.path());
    let envelope = envelope(&run.stdout);

    assert!(
        envelope["metadata"]["source_bytes_scanned"]
            .as_u64()
            .expect("source_bytes_scanned must be present")
            > 0,
        "the fixture must actually scan something"
    );
    assert_eq!(
        run.code,
        Some(0),
        "looked and found nothing stays exit 0; stdout={} stderr={}",
        run.stdout,
        run.stderr
    );
    let reasons = gap_reasons(&envelope);
    assert!(
        !reasons
            .iter()
            .any(|reason| reason.contains("scan covered nothing")),
        "a scan that read bytes must not claim it covered nothing; reasons={reasons:?}"
    );
}

/// The text surface must not print the clean-bill line either. `--format json`
/// consumers get the gap rows; a human running the default format got the
/// friendliest possible lie.
#[test]
fn empty_scan_text_output_says_it_covered_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("creds.env"), "AWS=AKIAJP3GG7XYRIBQXOLA\n")
        .expect("write creds");
    std::fs::write(dir.path().join(".keyhogignore"), "path:**\n").expect("write ignore file");

    let run = scan(&[], dir.path());

    assert!(
        !run.stdout
            .contains("No secrets detected in the scanned files."),
        "a scan with no scanned files must not print the clean-scan line; stdout={}",
        run.stdout
    );
    assert!(
        run.stdout.contains("This scan covered nothing"),
        "the text report must state that nothing was covered; stdout={}",
        run.stdout
    );
}
