//! Regression: `keyhog scan --output <path>` — path-handling and per-format
//! contract that the sibling `regression_cli_output_file.rs` does NOT cover.
//!
//! Everything here drives the REAL shipped binary (`--no-daemon`, `--backend
//! cpu`, `KEYHOG_NO_GPU=1` so NO accelerator is assumed — host-independent) and
//! every assertion pins a CONCRETE value (exact bytes / JSON value / line count
//! / substring / bool / exit code). No bare `!is_empty` / `is_ok`.
//!
//! Distinct contracts pinned here:
//!   * a RELATIVE `--output report.json` lands in the process CWD (the
//!     parentless-path `.`-parent branch of `atomic_file`).
//!   * `--format jsonl` writes ONE JSON OBJECT PER LINE (not a JSON array); two
//!     distinct planted secrets → exactly two lines, each an object.
//!   * `--format text` written to a file carries NO ANSI colour (the file path
//!     forces `color=false`) yet still contains the detector id.
//!   * `--format github-annotations` writes an `::error ` workflow command whose
//!     title is `keyhog critical github-classic-pat`.
//!   * `--format junit` writes the XML prologue and a `<testsuite …
//!     tests="1" failures="1" errors="0">`.
//!   * `--format gitlab-sast` writes a JSON doc whose `vulnerabilities` array
//!     has exactly one element.
//!   * with `--output`, stdout stays byte-empty for a text scan (report went to
//!     the file, not the console).
//!   * a CLEAN scan atomically REPLACES a LARGER stale file with exactly `[]`.
//!   * the written path is a REGULAR FILE (persist target, not a symlink/tmp).
//!   * a SUCCESSFUL atomic write leaves NO stray `NamedTempFile` sibling in the
//!     parent directory — the only entry is the requested file.
//!   * an INVALID `--format` value is rejected by the arg parser (exit 2) and
//!     writes NO output file.
//!   * `--stream` puts the redacted `[stream]` preview on stderr while the JSON
//!     report goes to the FILE and stdout stays empty.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// A planted GitHub classic PAT (`ghp_` + 36 alnum) with a valid CRC32 tail:
/// fires exactly `github-classic-pat`. Same canonical token the sibling
/// output-file and format-parity e2e tests plant.
const PLANTED: &str = "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";

/// A SECOND, distinct valid classic PAT (all-zero body, valid CRC tail). A
/// different value → a different credential hash → a second, non-deduped
/// finding.
const PLANTED_2: &str = "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";

/// The detector id both planted secrets must carry.
const DETECTOR_ID: &str = "github-classic-pat";
/// The human `text` report names the detector by its TOML display `name`, not the
/// machine id — the JSON/SARIF formats carry the id (see the json/sarif tests).
const DETECTOR_NAME: &str = "GitHub Classic PAT";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Tempdir with a `dump.txt` holding a single bare planted PAT: one finding.
fn leak_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("dump.txt");
    std::fs::write(&path, format!("{PLANTED}\n")).expect("write leak fixture");
    (dir, path)
}

/// Tempdir with a `dump.txt` holding TWO distinct planted PATs on their own
/// lines: two distinct-value findings.
fn two_leak_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("dump.txt");
    std::fs::write(&path, format!("{PLANTED}\n{PLANTED_2}\n")).expect("write two-leak fixture");
    (dir, path)
}

/// Tempdir with a file that has no credential-shaped content at all.
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

/// Base `keyhog scan` invocation shared by every test: in-process, CPU backend,
/// no accelerator, and test fixtures NOT suppressed so the planted token
/// reports.
fn base_cmd(target: &Path, format: &str, out: Option<&Path>) -> Command {
    let mut cmd = Command::new(binary());
    cmd.args([
        "scan",
        "--no-daemon",
        "--backend",
        "cpu",
        "--no-suppress-test-fixtures",
        "--format",
        format,
    ]);
    if let Some(o) = out {
        cmd.arg("--output").arg(o);
    }
    cmd.arg(target).env("KEYHOG_NO_GPU", "1");
    cmd
}

/// Run `base_cmd` and return `(exit code, stdout, stderr)`.
fn run(target: &Path, format: &str, out: Option<&Path>) -> (Option<i32>, String, String) {
    let output = base_cmd(target, format, out)
        .output()
        .expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// Relative / parentless output path lands in the process CWD
// ---------------------------------------------------------------------------

/// A RELATIVE `--output report.json` (no directory component) writes into the
/// process's current working directory — the `.`-parent branch of
/// `atomic_file::write_with_file`.
#[test]
fn relative_output_path_lands_in_cwd() {
    let (_dir, target) = leak_fixture();
    let cwd = TempDir::new().expect("cwd tempdir");

    let output = base_cmd(&target, "json", Some(Path::new("report.json")))
        .current_dir(cwd.path())
        .output()
        .expect("spawn keyhog scan");
    assert_eq!(
        output.status.code(),
        Some(1),
        "scan with a finding exits 1; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let landed = cwd.path().join("report.json");
    let bytes =
        std::fs::read_to_string(&landed).expect("relative --output must land in the process CWD");
    let v: serde_json::Value = serde_json::from_str(&bytes).expect("cwd file must be json");
    assert_eq!(
        v.as_array()
            .and_then(|a| a.first())
            .and_then(|o| o.get("detector_id"))
            .and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "the CWD-relative file must carry the detector id"
    );
}

// ---------------------------------------------------------------------------
// jsonl: one object per line, never an array
// ---------------------------------------------------------------------------

/// `--format jsonl` writes exactly one JSON OBJECT per line. Two distinct
/// planted secrets → exactly two lines, each parsing to an object carrying the
/// detector id; the payload is NOT a top-level array.
#[test]
fn jsonl_output_file_two_objects_two_lines() {
    let (_dir, target) = two_leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.jsonl");

    let (code, _out, err) = run(&target, "jsonl", Some(&out_file));
    assert_eq!(code, Some(1), "two findings still exits 1; stderr={err}");

    let bytes = std::fs::read_to_string(&out_file).expect("jsonl file must exist");
    // Whole document is NOT a JSON array (that is the `json` format's shape).
    assert!(
        serde_json::from_str::<serde_json::Value>(bytes.trim()).is_err(),
        "jsonl must NOT be a single parseable JSON document; got:\n{bytes}"
    );
    let lines: Vec<&str> = bytes.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "two distinct secrets → two jsonl lines");
    for line in &lines {
        let v: serde_json::Value =
            serde_json::from_str(line).expect("each jsonl line must be a json object");
        assert!(v.is_object(), "each jsonl line is an object, not an array");
        assert_eq!(
            v.get("detector_id").and_then(|x| x.as_str()),
            Some(DETECTOR_ID),
            "each jsonl line carries the planted detector id"
        );
    }
}

// ---------------------------------------------------------------------------
// text to file: no ANSI colour, but the detector id is present
// ---------------------------------------------------------------------------

/// `--format text` to a FILE renders with `color=false` (the file path is never
/// a TTY): the bytes contain NO ANSI escape yet still name the detector id.
#[test]
fn text_output_file_has_no_ansi_but_names_detector() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.txt");

    let (code, _out, err) = run(&target, "text", Some(&out_file));
    assert_eq!(
        code,
        Some(1),
        "text scan with finding exits 1; stderr={err}"
    );

    let bytes = std::fs::read_to_string(&out_file).expect("text file must exist");
    assert!(
        !bytes.contains('\u{1b}'),
        "a report written to a file must carry no ANSI colour escape; got:\n{bytes}"
    );
    assert!(
        bytes.contains(DETECTOR_NAME),
        "the text report file must name the detector (display name); got:\n{bytes}"
    );
}

// ---------------------------------------------------------------------------
// github-annotations: exact workflow command shape
// ---------------------------------------------------------------------------

/// `--format github-annotations` writes a `::error ` workflow command (critical
/// → error) whose title property is `keyhog critical github-classic-pat`.
#[test]
fn github_annotations_output_file_error_command() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.gha");

    let (code, _out, err) = run(&target, "github-annotations", Some(&out_file));
    assert_eq!(code, Some(1), "annotation scan exits 1; stderr={err}");

    let bytes = std::fs::read_to_string(&out_file).expect("annotation file must exist");
    let first = bytes
        .lines()
        .find(|l| !l.trim().is_empty())
        .expect("annotation file must have a command line");
    assert!(
        first.starts_with("::error "),
        "critical finding → `::error ` workflow command; got: {first:?}"
    );
    assert!(
        first.contains("title=keyhog critical github-classic-pat"),
        "the annotation title must name severity+detector; got: {first:?}"
    );
}

// ---------------------------------------------------------------------------
// junit: XML prologue + testsuite counts
// ---------------------------------------------------------------------------

/// `--format junit` writes the XML declaration and a `<testsuite>` element whose
/// tests/failures counts are both 1 and errors is 0 for one reported finding.
#[test]
fn junit_output_file_prologue_and_counts() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.xml");

    let (code, _out, err) = run(&target, "junit", Some(&out_file));
    assert_eq!(code, Some(1), "junit scan exits 1; stderr={err}");

    let bytes = std::fs::read_to_string(&out_file).expect("junit file must exist");
    assert!(
        bytes.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
        "junit file must open with the XML declaration; got:\n{bytes}"
    );
    assert!(
        bytes.contains(
            "<testsuite name=\"keyhog\" tests=\"1\" failures=\"1\" errors=\"0\" time=\"0.0\">"
        ),
        "junit file must carry the 1-test / 1-failure suite header; got:\n{bytes}"
    );
}

// ---------------------------------------------------------------------------
// gitlab-sast: vulnerabilities array of exactly one
// ---------------------------------------------------------------------------

/// `--format gitlab-sast` writes a JSON doc whose `vulnerabilities` array has
/// exactly one element for one reported finding.
#[test]
fn gitlab_sast_output_file_single_vulnerability() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("gl-sast.json");

    let (code, _out, err) = run(&target, "gitlab-sast", Some(&out_file));
    assert_eq!(code, Some(1), "gitlab-sast scan exits 1; stderr={err}");

    let bytes = std::fs::read_to_string(&out_file).expect("gitlab-sast file must exist");
    let v: serde_json::Value =
        serde_json::from_str(&bytes).expect("gitlab-sast file must parse as json");
    assert_eq!(
        v.get("vulnerabilities")
            .and_then(|x| x.as_array())
            .map(Vec::len),
        Some(1),
        "one finding → one gitlab-sast vulnerability; doc was:\n{bytes}"
    );
}

// ---------------------------------------------------------------------------
// stdout stays empty when the report is redirected to a file (text format)
// ---------------------------------------------------------------------------

/// With `--output`, a `text` scan writes the human report to the FILE and
/// leaves stdout byte-empty (the console must not double-print the report).
#[test]
fn text_output_leaves_stdout_empty() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.txt");

    let (code, stdout, err) = run(&target, "text", Some(&out_file));
    assert_eq!(code, Some(1), "text scan exits 1; stderr={err}");
    assert!(
        stdout.trim().is_empty(),
        "with --output the text report must not also print to stdout; stdout was:\n{stdout}"
    );
    // The file, meanwhile, carries the detector (display name in text format).
    let bytes = std::fs::read_to_string(&out_file).expect("text file must exist");
    assert!(
        bytes.contains(DETECTOR_NAME),
        "the report must be in the file; file was:\n{bytes}"
    );
}

// ---------------------------------------------------------------------------
// clean scan atomically REPLACES a LARGER stale file with `[]`
// ---------------------------------------------------------------------------

/// A CLEAN scan atomically replaces a LARGER pre-existing file with exactly the
/// empty-array bytes `[]` — no trailing remnants of the longer stale content.
#[test]
fn clean_scan_replaces_larger_stale_file_with_empty_array() {
    let (_dir, target) = clean_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.json");
    // Stale content much longer than the `[]` a clean scan writes, to catch a
    // truncate-vs-replace bug (leftover tail bytes).
    let stale = "X".repeat(4096);
    std::fs::write(&out_file, &stale).expect("seed large stale file");

    let (code, _out, err) = run(&target, "json", Some(&out_file));
    assert_eq!(code, Some(0), "clean scan exits 0; stderr={err}");

    let bytes = std::fs::read_to_string(&out_file).expect("clean run must still write the file");
    assert_eq!(
        bytes.trim_end(),
        "[]",
        "a clean scan must replace the whole stale file with `[]`; got: {bytes:?}"
    );
    assert!(
        !bytes.contains('X'),
        "no byte of the larger stale content may survive the atomic replace"
    );
}

// ---------------------------------------------------------------------------
// the written path is a regular file, and no temp sibling is left behind
// ---------------------------------------------------------------------------

/// The `--output` target is written as a REGULAR file (the atomic persist
/// target), not a symlink or FIFO.
#[test]
fn output_target_is_regular_file() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.json");

    let (code, _out, err) = run(&target, "json", Some(&out_file));
    assert_eq!(code, Some(1), "scan exits 1; stderr={err}");

    let meta = std::fs::symlink_metadata(&out_file).expect("output file must exist");
    assert!(
        meta.file_type().is_file(),
        "the --output target must be a plain regular file, got: {:?}",
        meta.file_type()
    );
}

/// A SUCCESSFUL atomic write leaves NO stray `NamedTempFile` sibling: the parent
/// directory holds exactly the one requested output file after the scan.
#[test]
fn successful_write_leaves_no_temp_sibling() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.json");

    let (code, _out, err) = run(&target, "json", Some(&out_file));
    assert_eq!(code, Some(1), "scan exits 1; stderr={err}");

    let entries: Vec<String> = std::fs::read_dir(out_dir.path())
        .expect("read out dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        entries,
        vec!["report.json".to_string()],
        "only the requested output file may remain; the atomic temp must be gone. Found: {entries:?}"
    );
}

// ---------------------------------------------------------------------------
// invalid --format is rejected before any file is written
// ---------------------------------------------------------------------------

/// An INVALID `--format` value is rejected by the argument parser (exit 2) and
/// NO output file is created — the parse error precedes any scan or write.
#[test]
fn invalid_format_value_writes_no_output_file() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("never.json");

    let (code, _out, stderr) = run(&target, "bogus-format", Some(&out_file));
    assert_eq!(
        code,
        Some(2),
        "an unknown --format is a clap usage error → exit 2; stderr={stderr}"
    );
    assert!(
        !out_file.exists(),
        "a rejected --format must not create the output file"
    );
}

// ---------------------------------------------------------------------------
// --stream preview on stderr, report in the file, stdout empty
// ---------------------------------------------------------------------------

/// `--stream` emits the redacted `[stream]` preview on STDERR while the JSON
/// report is written to the FILE and stdout stays empty. The three streams
/// carry three distinct things at once.
#[test]
fn stream_preview_on_stderr_report_in_file_stdout_empty() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.json");

    let mut cmd = base_cmd(&target, "json", Some(&out_file));
    cmd.arg("--stream");
    let output = cmd.output().expect("spawn keyhog scan --stream");
    let code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert_eq!(
        code,
        Some(1),
        "stream scan with finding exits 1; stderr={stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "with --output the JSON report must not print to stdout; stdout was:\n{stdout}"
    );
    assert!(
        stderr.contains("[stream]"),
        "the redacted preview must carry the `[stream]` tag on stderr; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains(DETECTOR_ID),
        "the `[stream]` preview must name the reported detector; stderr was:\n{stderr}"
    );
    // The file carries the actual JSON report, one element.
    let bytes = std::fs::read_to_string(&out_file).expect("report file must exist");
    let v: serde_json::Value = serde_json::from_str(&bytes).expect("file must be json");
    assert_eq!(
        v.as_array().map(Vec::len),
        Some(1),
        "the file must hold the one-element JSON report; file was:\n{bytes}"
    );
}
