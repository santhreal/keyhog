//! Regression: `keyhog scan --output <file>` writes the findings report to the
//! named file, exactly the bytes that would otherwise go to stdout. WITHOUT
//! changing the process exit code, and reports a bad output path as a clean,
//! actionable error (never a silent no-op, never a stray partial file).
//!
//! Contract pinned here, all via the REAL shipped binary (`--daemon=off`,
//! `--backend cpu`, `KEYHOG_NO_GPU=1` for host-independence, no accelerator is
//! assumed):
//!   * `--output f` writes the report to `f`; `f`'s bytes parse to the SAME JSON
//!     value that the same scan prints to stdout with no `--output`.
//!   * the file carries the exact planted detector id `github-classic-pat`.
//!   * with `--output`, the JSON report does NOT also appear on stdout (it is
//!     redirected to the file, not duplicated).
//!   * exit code is UNCHANGED by `--output`: 1 with a finding, 0 when clean.
//!   * a clean scan still WRITES the file, and its bytes are exactly `[]`.
//!   * `--output` atomically REPLACES an existing file (old bytes gone).
//!   * a missing parent directory in the output path is CREATED.
//!   * `-o` (short) is equivalent to `--output` (long).
//!   * csv / sarif reports round-trip to the file with their exact structure.
//!   * a bad output path (an intermediate component that is a regular file, so
//!     the parent directory cannot be created) fails with the actionable
//!     "atomically writing report" context, the report-write error exit code
//!     `2` (EXIT_USER_ERROR, same code the `-o /dev/null` regression pins for a
//!     report-write failure), and writes NO output file.
//!
//! Every assertion pins a concrete value (exact bytes / JSON value / detector id
//! / bool / count / exit code). None is a bare `!is_empty` / `is_ok`.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// A planted GitHub classic PAT (`ghp_` + 36 alnum) with a valid CRC32 tail
/// the canonical token from the format/backend parity e2e. Fires exactly one
/// detector, `github-classic-pat` (severity critical, service github).
const PLANTED: &str = "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";

/// The detector id the planted secret must carry in every rendered report.
const DETECTOR_ID: &str = "github-classic-pat";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A tempdir holding a `dump.txt` with a single bare planted PAT on its own
/// line: fires `github-classic-pat` and carries no key=value keyword context, so
/// exactly one finding is produced.
fn leak_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("dump.txt");
    std::fs::write(&path, format!("{PLANTED}\n")).expect("write leak fixture");
    (dir, path)
}

/// A tempdir holding a file with no credential-shaped content at all.
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

/// Run `keyhog scan --daemon=off --backend cpu --format <format> [--output out]
/// <target>`. When `out` is `Some`, `--output` is passed. Returns (exit code,
/// stdout, stderr).
fn run(target: &PathBuf, format: &str, out: Option<&PathBuf>) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args([
        "scan",
        "--daemon=off",
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
    let output = cmd.output().expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// Content parity: file bytes == what stdout would have carried
// ---------------------------------------------------------------------------

/// The JSON report written to `--output` parses to the SAME serde_json Value as
/// the identical scan printed to stdout, the file path must not alter report
/// content in any way.
#[test]
fn json_output_file_value_equals_stdout_value() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.json");

    // Same scan, once to stdout, once to the file.
    let (_c_std, stdout, _e_std) = run(&target, "json", None);
    let (_c_file, file_stdout, _e_file) = run(&target, "json", Some(&out_file));

    let stdout_val: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout json must parse");
    let file_bytes = std::fs::read_to_string(&out_file).expect("output file must exist");
    let file_val: serde_json::Value =
        serde_json::from_str(&file_bytes).expect("output-file json must parse");

    assert_eq!(
        file_val, stdout_val,
        "the --output file report must be byte-for-byte the same JSON the scan \
         prints to stdout; stdout-json path stdout was:\n{file_stdout}"
    );
}

/// The written JSON file is a one-element array whose sole element carries the
/// exact planted detector id.
#[test]
fn json_output_file_has_exact_detector_id() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.json");

    let (code, _out, err) = run(&target, "json", Some(&out_file));
    assert_eq!(code, Some(1), "scan with a finding exits 1; stderr={err}");

    let bytes = std::fs::read_to_string(&out_file).expect("output file must exist");
    let v: serde_json::Value = serde_json::from_str(&bytes).expect("file json must parse");
    let arr = v.as_array().expect("report must be a top-level array");
    assert_eq!(arr.len(), 1, "exactly one planted secret -> one element");
    assert_eq!(
        arr[0].get("detector_id").and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "file[0].detector_id must be the planted detector id"
    );
}

/// With `--output`, the JSON report is redirected to the file and does NOT also
/// appear on stdout (no duplication). stdout must not contain the detector id or
/// a JSON array open.
#[test]
fn output_flag_redirects_report_off_stdout() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.json");

    let (_code, stdout, _err) = run(&target, "json", Some(&out_file));
    assert!(
        !stdout.contains(DETECTOR_ID),
        "the detector id must go to the file, not stdout; stdout was:\n{stdout}"
    );
    // The stdout stream must not carry the JSON report array either. A non-JSON
    // stdout is the desired outcome (parse error => not a findings array); only a
    // single-element findings array is the duplication we catch.
    assert!(
        !serde_json::from_str::<serde_json::Value>(stdout.trim())
            .is_ok_and(|value| value.as_array().is_some_and(|array| array.len() == 1)),
        "the JSON findings array must not be duplicated on stdout; stdout was:\n{stdout}"
    );
    // The file, meanwhile, DOES carry it.
    let bytes = std::fs::read_to_string(&out_file).expect("output file must exist");
    assert!(
        bytes.contains(DETECTOR_ID),
        "the file must carry the detector id; file was:\n{bytes}"
    );
}

// ---------------------------------------------------------------------------
// Exit code is unchanged by --output
// ---------------------------------------------------------------------------

/// `--output` does not change the findings exit code: a planted secret still
/// exits 1 whether the report went to stdout or a file.
#[test]
fn output_flag_exit_code_unchanged_with_finding() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.json");

    let (code_std, _o1, _e1) = run(&target, "json", None);
    let (code_file, _o2, _e2) = run(&target, "json", Some(&out_file));
    assert_eq!(code_std, Some(1), "stdout scan with finding exits 1");
    assert_eq!(
        code_file, code_std,
        "--output must not change the exit code for a scan with a finding"
    );
}

/// A clean scan with `--output` exits 0 (same as stdout) AND still writes the
/// file, whose content is exactly the empty-array bytes `[]`.
#[test]
fn clean_scan_output_file_is_exact_bracket_pair_exit_zero() {
    let (_dir, target) = clean_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("clean.json");

    let (code, _out, err) = run(&target, "json", Some(&out_file));
    assert_eq!(code, Some(0), "clean scan must exit 0; stderr={err}");

    let bytes = std::fs::read_to_string(&out_file).expect("clean run must still write the file");
    assert_eq!(
        bytes.trim_end(),
        "[]",
        "an empty json run written to file must be exactly the bracket pair, got: {bytes:?}"
    );
}

// ---------------------------------------------------------------------------
// Atomic replace + parent creation + short flag
// ---------------------------------------------------------------------------

/// `--output` atomically REPLACES an existing file: pre-existing junk bytes are
/// gone, replaced by exactly the new report (a one-element array).
#[test]
fn output_atomically_replaces_existing_file() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("stale.json");
    std::fs::write(&out_file, "STALE-PRIOR-CONTENTS-THAT-MUST-VANISH").expect("seed stale file");

    let (code, _out, err) = run(&target, "json", Some(&out_file));
    assert_eq!(code, Some(1), "scan exits 1; stderr={err}");

    let bytes = std::fs::read_to_string(&out_file).expect("output file must exist");
    assert!(
        !bytes.contains("STALE-PRIOR-CONTENTS"),
        "the prior file contents must be fully replaced, got:\n{bytes}"
    );
    let v: serde_json::Value = serde_json::from_str(&bytes).expect("replaced file must be json");
    assert_eq!(
        v.as_array().map(|a| a.len()),
        Some(1),
        "the replaced file must be the fresh one-element report"
    );
}

/// A missing parent directory in the output path is created (`create_dir_all`),
/// and the report lands at the full nested path.
#[test]
fn output_creates_missing_parent_directories() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    // Neither `nested` nor `deep` exist yet.
    let out_file = out_dir
        .path()
        .join("nested")
        .join("deep")
        .join("report.json");
    assert!(
        !out_file.parent().unwrap().exists(),
        "precondition: the nested parent must not exist yet"
    );

    let (code, _out, err) = run(&target, "json", Some(&out_file));
    assert_eq!(code, Some(1), "scan exits 1; stderr={err}");

    let bytes = std::fs::read_to_string(&out_file)
        .expect("report must be written into the freshly-created nested directory");
    let v: serde_json::Value = serde_json::from_str(&bytes).expect("nested file must be json");
    assert_eq!(
        v.as_array()
            .and_then(|a| a.first())
            .and_then(|o| o.get("detector_id"))
            .and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "the nested-path file must carry the detector id"
    );
}

/// The short `-o` flag is equivalent to `--output`: same file content.
#[test]
fn short_o_flag_equivalent_to_long_output() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let long_file = out_dir.path().join("long.json");
    let short_file = out_dir.path().join("short.json");

    let (code_long, _lo, _le) = run(&target, "json", Some(&long_file));

    // Same scan via the short flag.
    let (code_short, _so, _se) = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--no-suppress-test-fixtures",
            "--format",
            "json",
            "-o",
        ])
        .arg(&short_file)
        .arg(&target)
        .env("KEYHOG_NO_GPU", "1")
        .output()
        .map(|o| {
            (
                o.status.code(),
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            )
        })
        .expect("spawn short-flag scan");

    assert_eq!(code_long, Some(1), "long-flag scan exits 1");
    assert_eq!(code_short, Some(1), "short-flag scan exits 1");

    let long_bytes = std::fs::read_to_string(&long_file).expect("long file exists");
    let short_bytes = std::fs::read_to_string(&short_file).expect("short file exists");
    let long_val: serde_json::Value = serde_json::from_str(&long_bytes).expect("long json");
    let short_val: serde_json::Value = serde_json::from_str(&short_bytes).expect("short json");
    assert_eq!(
        short_val, long_val,
        "`-o` and `--output` must produce identical report content"
    );
}

// ---------------------------------------------------------------------------
// Other formats round-trip to the file with their exact structure
// ---------------------------------------------------------------------------

/// CSV `--output`: the file's first line is the exact 15-field header and there
/// is exactly one data row whose first cell is the detector id.
#[test]
fn csv_output_file_header_and_single_row() {
    const CSV_HEADER: &str = "detector_id,detector_name,service,severity,credential_redacted,credential_hash,source,file_path,line,offset,commit,author,date,verification,confidence";
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.csv");

    let (code, _out, err) = run(&target, "csv", Some(&out_file));
    assert_eq!(code, Some(1), "csv scan with finding exits 1; stderr={err}");

    let bytes = std::fs::read_to_string(&out_file).expect("csv file must exist");
    let lines: Vec<&str> = bytes.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines[0].trim_end(),
        CSV_HEADER,
        "csv file's first line must be the exact documented header"
    );
    let data: Vec<&str> = lines.iter().skip(1).copied().collect();
    assert_eq!(data.len(), 1, "one planted secret -> one csv data row");
    assert_eq!(
        data[0].split(',').next(),
        Some(DETECTOR_ID),
        "the csv data row's first cell must be the detector id"
    );
}

/// SARIF `--output`: the file is valid JSON whose single result's `ruleId` is
/// the detector id and whose `level` is `error` (critical).
#[test]
fn sarif_output_file_ruleid_and_level() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.sarif");

    let (code, _out, err) = run(&target, "sarif", Some(&out_file));
    assert_eq!(
        code,
        Some(1),
        "sarif scan with finding exits 1; stderr={err}"
    );

    let bytes = std::fs::read_to_string(&out_file).expect("sarif file must exist");
    let v: serde_json::Value = serde_json::from_str(&bytes).expect("sarif file must parse as json");
    assert_eq!(
        v.pointer("/runs/0/results/0/ruleId")
            .and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "sarif file results[0].ruleId must be the detector id"
    );
    assert_eq!(
        v.pointer("/runs/0/results/0/level")
            .and_then(|x| x.as_str()),
        Some("error"),
        "critical severity -> SARIF level `error`"
    );
}

// ---------------------------------------------------------------------------
// Bad output path fails closed, actionably, with no stray file
// ---------------------------------------------------------------------------

/// A bad output path, an intermediate path component that is a regular FILE, so
/// the parent directory cannot be created, fails with the actionable
/// "atomically writing report" context and the report-write error exit code 2
/// (EXIT_USER_ERROR), and writes NO output file at the requested path.
#[test]
fn bad_output_path_intermediate_is_file_exits_user_error_no_file() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    // `blocker` is a regular file; using it as a directory component means the
    // parent of `out.json` cannot be created.
    let blocker = out_dir.path().join("blocker");
    std::fs::write(&blocker, b"i am a regular file, not a directory").expect("seed blocker file");
    let out_file = blocker.join("out.json");

    let (code, stdout, stderr) = run(&target, "json", Some(&out_file));

    assert_eq!(
        code,
        Some(2),
        "a report-write failure must exit 2 (EXIT_USER_ERROR); stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("atomically writing report"),
        "the error must name the failing operation and path; stderr was:\n{stderr}"
    );
    assert!(
        !out_file.exists(),
        "no output file may be left at the un-writable target path"
    );
    // `blocker` must remain the untouched regular file it started as.
    let blocker_bytes = std::fs::read(&blocker).expect("blocker still readable");
    assert_eq!(
        blocker_bytes, b"i am a regular file, not a directory",
        "the blocking file must be left byte-for-byte untouched"
    );
}

/// The bad-path failure is loud on stderr and produces NO JSON report on stdout
/// (fail-closed: the operator gets the error, not a silently-swallowed empty
/// report).
#[test]
fn bad_output_path_does_not_emit_report_to_stdout() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let blocker = out_dir.path().join("blocker");
    std::fs::write(&blocker, b"file").expect("seed blocker");
    let out_file = blocker.join("out.json");

    let (_code, stdout, _stderr) = run(&target, "json", Some(&out_file));
    assert!(
        !stdout.contains(DETECTOR_ID),
        "a failed --output write must not leak the report to stdout; stdout:\n{stdout}"
    );
    assert!(
        stdout.trim().is_empty()
            || serde_json::from_str::<serde_json::Value>(stdout.trim()).is_err(),
        "stdout must not carry a valid findings report when the output write failed; \
         stdout:\n{stdout}"
    );
}
