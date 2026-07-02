//! Regression: `keyhog scan --exclude-paths <glob>...` filters the walked
//! filesystem tree by gitignore-style glob patterns, through the REAL shipped
//! binary (`--no-daemon`, `--backend cpu`).
//!
//! The CLI exposes exactly ONE user-facing scan-glob filter: `--exclude-paths`
//! (see `crates/cli/src/args/scan.rs` — there is deliberately NO `--include`
//! glob flag; the `include_paths` machinery is git-staged-only). These tests
//! pin that real surface end to end:
//!   * `--exclude-paths '*.txt'` scans only `a.rs` (exact one-finding set).
//!   * `--exclude-paths '*.rs'`  scans only `b.txt`.
//!   * both patterns together prune everything -> `[]` + exit 0.
//!   * a bare basename glob (`*.rs`) matches at ANY depth (gitignore semantics).
//!   * a directory name (`sub`) prunes the whole subtree.
//!   * a non-matching glob (`*.md`) keeps every finding (negative twin).
//!   * exact filename (`b.txt`) drops just that file.
//!   * the nonexistent `--include` flag is a clap usage error (exit 2).
//!
//! Two DISTINCT valid GitHub classic PATs are planted (identical values would
//! be deduped into one finding with an extra `additional_locations` entry —
//! test #11 pins exactly that), so which file survived a filter is provable by
//! the surviving finding's file path AND its `credential_hash`.
//!
//! HOST-INDEPENDENT: `--backend cpu` forces the scalar path; the planted
//! detector (`github-classic-pat`) is an AC-literal (`ghp_`) detector that
//! fires on the CPU/scalar path, so no accelerator is assumed. Every assertion
//! pins a concrete value (exact count / basename / hash / exit code / bytes /
//! error substring); none is a bare `!is_empty`/`is_ok`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// Valid GitHub classic PAT planted in `a.rs` (`ghp_` + 36 alnum, valid
/// checksum tail). Fires `github-classic-pat` on its own bytes.
const TOKEN_A: &str = "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";
/// SHA-256 the reporter emits for `TOKEN_A` (`credential_hash`).
const HASH_A: &str = "7b85310a29300230c865bc48ca1836f15b81bd50ac85e8c0785e8145e98ff175";
/// Redacted form the reporter prints for `TOKEN_A`.
const REDACTED_A: &str = "ghp_...DSiF";

/// A DIFFERENT valid GitHub classic PAT planted in `b.txt`.
const TOKEN_B: &str = "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";
/// SHA-256 for `TOKEN_B`.
const HASH_B: &str = "b1b3c6272a683aa8a4ca50250745b4c8b9d9c88570e8acb73eae2f9de9ec65e3";
/// Redacted form for `TOKEN_B`.
const REDACTED_B: &str = "ghp_...8GjS";

/// A third distinct valid PAT planted in `sub/c.rs` for subtree/depth tests.
const TOKEN_C: &str = "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";
/// SHA-256 for `TOKEN_C`.
const HASH_C: &str = "97dc6af90caace47c39142ab4d92f1e58eaebd858842ea9a2f0ee6e7542bce7f";

/// The detector every planted token fires.
const DETECTOR_ID: &str = "github-classic-pat";
/// The severity band the reporter assigns it.
const SEVERITY: &str = "critical";

const EXIT_SUCCESS: i32 = 0;
const EXIT_FINDINGS: i32 = 1;
const EXIT_USER_ERROR: i32 = 2;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Plant `a.rs` (TOKEN_A) and `b.txt` (TOKEN_B) at the tree root.
fn plant_flat() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("a.rs"), format!("{TOKEN_A}\n")).expect("write a.rs");
    std::fs::write(dir.path().join("b.txt"), format!("{TOKEN_B}\n")).expect("write b.txt");
    dir
}

/// Plant `a.rs`, `b.txt`, and a nested `sub/c.rs` (TOKEN_C).
fn plant_with_subdir() -> TempDir {
    let dir = plant_flat();
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).expect("mkdir sub");
    std::fs::write(sub.join("c.rs"), format!("{TOKEN_C}\n")).expect("write sub/c.rs");
    dir
}

/// One decoded finding, reduced to the fields these tests assert on.
struct Finding {
    /// File basename (last `/`-segment of `location.file_path`).
    basename: String,
    hash: String,
    detector_id: String,
    severity: String,
    line: i64,
    offset: i64,
    additional_locations: usize,
}

/// Run `keyhog scan` on `root` with the given extra args in JSON mode, on the
/// CPU backend, with the daemon disabled and test-fixture suppression off.
///
/// Returns `(exit_code, findings, stdout_bytes, stderr)`. The `--exclude-paths`
/// flag is variadic (`num_args = 1..`) and would swallow a trailing positional
/// scan path, so the root is always passed via `--path` and the caller's extra
/// args (which may end in `--exclude-paths ...`) come last.
fn run_json(root: &Path, extra: &[&str]) -> (i32, Vec<Finding>, Vec<u8>, String) {
    let root_str = root.to_str().expect("utf8 tempdir path").to_owned();
    let mut args: Vec<String> = vec![
        "scan".into(),
        "--no-daemon".into(),
        "--backend".into(),
        "cpu".into(),
        "--no-suppress-test-fixtures".into(),
        "--format".into(),
        "json".into(),
        "--path".into(),
        root_str,
    ];
    for a in extra {
        args.push((*a).to_owned());
    }
    let output = Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn keyhog");
    let code = output.status.code().expect("exit code");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    // A clap usage failure (exit 2) prints no JSON; callers that expect that
    // path assert on the exit code + stderr, so decode leniently to `[]`.
    let findings = if code == EXIT_SUCCESS || code == EXIT_FINDINGS {
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout is a JSON array");
        let array = value.as_array().expect("top-level JSON array").clone();
        array
            .into_iter()
            .map(|f| {
                let file_path = f["location"]["file_path"]
                    .as_str()
                    .expect("location.file_path string");
                let basename = file_path
                    .rsplit('/')
                    .next()
                    .expect("non-empty path")
                    .to_owned();
                Finding {
                    basename,
                    hash: f["credential_hash"]
                        .as_str()
                        .expect("credential_hash string")
                        .to_owned(),
                    detector_id: f["detector_id"]
                        .as_str()
                        .expect("detector_id string")
                        .to_owned(),
                    severity: f["severity"].as_str().expect("severity string").to_owned(),
                    line: f["location"]["line"].as_i64().expect("line int"),
                    offset: f["location"]["offset"].as_i64().expect("offset int"),
                    additional_locations: f["additional_locations"]
                        .as_array()
                        .expect("additional_locations array")
                        .len(),
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    (code, findings, output.stdout, stderr)
}

/// The set of basenames present in a finding list.
fn basenames(findings: &[Finding]) -> BTreeSet<String> {
    findings.iter().map(|f| f.basename.clone()).collect()
}

/// Look up the single finding for a basename (panics if 0 or >1 match).
fn finding_for<'a>(findings: &'a [Finding], basename: &str) -> &'a Finding {
    let matches: Vec<&Finding> = findings.iter().filter(|f| f.basename == basename).collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one finding for {basename}, got {}",
        matches.len()
    );
    matches[0]
}

// ---------------------------------------------------------------------------

/// Baseline: with no filter, BOTH planted files are scanned. Exact set of two
/// findings, each mapped to its own file by hash, exit 1 (findings present).
#[test]
fn default_scan_finds_both_files() {
    let dir = plant_flat();
    let (code, findings, _stdout, stderr) = run_json(dir.path(), &[]);
    assert_eq!(
        code, EXIT_FINDINGS,
        "findings present -> exit 1; stderr:\n{stderr}"
    );
    assert_eq!(findings.len(), 2, "one finding per planted file");
    assert_eq!(
        basenames(&findings),
        BTreeSet::from(["a.rs".to_owned(), "b.txt".to_owned()]),
        "both files present"
    );
    assert_eq!(
        finding_for(&findings, "a.rs").hash,
        HASH_A,
        "a.rs carries TOKEN_A"
    );
    assert_eq!(
        finding_for(&findings, "b.txt").hash,
        HASH_B,
        "b.txt carries TOKEN_B"
    );
}

/// `--exclude-paths '*.txt'` prunes b.txt: the surviving finding set is EXACTLY
/// {a.rs} with TOKEN_A's hash. Still exit 1 (a finding remains).
#[test]
fn exclude_txt_glob_keeps_only_rs() {
    let dir = plant_flat();
    let (code, findings, _stdout, stderr) = run_json(dir.path(), &["--exclude-paths", "*.txt"]);
    assert_eq!(
        code, EXIT_FINDINGS,
        "a.rs still leaks -> exit 1; stderr:\n{stderr}"
    );
    assert_eq!(findings.len(), 1, "only a.rs survives the *.txt exclude");
    let only = &findings[0];
    assert_eq!(only.basename, "a.rs");
    assert_eq!(
        only.hash, HASH_A,
        "surviving finding is TOKEN_A, not TOKEN_B"
    );
    assert_eq!(only.detector_id, DETECTOR_ID);
}

/// Twin of the above: `--exclude-paths '*.rs'` prunes a.rs; only b.txt / TOKEN_B
/// survives.
#[test]
fn exclude_rs_glob_keeps_only_txt() {
    let dir = plant_flat();
    let (code, findings, _stdout, stderr) = run_json(dir.path(), &["--exclude-paths", "*.rs"]);
    assert_eq!(
        code, EXIT_FINDINGS,
        "b.txt still leaks -> exit 1; stderr:\n{stderr}"
    );
    assert_eq!(findings.len(), 1, "only b.txt survives the *.rs exclude");
    let only = &findings[0];
    assert_eq!(only.basename, "b.txt");
    assert_eq!(
        only.hash, HASH_B,
        "surviving finding is TOKEN_B, not TOKEN_A"
    );
}

/// Both globs together prune every file: an HONEST empty result — exit 0 and a
/// literal `[]` JSON array (not a crash, not a usage error).
#[test]
fn exclude_both_globs_finds_nothing_exit_zero() {
    let dir = plant_flat();
    let (code, findings, stdout, stderr) =
        run_json(dir.path(), &["--exclude-paths", "*.rs", "*.txt"]);
    assert_eq!(
        code, EXIT_SUCCESS,
        "no findings -> exit 0; stderr:\n{stderr}"
    );
    assert_eq!(findings.len(), 0, "everything excluded");
    assert_eq!(
        stdout, b"[]",
        "empty findings render as the exact bytes `[]`"
    );
}

/// An exact filename (`b.txt`, no glob metachar) is a valid exclude and drops
/// exactly that file.
#[test]
fn exclude_exact_filename_skips_that_file() {
    let dir = plant_flat();
    let (code, findings, _stdout, _stderr) = run_json(dir.path(), &["--exclude-paths", "b.txt"]);
    assert_eq!(code, EXIT_FINDINGS);
    assert_eq!(basenames(&findings), BTreeSet::from(["a.rs".to_owned()]));
    assert_eq!(findings[0].hash, HASH_A);
}

/// Negative twin: a glob that matches NOTHING (`*.md`) leaves both findings
/// intact — the filter must never over-prune.
#[test]
fn exclude_nonmatching_glob_keeps_all() {
    let dir = plant_flat();
    let (code, findings, _stdout, _stderr) = run_json(dir.path(), &["--exclude-paths", "*.md"]);
    assert_eq!(code, EXIT_FINDINGS);
    assert_eq!(findings.len(), 2, "*.md matches no planted file");
    assert_eq!(
        basenames(&findings),
        BTreeSet::from(["a.rs".to_owned(), "b.txt".to_owned()])
    );
}

/// A bare directory name (`sub`) prunes the entire nested subtree: `sub/c.rs`
/// disappears while the two root files remain.
#[test]
fn exclude_subdirectory_prunes_whole_subtree() {
    let dir = plant_with_subdir();
    let (code, findings, _stdout, stderr) = run_json(dir.path(), &["--exclude-paths", "sub"]);
    assert_eq!(
        code, EXIT_FINDINGS,
        "root files still leak; stderr:\n{stderr}"
    );
    assert_eq!(findings.len(), 2, "sub/c.rs pruned, a.rs+b.txt kept");
    assert_eq!(
        basenames(&findings),
        BTreeSet::from(["a.rs".to_owned(), "b.txt".to_owned()])
    );
    assert!(
        !findings.iter().any(|f| f.hash == HASH_C),
        "TOKEN_C under sub/ must not survive"
    );
}

/// Gitignore semantics: a slash-less basename glob (`*.rs`) matches at ANY
/// depth, so BOTH the root `a.rs` and the nested `sub/c.rs` are pruned; only
/// `b.txt` survives.
#[test]
fn bare_basename_glob_matches_at_any_depth() {
    let dir = plant_with_subdir();
    let (code, findings, _stdout, _stderr) = run_json(dir.path(), &["--exclude-paths", "*.rs"]);
    assert_eq!(code, EXIT_FINDINGS);
    assert_eq!(findings.len(), 1, "*.rs prunes a.rs AND sub/c.rs");
    assert_eq!(findings[0].basename, "b.txt");
    assert_eq!(findings[0].hash, HASH_B);
}

/// The explicit recursive glob `**/*.rs` also strips every `.rs` at any depth,
/// leaving only `b.txt`.
#[test]
fn recursive_glob_excludes_all_rs() {
    let dir = plant_with_subdir();
    let (code, findings, _stdout, _stderr) = run_json(dir.path(), &["--exclude-paths", "**/*.rs"]);
    assert_eq!(code, EXIT_FINDINGS);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].basename, "b.txt");
    assert_eq!(findings[0].hash, HASH_B);
}

/// Combining exclude with an include-like intent still works: two distinct
/// excludes (`b.txt` and the whole `sub` tree) narrow the scan down to exactly
/// `a.rs`. Proves multiple `--exclude-paths` operands compose.
#[test]
fn multiple_excludes_compose_to_single_file() {
    let dir = plant_with_subdir();
    let (code, findings, _stdout, _stderr) =
        run_json(dir.path(), &["--exclude-paths", "b.txt", "sub"]);
    assert_eq!(code, EXIT_FINDINGS);
    assert_eq!(findings.len(), 1, "only a.rs remains after both excludes");
    assert_eq!(findings[0].basename, "a.rs");
    assert_eq!(findings[0].hash, HASH_A);
}

/// Adversarial: there is NO `--include` scan-glob flag. Passing one is a clap
/// usage error — exit 2, with the argument named on stderr. This pins that the
/// filter surface is exclude-only (the include machinery is git-staged-only).
#[test]
fn unknown_include_flag_is_usage_error() {
    let dir = plant_flat();
    let root = dir.path().to_str().expect("utf8").to_owned();
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "cpu",
            "--path",
            &root,
            "--include",
            "*.rs",
        ])
        .output()
        .expect("spawn keyhog");
    let code = output.status.code().expect("exit code");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        code, EXIT_USER_ERROR,
        "unknown flag -> exit 2; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("unexpected argument") && stderr.contains("--include"),
        "clap must name the rejected --include flag; got:\n{stderr}"
    );
}

/// Adversarial dedup: the SAME token value in two DIFFERENT files collapses to
/// ONE finding (dedup is by credential value) with one `additional_locations`
/// entry — which is exactly why the other tests plant DISTINCT tokens to prove
/// which file survived a filter.
#[test]
fn identical_value_in_two_files_dedups_to_one() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("a.rs"), format!("{TOKEN_A}\n")).expect("write a.rs");
    std::fs::write(dir.path().join("b.txt"), format!("{TOKEN_A}\n")).expect("write b.txt");
    let (code, findings, _stdout, _stderr) = run_json(dir.path(), &[]);
    assert_eq!(code, EXIT_FINDINGS);
    assert_eq!(findings.len(), 1, "identical value dedups across files");
    assert_eq!(findings[0].hash, HASH_A);
    assert_eq!(
        findings[0].additional_locations, 1,
        "the second file is recorded as one additional location, not a 2nd finding"
    );
}

/// Field-level pin: the a.rs finding lands on line 1, offset 0, severity
/// critical, detector github-classic-pat — so the tests above assert against a
/// fully-pinned finding, not a fuzzy shape.
#[test]
fn surviving_finding_fields_are_pinned() {
    let dir = plant_flat();
    let (_code, findings, _stdout, _stderr) = run_json(dir.path(), &["--exclude-paths", "*.txt"]);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.basename, "a.rs");
    assert_eq!(f.detector_id, DETECTOR_ID);
    assert_eq!(f.severity, SEVERITY);
    assert_eq!(f.line, 1, "planted on the first line");
    assert_eq!(f.offset, 0, "token starts at byte 0 of the line");
    assert_eq!(
        f.additional_locations, 0,
        "single location for a unique value"
    );
}

/// The human `--format text` summary reflects the FILTERED result: excluding
/// `*.txt` yields a "1 secret found" roll-up that shows TOKEN_A's redaction and
/// never TOKEN_B's.
#[test]
fn text_summary_reflects_exclude_filter() {
    let dir = plant_flat();
    let root = dir.path().to_str().expect("utf8").to_owned();
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "cpu",
            "--no-suppress-test-fixtures",
            "--format",
            "text",
            "--path",
            &root,
            "--exclude-paths",
            "*.txt",
        ])
        .output()
        .expect("spawn keyhog");
    assert_eq!(output.status.code(), Some(EXIT_FINDINGS));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1 secret found"),
        "filtered scan reports exactly one secret; got:\n{stdout}"
    );
    assert!(
        stdout.contains(REDACTED_A),
        "the surviving a.rs secret ({REDACTED_A}) is shown; got:\n{stdout}"
    );
    assert!(
        !stdout.contains(REDACTED_B),
        "the excluded b.txt secret ({REDACTED_B}) must NOT appear; got:\n{stdout}"
    );
}
