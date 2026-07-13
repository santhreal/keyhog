//! Regression: `keyhog scan --exclude-paths <glob>...` prunes the walked
//! filesystem tree, exercised specifically for the `**/skip/**` /
//! nested-`skip/`-subtree scenario through the REAL shipped binary
//! (`--daemon=off`, `--backend cpu`).
//!
//! This file is DISTINCT from `regression_cli_glob_filters.rs` (which pins the
//! flat `a.rs`/`b.txt`/`sub` cases): here the fixtures are `.env` files under a
//! `skip/` directory, and the focus is the *exclude* surface, that
//! `--exclude-paths '**/skip/**'` drops the nested `skip/**` finding while
//! keeping the root file, that multiple `--exclude-paths` operands compose, that
//! a non-matching glob is an honest no-op, and that the flag is spelled
//! `--exclude-paths` (a bare `--exclude` is a clap usage error, exit 2).
//!
//! GLOB SEMANTICS (verified in code): each `--exclude-paths <p>` operand is
//! merged into the source ignore list and turned into an `ignore`-crate override
//! `!<p>` (`crates/sources/src/filesystem/filter.rs`), matched against the
//! root-relative path. So a slash-less glob (`*.env`, `skip`) matches at ANY
//! depth (gitignore semantics), and `**/skip/**` / an anchored `skip/b.env`
//! match the nested file.
//!
//! HOST-INDEPENDENT: `--backend cpu` forces the scalar path; the planted
//! detector (`github-classic-pat`) is an AC-literal (`ghp_`) detector that fires
//! on the CPU/scalar path, so no accelerator is assumed. `.env` files are NOT in
//! the bundled default-exclude policy (`rules/default_excludes.toml`), so the
//! baseline scan reaches them. Every assertion pins a concrete value (exact
//! count / basename / hash / exit code / bytes / error substring); none is a
//! bare `!is_empty`/`is_ok`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// Valid GitHub classic PAT (`ghp_` + 36 alnum, valid checksum tail). Fires
/// `github-classic-pat` on its own bytes. (Same validated fixture value used by
/// the sibling glob-filter regression; reused so the checksum + SHA-256 are
/// known-good rather than guessed.)
const TOKEN_A: &str = "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";
/// SHA-256 the reporter emits for `TOKEN_A` (`credential_hash`).
const HASH_A: &str = "7b85310a29300230c865bc48ca1836f15b81bd50ac85e8c0785e8145e98ff175";
/// Redacted form the reporter prints for `TOKEN_A`.
const REDACTED_A: &str = "ghp_...DSiF";

/// A DIFFERENT valid GitHub classic PAT planted in the nested `skip/b.env`.
const TOKEN_B: &str = "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";
/// SHA-256 for `TOKEN_B`.
const HASH_B: &str = "b1b3c6272a683aa8a4ca50250745b4c8b9d9c88570e8acb73eae2f9de9ec65e3";
/// Redacted form for `TOKEN_B`.
const REDACTED_B: &str = "ghp_...8GjS";

/// A third distinct valid PAT planted deeper under `skip/deep/c.env`.
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

/// Plant `a.env` (TOKEN_A) at the root and `skip/b.env` (TOKEN_B) one level
/// down. The tokens are DISTINCT so which file survived a filter is provable by
/// the surviving finding's `credential_hash`.
fn plant_skip_tree() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("a.env"), format!("{TOKEN_A}\n")).expect("write a.env");
    let skip = dir.path().join("skip");
    std::fs::create_dir(&skip).expect("mkdir skip");
    std::fs::write(skip.join("b.env"), format!("{TOKEN_B}\n")).expect("write skip/b.env");
    dir
}

/// Plant `a.env` (TOKEN_A) at the root and `skip/deep/c.env` (TOKEN_C) two
/// levels down, to prove a `skip/` exclude prunes the WHOLE subtree, not just
/// its immediate children.
fn plant_deep_skip_tree() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("a.env"), format!("{TOKEN_A}\n")).expect("write a.env");
    let deep = dir.path().join("skip").join("deep");
    std::fs::create_dir_all(&deep).expect("mkdir skip/deep");
    std::fs::write(deep.join("c.env"), format!("{TOKEN_C}\n")).expect("write skip/deep/c.env");
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

/// Run `keyhog scan` on `root` with extra args in JSON mode, CPU backend, daemon
/// disabled, test-fixture suppression off. Returns
/// `(exit_code, findings, stdout_bytes, stderr)`.
///
/// `--exclude-paths` is variadic (`num_args = 1..`) and would swallow a trailing
/// positional scan path, so the root is passed via `--path` and the caller's
/// extra args (which may end in `--exclude-paths ...`) come last.
fn run_json(root: &Path, extra: &[&str]) -> (i32, Vec<Finding>, Vec<u8>, String) {
    let root_str = root.to_str().expect("utf8 tempdir path").to_owned();
    let mut args: Vec<String> = vec![
        "scan".into(),
        "--daemon=off".into(),
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

/// The set of hashes present in a finding list.
fn hashes(findings: &[Finding]) -> BTreeSet<String> {
    findings.iter().map(|f| f.hash.clone()).collect()
}

// ---------------------------------------------------------------------------

/// Baseline: with no exclude, BOTH the root `a.env` and the nested `skip/b.env`
/// are scanned (exactly two findings mapped to their tokens by hash, exit 1).
#[test]
fn baseline_finds_root_and_nested_env() {
    let dir = plant_skip_tree();
    let (code, findings, _stdout, stderr) = run_json(dir.path(), &[]);
    assert_eq!(
        code, EXIT_FINDINGS,
        "findings present -> exit 1; stderr:\n{stderr}"
    );
    assert_eq!(findings.len(), 2, "one finding per planted .env file");
    assert_eq!(
        basenames(&findings),
        BTreeSet::from(["a.env".to_owned(), "b.env".to_owned()]),
        "root a.env and nested skip/b.env both scanned"
    );
    assert_eq!(
        hashes(&findings),
        BTreeSet::from([HASH_A.to_owned(), HASH_B.to_owned()]),
        "distinct tokens produce distinct credential hashes"
    );
}

/// Core case: `--exclude-paths '**/skip/**'` prunes the nested `skip/b.env`; the
/// surviving finding set is EXACTLY {a.env} carrying TOKEN_A's hash, exit 1.
#[test]
fn exclude_skip_globstar_drops_nested_env() {
    let dir = plant_skip_tree();
    let (code, findings, _stdout, stderr) =
        run_json(dir.path(), &["--exclude-paths", "**/skip/**"]);
    assert_eq!(
        code, EXIT_FINDINGS,
        "root a.env still leaks -> exit 1; stderr:\n{stderr}"
    );
    assert_eq!(
        findings.len(),
        1,
        "only a.env survives the **/skip/** exclude"
    );
    let only = &findings[0];
    assert_eq!(only.basename, "a.env");
    assert_eq!(
        only.hash, HASH_A,
        "surviving finding is TOKEN_A, not TOKEN_B"
    );
    assert_eq!(only.detector_id, DETECTOR_ID);
    assert!(
        !findings.iter().any(|f| f.hash == HASH_B),
        "the excluded skip/b.env (TOKEN_B) must not survive"
    );
}

/// A bare directory name (`skip`, no slash, no metachar) prunes the whole
/// subtree at any depth (same result as the globstar form. Only `a.env` remains).
#[test]
fn exclude_bare_dirname_prunes_skip_subtree() {
    let dir = plant_skip_tree();
    let (code, findings, _stdout, stderr) = run_json(dir.path(), &["--exclude-paths", "skip"]);
    assert_eq!(
        code, EXIT_FINDINGS,
        "root a.env still leaks; stderr:\n{stderr}"
    );
    assert_eq!(findings.len(), 1, "skip/ pruned, a.env kept");
    assert_eq!(basenames(&findings), BTreeSet::from(["a.env".to_owned()]));
    assert_eq!(findings[0].hash, HASH_A);
}

/// `**/skip/**` prunes an entire nested subtree, not just direct children:
/// `skip/deep/c.env` (two levels down) disappears while root `a.env` survives.
#[test]
fn exclude_skip_globstar_prunes_deep_subtree() {
    let dir = plant_deep_skip_tree();
    let (code, findings, _stdout, stderr) =
        run_json(dir.path(), &["--exclude-paths", "**/skip/**"]);
    assert_eq!(
        code, EXIT_FINDINGS,
        "root a.env still leaks; stderr:\n{stderr}"
    );
    assert_eq!(findings.len(), 1, "the whole skip/deep subtree is pruned");
    assert_eq!(findings[0].basename, "a.env");
    assert_eq!(findings[0].hash, HASH_A);
    assert!(
        !findings.iter().any(|f| f.hash == HASH_C),
        "deeply-nested TOKEN_C under skip/deep must not survive"
    );
}

/// Negative twin: an exclude glob that matches NOTHING (`**/other/**`) leaves
/// both findings intact (the filter must never over-prune).
#[test]
fn exclude_nonmatching_glob_keeps_both() {
    let dir = plant_skip_tree();
    let (code, findings, _stdout, _stderr) =
        run_json(dir.path(), &["--exclude-paths", "**/other/**"]);
    assert_eq!(code, EXIT_FINDINGS);
    assert_eq!(findings.len(), 2, "**/other/** matches no planted file");
    assert_eq!(
        basenames(&findings),
        BTreeSet::from(["a.env".to_owned(), "b.env".to_owned()])
    );
    assert_eq!(
        hashes(&findings),
        BTreeSet::from([HASH_A.to_owned(), HASH_B.to_owned()])
    );
}

/// A slash-less basename glob (`*.env`) matches at ANY depth (gitignore
/// semantics), so BOTH the root `a.env` and the nested `skip/b.env` are pruned:
/// an HONEST empty result (exit 0 and the literal `[]` bytes).
#[test]
fn exclude_star_env_matches_any_depth_empties_result() {
    let dir = plant_skip_tree();
    let (code, findings, stdout, stderr) = run_json(dir.path(), &["--exclude-paths", "*.env"]);
    assert_eq!(
        code, EXIT_SUCCESS,
        "every .env excluded -> exit 0; stderr:\n{stderr}"
    );
    assert_eq!(findings.len(), 0, "*.env prunes a.env AND skip/b.env");
    assert_eq!(
        stdout, b"[]",
        "empty findings render as the exact bytes `[]`"
    );
}

/// The explicit recursive glob `**/*.env` also strips every `.env` at any depth
///: same empty, exit-0 result as the bare `*.env` form.
#[test]
fn exclude_recursive_env_glob_empties_result() {
    let dir = plant_skip_tree();
    let (code, findings, stdout, _stderr) = run_json(dir.path(), &["--exclude-paths", "**/*.env"]);
    assert_eq!(code, EXIT_SUCCESS, "no .env survives -> exit 0");
    assert_eq!(findings.len(), 0);
    assert_eq!(stdout, b"[]");
}

/// An anchored root-relative path (`skip/b.env`, contains a `/`) drops exactly
/// that one file; the root `a.env` is untouched.
#[test]
fn exclude_anchored_relative_path_drops_one() {
    let dir = plant_skip_tree();
    let (code, findings, _stdout, stderr) =
        run_json(dir.path(), &["--exclude-paths", "skip/b.env"]);
    assert_eq!(code, EXIT_FINDINGS, "a.env still leaks; stderr:\n{stderr}");
    assert_eq!(findings.len(), 1, "only skip/b.env pruned");
    assert_eq!(findings[0].basename, "a.env");
    assert_eq!(findings[0].hash, HASH_A);
}

/// Multiple `--exclude-paths` operands COMPOSE: excluding both the root file and
/// the whole skip subtree prunes everything -> exit 0 and `[]`.
#[test]
fn multiple_excludes_compose_to_empty() {
    let dir = plant_skip_tree();
    let (code, findings, stdout, stderr) =
        run_json(dir.path(), &["--exclude-paths", "a.env", "**/skip/**"]);
    assert_eq!(
        code, EXIT_SUCCESS,
        "both operands prune everything -> exit 0; stderr:\n{stderr}"
    );
    assert_eq!(findings.len(), 0, "a.env and skip/** both excluded");
    assert_eq!(stdout, b"[]");
}

/// Multiple operands where only ONE matches: a non-matching glob alongside
/// `**/skip/**` still narrows down to exactly `a.env` (the non-matching operand
/// is a no-op, not an over-prune).
#[test]
fn multiple_excludes_partial_match_keeps_root() {
    let dir = plant_skip_tree();
    let (code, findings, _stdout, _stderr) =
        run_json(dir.path(), &["--exclude-paths", "**/nope/**", "**/skip/**"]);
    assert_eq!(code, EXIT_FINDINGS);
    assert_eq!(findings.len(), 1, "only skip/** matched; a.env survives");
    assert_eq!(findings[0].basename, "a.env");
    assert_eq!(findings[0].hash, HASH_A);
}

/// Adversarial flag-name pin: the flag is `--exclude-paths`, NOT `--exclude`.
/// A bare `--exclude` is an unknown argument -> clap usage error (exit 2), with
/// the rejected token named on stderr. (No `infer_long_args`, so no prefix
/// matching to `--exclude-paths`.)
#[test]
fn bare_exclude_flag_is_usage_error() {
    let dir = plant_skip_tree();
    let root = dir.path().to_str().expect("utf8").to_owned();
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--path",
            &root,
            "--exclude",
            "**/skip/**",
        ])
        .output()
        .expect("spawn keyhog");
    let code = output.status.code().expect("exit code");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        code, EXIT_USER_ERROR,
        "bare --exclude is unknown -> exit 2; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("--exclude"),
        "clap must name the rejected --exclude token; got:\n{stderr}"
    );
}

/// Field-level pin: after excluding the skip subtree, the surviving a.env
/// finding lands on line 1, offset 0, severity critical, detector
/// github-classic-pat, with no additional locations, so the set-level tests
/// above assert against a fully-pinned finding, not a fuzzy shape.
#[test]
fn surviving_env_finding_fields_are_pinned() {
    let dir = plant_skip_tree();
    let (_code, findings, _stdout, _stderr) =
        run_json(dir.path(), &["--exclude-paths", "**/skip/**"]);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.basename, "a.env");
    assert_eq!(f.hash, HASH_A);
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
/// `**/skip/**` yields a "1 secret found" roll-up that shows TOKEN_A's
/// redaction and never TOKEN_B's.
#[test]
fn text_summary_reflects_skip_exclude() {
    let dir = plant_skip_tree();
    let root = dir.path().to_str().expect("utf8").to_owned();
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--no-suppress-test-fixtures",
            "--format",
            "text",
            "--path",
            &root,
            "--exclude-paths",
            "**/skip/**",
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
        "the surviving a.env secret ({REDACTED_A}) is shown; got:\n{stdout}"
    );
    assert!(
        !stdout.contains(REDACTED_B),
        "the excluded skip/b.env secret ({REDACTED_B}) must NOT appear; got:\n{stdout}"
    );
}
