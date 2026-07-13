//! Regression coverage for the PRODUCT-LEVEL (real `keyhog` binary) behaviour
//! of git-aware `.gitignore` / `.keyhogignore` / `--exclude-paths` skipping on
//! the default `keyhog scan` command.
//!
//! This is the CLI/e2e twin of the in-process walker contract in
//! `crates/sources/tests/regression_gitignore_nesting.rs`: that file proves the
//! `FilesystemSource` walker semantics directly; THIS file proves the same
//! observable outcomes survive end-to-end through `keyhog scan`'s source
//! construction (`crates/cli/src/sources.rs::build_sources`, which builds
//! `FilesystemSource` with its default `respect_gitignore = true` and NEVER
//! overrides it) and reach the JSON report a user actually sees.
//!
//! Pinned product contract (read from the code, not assumed):
//!   * `keyhog scan` honours `.gitignore` by DEFAULT, but only INSIDE a git
//!     repository, codewalk lowers `respect_gitignore(true)` to
//!     `ignore::WalkBuilder` with the crate-default `require_git = true`, so a
//!     bare `.git/HEAD` marks the repo root and the git binary is never invoked.
//!     Without a `.git/` the `.gitignore` rules are fully inert (git-aware OFF).
//!   * There is NO `keyhog scan` flag to force-scan gitignored files: the
//!     `--respect-gitignore` toggle lives ONLY on the `scan-system` subcommand
//!     (default OFF there, because a system scan is paranoid). `scan --help`
//!     therefore does NOT advertise a gitignore-override flag; `scan-system
//!     --help` does. Both facts are pinned as coherence tests below.
//!   * `--no-default-excludes` toggles the lock-file/minified/build-output
//!     classifier ONLY, it is an INDEPENDENT knob from `.gitignore` and must
//!     NOT re-include a gitignored secret.
//!   * `.keyhogignore` is a custom ignore file honoured REGARDLESS of git
//!     presence; `--exclude-paths <glob>` suppresses a matching file too.
//!
//! Host-independence: every scan forces `--backend cpu`, the always-available
//! scalar path, so an accelerator is never assumed and the result is identical
//! on a GPU host and a GPU-less CI runner. The planted AWS access-key IDs are
//! caught by the literal-anchored `aws-access-key` detector (regex
//! `(?-i)(AKIA|ASIA)[0-9A-Z]{16}\b`, no checksum) which fires on the CPU path.
//! `--no-suppress-test-fixtures` guarantees no invented key is silently dropped
//! by the public-demo-credential suppression list.
//!
//! Truth-law: every assertion pins a concrete value, an exact process exit
//! code (0 = clean, 1 = unverified findings), an exact AWS-finding count, an
//! exact set of finding provenance basenames, or an exact substring
//! presence/absence in `--help`. No test asserts only `!is_empty()`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

// Split literals so this test file is not itself a planted-secret tripwire for
// keyhog's own dogfood self-scan. Each is `AKIA` + 16 uppercase-alnum chars, a
// syntactically valid (but non-live) AWS access-key ID.
const KEY_HIDDEN: &str = concat!("AKIA", "QYLPMN5HFIQR7XYA");
const KEY_VISIBLE: &str = concat!("AKIA", "KPQXRMSNTBVWYZBN");
const KEY_KEEP: &str = concat!("AKIA", "3M7XZ9QWPLND6KRT");
const KEY_DROP: &str = concat!("AKIA", "Z3KLMN7PQRS5TUVW");

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Mark `root` as a git repository so codewalk's `require_git = true` gitignore
/// semantics activate WITHOUT invoking the git binary (identical setup to
/// `regression_gitignore_nesting.rs::init_git_repo`). `.git` is itself a
/// default-excluded directory so it never becomes a scanned file.
fn init_git_repo(root: &Path) {
    let git = root.join(".git");
    std::fs::create_dir(&git).expect("mkdir .git");
    std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").expect("write .git/HEAD");
}

fn write(path: PathBuf, body: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("mkdir parent");
    }
    std::fs::write(path, body).expect("write fixture");
}

/// Drive the real `keyhog scan` binary on `root` with the host-independent CPU
/// backend and JSON output. Returns the parsed findings array (owned) and the
/// process exit code.
fn scan(root: &Path, extra: &[&str]) -> (Vec<serde_json::Value>, Option<i32>) {
    let mut cmd = Command::new(binary());
    cmd.arg("scan")
        .arg("--daemon=off")
        .args(["--backend", "cpu"])
        .arg("--no-suppress-test-fixtures")
        .args(extra)
        .args(["--format", "json"])
        .arg(root)
        .env_remove("KEYHOG_BACKEND");
    let output = cmd.output().expect("spawn keyhog scan");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!("keyhog scan stdout was not JSON: {error}\nstdout={stdout}\nstderr={stderr}")
    });
    let arr = value
        .as_array()
        .unwrap_or_else(|| panic!("findings JSON is not an array: {stdout}"))
        .clone();
    (arr, output.status.code())
}

/// The findings attributable to the literal-anchored AWS access-key detector.
/// An `AKIA…` key is caught by the named `aws-access-key` detector, or by the
/// simdsieve fast path `hot-aws_key` when it engages, both are a correct AWS
/// detection, so accept either id (matches the e2e_binary contract).
fn aws_findings(findings: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    findings
        .iter()
        .filter(|f| {
            matches!(
                f.get("detector_id").and_then(|v| v.as_str()),
                Some("aws-access-key" | "hot-aws_key")
            )
        })
        .collect()
}

/// The set of file basenames the given findings point at (provenance), read
/// from each finding's `location.file_path`. Used to pin exactly WHICH file a
/// surfaced secret came from (the crux of "skipped vs scanned").
fn provenance_basenames(findings: &[&serde_json::Value]) -> BTreeSet<String> {
    findings
        .iter()
        .map(|f| {
            let path = f
                .pointer("/location/file_path")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("finding missing location.file_path: {f}"));
            Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string())
        })
        .collect()
}

/// Run `keyhog <subcommand> --help` and return (stdout, exit code).
fn help(subcommand: &str) -> (String, Option<i32>) {
    let output = Command::new(binary())
        .arg(subcommand)
        .arg("--help")
        .output()
        .expect("spawn keyhog --help");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        output.status.code(),
    )
}

// ---------------------------------------------------------------------------
// 1. Default `keyhog scan` inside a git repo SKIPS a gitignored secret.
// ---------------------------------------------------------------------------

#[test]
fn default_scan_skips_gitignored_secret_in_git_repo() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    init_git_repo(root);
    write(root.join(".gitignore"), "hidden.env\n");
    write(
        root.join("hidden.env"),
        &format!("aws_key = \"{KEY_HIDDEN}\"\n"),
    );

    let (findings, code) = scan(root, &[]);
    // Clean: the only walked-and-scanned file is `.gitignore` (a pattern list,
    // no secret), so keyhog reports zero findings and exits 0.
    assert_eq!(
        code,
        Some(0),
        "gitignored secret must be skipped => clean exit 0; findings={findings:?}"
    );
    assert_eq!(
        aws_findings(&findings).len(),
        0,
        "no AWS finding may surface from the gitignored hidden.env; got {findings:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. Negative twin: the SAME secret in a NON-ignored file IS found.
// ---------------------------------------------------------------------------

#[test]
fn default_scan_finds_secret_in_tracked_file() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    init_git_repo(root);
    write(root.join(".gitignore"), "hidden.env\n");
    // The secret lives in tracked.txt, which the .gitignore does NOT name.
    write(
        root.join("tracked.txt"),
        &format!("aws_key = \"{KEY_VISIBLE}\"\n"),
    );

    let (findings, code) = scan(root, &[]);
    assert_eq!(
        code,
        Some(1),
        "an un-ignored planted secret must surface => exit 1; findings={findings:?}"
    );
    let aws = aws_findings(&findings);
    assert_eq!(
        aws.len(),
        1,
        "exactly one AWS finding expected; got {aws:?}"
    );
    assert_eq!(
        provenance_basenames(&aws),
        BTreeSet::from(["tracked.txt".to_string()]),
        "the surfaced AWS secret must come from tracked.txt"
    );
}

// ---------------------------------------------------------------------------
// 3. Partition: with an ignored twin AND a tracked twin (DISTINCT keys, so
//    value-dedup cannot mask the partition), ONLY the tracked one surfaces.
// ---------------------------------------------------------------------------

#[test]
fn gitignored_and_tracked_twins_only_tracked_surfaces() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    init_git_repo(root);
    write(root.join(".gitignore"), "hidden.env\n");
    write(
        root.join("hidden.env"),
        &format!("aws_key = \"{KEY_HIDDEN}\"\n"),
    );
    write(
        root.join("tracked.txt"),
        &format!("aws_key = \"{KEY_VISIBLE}\"\n"),
    );

    let (findings, code) = scan(root, &[]);
    assert_eq!(code, Some(1), "the tracked twin must surface => exit 1");
    let aws = aws_findings(&findings);
    assert_eq!(
        aws.len(),
        1,
        "only the tracked twin may surface (the gitignored twin is dropped); got {aws:?}"
    );
    let names = provenance_basenames(&aws);
    assert_eq!(
        names,
        BTreeSet::from(["tracked.txt".to_string()]),
        "provenance must be exactly tracked.txt"
    );
    assert!(
        !names.contains("hidden.env"),
        "no finding may be attributed to the gitignored hidden.env"
    );
}

// ---------------------------------------------------------------------------
// 4. Git-aware OFF analog: WITHOUT a `.git/`, the identical `.gitignore` is
//    inert, so the "hidden" secret IS scanned and surfaces.
// ---------------------------------------------------------------------------

#[test]
fn gitignore_inert_without_git_repo_secret_surfaces() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    // Deliberately NO init_git_repo: require_git = true => .gitignore has no
    // authority outside a repo, so hidden.env is walked and scanned.
    write(root.join(".gitignore"), "hidden.env\n");
    write(
        root.join("hidden.env"),
        &format!("aws_key = \"{KEY_HIDDEN}\"\n"),
    );

    let (findings, code) = scan(root, &[]);
    assert_eq!(
        code,
        Some(1),
        "without a .git/ the gitignore is inert and the secret surfaces => exit 1"
    );
    let aws = aws_findings(&findings);
    assert_eq!(aws.len(), 1, "one AWS finding expected; got {aws:?}");
    assert_eq!(
        provenance_basenames(&aws),
        BTreeSet::from(["hidden.env".to_string()]),
        "the non-repo scan must surface the secret from hidden.env"
    );
}

// ---------------------------------------------------------------------------
// 5. Adversarial: `--no-default-excludes` is an INDEPENDENT knob and does NOT
//    re-include a gitignored secret.
// ---------------------------------------------------------------------------

#[test]
fn no_default_excludes_does_not_reinclude_gitignored_secret() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    init_git_repo(root);
    write(root.join(".gitignore"), "hidden.env\n");
    write(
        root.join("hidden.env"),
        &format!("aws_key = \"{KEY_HIDDEN}\"\n"),
    );

    let (findings, code) = scan(root, &["--no-default-excludes"]);
    assert_eq!(
        code,
        Some(0),
        "--no-default-excludes must NOT re-include a gitignored file => still clean exit 0; \
         findings={findings:?}"
    );
    assert_eq!(
        aws_findings(&findings).len(),
        0,
        "the gitignored secret stays skipped even with default excludes off"
    );
}

// ---------------------------------------------------------------------------
// 6. `.keyhogignore` is honoured REGARDLESS of git presence (no `.git/` here).
// ---------------------------------------------------------------------------

#[test]
fn keyhogignore_skips_secret_without_git_repo() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    // No init_git_repo: `.keyhogignore` is a custom ignore file, not a git file,
    // so it applies with or without a repo.
    write(root.join(".keyhogignore"), "hidden.env\n");
    write(
        root.join("hidden.env"),
        &format!("aws_key = \"{KEY_HIDDEN}\"\n"),
    );
    write(
        root.join("visible.txt"),
        &format!("aws_key = \"{KEY_VISIBLE}\"\n"),
    );

    let (findings, code) = scan(root, &[]);
    assert_eq!(
        code,
        Some(1),
        "visible.txt surfaces while .keyhogignore drops hidden.env => exit 1"
    );
    let aws = aws_findings(&findings);
    assert_eq!(
        aws.len(),
        1,
        "exactly one AWS finding expected; got {aws:?}"
    );
    assert_eq!(
        provenance_basenames(&aws),
        BTreeSet::from(["visible.txt".to_string()]),
        ".keyhogignore must drop hidden.env and keep visible.txt"
    );
}

// ---------------------------------------------------------------------------
// 7. `--exclude-paths <glob>` suppresses the matching file at the CLI.
// ---------------------------------------------------------------------------

#[test]
fn exclude_paths_cli_suppresses_matching_file() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    write(
        root.join("hidden.env"),
        &format!("aws_key = \"{KEY_HIDDEN}\"\n"),
    );
    write(
        root.join("visible.txt"),
        &format!("aws_key = \"{KEY_VISIBLE}\"\n"),
    );

    let (findings, code) = scan(root, &["--exclude-paths", "hidden.env"]);
    assert_eq!(
        code,
        Some(1),
        "visible.txt still surfaces while --exclude-paths drops hidden.env => exit 1"
    );
    let aws = aws_findings(&findings);
    assert_eq!(
        aws.len(),
        1,
        "exactly one AWS finding expected; got {aws:?}"
    );
    assert_eq!(
        provenance_basenames(&aws),
        BTreeSet::from(["visible.txt".to_string()]),
        "--exclude-paths hidden.env must suppress hidden.env only"
    );
}

// ---------------------------------------------------------------------------
// 8. `.gitignore` same-file negation (`*.env` then `!keep.env`) re-includes the
//    negated file at the product level; the wildcard still drops the sibling.
// ---------------------------------------------------------------------------

#[test]
fn gitignore_same_file_negation_reincludes_at_cli() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    init_git_repo(root);
    write(root.join(".gitignore"), "*.env\n!keep.env\n");
    write(
        root.join("keep.env"),
        &format!("aws_key = \"{KEY_KEEP}\"\n"),
    );
    write(
        root.join("drop.env"),
        &format!("aws_key = \"{KEY_DROP}\"\n"),
    );

    let (findings, code) = scan(root, &[]);
    assert_eq!(
        code,
        Some(1),
        "keep.env is re-included and surfaces => exit 1"
    );
    let aws = aws_findings(&findings);
    assert_eq!(
        aws.len(),
        1,
        "only the re-included keep.env surfaces; drop.env stays ignored; got {aws:?}"
    );
    let names = provenance_basenames(&aws);
    assert_eq!(
        names,
        BTreeSet::from(["keep.env".to_string()]),
        "the later '!keep.env' negation wins over '*.env'"
    );
    assert!(
        !names.contains("drop.env"),
        "drop.env matches only '*.env' and must stay ignored"
    );
}

// ---------------------------------------------------------------------------
// 9. A `.gitignore` DIRECTORY rule skips a nested secret; a sibling outside the
//    ignored dir still surfaces. `secretstash/` is NOT a default-excluded dir,
//    so the skip is attributable solely to `.gitignore`.
// ---------------------------------------------------------------------------

#[test]
fn gitignore_directory_rule_skips_nested_secret() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    init_git_repo(root);
    write(root.join(".gitignore"), "secretstash/\n");
    write(
        root.join("secretstash").join("lib.txt"),
        &format!("aws_key = \"{KEY_HIDDEN}\"\n"),
    );
    write(
        root.join("main.txt"),
        &format!("aws_key = \"{KEY_VISIBLE}\"\n"),
    );

    let (findings, code) = scan(root, &[]);
    assert_eq!(
        code,
        Some(1),
        "main.txt surfaces; secretstash/ is skipped => exit 1"
    );
    let aws = aws_findings(&findings);
    assert_eq!(aws.len(), 1, "only main.txt surfaces; got {aws:?}");
    let names = provenance_basenames(&aws);
    assert_eq!(
        names,
        BTreeSet::from(["main.txt".to_string()]),
        "the 'secretstash/' directory rule must drop the nested lib.txt"
    );
    assert!(
        !names.contains("lib.txt"),
        "no finding may come from the gitignored secretstash/ subtree"
    );
}

// ---------------------------------------------------------------------------
// 10. A nested (child-directory) `.gitignore` rule is scoped to its subtree
//     only: a `*.env` rule in sub/ drops sub/b.env but never reaches root/a.env.
// ---------------------------------------------------------------------------

#[test]
fn nested_child_gitignore_scoped_to_subtree_at_cli() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    init_git_repo(root);
    // Empty root ignore; the child introduces the *.env rule (mirrors the
    // proven sources-level `child_gitignore_new_rule_scoped_to_subtree_only`).
    write(root.join(".gitignore"), "\n");
    write(root.join("sub").join(".gitignore"), "*.env\n");
    write(
        root.join("a.env"),
        &format!("aws_key = \"{KEY_VISIBLE}\"\n"),
    );
    write(
        root.join("sub").join("b.env"),
        &format!("aws_key = \"{KEY_HIDDEN}\"\n"),
    );

    let (findings, code) = scan(root, &[]);
    assert_eq!(code, Some(1), "root a.env surfaces => exit 1");
    let aws = aws_findings(&findings);
    assert_eq!(
        aws.len(),
        1,
        "the child *.env rule drops sub/b.env only; root a.env stays; got {aws:?}"
    );
    let names = provenance_basenames(&aws);
    assert_eq!(
        names,
        BTreeSet::from(["a.env".to_string()]),
        "the child .gitignore *.env must not reach up to the root a.env"
    );
    assert!(
        !names.contains("b.env"),
        "sub/b.env is dropped by the child's own *.env rule"
    );
}

// ---------------------------------------------------------------------------
// 11. A wildcard `.gitignore` rule (`*.env`) drops EVERY matching secret =>
//     clean exit 0.
// ---------------------------------------------------------------------------

#[test]
fn wildcard_gitignore_drops_all_matching_secrets() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    init_git_repo(root);
    write(root.join(".gitignore"), "*.env\n");
    write(root.join("a.env"), &format!("aws_key = \"{KEY_HIDDEN}\"\n"));
    write(root.join("b.env"), &format!("aws_key = \"{KEY_DROP}\"\n"));

    let (findings, code) = scan(root, &[]);
    assert_eq!(
        code,
        Some(0),
        "every *.env secret is gitignored => clean exit 0; findings={findings:?}"
    );
    assert_eq!(
        aws_findings(&findings).len(),
        0,
        "no AWS finding may surface when all secret-bearing files match '*.env'"
    );
}

// ---------------------------------------------------------------------------
// 12. Coherence: the real gitignore-override toggle is documented ONLY on
//     `scan-system`, whose `--help` advertises `--respect-gitignore`.
// ---------------------------------------------------------------------------

#[test]
fn scan_system_help_advertises_respect_gitignore_flag() {
    let (stdout, code) = help("scan-system");
    assert_eq!(code, Some(0), "`scan-system --help` must exit 0");
    assert!(
        stdout.contains("--respect-gitignore"),
        "`scan-system --help` must advertise the --respect-gitignore toggle; got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// 13. Coherence / gap-pin: `keyhog scan --help` does NOT advertise any
//     gitignore-override flag (there is none, the override lives on
//     scan-system). The anchor assert proves the help actually rendered.
// ---------------------------------------------------------------------------

#[test]
fn scan_help_omits_gitignore_override_flag() {
    let (stdout, code) = help("scan");
    assert_eq!(code, Some(0), "`scan --help` must exit 0");
    // Anchor: help really rendered the scan flag surface.
    assert!(
        stdout.contains("--exclude-paths"),
        "`scan --help` should list --exclude-paths; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("respect-gitignore"),
        "`keyhog scan` must NOT expose a --respect-gitignore override (only scan-system does)"
    );
    assert!(
        !stdout.contains("no-respect-gitignore") && !stdout.contains("no-gitignore"),
        "`keyhog scan` exposes no gitignore-disable flag; got:\n{stdout}"
    );
}
