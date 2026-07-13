//! Regression e2e, directory-recursion coverage of `keyhog scan`, driven over
//! the SHIPPED `keyhog` binary with `--daemon=off` and pinned to EXACT values.
//!
//! WHAT THIS FILE PINS (and a bug it documents)
//! ---------------------------------------------
//! The task that spawned this file asked for a `keyhog scan --max-depth N`
//! traversal-depth limiter (find only depth-1, then 1+2, then all). That flag
//! DOES NOT EXIST in keyhog: a literal repo-wide search for `max-depth` /
//! `max_depth` finds no CLI argument, no config field, and no walker knob. The
//! only depth flags on `scan` are `--decode-depth` (recursive base64/archive
//! DECODE depth, 1..=10) and `--fused-depth` (pipeline channel depth), neither
//! bounds directory recursion. keyhog's filesystem source walks the whole tree
//! UNCONDITIONALLY; there is no operator control to stop at a directory depth.
//!
//! So this file pins the behavior that actually ships:
//!   * a scan of a root recurses to EVERY depth (1, 2, 3) with no limit, the
//!     union of finding locations is exactly the planted files;
//!   * scoping the ROOT to a subtree is the only way to exclude shallow files
//!     (scan `root/lvl1` → depth-1 file absent), and that is exact;
//!   * `--max-depth` is REJECTED by clap as an unknown argument (exit 2), which
//!     is the observable proof the requested feature is unimplemented.
//!
//! Finding-schema facts pinned below (read from `core::finding`):
//!   * JSON array report; each element serializes a `VerifiedFinding`.
//!   * The file path lives at `location.file_path` (NESTED), line at
//!     `location.line`; duplicate hits of one credential under the default
//!     `--dedup credential` fold into `additional_locations[*].file_path`.
//!   * `credential_hash` is the lower-case hex SHA-256 of the raw token.
//!   * `severity` serializes kebab-case (`critical`).
//!
//! The planted token is the canonical valid-CRC32 GitHub classic PAT used across
//! the scanner parity suites; it fires `github-classic-pat` (severity
//! `critical`) on both the SIMD and CPU literal paths (it carries the `ghp_`
//! literal, so it is NOT a Hyperscan-only no-literal detector). Split-literal so
//! this test file is not itself a self-scan tripwire.
//!
//! HOST-INDEPENDENCE: no assertion assumes an accelerator. The only backend
//! comparison is SIMD-vs-CPU (both always available); it asserts IDENTICAL depth
//! coverage, so a silent per-backend degrade would fail rather than pass.
//!
//! Every assertion pins a concrete load-bearing value, an exact exit code, an
//! integer finding count, a file-name set, a detector id, a severity string, a
//! 64-char credential hash, a redacted form, or a 1-based line number. No
//! assertion uses `is_empty()` / `is_ok()` / `len() > 0` as its only check.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Canonical GitHub classic PAT with a VALID CRC32 tail. Fires
/// `github-classic-pat` at `critical`. Split so the file is not a self-scan hit.
const PLANTED: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");
/// Detector this token fires and its kebab-case severity string.
const DETECTOR_ID: &str = "github-classic-pat";
const SEVERITY: &str = "critical";
/// `first4...last4` default redaction of PLANTED.
const REDACTED: &str = "ghp_...DSiF";
/// Lower-case hex SHA-256 of PLANTED (`printf %s <tok> | sha256sum`). Every
/// finding of this token must carry exactly this `credential_hash`.
const PLANTED_HASH: &str = "7b85310a29300230c865bc48ca1836f15b81bd50ac85e8c0785e8145e98ff175";

/// One line of file content that plants the token at 1-based line 1.
fn leak_line() -> String {
    format!("GITHUB_TOKEN={PLANTED}\n")
}

/// Build the canonical depth-1/2/3 tree and return its tempdir root:
///   <root>/top.env            (depth 1)
///   <root>/lvl1/mid.env       (depth 2)
///   <root>/lvl1/lvl2/deep.env (depth 3)
/// Each file plants PLANTED at line 1.
fn plant_depth_tree() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    let root = dir.path();
    let lvl1 = root.join("lvl1");
    let lvl2 = lvl1.join("lvl2");
    std::fs::create_dir_all(&lvl2).expect("mkdir lvl1/lvl2");
    std::fs::write(root.join("top.env"), leak_line()).expect("write top.env");
    std::fs::write(lvl1.join("mid.env"), leak_line()).expect("write mid.env");
    std::fs::write(lvl2.join("deep.env"), leak_line()).expect("write deep.env");
    dir
}

/// Run `keyhog scan --daemon=off [--backend cpu] <extra…> <path>`, hermetic env,
/// returning (exit-code, stdout, stderr). `--backend cpu` is injected unless the
/// caller pins a backend: the scalar CpuFallback path is always available on
/// every host and build (including the hyperscan-less `ci` feature set), so the
/// depth-coverage results are deterministic and host-independent. `--backend
/// simd` fails closed (exit 3) when the SIMD/Hyperscan prefilter is absent, which
/// is verified separately in `simd_and_cpu_backends_yield_identical_depth_coverage`.
fn scan(path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off"]);
    if !extra.contains(&"--backend") {
        cmd.args(["--backend", "cpu"]);
    }
    cmd.args(extra);
    cmd.arg(path);
    cmd.env("NO_COLOR", "1");
    cmd.env_remove("KEYHOG_BACKEND");
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Parse a `--format json` array, panicking with the raw bytes on failure.
fn json_array(stdout: &str) -> Vec<serde_json::Value> {
    let v: serde_json::Value =
        serde_json::from_str(stdout).unwrap_or_else(|e| panic!("stdout not JSON ({e}):\n{stdout}"));
    v.as_array()
        .unwrap_or_else(|| panic!("json report is not an array:\n{stdout}"))
        .clone()
}

/// Final path segment (basename) of a `/`-separated path string.
fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// The set of file BASENAMES a scan touched: every finding's primary
/// `location.file_path` plus each `additional_locations[*].file_path`. This is
/// dedup-scope-independent, so it reflects true traversal coverage whether the
/// same token folded (default `--dedup credential`) or not (`--dedup none`).
fn covered_basenames(stdout: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for f in json_array(stdout) {
        if let Some(p) = f["location"]["file_path"].as_str() {
            set.insert(basename(p));
        }
        if let Some(extra) = f["additional_locations"].as_array() {
            for loc in extra {
                if let Some(p) = loc["file_path"].as_str() {
                    set.insert(basename(p));
                }
            }
        }
    }
    set
}

fn set_of(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

// ---------------------------------------------------------------------------
// UNBOUNDED RECURSION, a scan reaches every directory depth (no limit exists)
// ---------------------------------------------------------------------------

/// Default `--dedup credential`: the one folded finding's primary +
/// additional_locations must cover ALL THREE depths. Proves recursion is
/// unbounded (there is no `--max-depth` to stop it at depth 1 or 2).
#[test]
fn default_recursive_scan_reaches_all_three_depths() {
    let tree = plant_depth_tree();
    let (code, stdout, stderr) = scan(tree.path(), &["--format", "json"]);
    assert_eq!(code, Some(1), "planted leaks → exit 1; stderr={stderr}");
    assert_eq!(
        covered_basenames(&stdout),
        set_of(&["top.env", "mid.env", "deep.env"]),
        "an unbounded walk must reach depth 1, 2 AND 3; stdout={stdout}"
    );
}

/// `--dedup none`: exactly ONE finding per planted file (3), each firing the
/// same detector. Pins both the count and the per-file traversal set.
#[test]
fn dedup_none_yields_exactly_three_findings_one_per_depth() {
    let tree = plant_depth_tree();
    let (code, stdout, stderr) = scan(tree.path(), &["--format", "json", "--dedup", "none"]);
    assert_eq!(code, Some(1), "planted leaks → exit 1; stderr={stderr}");

    let findings = json_array(&stdout);
    assert_eq!(
        findings.len(),
        3,
        "--dedup none must keep one finding per depth file; stdout={stdout}"
    );
    assert_eq!(
        covered_basenames(&stdout),
        set_of(&["top.env", "mid.env", "deep.env"]),
        "each depth's file must be represented; stdout={stdout}"
    );
    for f in &findings {
        assert_eq!(
            f["detector_id"].as_str(),
            Some(DETECTOR_ID),
            "every planted PAT fires {DETECTOR_ID}; got {f}"
        );
    }
}

/// All three depths carry the SAME token, so every finding's `credential_hash`
/// is the identical, exact SHA-256 hex (a single-element set).
#[test]
fn all_depths_share_the_exact_planted_credential_hash() {
    let tree = plant_depth_tree();
    let (_code, stdout, _stderr) = scan(tree.path(), &["--format", "json", "--dedup", "none"]);
    let hashes: BTreeSet<String> = json_array(&stdout)
        .iter()
        .filter_map(|f| f["credential_hash"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        hashes,
        set_of(&[PLANTED_HASH]),
        "one token across all depths → one exact hash; stdout={stdout}"
    );
}

/// Each finding redacts to `ghp_...DSiF` and the FULL plaintext token never
/// appears anywhere in stdout (a leak-safety contract independent of depth).
#[test]
fn every_depth_finding_redacts_and_stdout_omits_plaintext() {
    let tree = plant_depth_tree();
    let (_code, stdout, _stderr) = scan(tree.path(), &["--format", "json", "--dedup", "none"]);
    let findings = json_array(&stdout);
    assert_eq!(findings.len(), 3, "expected 3 findings; stdout={stdout}");
    for f in &findings {
        assert_eq!(
            f["credential_redacted"].as_str(),
            Some(REDACTED),
            "each finding must render the first4…last4 redaction; got {f}"
        );
    }
    assert!(
        !stdout.contains(PLANTED),
        "the raw PAT must NEVER appear in report output; stdout={stdout}"
    );
}

/// Every planted line is file line 1, so `location.line` is exactly 1 for all.
#[test]
fn every_depth_finding_reports_line_one() {
    let tree = plant_depth_tree();
    let (_code, stdout, _stderr) = scan(tree.path(), &["--format", "json", "--dedup", "none"]);
    let findings = json_array(&stdout);
    assert_eq!(findings.len(), 3, "expected 3 findings; stdout={stdout}");
    for f in &findings {
        assert_eq!(
            f["location"]["line"].as_u64(),
            Some(1),
            "token planted on line 1 must report line 1; got {f}"
        );
    }
}

/// Every finding is `critical` and fires `github-classic-pat`. Pins the exact
/// detector id + kebab-case severity string at each depth.
#[test]
fn every_depth_finding_is_critical_github_pat() {
    let tree = plant_depth_tree();
    let (_code, stdout, _stderr) = scan(tree.path(), &["--format", "json", "--dedup", "none"]);
    let findings = json_array(&stdout);
    assert_eq!(findings.len(), 3, "expected 3 findings; stdout={stdout}");
    for f in &findings {
        assert_eq!(
            f["detector_id"].as_str(),
            Some(DETECTOR_ID),
            "detector; {f}"
        );
        assert_eq!(f["severity"].as_str(), Some(SEVERITY), "severity; {f}");
    }
}

// ---------------------------------------------------------------------------
// ROOT SCOPING, the only real way to exclude shallow files is the START root
// ---------------------------------------------------------------------------

/// Scanning the DEEPEST subdir surfaces only its file, the depth-1 and depth-2
/// files above the chosen root are outside the walk. Negative twin of the
/// unbounded-root case.
#[test]
fn scanning_deepest_subdir_finds_only_the_deep_file() {
    let tree = plant_depth_tree();
    let deepest = tree.path().join("lvl1").join("lvl2");
    let (code, stdout, stderr) = scan(&deepest, &["--format", "json", "--dedup", "none"]);
    assert_eq!(code, Some(1), "the deep leak → exit 1; stderr={stderr}");
    assert_eq!(
        json_array(&stdout).len(),
        1,
        "only one file lives under the deepest root; stdout={stdout}"
    );
    assert_eq!(
        covered_basenames(&stdout),
        set_of(&["deep.env"]),
        "shallower files are outside the chosen root; stdout={stdout}"
    );
}

/// Scanning the MID subtree covers the depth-2 and depth-3 files but NOT the
/// depth-1 file that sits above the root, the exact set, with an explicit
/// negative check on `top.env`.
#[test]
fn scanning_mid_subtree_excludes_the_top_level_file() {
    let tree = plant_depth_tree();
    let mid = tree.path().join("lvl1");
    let (code, stdout, stderr) = scan(&mid, &["--format", "json", "--dedup", "none"]);
    assert_eq!(code, Some(1), "leaks under lvl1 → exit 1; stderr={stderr}");
    let covered = covered_basenames(&stdout);
    assert_eq!(
        covered,
        set_of(&["mid.env", "deep.env"]),
        "lvl1 root covers depth-2 and depth-3 only; stdout={stdout}"
    );
    assert!(
        !covered.contains("top.env"),
        "the depth-1 file above the root must NOT be scanned; got {covered:?}"
    );
}

/// Naming a single FILE as the root yields exactly that one finding.
#[test]
fn scanning_a_single_file_root_finds_exactly_that_file() {
    let tree = plant_depth_tree();
    let top = tree.path().join("top.env");
    let (code, stdout, stderr) = scan(&top, &["--format", "json", "--dedup", "none"]);
    assert_eq!(code, Some(1), "single-file leak → exit 1; stderr={stderr}");
    let findings = json_array(&stdout);
    assert_eq!(findings.len(), 1, "one file, one finding; stdout={stdout}");
    assert_eq!(
        covered_basenames(&stdout),
        set_of(&["top.env"]),
        "the named file is the whole scope; stdout={stdout}"
    );
    assert_eq!(
        findings[0]["detector_id"].as_str(),
        Some(DETECTOR_ID),
        "detector id; {}",
        findings[0]
    );
}

/// Sibling directories at the SAME depth are all walked, traversal is not a
/// single deepening chain. Root has one depth-1 file and two depth-2 branches.
#[test]
fn sibling_dirs_at_the_same_depth_are_both_scanned() {
    let dir = TempDir::new().expect("tempdir");
    let root = dir.path();
    let branch_a = root.join("branch_a");
    let branch_b = root.join("branch_b");
    std::fs::create_dir_all(&branch_a).expect("mkdir branch_a");
    std::fs::create_dir_all(&branch_b).expect("mkdir branch_b");
    std::fs::write(root.join("top.env"), leak_line()).expect("write top.env");
    std::fs::write(branch_a.join("a.env"), leak_line()).expect("write a.env");
    std::fs::write(branch_b.join("b.env"), leak_line()).expect("write b.env");

    let (code, stdout, stderr) = scan(root, &["--format", "json", "--dedup", "none"]);
    assert_eq!(
        code,
        Some(1),
        "leaks in both branches → exit 1; stderr={stderr}"
    );
    assert_eq!(
        json_array(&stdout).len(),
        3,
        "one finding per file across both siblings; stdout={stdout}"
    );
    assert_eq!(
        covered_basenames(&stdout),
        set_of(&["top.env", "a.env", "b.env"]),
        "both same-depth siblings plus the root file are covered; stdout={stdout}"
    );
}

/// A nested tree with NO secrets exits 0 with an empty JSON array, recursion
/// over clean directories does not fabricate findings.
#[test]
fn clean_nested_tree_exits_zero_with_empty_array() {
    let dir = TempDir::new().expect("tempdir");
    let deep = dir.path().join("a").join("b").join("c");
    std::fs::create_dir_all(&deep).expect("mkdir a/b/c");
    std::fs::write(dir.path().join("r.rs"), "fn main() {}\n").expect("write r.rs");
    std::fs::write(deep.join("d.rs"), "pub fn ok() -> u8 { 0 }\n").expect("write d.rs");

    let (code, stdout, stderr) = scan(dir.path(), &["--format", "json"]);
    assert_eq!(code, Some(0), "clean nested tree → exit 0; stderr={stderr}");
    assert_eq!(
        json_array(&stdout).len(),
        0,
        "no secrets anywhere in the tree; stdout={stdout}"
    );
}

// ---------------------------------------------------------------------------
// THE REQUESTED FLAG DOES NOT EXIST: `--max-depth` is rejected (exit 2)
// ---------------------------------------------------------------------------

/// `scan --max-depth 1` is an UNKNOWN argument: clap exits 2 (user error), the
/// error text names the offending flag, and NO findings are printed. This is the
/// observable proof that the traversal-depth limiter is unimplemented.
#[test]
fn max_depth_flag_is_rejected_as_unknown_argument() {
    let tree = plant_depth_tree();
    let (code, stdout, stderr) = scan(tree.path(), &["--format", "json", "--max-depth", "1"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown --max-depth flag is a user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("max-depth"),
        "the error must name the unrecognized flag; stderr={stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "a rejected parse must print no findings to stdout; stdout={stdout}"
    );
}

/// The boundary value the task wanted (`--max-depth 0`) is likewise rejected:
/// there is no value of the flag that keyhog accepts.
#[test]
fn max_depth_zero_is_also_rejected_exit_two() {
    let tree = plant_depth_tree();
    let (code, _stdout, stderr) = scan(tree.path(), &["--format", "json", "--max-depth", "0"]);
    assert_eq!(
        code,
        Some(2),
        "no --max-depth value is accepted → exit 2; stderr={stderr}"
    );
}

// ---------------------------------------------------------------------------
// HOST-INDEPENDENCE: SIMD and CPU walk identically (no silent per-backend gap)
// ---------------------------------------------------------------------------

/// The CPU (always-available) path is the source of truth: it must reach all
/// three depths at exit 1. The SIMD path must EITHER surface the identical depth
/// coverage (when the Hyperscan prefilter is present) OR fail closed with exit 3
/// and the forbidden-silent-fallback message (when it is absent, e.g. the
/// hyperscan-less `ci` build). What is NOT permitted is a silent per-backend
/// recall degrade, simd succeeding (exit 1) with a SMALLER coverage set than cpu
/// (Law 10). This keeps the test host/build-independent while still catching a
/// real silent degrade.
#[test]
fn simd_and_cpu_backends_yield_identical_depth_coverage() {
    let tree = plant_depth_tree();
    let (cpu_code, cpu_out, cpu_err) = scan(
        tree.path(),
        &["--format", "json", "--dedup", "none", "--backend", "cpu"],
    );
    let (simd_code, simd_out, simd_err) = scan(
        tree.path(),
        &["--format", "json", "--dedup", "none", "--backend", "simd"],
    );

    assert_eq!(cpu_code, Some(1), "cpu → exit 1; stderr={cpu_err}");
    let cpu_cov = covered_basenames(&cpu_out);
    assert_eq!(
        cpu_cov,
        set_of(&["top.env", "mid.env", "deep.env"]),
        "cpu must reach all three depths; stdout={cpu_out}"
    );

    match simd_code {
        Some(1) => {
            // Prefilter present: simd must match cpu exactly (no silent degrade).
            let simd_cov = covered_basenames(&simd_out);
            assert_eq!(
                simd_cov, cpu_cov,
                "simd depth coverage must equal cpu's, no silent per-backend degrade; \
                 stdout={simd_out}"
            );
        }
        Some(3) => {
            // Prefilter absent: simd MUST fail closed loudly, never silently degrade.
            assert!(
                simd_err.contains("silent cpu-fallback execution is forbidden"),
                "simd without the prefilter must fail closed with the forbidden-\
                 silent-fallback message, got stderr={simd_err}"
            );
        }
        other => panic!(
            "simd backend must either match cpu (exit 1) or fail closed (exit 3), \
             got exit {other:?}; stderr={simd_err}"
        ),
    }
}
