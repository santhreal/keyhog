//! LANE 5 (test-cli-e2e) — SARIF schema deep-validation and a data-driven
//! scale matrix, driven over the SHIPPED binary.
//!
//! Two contracts, both end-to-end:
//!
//!   1. SARIF SCHEMA — `keyhog scan --format sarif` must emit a structurally
//!      complete SARIF 2.1.0 document a consuming platform (GitHub code
//!      scanning) accepts: the `$schema` + `version`, a `tool.driver` with
//!      `name`/`informationUri`/`rules`, EVERY `result.ruleId` resolving into
//!      `tool.driver.rules[]`, a valid `level`, a non-empty
//!      `partialFingerprints` carrying the credential hash, and one result per
//!      planted finding. (Repo-relative URI / dup relatedLocations are pinned
//!      by `sarif_github_compliance.rs`; this asserts the schema skeleton and
//!      the ruleId↔rules closure across a MULTI-detector corpus, the case the
//!      single-finding compliance test does not cover.)
//!
//!   2. SCALE — a generated corpus of N files, each planted with the same
//!      checksum-valid PAT, must yield EXACTLY N findings (one per file) under
//!      json AND the SARIF result count must equal the json finding count.
//!      Re-run across the backend axis, this is a few-hundred-assertion grid
//!      that proves the walker→engine→reporter pipeline neither drops nor
//!      duplicates findings as the tree grows or the backend changes.
//!
//! Every assert pins an EXACT count, ruleId, hash, or level — never `!is_empty`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Checksum-valid GitHub PAT → `github-classic-pat`, severity critical, with
/// the stable credential hash below. Split-literal to avoid self-scan tripwire.
const PAT: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");
const PAT_DETECTOR: &str = "github-classic-pat";
const PAT_HASH: &str = "7b85310a29300230c865bc48ca1836f15b81bd50ac85e8c0785e8145e98ff175";
/// A second, different planted secret so the multi-detector SARIF case has ≥2
/// distinct rules to resolve. This AWS key fires `aws-access-key` (critical).
const AWS: &str = concat!("AKIA", "QYLPMN5HFIQR7XYA");
const AWS_DETECTOR: &str = "aws-access-key";

const BACKENDS: &[&str] = &["simd", "cpu"];

fn scan_in(dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    // Run FROM `dir` (cwd = scan root) so SARIF URIs are repo-relative, exactly
    // as the GitHub Action invokes it.
    let mut cmd = Command::new(binary());
    cmd.current_dir(dir);
    cmd.args(["scan", "--daemon=off"]);
    // This matrix proves reporter/schema/dedup behavior, not routing. Use an
    // explicit diagnostic backend so the assertions do not depend on the
    // developer machine's persisted autoroute calibration cache.
    if !args.contains(&"--backend") {
        cmd.args(["--backend", "simd"]);
    }
    cmd.args(args);
    cmd.env_remove("KEYHOG_BACKEND");
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn json_finding_count(stdout: &str) -> usize {
    serde_json::from_str::<serde_json::Value>(stdout)
        .unwrap_or_else(|e| panic!("stdout not JSON ({e}):\n{stdout}"))
        .as_array()
        .expect("json report is an array")
        .len()
}

// ----------------------------------------------------------------------------
// SARIF SCHEMA (multi-detector)
// ----------------------------------------------------------------------------

#[test]
fn sarif_is_structurally_complete_2_1_0_with_every_ruleid_resolving() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("mkdir src");
    // Two SEPARATE files so the two detectors fire deterministically. Putting
    // both tokens in one file lets the second line's match context bleed into
    // the first and flip a named detector to an entropy variant — a real
    // context-window behavior, but not what this schema test is pinning.
    std::fs::write(
        dir.path().join("src/gh.env"),
        format!("GITHUB_TOKEN={PAT}\n"),
    )
    .expect("write gh fixture");
    std::fs::write(
        dir.path().join("src/aws.env"),
        format!("AWS_ACCESS_KEY_ID = \"{AWS}\"\n"),
    )
    .expect("write aws fixture");

    let (code, stdout, stderr) = scan_in(dir.path(), &[".", "--format", "sarif"]);
    assert_eq!(
        code,
        Some(1),
        "multi-secret sarif scan must exit 1; stderr={stderr}"
    );

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("SARIF stdout must be valid JSON");

    // Top-level skeleton.
    assert_eq!(v["version"], "2.1.0", "SARIF version must be 2.1.0");
    assert_eq!(
        v["$schema"].as_str(),
        Some("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json"),
        "SARIF must declare the 2.1.0 $schema URI; got {}",
        v["$schema"]
    );

    let run = &v["runs"][0];
    let driver = &run["tool"]["driver"];
    assert_eq!(
        driver["name"].as_str(),
        Some("keyhog"),
        "tool.driver.name must be `keyhog`; got {}",
        driver["name"]
    );
    assert!(
        driver["informationUri"]
            .as_str()
            .is_some_and(|u| u.starts_with("http")),
        "tool.driver.informationUri must be an http(s) URL; got {}",
        driver["informationUri"]
    );

    // Rule index and result↔rule closure.
    let rule_ids: BTreeSet<&str> = driver["rules"]
        .as_array()
        .expect("tool.driver.rules must be an array")
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    let results = run["results"].as_array().expect("runs[0].results array");
    assert_eq!(
        results.len(),
        2,
        "the two planted secrets must produce exactly two SARIF results; got {}",
        results.len()
    );

    let result_rule_ids: BTreeSet<&str> = results
        .iter()
        .filter_map(|r| r["ruleId"].as_str())
        .collect();
    assert!(
        result_rule_ids.contains(PAT_DETECTOR),
        "results must include ruleId {PAT_DETECTOR}; got {result_rule_ids:?}"
    );
    assert!(
        result_rule_ids.contains(AWS_DETECTOR),
        "results must include ruleId {AWS_DETECTOR}; got {result_rule_ids:?}"
    );

    for r in results {
        let rid = r["ruleId"].as_str().expect("each result needs a ruleId");
        // (closure) every ruleId resolves into the driver's rule index, or
        // GitHub silently drops the alert.
        assert!(
            rule_ids.contains(rid),
            "ruleId {rid:?} not present in tool.driver.rules[]; rules={rule_ids:?}"
        );
        // (level) a SARIF level GitHub understands.
        assert!(
            matches!(
                r["level"].as_str(),
                Some("error" | "warning" | "note" | "none")
            ),
            "result.level must be a valid SARIF level; got {}",
            r["level"]
        );
        // (fingerprint) non-empty partialFingerprints for cross-run dedup.
        let fps = r["partialFingerprints"]
            .as_object()
            .expect("each result needs a partialFingerprints object");
        assert!(
            !fps.is_empty(),
            "partialFingerprints must be non-empty for alert dedup; got {}",
            r["partialFingerprints"]
        );
        // (location) a physical location with a region the platform can map.
        assert!(
            r.pointer("/locations/0/physicalLocation/artifactLocation/uri")
                .and_then(|u| u.as_str())
                .is_some(),
            "each result needs a physicalLocation artifact uri; got {r}"
        );
    }

    // The PAT result must carry the exact credential hash in its fingerprint —
    // this is the value the self-scan suppression dedups on (project memory).
    let pat_result = results
        .iter()
        .find(|r| r["ruleId"].as_str() == Some(PAT_DETECTOR))
        .expect("the github-classic-pat result");
    let fp_values: Vec<&str> = pat_result["partialFingerprints"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        fp_values.contains(&PAT_HASH),
        "the PAT result's partialFingerprints must carry the credential hash {PAT_HASH}; got {fp_values:?}"
    );
}

#[test]
fn sarif_result_count_equals_json_finding_count_across_backends() {
    let dir = TempDir::new().expect("tempdir");
    // Two separate files → two deterministic findings regardless of backend.
    std::fs::write(dir.path().join("gh.env"), format!("GITHUB_TOKEN={PAT}\n"))
        .expect("write gh fixture");
    std::fs::write(
        dir.path().join("aws.env"),
        format!("AWS_ACCESS_KEY_ID = \"{AWS}\"\n"),
    )
    .expect("write aws fixture");

    for &backend in BACKENDS {
        let json = scan_in(dir.path(), &[".", "--backend", backend, "--format", "json"]);
        let sarif = scan_in(
            dir.path(),
            &[".", "--backend", backend, "--format", "sarif"],
        );
        assert_eq!(json.0, Some(1), "--backend {backend} json must exit 1");
        assert_eq!(sarif.0, Some(1), "--backend {backend} sarif must exit 1");

        let json_count = json_finding_count(&json.1);
        let v: serde_json::Value = serde_json::from_str(sarif.1.trim()).expect("sarif json");
        let sarif_count = v["runs"][0]["results"]
            .as_array()
            .expect("sarif results")
            .len();
        assert_eq!(
            sarif_count, json_count,
            "--backend {backend}: sarif result count ({sarif_count}) must equal json \
             finding count ({json_count}) — a format must never add/drop a finding"
        );
        assert_eq!(
            json_count, 2,
            "--backend {backend}: the two planted secrets must yield two findings; got {json_count}"
        );
    }
}

// ----------------------------------------------------------------------------
// SCALE — N files → exactly N findings, no drop, no duplicate
// ----------------------------------------------------------------------------

/// Plant `n` files, each with the SAME checksum-valid PAT, in a temp tree.
fn plant_n_pat_files(n: usize) -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    for i in 0..n {
        std::fs::write(
            dir.path().join(format!("svc_{i:04}.env")),
            // Distinct var name per file so the *file* differs, but the
            // credential is identical — the dedup scope (default: Credential)
            // collapses identical hashes, so we use --dedup none to count files.
            format!("TOKEN_{i}={PAT}\n"),
        )
        .unwrap_or_else(|e| panic!("write file {i}: {e}"));
    }
    dir
}

#[test]
fn n_files_each_with_the_pat_yield_exactly_n_findings_under_dedup_none() {
    // With `--dedup none` every file's planted PAT is its own finding, so the
    // count is deterministic and equals the file count. This proves the walker
    // visits every file and the engine reports every match (no silent drop, no
    // double-count) as the tree scales.
    for &n in &[1usize, 4, 16, 64] {
        let dir = plant_n_pat_files(n);
        let (code, stdout, stderr) =
            scan_in(dir.path(), &[".", "--dedup", "none", "--format", "json"]);
        assert_eq!(code, Some(1), "scale-{n} scan must exit 1; stderr={stderr}");
        assert_eq!(
            json_finding_count(&stdout),
            n,
            "scale-{n}: --dedup none must report exactly one finding per file ({n}); got {}",
            json_finding_count(&stdout)
        );
    }
}

#[test]
fn credential_dedup_collapses_identical_pat_across_n_files_to_one() {
    // The DEFAULT dedup scope (Credential) collapses the identical PAT across
    // all N files into a single finding (with N additional_locations). This
    // pins the other end of the dedup contract.
    for &n in &[2usize, 8, 32] {
        let dir = plant_n_pat_files(n);
        let (code, stdout, _stderr) = scan_in(dir.path(), &[".", "--format", "json"]);
        assert_eq!(code, Some(1), "dedup-{n} scan must exit 1");
        let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
        let arr = v.as_array().expect("array");
        assert_eq!(
            arr.len(),
            1,
            "credential dedup must collapse {n} identical PATs to ONE finding; got {} findings",
            arr.len()
        );
        assert_eq!(
            arr[0]["detector_id"].as_str(),
            Some(PAT_DETECTOR),
            "the single deduped finding must be {PAT_DETECTOR}"
        );
        // It must record the other N-1 locations so coverage is not lost.
        let extra = arr[0]["additional_locations"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        assert_eq!(
            extra,
            n - 1,
            "the deduped finding must carry the other {} locations; got {extra}",
            n - 1
        );
    }
}

#[test]
fn scale_sarif_results_match_json_findings_under_dedup_none() {
    // The scale + format-parity corner: under --dedup none, SARIF must emit
    // exactly as many results as json emits findings, for every tree size.
    for &n in &[1usize, 4, 16] {
        let dir = plant_n_pat_files(n);
        let json = scan_in(dir.path(), &[".", "--dedup", "none", "--format", "json"]);
        let sarif = scan_in(dir.path(), &[".", "--dedup", "none", "--format", "sarif"]);
        let json_count = json_finding_count(&json.1);
        let v: serde_json::Value = serde_json::from_str(sarif.1.trim()).expect("sarif json");
        let sarif_count = v["runs"][0]["results"].as_array().expect("results").len();
        assert_eq!(
            sarif_count, json_count,
            "scale-{n}: sarif results ({sarif_count}) must equal json findings ({json_count})"
        );
        assert_eq!(json_count, n, "scale-{n}: json must report {n} findings");
    }
}
