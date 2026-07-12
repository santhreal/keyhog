//! e2e: the `--backend` selector must NEVER change the finding set (lane:
//! WIRING vector 9 + TESTING vector 12, backend recall parity through the REAL
//! shipped binary).
//!
//! A `--backend` override picks the *engine* (scalar CPU / Hyperscan-SIMD /
//! calibrated autoroute), not the *policy*. So for one planted secret every
//! engine the operator can select must surface the SAME detector id, the SAME
//! credential hash, at the SAME location, with the SAME exit code and the SAME
//! finding count. A backend that drops, adds, relocates, or re-classifies a
//! finding is a silent recall/precision hole an operator hits just by flipping
//! `--backend`.
//!
//! Every assertion pins an EXACT value (detector id, count, exit code, hash
//! set, line/offset tuple) — never `!is_empty()`. Deterministic: planted
//! secrets with valid checksums, otherwise-clean fixtures, `--daemon=off` (no
//! background-process nondeterminism), and a hermetic `HOME`/`XDG_CACHE_HOME`
//! so the autoroute cache is isolated from the dev host.
//!
//! Pinned facts, read from source (not guessed):
//!   * `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` has a valid CRC32 tail and
//!     fires `github-classic-pat` (scanner boundary/parity fixtures).
//!   * `AKIAQYLPMN5HFIQR7XYA` fires `aws-access-key`
//!     (`backend_parity_determinism_fixed_corpus.rs`).
//!   * `--backend` accepts `BACKEND_OVERRIDE_VALUES`
//!     (`crates/scanner/src/hw_probe/select.rs`): `auto`, `simd`, `simd-regex`,
//!     `cpu`, `cpu-fallback`, plus the gpu variants. `scalar` is a canonical
//!     alias inside `parse_backend_str` but is NOT in `BACKEND_OVERRIDE_VALUES`,
//!     so clap rejects `--backend scalar` (exit 2) — pinned as a coherence gap.
//!   * findings present, none verified live -> exit 1 (`EXIT_FINDINGS`); a
//!     clean scan -> exit 0 (`EXIT_SUCCESS`); a bad flag value -> exit 2
//!     (`EXIT_USER_ERROR`).
//!   * HOST-INDEPENDENT accelerator contract (Law 10, no silent fallback): on a
//!     host with the Hyperscan/SIMD prefilter, `--backend simd`/`simd-regex`
//!     produce a byte-identical finding set to `cpu`; on a host WITHOUT it they
//!     FAIL CLOSED at exit 3 ("silent cpu-fallback execution is forbidden")
//!     rather than silently degrade. `--backend auto` with no calibration either
//!     fails closed (exit 2, "autoroute calibration required") or completes a
//!     scan matching cpu (exit 1) — never a silently-wrong result. These tests
//!     assert that disjunction so they are green on accel and no-accel hosts.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

use serde_json::Value;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A planted GitHub classic PAT with a valid CRC32 tail: fires
/// `github-classic-pat` on its own bytes.
const GHP: &str = "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";
const GHP_DETECTOR: &str = "github-classic-pat";

/// A planted AWS access-key id: fires `aws-access-key`.
const AKIA: &str = "AKIAQYLPMN5HFIQR7XYA";
const AKIA_DETECTOR: &str = "aws-access-key";

/// Hermetic cache home: both `HOME` and `XDG_CACHE_HOME` point at a fresh
/// tempdir so `dirs::cache_dir()` (the autoroute cache root) lands inside it.
fn cache_home() -> TempDir {
    TempDir::new().expect("tempdir")
}

/// Write `content` to a fresh file and return (owning dir, path).
fn fixture(name: &str, content: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write fixture");
    (dir, path)
}

/// Run `keyhog scan --daemon=off --format json [--backend B] [extra…] <path>`
/// under a hermetic cache home. Returns (exit code, stdout, stderr) as owned
/// Strings (no borrows of dropped temporaries).
fn scan(
    home: &Path,
    path: &Path,
    backend: Option<&str>,
    extra: &[&str],
) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.env("HOME", home)
        .env("XDG_CACHE_HOME", home)
        .env("NO_COLOR", "1");
    cmd.args(["scan", "--daemon=off", "--format", "json"]);
    if let Some(b) = backend {
        cmd.args(["--backend", b]);
    }
    for a in extra {
        cmd.arg(a);
    }
    cmd.arg(path);
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Parse the JSON-array report into the finding objects.
fn findings(stdout: &str) -> Vec<Value> {
    let v: Value = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("scan stdout must be a JSON array ({e}); stdout={stdout:?}"));
    v.as_array()
        .expect("JSON report is a top-level array")
        .clone()
}

/// Sorted detector-id list across every finding (a MULTISET as a sorted Vec, so
/// duplicates are preserved — a backend that emits a finding twice is caught).
fn detector_ids(stdout: &str) -> Vec<String> {
    let mut ids: Vec<String> = findings(stdout)
        .iter()
        .map(|f| {
            f.get("detector_id")
                .and_then(Value::as_str)
                .expect("every finding carries a detector_id string")
                .to_string()
        })
        .collect();
    ids.sort();
    ids
}

/// The set of credential hashes across every finding.
fn cred_hashes(stdout: &str) -> BTreeSet<String> {
    findings(stdout)
        .iter()
        .filter_map(|f| {
            f.get("credential_hash")
                .and_then(Value::as_str)
                .map(String::from)
        })
        .collect()
}

/// The full findings deterministically ordered by (detector_id, offset) so two
/// backends can be compared value-for-value regardless of emission order.
fn ordered_findings(stdout: &str) -> Vec<Value> {
    let mut fs = findings(stdout);
    fs.sort_by(|a, b| {
        let da = a.get("detector_id").and_then(Value::as_str).unwrap_or("");
        let db = b.get("detector_id").and_then(Value::as_str).unwrap_or("");
        let oa = a
            .pointer("/location/offset")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let ob = b
            .pointer("/location/offset")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        (da, oa).cmp(&(db, ob))
    });
    fs
}

/// The stderr signature keyhog emits when `--backend simd` is selected on a
/// host whose Hyperscan/SIMD prefilter is unavailable: it FAILS CLOSED (exit 3)
/// rather than silently substituting the cpu engine (Law 10: no silent
/// fallback). Pinned from `crates/cli/src/.../backend` selection.
const SIMD_FAIL_CLOSED_MSG: &str = "silent cpu-fallback execution is forbidden";
const EXIT_BACKEND_UNAVAILABLE: i32 = 3;

/// Host-INDEPENDENT contract for an accelerated backend `b` (simd / simd-regex):
/// on a host where the accelerator is present it must produce a byte-identical
/// finding set + exit code to `--backend cpu`; on a host without it, keyhog must
/// FAIL CLOSED (exit 3, forbidding a silent cpu substitution) — it must NEVER
/// silently return a degraded/empty result. Returns true iff the accelerator was
/// actually exercised (so a caller can add availability-only assertions).
fn assert_accel_matches_cpu_or_fails_closed(home: &Path, path: &Path, b: &str) -> bool {
    let (code_cpu, out_cpu, _) = scan(home, path, Some("cpu"), &[]);
    let (code_accel, out_accel, err_accel) = scan(home, path, Some(b), &[]);
    if code_accel == Some(EXIT_BACKEND_UNAVAILABLE) {
        assert!(
            err_accel.contains(SIMD_FAIL_CLOSED_MSG),
            "`--backend {b}` unavailable must fail closed (exit 3) with the \
             no-silent-fallback message; stderr={err_accel}"
        );
        false
    } else {
        assert_eq!(
            code_accel, code_cpu,
            "`--backend {b}` (available) must share cpu's exit code; stderr={err_accel}"
        );
        assert_eq!(
            ordered_findings(&out_accel),
            ordered_findings(&out_cpu),
            "`--backend {b}` (available) must produce byte-identical findings to cpu"
        );
        true
    }
}

// ---------------------------------------------------------------------------
// Positive: each explicit CPU-class / SIMD engine surfaces exactly the plant.
// ---------------------------------------------------------------------------

#[test]
fn cpu_backend_surfaces_exactly_the_planted_github_pat() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let (code, out, err) = scan(home.path(), &path, Some("cpu"), &[]);

    assert_eq!(
        code,
        Some(1),
        "findings present, none verified -> exit 1; stderr={err}"
    );
    assert_eq!(
        detector_ids(&out),
        vec![GHP_DETECTOR.to_string()],
        "the cpu backend must surface exactly one github-classic-pat finding; stdout={out}"
    );
}

#[test]
fn simd_backend_surfaces_the_planted_github_pat_or_fails_closed() {
    // On a Hyperscan-capable host the simd engine surfaces exactly the plant
    // (identical to cpu); on a host without the prefilter keyhog fails closed
    // (exit 3) rather than silently degrading. Both are asserted host-agnostic.
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let available = assert_accel_matches_cpu_or_fails_closed(home.path(), &path, "simd");
    if available {
        let (code, out, _) = scan(home.path(), &path, Some("simd"), &[]);
        assert_eq!(
            code,
            Some(1),
            "simd (available) on a planted secret -> exit 1"
        );
        assert_eq!(
            detector_ids(&out),
            vec![GHP_DETECTOR.to_string()],
            "the simd backend must surface exactly one github-classic-pat finding; stdout={out}"
        );
    }
}

// ---------------------------------------------------------------------------
// Parity: cpu vs simd must agree on id set, count, exit code, hash, location.
// ---------------------------------------------------------------------------

#[test]
fn cpu_and_simd_agree_on_detector_ids_count_and_exit_code() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    // cpu is always available: pin its exact result.
    let (code_cpu, out_cpu, _) = scan(home.path(), &path, Some("cpu"), &[]);
    assert_eq!(code_cpu, Some(1), "cpu exits 1 on the planted secret");
    assert_eq!(detector_ids(&out_cpu), vec![GHP_DETECTOR.to_string()]);

    // simd must match cpu's id-set + exit code where available, else fail closed.
    assert_accel_matches_cpu_or_fails_closed(home.path(), &path, "simd");
}

#[test]
fn cpu_and_simd_agree_on_the_credential_hash_set() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let (_c, out_cpu, _) = scan(home.path(), &path, Some("cpu"), &[]);
    let cpu = cred_hashes(&out_cpu);
    assert_eq!(
        cpu.len(),
        1,
        "one planted credential -> one hash; cpu={cpu:?}"
    );

    // Where simd is available its byte-identical findings imply an identical
    // hash set; where unavailable it fails closed. Assert the specific hash-set
    // equality only on the available path.
    if assert_accel_matches_cpu_or_fails_closed(home.path(), &path, "simd") {
        let (_s, out_simd, _) = scan(home.path(), &path, Some("simd"), &[]);
        assert_eq!(
            cpu,
            cred_hashes(&out_simd),
            "cpu and simd must derive the SAME credential hash for the same bytes"
        );
    }
}

#[test]
fn cpu_and_simd_agree_value_for_value_including_location() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let (_c, out_cpu, _) = scan(home.path(), &path, Some("cpu"), &[]);
    let cpu = ordered_findings(&out_cpu);

    assert_eq!(
        cpu.len(),
        1,
        "single planted secret yields a single finding; cpu={cpu:?}"
    );
    // Pin the concrete cpu location so a silent offset drift is caught.
    let offset = cpu[0]
        .pointer("/location/offset")
        .and_then(Value::as_u64)
        .expect("finding carries a numeric location.offset");
    assert_eq!(
        offset, 13,
        "the token starts after `GITHUB_TOKEN=` (13 bytes); got offset {offset}"
    );
    // Full deep-equality (detector_id, name, service, severity, hash, location,
    // verification, metadata, remediation) is asserted by the helper on the
    // available path; unavailable simd fails closed.
    assert_accel_matches_cpu_or_fails_closed(home.path(), &path, "simd");
}

// ---------------------------------------------------------------------------
// Backend-alias parity: canonical aliases must route to the same engine.
// ---------------------------------------------------------------------------

#[test]
fn cpu_fallback_alias_matches_cpu() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let (code_cpu, out_cpu, _) = scan(home.path(), &path, Some("cpu"), &[]);
    let (code_alias, out_alias, _) = scan(home.path(), &path, Some("cpu-fallback"), &[]);

    assert_eq!(code_cpu, Some(1));
    assert_eq!(
        code_alias, code_cpu,
        "`cpu-fallback` is an alias of `cpu` and must share its exit code"
    );
    assert_eq!(
        ordered_findings(&out_alias),
        ordered_findings(&out_cpu),
        "`--backend cpu-fallback` must be identical to `--backend cpu`"
    );
}

#[test]
fn simd_regex_alias_matches_simd() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    // `simd-regex` and `simd` are aliases of the SAME engine, so they must give
    // an identical (exit code, finding set) on ANY host — whether that host runs
    // the accelerator (exit 1 + plant) or fails closed (exit 3). Alias parity is
    // therefore host-independent WITHOUT assuming the accelerator is present.
    let (code_simd, out_simd, _) = scan(home.path(), &path, Some("simd"), &[]);
    let (code_alias, out_alias, _) = scan(home.path(), &path, Some("simd-regex"), &[]);

    assert_eq!(
        code_alias, code_simd,
        "`simd-regex` is an alias of `simd` and must share its exit code"
    );
    // Compare finding sets only when the engine actually ran (a fail-closed
    // exit 3 emits no JSON report, so both aliases share empty stdout).
    if code_simd != Some(EXIT_BACKEND_UNAVAILABLE) {
        assert_eq!(
            ordered_findings(&out_alias),
            ordered_findings(&out_simd),
            "`--backend simd-regex` must be identical to `--backend simd`"
        );
    } else {
        assert_eq!(
            out_alias, out_simd,
            "both aliases must fail closed with identical (empty) output"
        );
    }
}

// ---------------------------------------------------------------------------
// Multi-detector parity: two distinct secrets, same set across backends.
// ---------------------------------------------------------------------------

#[test]
fn two_distinct_secrets_surface_identically_across_cpu_and_simd() {
    let home = cache_home();
    let content = format!("GITHUB_TOKEN={GHP}\nAWS_ACCESS_KEY_ID={AKIA}\n");
    let (_d, path) = fixture("multi.env", &content);

    let (code_cpu, out_cpu, _) = scan(home.path(), &path, Some("cpu"), &[]);
    assert_eq!(code_cpu, Some(1));

    // sorted -> aws-access-key before github-classic-pat.
    let ids_cpu = detector_ids(&out_cpu);
    assert_eq!(
        ids_cpu,
        vec![AKIA_DETECTOR.to_string(), GHP_DETECTOR.to_string()],
        "cpu must surface BOTH planted detectors; got {ids_cpu:?}\nstdout={out_cpu}"
    );

    // simd (available) must surface the SAME two detectors + both hashes;
    // simd (unavailable) fails closed — never an engine-specific drop.
    assert_accel_matches_cpu_or_fails_closed(home.path(), &path, "simd");
}

// ---------------------------------------------------------------------------
// Boundary: a clean file yields the empty set on every engine.
// ---------------------------------------------------------------------------

#[test]
fn clean_file_yields_zero_findings_and_exit_zero_on_cpu() {
    let home = cache_home();
    let (_d, path) = fixture("clean.txt", "the quick brown fox jumps over the lazy dog\n");

    let (code, out, err) = scan(home.path(), &path, Some("cpu"), &[]);

    assert_eq!(
        code,
        Some(0),
        "a clean file exits 0 (no secrets); stderr={err}"
    );
    assert_eq!(
        detector_ids(&out),
        Vec::<String>::new(),
        "the cpu backend must report ZERO findings for clean text; stdout={out}"
    );
}

#[test]
fn clean_file_yields_the_same_empty_set_on_cpu_and_simd() {
    let home = cache_home();
    let (_d, path) = fixture("clean.txt", "the quick brown fox jumps over the lazy dog\n");

    let (code_cpu, out_cpu, _) = scan(home.path(), &path, Some("cpu"), &[]);
    assert_eq!(code_cpu, Some(0), "cpu clean-file exit 0");
    assert_eq!(detector_ids(&out_cpu), Vec::<String>::new());

    // simd (available) must agree the clean file is empty (exit 0, no
    // engine-specific FP); simd (unavailable) fails closed at engine selection.
    assert_accel_matches_cpu_or_fails_closed(home.path(), &path, "simd");
}

// ---------------------------------------------------------------------------
// Adversarial / negative twins: invalid selectors and fail-closed autoroute.
// ---------------------------------------------------------------------------

#[test]
fn scalar_alias_is_rejected_by_the_cli_parser_exit_2() {
    // COHERENCE GAP: `scalar` is a canonical alias inside
    // `keyhog_scanner::hw_probe::parse_backend_str` (-> CpuFallback), whose own
    // doc calls itself "the single source of truth for CLI/config backend
    // parsing" — yet it is NOT in `BACKEND_OVERRIDE_VALUES`, the list clap
    // validates `--backend` against. So the CLI rejects `--backend scalar`
    // before routing ever sees it. This test pins the CURRENT (buggy) behavior:
    // exit 2, not a scan.
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let (code, _out, err) = scan(home.path(), &path, Some("scalar"), &[]);

    assert_eq!(
        code,
        Some(2),
        "clap rejects the unadvertised `scalar` value -> exit 2 (user error); stderr={err}"
    );
    assert!(
        err.contains("scalar"),
        "the parser error must name the rejected value; stderr={err}"
    );
    assert!(
        err.contains("possible values") || err.contains("invalid value"),
        "clap must explain the valid set / invalid value; stderr={err}"
    );
}

#[test]
fn unknown_backend_value_is_rejected_by_the_cli_parser_exit_2() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let (code, _out, err) = scan(home.path(), &path, Some("turbo"), &[]);

    assert_eq!(
        code,
        Some(2),
        "an unknown backend value must fail closed at parse time -> exit 2; stderr={err}"
    );
    assert!(
        err.contains("turbo"),
        "the parser error must name the rejected `turbo` value; stderr={err}"
    );
}

#[test]
fn auto_backend_without_calibration_never_returns_a_silently_wrong_result() {
    // `--backend auto` routes through the persisted autoroute cache. With the
    // cache disabled (`--autoroute-cache off`) there is no cached decision, so
    // auto must NEVER return a silently-wrong answer (Law 10). The host-agnostic
    // contract is a disjunction:
    //   (a) FAIL CLOSED — exit 2 with "autoroute calibration required", OR
    //   (b) COMPLETE with a correct scan — exit 1 and the SAME finding set as
    //       an explicit cpu run (auto legitimately resolved a real engine).
    // What is forbidden is exit 1 with a dropped/empty finding set, or exit 0
    // on a file that plainly carries a secret.
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let (code, out, err) = scan(
        home.path(),
        &path,
        Some("auto"),
        &["--autoroute-cache", "off"],
    );

    let (_c, out_cpu, _) = scan(home.path(), &path, Some("cpu"), &[]);
    if code == Some(2) {
        assert!(
            err.contains("autoroute calibration required"),
            "fail-closed auto must tell the operator to calibrate; stderr={err}"
        );
    } else {
        assert_eq!(
            code,
            Some(1),
            "uncalibrated auto must either fail closed (2) or complete (1), \
             never exit 0 on a file with a secret; stdout={out} stderr={err}"
        );
        assert_eq!(
            ordered_findings(&out),
            ordered_findings(&out_cpu),
            "a completing auto run must match cpu's finding set exactly (no silent drop)"
        );
    }
}

#[test]
fn calibrated_auto_backend_surfaces_the_same_finding_set_as_cpu() {
    // Positive counterpart to the fail-closed test: once the autoroute cache is
    // primed, `--backend auto` must resolve a real engine and surface the SAME
    // finding an explicit engine does. Calibration and the scan share the
    // hermetic HOME/XDG_CACHE_HOME so both resolve the same on-disk cache.
    let home = cache_home();

    let calibrate = Command::new(binary())
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .env("NO_COLOR", "1")
        .args(["calibrate-autoroute", "--quiet"])
        .output()
        .expect("spawn keyhog calibrate-autoroute");
    assert_eq!(
        calibrate.status.code(),
        Some(0),
        "calibrate-autoroute must prime the cache (exit 0); stderr={}",
        String::from_utf8_lossy(&calibrate.stderr)
    );

    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let (code_auto, out_auto, err_auto) = scan(home.path(), &path, Some("auto"), &[]);
    let (_code_cpu, out_cpu, _) = scan(home.path(), &path, Some("cpu"), &[]);

    assert_eq!(
        code_auto,
        Some(1),
        "calibrated autoroute must complete the scan and find the plant (exit 1); \
         stdout={out_auto} stderr={err_auto}"
    );
    assert_eq!(
        detector_ids(&out_auto),
        vec![GHP_DETECTOR.to_string()],
        "calibrated auto must surface exactly github-classic-pat; stdout={out_auto}"
    );
    assert_eq!(
        cred_hashes(&out_auto),
        cred_hashes(&out_cpu),
        "calibrated auto and explicit cpu must agree on the credential hash"
    );
}
