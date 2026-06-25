//! Dogfood release-gate (CLAUDE.md "release gate" + whole-path contract).
//!
//! Drives the real `keyhog` binary over a fixed, committed corpus and
//! asserts exit code, a duration band, and exact findings (detector id +
//! line) per scenario. Each scenario is one TOML file under `scenarios/`;
//! drop a new TOML plus its corpus file under `corpus/` and the gate picks
//! it up automatically: no runner edit needed.
//!
//! Why TempDir: the corpus lives under `tests/`, where keyhog's path
//! heuristic suppresses matches, so the committed sample credentials never
//! trip the repo self-scan in CI. The runner copies each scenario's corpus
//! into a fresh TempDir (a non-`tests/` path) before scanning, so detection
//! fires at real confidence, mirroring the existing e2e_binary tests.
//!
//! Intentional output drift = update the scenario TOML + add a one-line WHY
//! row to `tests/dogfood/CHANGELOG` in the same commit.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::e2e::support::apply_default_scan_backend;
#[cfg(unix)]
use crate::e2e::support::DaemonGuard;
use serde::Deserialize;
use tempfile::TempDir;

#[derive(Deserialize)]
struct Scenario {
    #[allow(dead_code)]
    description: String,
    #[serde(default)]
    corpus: Vec<String>,
    args: Vec<String>,
    exit_code: i32,
    max_ms: u64,
    #[serde(default)]
    expect: Vec<ExpectFinding>,
    expect_total: Option<usize>,
    #[serde(default)]
    forbid: Vec<String>,
    #[serde(default)]
    stdout_contains: Vec<String>,
    #[serde(default)]
    stdout_excludes: Vec<String>,
}

#[derive(Deserialize)]
struct ExpectFinding {
    detector_id: String,
    line: Option<u64>,
}

fn dogfood_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dogfood")
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Tokens that GitHub's secret-scanning push protection recognizes (Stripe,
/// Slack, ...) cannot be committed verbatim, so the corpus stores a
/// placeholder and the real value lives here hex-encoded (which matches no
/// provider pattern). The runner decodes and substitutes it into the
/// TempDir copy at scan time, so keyhog still sees the real bytes while the
/// committed tree stays push-clean. AWS/`ghp_` shapes are not push-protected
/// in this repo, so those corpus files hold them literally.
const RECONSTRUCT: &[(&str, &str)] = &[
    (
        "@@STRIPE@@",
        "736b5f6c6976655f353148387a39624b785977567554735271506f4e6d4c6b4a69486746654463426130",
    ),
    (
        "@@SLACK@@",
        "786f78622d323431373832333539322d323431373832333539322d4162436445664768496a4b6c4d6e4f705172537455765778",
    ),
];

fn hex_decode(hex: &str) -> String {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex in RECONSTRUCT"))
        .collect();
    String::from_utf8(bytes).expect("RECONSTRUCT decodes to UTF-8")
}

/// Read a corpus file and substitute any push-protected placeholders with
/// their decoded values.
fn materialize(corpus_file: &Path) -> std::io::Result<String> {
    let mut content = std::fs::read_to_string(corpus_file)?;
    for (placeholder, hex) in RECONSTRUCT {
        if content.contains(placeholder) {
            content = content.replace(placeholder, &hex_decode(hex));
        }
    }
    Ok(content)
}

fn daemon_eligible_single_file_scan(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("scan") {
        return false;
    }
    if args
        .iter()
        .any(|arg| arg == "--no-daemon" || arg == "--daemon" || arg.starts_with("--daemon="))
    {
        return false;
    }
    let Some(path_arg) = args.last() else {
        return false;
    };
    let path = Path::new(path_arg);
    path.is_file()
}

fn run_scenario(path: &Path, daemon_runtime_dir: Option<&Path>) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    let sc: Scenario = toml::from_str(&raw).map_err(|e| format!("parse: {e}"))?;

    // Stage corpus into a fresh TempDir outside any `tests/` path so the
    // scanner does not down-weight it as a test fixture.
    let tmp = TempDir::new().map_err(|e| format!("tempdir: {e}"))?;
    for f in &sc.corpus {
        let content = materialize(&dogfood_dir().join("corpus").join(f))
            .map_err(|e| format!("stage {f}: {e}"))?;
        std::fs::write(tmp.path().join(f), content).map_err(|e| format!("write {f}: {e}"))?;
    }
    let corpus_dir = tmp.path().to_string_lossy().into_owned();
    let mut args: Vec<String> = sc
        .args
        .iter()
        .map(|a| a.replace("{corpus}", &corpus_dir))
        .collect();
    let daemon_routed = daemon_runtime_dir.is_some() && daemon_eligible_single_file_scan(&args);
    if daemon_routed {
        args.insert(1, "--daemon=on".to_string());
    }

    let start = Instant::now();
    let mut cmd = Command::new(binary());
    if let Some(runtime_dir) = daemon_runtime_dir {
        cmd.env("XDG_RUNTIME_DIR", runtime_dir);
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    if daemon_routed {
        // The daemon resolves its backend server-side (it is started with
        // `--backend simd` in `DaemonGuard`); a per-request `--backend` is a
        // control the daemon protocol forbids (it would exit 2 "cannot be
        // honored"). Route the scan as-is so the daemon's own simd backend runs.
        cmd.args(&arg_refs);
    } else {
        apply_default_scan_backend(&mut cmd, &arg_refs);
    }
    let out = cmd
        .current_dir(tmp.path())
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    let elapsed = start.elapsed().as_millis() as u64;

    let stdout = String::from_utf8_lossy(&out.stdout);
    let code = out.status.code();

    let mut errs = Vec::new();
    if code != Some(sc.exit_code) {
        errs.push(format!("exit code: want {}, got {:?}", sc.exit_code, code));
    }
    if elapsed > sc.max_ms {
        errs.push(format!("duration: {elapsed}ms exceeds max {}ms", sc.max_ms));
    }
    for needle in &sc.stdout_contains {
        if !stdout.contains(needle.as_str()) {
            errs.push(format!("stdout missing {needle:?}"));
        }
    }
    for needle in &sc.stdout_excludes {
        if stdout.contains(needle.as_str()) {
            errs.push(format!("stdout unexpectedly contains {needle:?}"));
        }
    }

    // Findings assertions are checked only when the scenario declares them,
    // and require stdout to parse as a JSON findings array.
    let need_findings = !sc.expect.is_empty() || sc.expect_total.is_some() || !sc.forbid.is_empty();
    if need_findings {
        match serde_json::from_str::<serde_json::Value>(&stdout) {
            Ok(serde_json::Value::Array(arr)) => {
                let got: Vec<(String, Option<u64>)> = arr
                    .iter()
                    .map(|f| {
                        let id = f
                            .get("detector_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let line = f
                            .get("location")
                            .and_then(|l| l.get("line"))
                            .and_then(|v| v.as_u64());
                        (id, line)
                    })
                    .collect();
                if let Some(total) = sc.expect_total {
                    if got.len() != total {
                        errs.push(format!(
                            "finding count: want {total}, got {} ({got:?})",
                            got.len()
                        ));
                    }
                }
                for ex in &sc.expect {
                    let hit = got.iter().any(|(id, line)| {
                        id == &ex.detector_id && (ex.line.is_none() || *line == ex.line)
                    });
                    if !hit {
                        errs.push(format!(
                            "missing finding {} @line {:?}; got {got:?}",
                            ex.detector_id, ex.line
                        ));
                    }
                }
                for fb in &sc.forbid {
                    if got.iter().any(|(id, _)| id == fb) {
                        errs.push(format!("forbidden detector {fb} fired"));
                    }
                }
            }
            _ => errs.push(format!(
                "expected JSON array on stdout; got: {}",
                stdout.chars().take(200).collect::<String>()
            )),
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

#[test]
fn dogfood_release_gate() {
    #[cfg(unix)]
    let daemon = DaemonGuard::start();
    #[cfg(unix)]
    let daemon_runtime_dir = Some(daemon.runtime_dir().to_path_buf());
    #[cfg(not(unix))]
    let daemon_runtime_dir: Option<PathBuf> = None;

    let scen_dir = dogfood_dir().join("scenarios");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&scen_dir)
        .unwrap_or_else(|e| panic!("read scenarios dir {scen_dir:?}: {e}"))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no dogfood scenarios found in {scen_dir:?}"
    );

    let mut failures = Vec::new();
    for f in &files {
        let name = f.file_stem().unwrap().to_string_lossy().into_owned();
        if let Err(why) = run_scenario(f, daemon_runtime_dir.as_deref()) {
            failures.push(format!("[{name}] {why}"));
        }
    }

    assert!(
        failures.is_empty(),
        "dogfood release gate: {} of {} scenarios failed:\n  {}",
        failures.len(),
        files.len(),
        failures.join("\n  ")
    );
    eprintln!("dogfood release gate: all {} scenarios passed", files.len());
}
