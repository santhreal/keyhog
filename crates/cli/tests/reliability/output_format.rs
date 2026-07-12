//! Every output format is a contract with a downstream consumer (jq, a SIEM, a
//! SARIF upload). It must be well-formed on BOTH clean and finding runs, carry
//! the documented fields, and stay free of ANSI when piped.

use std::path::Path;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

use crate::reliability::harness::binary;

const PLANTED_AWS: &str = "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n";

fn scan(content: &str, fmt: &str) -> (Option<i32>, String, String) {
    let d = TempDir::new().unwrap();
    let p = d.path().join("planted.txt");
    std::fs::write(&p, content).unwrap();
    scan_path(&p, fmt)
}

fn scan_path(p: &Path, fmt: &str) -> (Option<i32>, String, String) {
    let out = Command::new(binary())
        .args(["scan", "--no-daemon", "--backend", "simd", "--format", fmt])
        .arg(p)
        .output()
        .expect("spawn keyhog");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn json_clean_is_valid_json() {
    let (_c, o, _e) = scan("clean prose\n", "json");
    serde_json::from_str::<Value>(o.trim()).expect("clean --format json must be valid JSON");
}

#[test]
fn json_finding_is_valid_json() {
    let (_c, o, _e) = scan(PLANTED_AWS, "json");
    serde_json::from_str::<Value>(o.trim()).expect("finding --format json must be valid JSON");
}

#[test]
fn json_finding_carries_documented_fields() {
    let (_c, o, _e) = scan(PLANTED_AWS, "json");
    let v: Value = serde_json::from_str(o.trim()).expect("valid JSON");
    // Locate any finding object in the doc (array root or under a key).
    let blob = v.to_string();
    assert!(
        blob.contains("line") && (blob.contains("detector") || blob.contains("rule")),
        "JSON finding lacks line/detector fields a consumer needs:\n{}",
        o.chars().take(500).collect::<String>()
    );
}

#[test]
fn jsonl_each_nonempty_line_is_a_json_object() {
    let (_c, o, _e) = scan(PLANTED_AWS, "jsonl");
    let mut sawn = 0;
    for (i, line) in o.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("jsonl line {i} is not valid JSON: {e}\n{line}"));
        assert!(v.is_object(), "jsonl line {i} is not a JSON object: {line}");
        sawn += 1;
    }
    assert!(sawn >= 1, "jsonl produced no objects for a planted secret");
}

#[test]
fn jsonl_has_no_multiline_objects() {
    // Each finding must be exactly one line so `while read` / streaming parsers
    // work. A line that fails to parse means an object was split across lines.
    let (_c, o, _e) = scan(PLANTED_AWS, "jsonl");
    for line in o.lines() {
        if line.trim().is_empty() {
            continue;
        }
        assert!(
            serde_json::from_str::<Value>(line).is_ok(),
            "jsonl emitted a multi-line / split object:\n{line}"
        );
    }
}

#[test]
fn sarif_finding_is_valid_and_has_runs() {
    let (_c, o, _e) = scan(PLANTED_AWS, "sarif");
    let v: Value = serde_json::from_str(o.trim()).expect("sarif must be valid JSON");
    assert!(
        v.get("runs").is_some(),
        "SARIF output missing top-level `runs` array:\n{}",
        o.chars().take(400).collect::<String>()
    );
    // Law 6: require BOTH the exact version AND the schema, not "either key
    // present" — a downstream SARIF consumer needs both to validate the document.
    assert_eq!(
        v["version"].as_str(),
        Some("2.1.0"),
        "SARIF `version` must be exactly 2.1.0; got {v}"
    );
    assert!(
        v["$schema"].as_str().is_some_and(|s| s.contains("sarif")),
        "SARIF must carry a `$schema` referencing the SARIF schema; got {v}"
    );
}

#[test]
fn sarif_clean_is_valid_and_has_runs() {
    let (_c, o, _e) = scan("clean prose\n", "sarif");
    let v: Value = serde_json::from_str(o.trim()).expect("clean sarif must be valid JSON");
    // Law 6: `runs` must be a real array with a run whose results are present and
    // EMPTY on a clean scan — not merely that the key exists.
    let runs = v["runs"]
        .as_array()
        .expect("clean SARIF must carry a runs array");
    assert!(
        !runs.is_empty(),
        "SARIF must have at least one run; got {v}"
    );
    assert!(
        runs[0]["results"].as_array().is_some_and(|r| r.is_empty()),
        "a clean scan must produce zero SARIF results; got {v}"
    );
}

#[test]
fn text_format_has_no_ansi_when_piped() {
    let (_c, o, e) = scan(PLANTED_AWS, "text");
    assert!(
        !o.as_bytes().contains(&0x1b) && !e.as_bytes().contains(&0x1b),
        "text format leaked ANSI escapes when piped (non-TTY)"
    );
}

#[test]
fn json_stdout_is_pure_json_no_log_noise() {
    // Logs go to stderr; stdout in --format json must be ONLY the JSON document.
    let (_c, o, _e) = scan(PLANTED_AWS, "json");
    let t = o.trim();
    assert!(
        t.starts_with('{') || t.starts_with('['),
        "json stdout has non-JSON leading content (log noise?):\n{}",
        t.chars().take(200).collect::<String>()
    );
}

#[test]
fn json_stays_clean_under_clicolor_force() {
    // CLICOLOR_FORCE forces color on human surfaces, but a machine-readable
    // format must NEVER be colored - ANSI in JSON breaks every parser.
    let d = TempDir::new().unwrap();
    let p = d.path().join("planted.txt");
    std::fs::write(&p, PLANTED_AWS).unwrap();
    let out = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
        ])
        .arg(&p)
        .env("CLICOLOR_FORCE", "1")
        .env_remove("NO_COLOR")
        .output()
        .unwrap();
    assert!(
        !out.stdout.contains(&0x1b),
        "--format json leaked ANSI under CLICOLOR_FORCE (machine output must stay clean)"
    );
    serde_json::from_slice::<Value>(&out.stdout).expect("json still valid under CLICOLOR_FORCE");
}

#[test]
fn finding_set_is_deterministic_across_runs() {
    // Scan the SAME file twice (a fresh temp file per run would differ only by
    // its random path, which is not the determinism we're testing).
    let d = TempDir::new().unwrap();
    let p = d.path().join("planted.txt");
    std::fs::write(&p, PLANTED_AWS).unwrap();
    let (_c1, a, _e1) = scan_path(&p, "json");
    let (_c2, b, _e2) = scan_path(&p, "json");
    let va: Value = serde_json::from_str(a.trim()).unwrap();
    let vb: Value = serde_json::from_str(b.trim()).unwrap();
    // Compare the structural finding payload (ignoring any timing/duration
    // fields by normalizing them out if present).
    fn strip_timing(mut v: Value) -> Value {
        if let Some(obj) = v.as_object_mut() {
            for k in [
                "duration_ms",
                "elapsed_ms",
                "scanned_at",
                "timestamp",
                "duration",
            ] {
                obj.remove(k);
            }
        }
        v
    }
    assert_eq!(
        strip_timing(va),
        strip_timing(vb),
        "the same scan produced a different finding set across runs (nondeterministic detection/order)"
    );
}
