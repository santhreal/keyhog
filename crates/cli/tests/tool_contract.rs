//! Real-tool contract tests: exercise the actual `keyhog` binary end-to-end and
//! assert TOOL behavior (exit codes, detector load-integrity, output-format
//! well-formedness). This file asserts NOTHING about detection accuracy
//! (precision/recall/F1) — that is the SecretBench scorer's job. Keep this
//! boundary: tests verify the tool; the bench measures detection.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_keyhog")
}

fn detectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

/// Run `keyhog <args>` and return (exit_code, stdout).
fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("keyhog binary runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// A scratch dir unique to this process, holding one planted-secret file and a
/// clean file. Uses a synthetic AWS access key SHAPE purely as scan INPUT; the
/// test asserts the tool's exit-code behavior, not that this value is "a secret".
fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("kh_tool_contract_{}", std::process::id()));
    let _ = fs::create_dir_all(d.join("planted"));
    let _ = fs::create_dir_all(d.join("clean"));
    fs::write(
        d.join("planted/app.env"),
        "AWS_KEY = \"AKIA".to_string() + "IOSFODNN7DOGFOOD\"\n",
    )
    .unwrap();
    fs::write(
        d.join("clean/notes.txt"),
        "plain prose, nothing sensitive\n",
    )
    .unwrap();
    d
}

#[test]
fn exit_code_contract_clean_findings_error() {
    let d = fixture_dir();
    let clean = d.join("clean");
    let planted = d.join("planted");

    let (clean_ec, _) = run(&["scan", clean.to_str().unwrap(), "--no-daemon"]);
    assert_eq!(clean_ec, 0, "clean scan must exit 0 (no findings)");

    let (planted_ec, _) = run(&["scan", planted.to_str().unwrap(), "--no-daemon"]);
    assert_eq!(planted_ec, 1, "scan with findings must exit 1");

    let (missing_ec, _) = run(&["scan", "/no/such/path/kh-contract", "--no-daemon"]);
    assert!(
        missing_ec >= 2,
        "scan of a nonexistent path must exit >=2 (user/source/system error), got {missing_ec}"
    );
}

#[test]
fn every_detector_toml_is_loaded_by_the_binary() {
    // Load-integrity at the BINARY level: a detector TOML that fails to parse or
    // compile is silently dropped from the embedded set (this is exactly how
    // discord-bot-token went dead). The count the binary reports must equal the
    // number of detector TOMLs on disk — no silent drops.
    let toml_count = fs::read_dir(detectors_dir())
        .expect("detectors dir readable")
        .flatten()
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("toml"))
        .count();
    assert!(
        toml_count > 800,
        "sanity: expected the full detector corpus, saw {toml_count}"
    );

    let (ec, stdout) = run(&["detectors"]);
    assert_eq!(ec, 0, "`keyhog detectors` must succeed");

    // Human listing prints a "<N> detectors" summary; extract N robustly.
    let reported = stdout
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| {
            w[1].trim_matches(|c: char| !c.is_alphanumeric())
                .starts_with("detector")
        })
        .and_then(|w| w[0].replace(',', "").parse::<usize>().ok())
        .expect("`keyhog detectors` prints a '<N> detectors' count");

    assert_eq!(
        reported, toml_count,
        "binary loaded {reported} detectors but {toml_count} TOMLs exist on disk — a detector was silently dropped (parse/compile failure)"
    );
}

#[test]
fn output_formats_are_well_formed() {
    let d = fixture_dir();
    let planted = d.join("planted");
    let p = planted.to_str().unwrap();

    for fmt in ["text", "json", "jsonl", "sarif", "csv", "junit", "html"] {
        let (ec, out) = run(&["scan", p, "--no-daemon", "--format", fmt]);
        assert!(
            ec == 0 || ec == 1,
            "--format {fmt} must exit 0/1 (not an operator/configuration error), got {ec}"
        );
        assert!(
            !out.trim().is_empty(),
            "--format {fmt} produced empty stdout"
        );
        match fmt {
            "sarif" => assert!(
                out.contains("\"version\"") && out.contains("\"runs\""),
                "sarif missing version/runs"
            ),
            "html" => assert!(out.contains("<!DOCTYPE html>"), "html missing doctype"),
            "json" | "jsonl" => assert!(out.contains('{'), "json/jsonl produced no object"),
            "junit" => assert!(
                out.contains("<testsuite") || out.contains("<testsuites"),
                "junit missing testsuite"
            ),
            "csv" => assert!(out.contains(','), "csv missing delimiter"),
            _ => {}
        }
    }
}
