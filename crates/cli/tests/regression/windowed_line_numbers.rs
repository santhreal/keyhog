//! Regression: findings in files past the windowing threshold must report
//! the ABSOLUTE file line, not the per-window line.
//!
//! Files larger than `DEFAULT_WINDOW_SIZE` (1 MiB) are scanned by the
//! filesystem `filesystem/windowed` path, which slices the file into
//! overlapping ~1 MiB windows. Every emit site already made the byte
//! `offset` absolute (`+ chunk.metadata.base_offset`), but the LINE was
//! left window-local: there was no `base_line` on `ChunkMetadata`, so a
//! secret on line 584307 of a 70 MiB file was reported at the per-window
//! line (~2), and the reported lines were even non-monotonic (a later
//! secret got a smaller line number than an earlier one). A scanner whose
//! `file:line` points nowhere near the leak is unusable for triage.
//!
//! The fix adds `ChunkMetadata::base_line` (the line analog of
//! `base_offset`), populated per-window by the filesystem source and added
//! at every line emit site. This test plants distinct AWS-key-shaped
//! secrets at known absolute lines that fall in three different windows of
//! a >2 MiB file, runs the real binary, and asserts every reported line is
//! exactly the planted absolute line. It also asserts the
//! `filesystem/windowed` source actually fired, so the test cannot silently
//! stop exercising the windowed path if the threshold changes.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use crate::e2e::support::apply_default_scan_backend;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// The repo's `detectors/` dir, so the real `aws-access-key` detector is
/// loaded rather than whatever subset the embedded corpus carries (same
/// anchor the daemon e2e tests use).
fn workspace_detectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../detectors")
        .canonicalize()
        .expect("workspace detectors dir")
}

/// Three distinct, valid-shape AWS access keys (`AKIA` + 16 base32 chars).
/// Distinct bodies so each finding is unambiguously matched back to the
/// line it was planted on. Split via `concat!` so this source file does not
/// trip a self-scan of the test tree.
fn planted_keys() -> [String; 3] {
    [
        concat!("AKIA", "QYLPMN5HFIQR7XYA").to_string(),
        concat!("AKIA", "2B3C4D5E6F7G2H3J").to_string(),
        concat!("AKIA", "K4L5M6N7P2Q3R4S5").to_string(),
    ]
}

#[test]
fn windowed_file_reports_absolute_line_numbers() {
    let keys = planted_keys();

    // Build a > 2 MiB file (multiple ~1 MiB windows). Plant the three keys
    // at line indices chosen to land in window 0, window 1, and window 2
    // respectively, tracking the true 1-based line of each as we build.
    let plant_at = [10usize, 33_000, 60_000];
    let total_lines = 66_000usize;
    let mut content = String::with_capacity(total_lines * 36);
    let mut planted_line: [usize; 3] = [0; 3];
    for i in 1..=total_lines {
        if let Some(slot) = plant_at.iter().position(|&p| p == i) {
            // 1-based line number == current line index `i`.
            planted_line[slot] = i;
            content.push_str(&format!("aws_key_{slot} = \"{}\"\n", keys[slot]));
        } else {
            content.push_str(&format!("const PLACEHOLDER_VALUE_{i:08} = {i};\n"));
        }
    }
    assert!(
        content.len() > 2 * 1024 * 1024,
        "fixture must exceed the 1 MiB window threshold (got {} bytes)",
        content.len()
    );
    assert!(
        planted_line.iter().all(|&l| l != 0),
        "every key must have been planted"
    );

    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("big_secrets.txt");
    {
        let mut f = std::fs::File::create(&file).expect("create fixture");
        f.write_all(content.as_bytes()).expect("write fixture");
    }

    let mut cmd = Command::new(binary());
    apply_default_scan_backend(
        &mut cmd,
        &[
            "scan",
            "--no-daemon",
            "--no-suppress-test-fixtures",
            "--detectors",
        ],
    );
    let output = cmd
        .arg(workspace_detectors())
        .arg("--format")
        .arg("json")
        .arg(&file)
        .output()
        .expect("run keyhog scan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("scan stdout was not JSON: {e}\n{stdout}"));
    let findings = parsed
        .get("findings")
        .and_then(|f| f.as_array())
        .cloned()
        .or_else(|| parsed.as_array().cloned())
        .expect("findings array in scan output");

    // Map each planted key's redacted prefix back to its reported line, and
    // confirm at least one finding came through the windowed source so we
    // know the windowed path was actually exercised.
    let mut saw_windowed = false;
    let mut reported_line: [Option<u64>; 3] = [None; 3];
    for f in &findings {
        let loc = f.get("location").expect("finding.location");
        let src = loc.get("source").and_then(|s| s.as_str()).unwrap_or("");
        if src.contains("windowed") {
            saw_windowed = true;
        }
        let redacted = f
            .get("credential_redacted")
            .and_then(|c| c.as_str())
            .unwrap_or("");
        let line = loc.get("line").and_then(|l| l.as_u64());
        // Redaction is `<first edge>...<last edge>` where edge =
        // (len/8).clamp(1,4) (see `core::redact`); these AWS keys are 20 ASCII
        // chars so edge = 2, i.e. `AK...<last2>`. Build the exact expected form
        // per key and match on equality so each finding maps unambiguously back
        // to the line it was planted on.
        for (slot, key) in keys.iter().enumerate() {
            let edge = (key.len() / 8).clamp(1, 4);
            let expected = format!("{}...{}", &key[..edge], &key[key.len() - edge..]);
            if redacted == expected {
                reported_line[slot] = line;
            }
        }
    }

    assert!(
        saw_windowed,
        "no finding came from the `filesystem/windowed` source — the >1 MiB \
         fixture did not exercise the windowed path; the threshold may have \
         changed and this regression is no longer testing what it claims"
    );

    for slot in 0..3 {
        let expected = planted_line[slot] as u64;
        let got = reported_line[slot].unwrap_or_else(|| {
            panic!(
                "key #{slot} planted on line {expected} was not reported at all \
                 (windowed-scan recall regression)"
            )
        });
        assert_eq!(
            got, expected,
            "windowed-scan line attribution: key #{slot} planted on absolute \
             line {expected} was reported on line {got} (window-local leak — \
             the base_line fix regressed)"
        );
    }
}
