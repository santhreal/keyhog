//! Whole-process profiling boundary contracts.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn detectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

/// The profile session must include config resolution and scanner compilation.
///
/// The former boundary started the session only after `ScanOrchestrator::new`
/// returned. On the canonical corpus, most process wall time was therefore
/// outside the profile even though the artifact claimed to describe the scan.
#[test]
fn explicit_profile_covers_most_of_whole_process_wall() {
    let temporary = TempDir::new().expect("create profile boundary fixture");
    let input = temporary.path().join(".env.secret");
    let output = temporary.path().join("result.json");
    let profile = temporary.path().join("profile.json");
    std::fs::write(
        &input,
        "GITHUB_TOKEN=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\n",
    )
    .expect("write scan fixture");

    let started = Instant::now();
    let result = Command::new(binary())
        .args([
            "scan",
            "--no-config",
            "--detectors",
            detectors().to_str().expect("detector path is UTF-8"),
            "--backend",
            "cpu",
            "--no-gpu",
            "--daemon=off",
            "--format",
            "json-envelope",
            "--output",
            output.to_str().expect("output path is UTF-8"),
            "--profile-out",
            profile.to_str().expect("profile path is UTF-8"),
            input.to_str().expect("input path is UTF-8"),
        ])
        .output()
        .expect("run profiled scanner");
    let external_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    assert!(
        matches!(result.status.code(), Some(0 | 1 | 10 | 13)),
        "profiled scan failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let artifact: Value = serde_json::from_slice(
        &std::fs::read(&profile).expect("profile artifact must be published"),
    )
    .expect("profile artifact must be JSON");
    let profile_ns = artifact["wall_time_ns"]
        .as_u64()
        .expect("profile wall_time_ns must be an integer");
    assert!(
        profile_ns <= external_ns,
        "profile cannot start before process spawn"
    );
    assert!(
        profile_ns.saturating_mul(2) >= external_ns,
        "profile excluded most process work: profile={profile_ns}ns external={external_ns}ns"
    );
    let stages = artifact["stages"]
        .as_array()
        .expect("profile stages must be an array");
    let elapsed = |name: &str| -> u64 {
        stages
            .iter()
            .filter(|stage| stage["stage"] == name)
            .map(|stage| stage["elapsed_ns"].as_u64().expect("stage elapsed_ns"))
            .sum()
    };
    assert!(
        elapsed("preprocess") > 0,
        "configuration preprocessing was not attributed"
    );
    assert!(
        elapsed("detector-load") > 0,
        "detector loading was not attributed"
    );
    assert!(
        elapsed("detector-validate") > 0,
        "detector validation was not attributed"
    );
    assert!(
        elapsed("execution-pack-select") > 0,
        "execution plan selection was not attributed"
    );
    assert!(
        elapsed("execution-pack-map") > 0,
        "execution plan materialization was not attributed"
    );
    assert!(
        elapsed("backend-acquire") > 0,
        "backend availability acquisition was not attributed"
    );
    assert!(
        elapsed("backend-init") > 0,
        "backend initialization was not attributed"
    );
    assert!(
        elapsed("source-acquire") > 0,
        "source acquisition was not attributed"
    );
    assert!(
        elapsed("source-walk") > 0,
        "filesystem fanout was not attributed"
    );
    assert!(
        elapsed("source-read") > 0,
        "source reads were not attributed"
    );
    assert!(
        elapsed("backend-dispatch") > 0,
        "scan dispatch was not attributed"
    );
    assert!(
        elapsed("source-queue-wait") > 0,
        "source producer queue wait was not attributed"
    );
    assert!(elapsed("suppression") > 0, "suppression was not attributed");
    assert!(
        elapsed("result-merge") > 0,
        "finding merge was not attributed"
    );
    assert!(
        elapsed("reporting") > 0,
        "report serialization was not attributed"
    );
    assert!(
        elapsed("teardown") > 0,
        "scanner teardown was not attributed"
    );
    assert_eq!(
        artifact["system"]["status"], "recorded",
        "retained process memory evidence is missing"
    );
    assert_eq!(
        artifact["system"]["value"]["memory"]["resident_bytes"]["value"]["status"], "recorded",
        "finish-time resident memory is missing"
    );
    assert_eq!(
        artifact["system"]["value"]["memory"]["resident_high_water_bytes"]["value"]["status"],
        "recorded",
        "peak resident memory is missing"
    );
    let live_bytes = artifact["system"]["value"]["memory"]["resident_bytes"]["value"]["value"]
        .as_u64()
        .expect("live resident bytes");
    let peak_bytes = artifact["system"]["value"]["memory"]["resident_high_water_bytes"]["value"]
        ["value"]
        .as_u64()
        .expect("peak resident bytes");
    assert!(
        live_bytes > 0 && peak_bytes >= live_bytes,
        "resident memory evidence is inconsistent: live={live_bytes} peak={peak_bytes}"
    );
    #[cfg(feature = "allocation-profile")]
    {
        let allocation = &artifact["system"]["value"]["allocation"];
        assert_eq!(
            allocation["totals"]["status"], "recorded",
            "allocation totals are missing"
        );
        let totals = &allocation["totals"]["value"];
        assert!(totals["allocations"].as_u64().expect("allocation count") > 0);
        assert!(totals["allocated_bytes"].as_u64().expect("allocated bytes") > 0);
        let owned = allocation["stages"]
            .as_array()
            .expect("allocation stage owners");
        for owner in ["detector-load", "backend-init", "reporting"] {
            let row = owned
                .iter()
                .find(|row| row["metric_id"] == owner)
                .unwrap_or_else(|| panic!("allocation owner {owner} missing"));
            assert!(
                row["allocated_bytes"]
                    .as_u64()
                    .expect("owner allocated bytes")
                    > 0,
                "allocation owner {owner} recorded no bytes"
            );
        }
    }
}
