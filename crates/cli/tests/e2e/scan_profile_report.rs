use super::support::{binary, write_temp_file};
use std::process::Command;

/// A profiled scan must emit one causal run report with source, backend, input, state, and resource evidence.
#[test]
fn scan_profile_emits_causal_run_identity_and_macro_measurements() {
    let (_dir, path) = write_temp_file("clean.txt", "ordinary profile fixture\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--quiet",
            "--profile",
            path.to_str().expect("utf-8 fixture path"),
        ])
        .output()
        .expect("run profiled scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert_eq!(stdout, "[]");
    assert!(!stderr.contains("=== keyhog profile [keyhog scan] ==="));
    assert!(stderr.contains(
        "state=completed source=filesystem workload=filesystem \
         backend_requested=cpu-fallback backend_selected=cpu-fallback cache=disabled daemon=off"
    ));
    assert!(stderr.contains("input_bytes=25 input_units=1 throughput_mib_s="));
    assert!(stderr.contains("source-acquire"));
    assert!(stderr.contains("source-walk"));
    assert!(stderr.contains("source-read"));
    assert!(stderr.contains("source-queue-wait"));
    assert!(stderr.contains("backend-select"));
    assert!(stderr.contains("result-merge"));
    assert!(stderr.contains("macro scanning"));
    assert!(stderr.contains("macro resolving"));
    assert!(stderr.contains("bottleneck macro="));
    // `backend-dispatch` is the GPU region-dispatch and literal-compile stage
    // (`crates/scanner/src/scan_profile.rs`); a `--backend cpu` run performs no
    // region dispatch, so the stage this scan attributes is `scan-pipeline`.
    assert!(stderr.contains("scan-pipeline"));
    assert!(
        !stderr.contains("backend-dispatch"),
        "a CPU-only scan must not attribute GPU region dispatch; stderr={stderr}"
    );
    assert!(stderr.contains("suppression"));
    assert!(stderr.contains("live-verification"));
    assert!(stderr.contains("reporting"));
    assert!(stderr.contains("resources aggregate_cpu="));
    assert!(stderr.contains("max_observed_rss_bytes="));
    let build_line = stderr
        .lines()
        .find(|line| line.starts_with("build binary_sha256="))
        .expect("profile build identity line");
    for field in [
        "binary_sha256=",
        "feature_sha256=",
        "target=",
        "profile=",
        "compiler=",
        "allocator=",
        "backends_sha256=",
    ] {
        assert!(build_line.contains(field), "missing {field}: {build_line}");
    }
    let binary_digest = build_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("binary_sha256="))
        .expect("binary SHA-256 field");
    let feature_digest = build_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("feature_sha256="))
        .expect("feature SHA-256 field");
    assert_eq!(binary_digest.len(), 64);
    assert_eq!(feature_digest.len(), 64);
    let detector_line = stderr
        .lines()
        .find(|line| line.starts_with("detectors corpus_sha256="))
        .expect("profile detector identity line");
    for field in [
        "corpus_sha256=",
        "compiled_plan_blake3=",
        "enabled_detector_blake3=",
        "backend_database=unavailable",
        "external_provenance_sha256=",
    ] {
        assert!(
            detector_line.contains(field),
            "missing {field}: {detector_line}"
        );
    }
    for field in [
        "corpus_sha256",
        "compiled_plan_blake3",
        "enabled_detector_blake3",
        "external_provenance_sha256",
    ] {
        let digest = detector_line
            .split_whitespace()
            .find_map(|value| value.strip_prefix(&format!("{field}=")))
            .unwrap_or_else(|| panic!("missing {field}: {detector_line}"));
        assert_eq!(digest.len(), 64, "{field} must remain a complete digest");
        assert!(
            digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{field} must be hexadecimal: {digest}"
        );
    }
    let config_line = stderr
        .lines()
        .find(|line| line.starts_with("config resolved_blake3="))
        .expect("profile config identity line");
    assert!(config_line.contains("policy_blake3="));
    assert!(config_line.contains("preset=default"));
    assert!(config_line.contains("protection=default-"));
    for field in ["resolved_blake3", "policy_blake3"] {
        let digest = config_line
            .split_whitespace()
            .find_map(|value| value.strip_prefix(&format!("{field}=")))
            .unwrap_or_else(|| panic!("missing {field}: {config_line}"));
        assert_eq!(digest.len(), 64, "{field} must remain a complete digest");
        assert!(
            digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{field} must be hexadecimal: {digest}"
        );
    }
    let source_line = stderr
        .lines()
        .find(|line| line.starts_with("source adapters="))
        .expect("profile source identity line");
    assert!(source_line.contains("adapters=filesystem"));
    for field in ["target_blake3", "partition_blake3"] {
        let digest = source_line
            .split_whitespace()
            .find_map(|value| value.strip_prefix(&format!("{field}=")))
            .unwrap_or_else(|| panic!("missing {field}: {source_line}"));
        assert_eq!(digest.len(), 64, "{field} must remain a complete digest");
        assert!(
            digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{field} must be hexadecimal: {digest}"
        );
    }
    assert!(stderr.contains(
        "workload class=filesystem raw_source_bytes=25 source_units=1 \
         container_bytes=unavailable expanded_payload_bytes=unavailable \
         derived_decoder_bytes=0 backend_dispatched_bytes=25 \
         size_bucket=tiny fanout_bucket=single"
    ));
    let route_line = stderr
        .lines()
        .find(|line| line.starts_with("route mode="))
        .expect("profile route identity line");
    assert_eq!(
        route_line,
        "route mode=explicit requested=cpu-fallback selected=cpu-fallback completed=cpu-fallback batches=1 recovered_batches=0 autoroute_decision_blake3=unavailable"
    );
    let outcome_line = stderr
        .lines()
        .find(|line| line.starts_with("outcome status="))
        .expect("profile outcome identity line");
    assert!(outcome_line.starts_with(
        "outcome status=completed coverage=complete errors=0 exit=0 findings_blake3="
    ));
    assert!(outcome_line.ends_with(" report_blake3=unavailable:unsupported"));
    let findings_digest = outcome_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("findings_blake3="))
        .expect("findings digest");
    assert_eq!(findings_digest.len(), 64);
    assert!(findings_digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let cache_lines = stderr
        .lines()
        .filter(|line| line.starts_with("cache layer="))
        .collect::<Vec<_>>();
    // Every `CacheLayerKindV2` variant except `legacy-aggregate` (the pre-v2
    // single-cache rollup) is a causal layer a scan must report. Adding a
    // variant without emitting it turns this red on the count.
    assert_eq!(
        cache_lines.len(),
        10,
        "every causal cache layer must be reported: {cache_lines:?}"
    );
    for layer in [
        "detector",
        "merkle",
        "autoroute",
        "verifier",
        "daemon",
        "page-cache",
        "hyperscan-shards",
        "matcher-artifacts",
        "gpu-programs",
        "lock-files",
    ] {
        assert!(
            cache_lines
                .iter()
                .any(|line| line.contains(&format!("layer={layer} "))),
            "missing cache layer {layer}: {cache_lines:?}"
        );
    }
    let detector_cache = cache_lines
        .iter()
        .find(|line| line.contains("layer=detector "))
        .expect("detector cache identity");
    assert!(detector_cache.contains("state=warm"));
    let detector_generation = detector_cache
        .split_whitespace()
        .find_map(|field| field.strip_prefix("generation="))
        .expect("detector generation");
    assert_eq!(detector_generation.len(), 64);
    assert!(detector_generation
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));
    assert!(cache_lines
        .iter()
        .any(|line| line == &"cache layer=merkle state=disabled generation=unavailable:disabled digest=unavailable:disabled"));
    assert!(cache_lines
        .iter()
        .any(|line| line == &"cache layer=verifier state=disabled generation=unavailable:disabled digest=unavailable:disabled"));
    assert!(cache_lines
        .iter()
        .any(|line| line == &"cache layer=daemon state=disabled generation=unavailable:disabled digest=unavailable:disabled"));
    assert!(cache_lines
        .iter()
        .any(|line| line == &"cache layer=page-cache state=unknown generation=unavailable:unsupported digest=unavailable:unsupported"));
    assert!(
        stderr
            .lines()
            .any(|line| line == "metric id=input-bytes kind=counter value=25"),
        "typed input-byte counter missing: {stderr}"
    );
    assert!(
        stderr
            .lines()
            .any(|line| line == "metric id=input-units kind=counter value=1"),
        "typed input-unit counter missing: {stderr}"
    );
    let latency_line = stderr
        .lines()
        .find(|line| line.starts_with("latency micro=source-read "))
        .expect("source-read latency distribution");
    assert!(
        latency_line.starts_with("latency micro=source-read macro=acquire calls="),
        "{latency_line}"
    );
    let latency_value = |name: &str| {
        latency_line
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name}: {latency_line}"))
            .parse::<u64>()
            .unwrap_or_else(|error| panic!("invalid {name}: {error}: {latency_line}"))
    };
    assert!(latency_value("calls") >= 1, "{latency_line}");
    let minimum_ns = latency_value("min_ns");
    let p50_ns = latency_value("p50_ns");
    let p90_ns = latency_value("p90_ns");
    let p95_ns = latency_value("p95_ns");
    let p99_ns = latency_value("p99_ns");
    let maximum_ns = latency_value("max_ns");
    assert!(
        minimum_ns <= p50_ns
            && p50_ns <= p90_ns
            && p90_ns <= p95_ns
            && p95_ns <= p99_ns
            && p99_ns <= maximum_ns,
        "{latency_line}"
    );
    let event_line = stderr
        .lines()
        .find(|line| line.starts_with("events spans="))
        .expect("causal event summary line");
    let event_value = |name: &str| {
        event_line
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name}: {event_line}"))
            .parse::<u64>()
            .unwrap_or_else(|error| panic!("invalid {name}: {error}: {event_line}"))
    };
    let span_count = event_value("spans");
    let root_count = event_value("roots");
    assert_eq!(
        event_value("points"),
        1,
        "one backend batch completion event"
    );
    assert_eq!(event_value("annotations"), 0);
    assert_eq!(event_value("sampled_out"), 0);
    let inclusive_ns = event_value("inclusive_ns");
    let exclusive_ns = event_value("exclusive_ns");
    assert!(
        span_count >= 1,
        "profile must contain runtime spans: {event_line}"
    );
    assert!(
        (1..=span_count).contains(&root_count),
        "root count must describe the recorded forest: {event_line}"
    );
    assert_eq!(
        event_value("dropped"),
        0,
        "tiny scan must retain every span"
    );
    assert!(
        inclusive_ns >= exclusive_ns && exclusive_ns > 0,
        "{event_line}"
    );
}

/// Incremental profiles must distinguish a missing Merkle generation from a trusted generation loaded on the next run.
#[test]
fn scan_profile_records_cold_then_warm_merkle_cache_generation() {
    let (dir, path) = write_temp_file("incremental.txt", "stable incremental fixture\n");
    let cache_path = dir.path().join("profile-merkle.json");
    let run = || {
        Command::new(binary())
            .args([
                "scan",
                "--daemon=off",
                "--backend",
                "cpu",
                "--format",
                "json",
                "--quiet",
                "--profile",
                "--incremental",
                "--incremental-cache",
                cache_path.to_str().expect("utf-8 cache path"),
                path.to_str().expect("utf-8 fixture path"),
            ])
            .output()
            .expect("run incremental profiled scan")
    };

    let cold = run();
    let cold_stderr = String::from_utf8_lossy(&cold.stderr);
    assert_eq!(cold.status.code(), Some(0), "stderr={cold_stderr}");
    let cold_line = cold_stderr
        .lines()
        .find(|line| line.starts_with("cache layer=merkle "))
        .expect("cold Merkle cache identity");
    assert!(cold_line.contains("state=cold"), "{cold_line}");
    assert!(
        cold_line.contains("digest=unavailable"),
        "a missing generation has no digest: {cold_line}"
    );
    assert!(
        cache_path.is_file(),
        "first scan must persist the generation"
    );

    let warm = run();
    let warm_stderr = String::from_utf8_lossy(&warm.stderr);
    assert_eq!(warm.status.code(), Some(0), "stderr={warm_stderr}");
    let warm_line = warm_stderr
        .lines()
        .find(|line| line.starts_with("cache layer=merkle "))
        .expect("warm Merkle cache identity");
    assert!(warm_line.contains("state=warm"), "{warm_line}");
    let generation = warm_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("generation="))
        .expect("Merkle generation identity");
    let digest = warm_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("digest="))
        .expect("Merkle cache content digest");
    for (name, value) in [("generation", generation), ("digest", digest)] {
        assert_eq!(value.len(), 64, "{name} must be a full digest: {warm_line}");
        assert!(
            value.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{name} must be hexadecimal: {warm_line}"
        );
    }
}

/// The opt-in perf trace must retain detailed per-pattern diagnostics without coupling them to the low-overhead run profile.
#[test]
fn perf_trace_owns_expensive_scanner_diagnostics() {
    let (_dir, path) = write_temp_file("clean.txt", "ordinary perf trace fixture\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--quiet",
            "--perf-trace",
            path.to_str().expect("utf-8 fixture path"),
        ])
        .output()
        .expect("run detailed perf trace");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert_eq!(stdout, "[]");
    assert!(stderr.contains("=== keyhog profile [keyhog scan] ==="));
    assert!(!stderr.contains("state=completed source=filesystem"));
}

/// A failure after profiling begins must finalize the record as failed instead of dropping all evidence.
#[test]
fn scan_profile_marks_reporting_failure_as_failed() {
    let (dir, path) = write_temp_file("clean.txt", "ordinary profile fixture\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--quiet",
            "--profile",
            "--output",
            dir.path().to_str().expect("utf-8 output directory"),
            path.to_str().expect("utf-8 fixture path"),
        ])
        .output()
        .expect("run profiled scan with invalid output path");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("state=failed source=filesystem workload=filesystem"));
    assert!(stderr.contains("backend_requested=cpu-fallback backend_selected=cpu-fallback"));
    assert!(stderr.contains("reporting"));
    assert!(stderr.contains("resources aggregate_cpu="));
    assert!(stderr.contains("build binary_sha256="));
    assert!(stderr.contains("detectors corpus_sha256="));
    assert!(stderr.contains("config resolved_blake3="));
    assert!(stderr.contains("source adapters=filesystem"));
    assert!(stderr.contains("workload class=filesystem raw_source_bytes=25 source_units=1"));
    let outcome_line = stderr
        .lines()
        .find(|line| line.starts_with("outcome status="))
        .expect("failed profile outcome identity line");
    assert!(outcome_line
        .starts_with("outcome status=failed coverage=failed errors=1 exit=3 findings_blake3="));
    assert!(outcome_line.ends_with(" report_blake3=unavailable:unsupported"));
}
