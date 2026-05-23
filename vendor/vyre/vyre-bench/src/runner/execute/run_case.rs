//! Per-case execution driver. Calls the case `prepare`, runs the
//! measured iterations, harvests metrics, and evaluates the
//! performance contract.

use std::collections::BTreeMap;
use std::time::Instant;

use crate::api::case::{BenchContext, Correctness, PerformanceContract, PerformanceEvaluation};
use crate::api::metric::MetricStats;
use crate::api::suite::SuiteKind;
use crate::report::json::CaseReport;

use super::collect::collect_samples;
use super::stats::{compute_stats, percentile};
use super::target_samples;
use super::RunConfig;

pub(super) fn run_case(
    case: &'static dyn crate::api::case::BenchCase,
    ctx: &mut BenchContext,
    prepared: &mut crate::api::case::PreparedCase,
    suite: SuiteKind,
    config: &RunConfig,
) -> Result<CaseReport, String> {
    let meta = case.metadata();
    let target_samples = config.measured_samples.unwrap_or_else(|| {
        let base = target_samples(suite);
        if base < 30 {
            30
        } else {
            base
        }
    });
    if std::env::var("VYRE_ALLOW_FEW_SAMPLES").is_err() && target_samples < 30 {
        return Err(format!(
                "measured_samples must be >= 30 for CLT validity; got {target_samples}. Fix: pass --measured-samples 30 or set VYRE_ALLOW_FEW_SAMPLES=1 for local smoke-only debugging."
            ));
    }
    let mut samples: BTreeMap<&'static str, Vec<u64>> = BTreeMap::new();
    let mut correctness = None;
    // ROADMAP M3 cold-vs-warm separation: capture the first warmup
    // sample's wall-clock and per-stage breakdown so the report can
    // attribute time to cold-start (compile / cache miss / first
    // dispatch) versus warm steady-state. Subsequent warmup runs are
    // discarded as before.
    let mut cold_metrics: Option<crate::api::metric::BenchMetrics> = None;
    let mut cold_wall_ns: Option<u64> = None;

    for warmup_index in 0..config.warmup_samples {
        let started = Instant::now();
        ctx.include_baseline_outputs = warmup_index == 0;
        let run_result = case
            .run(ctx, prepared)
            .map_err(|error| format!("Warmup error on sample {warmup_index}: {error}"))?;
        let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if warmup_index == 0 {
            case.verify(ctx, &run_result)
                .map_err(|error| format!("Warmup verify error: {error}"))?;
            cold_wall_ns = Some(elapsed_ns);
            cold_metrics = Some(run_result.metrics.clone());
        }
        if started.elapsed() > config.sample_timeout {
            return Err(format!(
                "Warmup sample {warmup_index} exceeded timeout {:?}",
                config.sample_timeout
            ));
        }
    }

    let mut determinism_p50s = Vec::new();

    for _d_run in 0..config.determinism_runs {
        let mut d_samples: BTreeMap<&'static str, Vec<u64>> = BTreeMap::new();
        for sample_index in 0..target_samples {
            let started = Instant::now();
            let alloc_before = crate::probes::AllocationSnapshot::capture();
            ctx.include_baseline_outputs = sample_index == 0;
            let mut run_result = case
                .run(ctx, prepared)
                .map_err(|error| format!("Run error on sample {sample_index}: {error}"))?;
            let (alloc_bytes, alloc_count) =
                crate::probes::AllocationSnapshot::capture().delta_since(alloc_before);
            run_result.metrics.alloc_bytes.get_or_insert(alloc_bytes);
            run_result.metrics.alloc_count.get_or_insert(alloc_count);

            let (read, written) = case.bytes_touched(prepared);
            if read > 0 || written > 0 {
                run_result.metrics.bytes_read.get_or_insert(read);
                run_result.metrics.bytes_written.get_or_insert(written);
                run_result
                    .metrics
                    .bytes_touched
                    .get_or_insert(read + written);
            }
            if started.elapsed() > config.sample_timeout {
                break;
            }
            if sample_index == 0 {
                correctness = Some(
                    case.verify(ctx, &run_result)
                        .map_err(|error| format!("Verify error: {error}"))?,
                );
            }

            // Only capture hardware telemetry on the final sample to avoid jitter
            if sample_index == target_samples - 1 {
                let nvml_counters = crate::probes::capture_nvml_telemetry().map_err(|error| {
                    format!("NVML telemetry error on sample {sample_index}: {error}")
                })?;
                run_result.metrics.gpu_counter.extend(nvml_counters);
            }

            let collect_baseline = sample_index >= config.baseline_warmup_runs
                || target_samples <= config.baseline_warmup_runs;
            collect_samples(&run_result, &mut d_samples, collect_baseline);
            collect_samples(&run_result, &mut samples, collect_baseline);
        }

        // B-4: Ensure we got enough samples before timing out
        let actual_samples = samples.get("wall_ns").map(|v| v.len()).unwrap_or(0);
        if actual_samples < 30 && std::env::var("VYRE_ALLOW_FEW_SAMPLES").is_err() {
            let requirements = case.requirements();
            let case_id = meta.id.0;
            return Ok(CaseReport {
                id: case_id.clone(),
                workload_fingerprint: workload_fingerprint(case_id.as_str(), None),
                name: meta.name,
                owner_crate: meta.owner_crate,
                workload_class: format!("{:?}", meta.workload),
                tags: meta.tags,
                backend_id: Some(ctx.preferred_backend.id().to_string()),
                needs_gpu: requirements.needs_gpu,
                min_vram_bytes: requirements.min_vram_bytes,
                min_input_bytes: requirements.min_input_bytes,
                required_features: requirements.feature_set,
                status: "failed".to_string(),
                wall_ns: None,
                correctness: Correctness::Invalid {
                    reason: format!(
                        "insufficient samples due to timeout ({} < 30)",
                        actual_samples
                    ),
                },
                contract: None,
                performance: None,
                metrics: BTreeMap::new(),
                optimization_passes_applied: vec![],
                artifacts: vec![],
            });
        }

        if let Some(active_ns) = d_samples
            .get("dispatch_ns")
            .filter(|samples| !samples.is_empty())
            .or_else(|| d_samples.get("wall_ns"))
        {
            let mut sorted = active_ns.clone();
            sorted.sort_unstable();
            determinism_p50s.push(percentile(&sorted, 50.0));
        }
    }
    let program_fingerprint = ctx.compiled_program_fingerprint;
    ctx.compiled_pipeline = None;
    ctx.compiled_program_fingerprint = None;

    let correctness = correctness.ok_or_else(|| {
        "benchmark produced no samples; target sample count must be greater than zero".to_string()
    })?;
    if let Correctness::Invalid { reason } = correctness {
        return Err(reason);
    }
    if samples.get("wall_ns").is_none_or(Vec::is_empty) {
        return Err("benchmark produced no wall_ns samples".to_string());
    }

    let mut metrics = BTreeMap::new();
    for (name, values) in samples {
        if !values.is_empty() {
            metrics.insert(name.to_string(), compute_stats(&values));
        }
    }
    // ROADMAP M3: surface the cold (first-warmup) sample as
    // synthetic-stat rows under `cold_*` keys. Stats are degenerate
    // (one sample → min == p50 == max) but they share the
    // MetricStats schema so downstream consumers (flamegraph
    // emitter, JSON report, sqlite writer) treat them uniformly.
    if let Some(cold_wall) = cold_wall_ns {
        metrics
            .entry("cold_wall_ns".to_string())
            .or_insert_with(|| single_sample_stats(cold_wall));
    }
    if let Some(cold) = cold_metrics.as_ref() {
        let cold_pairs: [(&str, Option<u64>); 6] = [
            ("cold_compile_ns", cold.compile_ns),
            ("cold_optimize_ns", cold.optimize_ns),
            ("cold_lower_ns", cold.lower_ns),
            ("cold_cache_lookup_ns", cold.cache_lookup_ns),
            ("cold_dispatch_ns", cold.dispatch_ns),
            ("cold_readback_ns", cold.readback_ns),
        ];
        for (key, value) in cold_pairs {
            if let Some(v) = value {
                metrics
                    .entry(key.to_string())
                    .or_insert_with(|| single_sample_stats(v));
            }
        }
    }
    normalize_release_evidence_metrics(&mut metrics, ctx.preferred_backend.id());
    for (name, value) in ctx.preferred_backend.backend_metric_snapshot() {
        metrics
            .entry(name.to_string())
            .or_insert_with(|| single_sample_stats(value));
    }

    let contract = case.performance_contract();
    let performance = contract
        .as_ref()
        .map(|contract| evaluate_contract(contract, &metrics, ctx.preferred_backend.id()));
    if config.enforce_budgets
        && performance
            .as_ref()
            .is_some_and(|performance| !performance.contract_passed)
    {
        return Err(format!(
            "Performance contract failed: {}",
            performance
                .as_ref()
                .map(|p| p.violations.join("; "))
                .unwrap_or_default()
        ));
    }

    let mut status = "pass".to_string();
    if determinism_p50s.len() > 1 {
        let sum: u64 = determinism_p50s.iter().sum();
        let mean = sum as f64 / determinism_p50s.len() as f64;
        let variance = determinism_p50s
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / determinism_p50s.len() as f64;
        let stddev = variance.sqrt();
        let cv = stddev / mean;

        // Populate determinism_cv on the active metric
        let target_metric = if metrics.contains_key("kernel_execute_ns") {
            "kernel_execute_ns"
        } else if metrics.contains_key("dispatch_ns") {
            "dispatch_ns"
        } else {
            "wall_ns"
        };
        if let Some(stats) = metrics.get_mut(target_metric) {
            stats.determinism_cv = Some(cv);
        }

        if cv > 0.05 {
            status = "unstable".to_string(); // Variance > 5%
        }
    }
    if metrics
        .get("thermal_unstable")
        .is_some_and(|stats| stats.max > 0)
    {
        status = "thermal_unstable".to_string();
    }

    let wall_ns = metrics.get("wall_ns").map(|s| s.mean);
    let requirements = case.requirements();
    let optimization_passes_applied =
        infer_optimization_passes_applied(&metrics, ctx.preferred_backend.id());
    let case_id = meta.id.0;
    Ok(CaseReport {
        id: case_id.clone(),
        workload_fingerprint: workload_fingerprint(case_id.as_str(), program_fingerprint),
        name: meta.name,
        owner_crate: meta.owner_crate,
        workload_class: format!("{:?}", meta.workload),
        tags: meta.tags,
        backend_id: Some(ctx.preferred_backend.id().to_string()),
        needs_gpu: requirements.needs_gpu,
        min_vram_bytes: requirements.min_vram_bytes,
        min_input_bytes: requirements.min_input_bytes,
        required_features: requirements.feature_set,
        status,
        wall_ns,
        correctness,
        contract,
        performance,
        metrics,
        optimization_passes_applied,
        artifacts: vec![],
    })
}

/// ROADMAP M3 helper: produce a degenerate `MetricStats` for a single
/// observation. Used to surface the cold (first-warmup) sample
/// alongside the warm-batch stats without inventing a separate
/// schema. min == p50 == max, samples == 1, stddev == 0.
fn single_sample_stats(value: u64) -> MetricStats {
    MetricStats {
        min: value,
        p50: value,
        p90: value,
        p95: value,
        p99: value,
        p999: value,
        p9999: value,
        max: value,
        mean: value as f64,
        stddev: 0.0,
        samples: 1,
        determinism_cv: None,
    }
}

fn normalize_release_evidence_metrics(
    metrics: &mut BTreeMap<String, MetricStats>,
    backend_id: &str,
) {
    if let Some(input) = metrics
        .get("input_bytes")
        .or_else(|| metrics.get("bytes_read"))
        .or_else(|| metrics.get("bytes_touched"))
        .cloned()
    {
        metrics
            .entry("host_to_device_bytes".to_string())
            .or_insert(input);
    }
    metrics
        .entry("host_to_device_bytes".to_string())
        .or_insert_with(|| single_sample_stats(0));
    if let Some(output) = metrics
        .get("output_bytes")
        .or_else(|| metrics.get("bytes_written"))
        .or_else(|| metrics.get("bytes_touched"))
        .cloned()
    {
        metrics
            .entry("device_to_host_bytes".to_string())
            .or_insert(output);
    }
    metrics
        .entry("device_to_host_bytes".to_string())
        .or_insert_with(|| single_sample_stats(0));
    if backend_id != "cpu-ref" {
        metrics
            .entry("kernel_launches".to_string())
            .or_insert_with(|| single_sample_stats(1));
    }
}

fn infer_optimization_passes_applied(
    metrics: &BTreeMap<String, MetricStats>,
    backend_id: &str,
) -> Vec<String> {
    let mut passes = Vec::new();
    if backend_id == "cuda" {
        passes.push("cuda-explicit-backend-selection".to_string());
    }
    if metrics.contains_key("cache_hit") || metrics.contains_key("cold_cache_lookup_ns") {
        passes.push("pipeline-cache-lookup".to_string());
    }
    if metrics.contains_key("cuda_ptx_source_cache_hits") {
        passes.push("cuda-ptx-source-cache".to_string());
    }
    if metrics.contains_key("optimize_ns") || metrics.contains_key("cold_optimize_ns") {
        passes.push("optimizer-pipeline".to_string());
    }
    if metrics.contains_key("lower_ns") || metrics.contains_key("cold_lower_ns") {
        passes.push("backend-lowering".to_string());
    }
    if metrics.contains_key("kernel_launches") {
        passes.push("single-dispatch-launch-plan".to_string());
    }
    if metrics.keys().any(|key| {
        key.starts_with("lower_") || key.starts_with("alias_") || key.starts_with("egraph_")
    }) {
        passes.push("measured-lower-optimization-family".to_string());
    }
    passes.sort();
    passes.dedup();
    passes
}

fn workload_fingerprint(case_id: &str, program_fingerprint: Option<[u8; 32]>) -> String {
    let Some(fingerprint) = program_fingerprint else {
        return format!("bench-case:{case_id}");
    };
    let mut encoded = String::with_capacity("program:".len() + 64);
    encoded.push_str("program:");
    for byte in fingerprint {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub(super) fn evaluate_contract(
    contract: &PerformanceContract,
    metrics: &BTreeMap<String, MetricStats>,
    backend_id: &str,
) -> PerformanceEvaluation {
    let active_gpu = metrics
        .get("dispatch_ns")
        .or_else(|| metrics.get("kernel_execute_ns"))
        .or_else(|| metrics.get("wall_ns"));
    let speedup_x = match (active_gpu, metrics.get("baseline_wall_ns")) {
        (Some(gpu), Some(cpu)) if gpu.p50 > 0 => Some(cpu.p50 as f64 / gpu.p50 as f64),
        _ => None,
    };
    let mut violations = Vec::new();
    for baseline in &contract.baselines {
        if !baseline.backend_ids.is_empty()
            && !baseline
                .backend_ids
                .iter()
                .any(|candidate| candidate == backend_id)
        {
            continue;
        }
        match speedup_x {
            Some(speedup) if speedup >= baseline.min_speedup_x => {}
            Some(speedup) => violations.push(format!(
                "{} requires {:.2}x over {}, observed {:.2}x",
                contract.primitive, baseline.min_speedup_x, baseline.name, speedup
            )),
            None => violations.push(format!(
                "{} requires a measured steady-state speedup over {}, but dispatch_ns/kernel_execute_ns/wall_ns or baseline_wall_ns were incomplete",
                contract.primitive, baseline.name
            )),
        }
    }
    PerformanceEvaluation {
        speedup_x,
        contract_passed: violations.is_empty(),
        violations,
    }
}
