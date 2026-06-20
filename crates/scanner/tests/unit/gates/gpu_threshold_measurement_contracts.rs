#[derive(serde::Deserialize)]
struct GpuCrossoverMeasurement {
    schema_version: u32,
    gpu: String,
    backend: String,
    payload: String,
    max_measured_mib: u64,
    first_gpu_win_mib: u64,
    points: Vec<CrossoverPoint>,
}

#[derive(serde::Deserialize)]
struct CrossoverPoint {
    mib: u64,
    cpu_mib_s: f64,
    simd_mib_s: f64,
    gpu_mib_s: f64,
    gpu_best_cpu_ratio: f64,
    winner: String,
}

#[derive(serde::Deserialize)]
struct GpuRegionPerfTrace {
    schema_version: u32,
    gpu: String,
    backend: String,
    payload: String,
    points: Vec<GpuRegionPerfPoint>,
}

#[derive(serde::Deserialize)]
struct GpuRegionPerfPoint {
    mib: u64,
    source_bytes: u64,
    coalesced_bytes: u64,
    batch_mode: String,
    simd_wall_ms: f64,
    gpu_wall_ms: f64,
    gpu_over_simd_wall_ratio: f64,
    winner: String,
    hits: u64,
    coalesce_s: f64,
    coalesce_mib_s: f64,
    dispatch_s: f64,
    confirmed_anchor_gpu_s: f64,
    phase2_gpu_s: f64,
    phase2_cpu_s: f64,
    gpu_presence_bits: u64,
    trigger_bits: u64,
    phase2_gpu_complete: bool,
    confirmed_anchor_gpu_complete: bool,
    confirmed_anchor_candidate_rows: u64,
    confirmed_anchor_candidates: u64,
}

fn threshold_u64(name: &str) -> u64 {
    let src = include_str!("../../../src/hw_probe/thresholds.rs");
    let prefix = format!("pub(crate) const {name}: u64 = ");
    let line = src
        .lines()
        .find(|line| line.trim_start().starts_with(&prefix))
        .unwrap_or_else(|| panic!("threshold constant {name} must exist"));
    let expr = line
        .split_once('=')
        .map(|(_, rhs)| rhs.trim().trim_end_matches(';'))
        .unwrap_or_else(|| panic!("threshold constant {name} must have a value"));
    expr.split('*')
        .map(|part| {
            part.trim()
                .replace('_', "")
                .parse::<u64>()
                .unwrap_or_else(|error| panic!("parse {name} term {part:?}: {error}"))
        })
        .product()
}

#[test]
fn rtx5090_region_perf_trace_records_direct_source_and_8mib_not_10x() {
    const MIB: u64 = 1024 * 1024;
    let raw = include_str!(
        "../../../../../benchmarks/baselines/gpu_region_perf_trace_rtx5090_2026-06-20.toml"
    );
    let measurement: GpuRegionPerfTrace =
        toml::from_str(raw).expect("parse RTX 5090 GPU region perf trace");

    assert_eq!(measurement.schema_version, 3);
    assert_eq!(measurement.gpu, "NVIDIA GeForce RTX 5090");
    assert_eq!(measurement.backend, "region-presence");
    assert_eq!(measurement.payload, "benign-sparse-single-chunk");

    for mib in [1, 8, 64] {
        let Some(point) = measurement.points.iter().find(|point| point.mib == mib) else {
            panic!("{mib} MiB perf-trace point must be present");
        };
        assert_eq!(point.source_bytes, mib * MIB);
        assert_eq!(
            point.coalesced_bytes, point.source_bytes,
            "single-chunk direct-source region scans must not add separator bytes"
        );
        assert_eq!(point.batch_mode, "borrowed-single-chunk");
        assert_eq!(point.winner, "gpu");
        assert!(
            point.gpu_wall_ms < point.simd_wall_ms,
            "{mib} MiB GPU route must beat Hyperscan in this refreshed trace"
        );
        let derived_ratio = point.gpu_wall_ms / point.simd_wall_ms;
        assert!(
            (derived_ratio - point.gpu_over_simd_wall_ratio).abs() < 0.005,
            "{mib} MiB ratio drift: derived={derived_ratio} recorded={}",
            point.gpu_over_simd_wall_ratio
        );
        assert!(
            point.hits > 0,
            "{mib} MiB trace must exercise recall parity"
        );
        assert!(point.coalesce_s > 0.0);
        assert!(
            point.coalesce_mib_s > 10_000.0,
            "{mib} MiB direct-source admission should report memory-rate evidence"
        );
        assert!(point.dispatch_s > 0.0);
        assert!(
            point.confirmed_anchor_gpu_s > 0.0,
            "{mib} MiB trace must account for positioned confirmed-anchor GPU candidate collection"
        );
        assert_eq!(point.phase2_gpu_s, 0.0);
        assert!(point.phase2_cpu_s > 0.0);
        assert_eq!(point.gpu_presence_bits, 39);
        assert_eq!(point.trigger_bits, 75);
        assert!(point.phase2_gpu_complete);
        assert!(point.confirmed_anchor_gpu_complete);
        assert_eq!(point.confirmed_anchor_candidate_rows, 1);
        assert!(
            point.confirmed_anchor_candidates > 0,
            "{mib} MiB trace must prove confirmed-anchor candidates were produced by GPU"
        );
    }

    let eight = measurement
        .points
        .iter()
        .find(|point| point.mib == 8)
        .expect("8 MiB perf-trace point");
    assert!(
        eight.gpu_over_simd_wall_ratio < 1.0,
        "8 MiB GPU must be recorded as a win after direct-source staging"
    );
    assert!(
        eight.gpu_over_simd_wall_ratio > 0.10,
        "8 MiB GPU is still not a 10x Hyperscan win; keep the product bar open"
    );
    assert!(
        eight.phase2_cpu_s > eight.dispatch_s && eight.phase2_cpu_s > eight.coalesce_s * 100.0,
        "8 MiB remaining wall time must identify the CPU phase-2 tail, not hide behind staging"
    );
    assert!(
        eight.confirmed_anchor_candidates >= 1_000,
        "8 MiB sparse payload should keep the confirmed-anchor GPU candidate proof complete"
    );
}

#[test]
fn high_tier_gpu_threshold_stays_above_measured_no_win_range() {
    const MIB: u64 = 1024 * 1024;
    let gpu_min_bytes_high_tier = threshold_u64("GPU_MIN_BYTES_HIGH_TIER");
    let gpu_bytes_breakeven_solo_high_tier = threshold_u64("GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER");
    let raw = include_str!(
        "../../../../../benchmarks/baselines/gpu_region_crossover_rtx5090_2026-06-19.toml"
    );
    let measurement: GpuCrossoverMeasurement =
        toml::from_str(raw).expect("parse RTX 5090 GPU crossover baseline");

    assert_eq!(measurement.schema_version, 1);
    assert_eq!(measurement.gpu, "NVIDIA GeForce RTX 5090");
    assert_eq!(measurement.backend, "region-presence");
    assert_eq!(measurement.payload, "benign-sparse");
    assert_eq!(
        measurement.first_gpu_win_mib, 0,
        "0 records that no GPU win was measured in this sweep"
    );

    let eight_mib = measurement
        .points
        .iter()
        .find(|point| point.mib == 8)
        .expect("8 MiB crossover point");
    assert_eq!(eight_mib.winner, "cpu");
    assert!(
        eight_mib.gpu_mib_s < eight_mib.cpu_mib_s.max(eight_mib.simd_mib_s),
        "8 MiB GPU route must not be treated as fastest: cpu={} simd={} gpu={}",
        eight_mib.cpu_mib_s,
        eight_mib.simd_mib_s,
        eight_mib.gpu_mib_s
    );
    assert!(
        eight_mib.gpu_best_cpu_ratio < 1.0,
        "8 MiB GPU ratio must stay below 1.0 until a newer artifact proves a win"
    );

    let measured_ceiling = measurement.max_measured_mib * MIB;
    assert!(
        gpu_min_bytes_high_tier > measured_ceiling,
        "high-tier heuristic min must stay above the measured no-win ceiling: threshold={} ceiling={}",
        gpu_min_bytes_high_tier,
        measured_ceiling
    );
    assert!(
        gpu_bytes_breakeven_solo_high_tier > measured_ceiling,
        "high-tier heuristic solo cap must stay above the measured no-win ceiling: threshold={} ceiling={}",
        gpu_bytes_breakeven_solo_high_tier,
        measured_ceiling
    );
}
