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
