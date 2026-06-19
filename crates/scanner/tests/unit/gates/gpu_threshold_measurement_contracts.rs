use keyhog_scanner::testing::thresholds;

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

#[test]
fn high_tier_gpu_threshold_stays_above_measured_no_win_range() {
    const MIB: u64 = 1024 * 1024;
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
        thresholds::GPU_MIN_BYTES_HIGH_TIER > measured_ceiling,
        "high-tier heuristic min must stay above the measured no-win ceiling: threshold={} ceiling={}",
        thresholds::GPU_MIN_BYTES_HIGH_TIER,
        measured_ceiling
    );
    assert!(
        thresholds::GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER > measured_ceiling,
        "high-tier heuristic solo cap must stay above the measured no-win ceiling: threshold={} ceiling={}",
        thresholds::GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER,
        measured_ceiling
    );
}
