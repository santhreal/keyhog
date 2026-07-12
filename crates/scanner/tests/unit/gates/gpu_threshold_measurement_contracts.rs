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
    positioned_literal_gpu_s: f64,
    phase2_gpu_s: f64,
    phase2_cpu_s: f64,
    gpu_presence_bits: u64,
    trigger_bits: u64,
    phase2_gpu_complete: bool,
    confirmed_anchor_gpu_complete: bool,
    confirmed_anchor_candidate_rows: u64,
    confirmed_anchor_candidates: u64,
    generic_keyword_gpu_complete: bool,
    generic_keyword_candidate_rows: u64,
    generic_keyword_candidates: u64,
}

/// Evaluate a `u64` constant from `hw_probe/thresholds.rs` by name.
///
/// The thresholds are `pub(crate)`, so they are invisible to this external
/// integration test; the gate reads the source and evaluates the constant's
/// right-hand side instead. The RHS is a `*`-product of terms where each term is
/// either a `u64` literal (with optional `_` digit separators) OR the name of
/// another `u64` constant defined in the same file — most importantly the shared
/// `MIB` unit. Named terms are resolved recursively against the same source.
///
/// This is what makes the gate robust to unit-constant refactors: writing a
/// threshold as `128 * MIB` instead of `128 * 1024 * 1024` evaluates to the same
/// value here, whereas the previous literal-only parser panicked on the `MIB`
/// term. It is a complete evaluator for the `N [* UNIT...]` form the thresholds
/// actually use, not a fallback layered over the old parser.
fn eval_threshold_const(src: &str, name: &str) -> u64 {
    let decl = format!("const {name}: u64 = ");
    let line = src
        .lines()
        .map(str::trim_start)
        .find(|line| {
            // Match the declaration regardless of `pub(crate)` / `pub` / no
            // visibility prefix; the `: u64 = ` tail keeps it specific.
            line.starts_with(&decl)
                || line
                    .strip_prefix("pub(crate) ")
                    .is_some_and(|l| l.starts_with(&decl))
                || line
                    .strip_prefix("pub ")
                    .is_some_and(|l| l.starts_with(&decl))
        })
        .unwrap_or_else(|| panic!("threshold constant {name} must exist"));
    let rhs = line
        .split_once('=')
        .map(|(_, rhs)| rhs.trim().trim_end_matches(';').trim())
        .unwrap_or_else(|| panic!("threshold constant {name} must have a value"));
    rhs.split('*')
        .map(|part| {
            let term = part.trim().replace('_', "");
            // A term is either a literal or the name of another constant.
            term.parse::<u64>()
                .unwrap_or_else(|_| eval_threshold_const(src, &term))
        })
        .product()
}

fn threshold_u64(name: &str) -> u64 {
    eval_threshold_const(include_str!("../../../src/hw_probe/thresholds.rs"), name)
}

#[test]
fn rtx5090_region_perf_trace_records_direct_source_and_8mib_not_10x() {
    const MIB: u64 = 1024 * 1024;
    let raw = include_str!(
        "../../../../../benchmarks/baselines/gpu_region_perf_trace_rtx5090_2026-06-20.toml"
    );
    let measurement: GpuRegionPerfTrace =
        toml::from_str(raw).expect("parse RTX 5090 GPU region perf trace");

    assert_eq!(measurement.schema_version, 5);
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
        assert!(point.positioned_literal_gpu_s > 0.0);
        assert_eq!(point.phase2_gpu_s, 0.0);
        assert!(point.phase2_cpu_s > 0.0);
        assert_eq!(
            point.gpu_presence_bits, 29,
            "{mib} MiB presence matcher must exclude positioned confirmed-anchor/generic rows"
        );
        assert_eq!(point.trigger_bits, 75);
        assert!(point.phase2_gpu_complete);
        assert!(point.confirmed_anchor_gpu_complete);
        assert_eq!(point.confirmed_anchor_candidate_rows, 1);
        assert!(
            point.confirmed_anchor_candidates > 0,
            "{mib} MiB trace must prove confirmed-anchor candidates were produced by GPU"
        );
        assert!(point.generic_keyword_gpu_complete);
        assert_eq!(point.generic_keyword_candidate_rows, 1);
        assert!(
            point.generic_keyword_candidates > 0,
            "{mib} MiB trace must prove generic keyword candidates were produced by GPU"
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
        eight.gpu_over_simd_wall_ratio < 0.23,
        "8 MiB split positioned matcher trace must retain the measured schema-v5 improvement"
    );
    assert!(
        eight.phase2_cpu_s > eight.dispatch_s && eight.phase2_cpu_s > eight.coalesce_s * 100.0,
        "8 MiB remaining wall time must identify the CPU phase-2 tail, not hide behind staging"
    );
    assert!(
        eight.confirmed_anchor_candidates >= 1_000,
        "8 MiB sparse payload should keep the confirmed-anchor GPU candidate proof complete"
    );
    assert!(
        eight.generic_keyword_candidates >= 100,
        "8 MiB sparse payload should keep the generic keyword GPU candidate proof complete"
    );
}

#[test]
fn fixed_high_tier_threshold_does_not_treat_a_warm_trace_as_cold_autoroute_proof() {
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
    assert!(measurement.max_measured_mib >= 8);
    // The 2026-06-20 perf trace (post split-positioned-matcher fix) shows GPU
    // winning at 1 MiB. first_gpu_win_mib=1 records this.
    assert!(
        measurement.first_gpu_win_mib > 0,
        "first_gpu_win_mib must be >0 (GPU wins measured): got {}",
        measurement.first_gpu_win_mib
    );

    let eight_mib = measurement
        .points
        .iter()
        .find(|point| point.mib == 8)
        .expect("8 MiB crossover point");
    // GPU wins at 8 MiB (4.5x faster than Hyperscan).
    assert_eq!(eight_mib.winner, "gpu");
    assert!(
        eight_mib.gpu_mib_s > eight_mib.cpu_mib_s.max(eight_mib.simd_mib_s),
        "8 MiB GPU route must be fastest: cpu={} simd={} gpu={}",
        eight_mib.cpu_mib_s,
        eight_mib.simd_mib_s,
        eight_mib.gpu_mib_s
    );
    assert!(
        eight_mib.gpu_best_cpu_ratio > 1.0,
        "8 MiB GPU ratio must be above 1.0 (GPU faster): got {}",
        eight_mib.gpu_best_cpu_ratio
    );

    // This artifact proves a warm kernel/path win, not cold one-shot process
    // cost. The fixed heuristic has no runtime-lifetime identity, so it remains
    // conservative; exact 8 MiB routing belongs to persisted calibration.
    let eight_mib_bytes = 8 * MIB;
    assert!(
        gpu_min_bytes_high_tier > eight_mib_bytes,
        "fixed high-tier minimum must stay above the warm-only 8 MiB trace: threshold={} 8mib={}",
        gpu_min_bytes_high_tier,
        eight_mib_bytes
    );
    assert!(
        gpu_bytes_breakeven_solo_high_tier > eight_mib_bytes,
        "fixed solo threshold must stay above the warm-only 8 MiB trace: threshold={} 8mib={}",
        gpu_bytes_breakeven_solo_high_tier,
        eight_mib_bytes
    );
}

// ── threshold-constant evaluator contract ────────────────────────────────────
//
// `eval_threshold_const` is the part that silently broke CI when a threshold was
// refactored from `128 * 1024 * 1024` to `128 * MIB`: the old literal-only parser
// panicked on the `MIB` term. These tests pin every term form the evaluator must
// handle — literals, underscores, named-unit resolution, visibility prefixes,
// nesting — plus the real constant values, so the gate's own parser can never
// regress unnoticed the way it just did.

const MIB_LITERAL: u64 = 1024 * 1024;

#[test]
fn evaluates_a_bare_literal() {
    let src = "const A: u64 = 42;";
    assert_eq!(eval_threshold_const(src, "A"), 42);
}

#[test]
fn evaluates_a_literal_with_underscore_separators() {
    let src = "const A: u64 = 1_048_576;";
    assert_eq!(eval_threshold_const(src, "A"), 1_048_576);
}

#[test]
fn evaluates_a_product_of_literals() {
    let src = "const A: u64 = 1024 * 1024;";
    assert_eq!(eval_threshold_const(src, "A"), MIB_LITERAL);
}

#[test]
fn evaluates_a_single_literal_with_no_multiply() {
    let src = "const A: u64 = 7;";
    assert_eq!(eval_threshold_const(src, "A"), 7);
}

#[test]
fn resolves_a_single_named_unit_term() {
    let src = "const MIB: u64 = 1024 * 1024;\nconst A: u64 = MIB;";
    assert_eq!(eval_threshold_const(src, "A"), MIB_LITERAL);
}

#[test]
fn resolves_a_literal_times_a_named_unit() {
    let src = "const MIB: u64 = 1024 * 1024;\nconst A: u64 = 128 * MIB;";
    assert_eq!(eval_threshold_const(src, "A"), 128 * MIB_LITERAL);
}

#[test]
fn resolves_a_named_unit_times_a_named_unit() {
    let src = "const KIB: u64 = 1024;\nconst A: u64 = KIB * KIB;";
    assert_eq!(eval_threshold_const(src, "A"), 1024 * 1024);
}

#[test]
fn resolves_a_three_term_product() {
    let src = "const A: u64 = 64 * 1024 * 1024;";
    assert_eq!(eval_threshold_const(src, "A"), 64 * 1024 * 1024);
}

#[test]
fn matches_a_pub_crate_visibility_prefix() {
    let src = "pub(crate) const A: u64 = 9;";
    assert_eq!(eval_threshold_const(src, "A"), 9);
}

#[test]
fn matches_a_pub_visibility_prefix() {
    let src = "pub const A: u64 = 11;";
    assert_eq!(eval_threshold_const(src, "A"), 11);
}

#[test]
fn matches_a_bare_const_with_no_visibility_prefix() {
    let src = "const A: u64 = 13;";
    assert_eq!(eval_threshold_const(src, "A"), 13);
}

#[test]
fn resolves_a_nested_named_constant_chain() {
    let src =
        "const MIB: u64 = 1024 * 1024;\nconst BLOCK: u64 = 4 * MIB;\nconst A: u64 = 2 * BLOCK;";
    assert_eq!(eval_threshold_const(src, "A"), 8 * MIB_LITERAL);
}

#[test]
fn tolerates_extra_whitespace_around_terms() {
    let src = "const MIB: u64 = 1024 * 1024;\nconst A: u64 =   256   *   MIB  ;";
    assert_eq!(eval_threshold_const(src, "A"), 256 * MIB_LITERAL);
}

#[test]
fn ignores_a_trailing_semicolon() {
    let src = "const A: u64 = 5 * 5;";
    assert_eq!(eval_threshold_const(src, "A"), 25);
}

#[test]
fn picks_the_named_constant_even_when_another_is_a_name_prefix() {
    // `A` must not be matched by a search for `A_HIGH`; the `: u64 = ` tail and
    // exact-name declaration keep them distinct.
    let src = "const A: u64 = 1;\nconst A_HIGH: u64 = 2;";
    assert_eq!(eval_threshold_const(src, "A"), 1);
    assert_eq!(eval_threshold_const(src, "A_HIGH"), 2);
}

#[test]
fn evaluation_is_deterministic() {
    let src = "const MIB: u64 = 1024 * 1024;\nconst A: u64 = 128 * MIB;";
    let first = eval_threshold_const(src, "A");
    for _ in 0..10 {
        assert_eq!(eval_threshold_const(src, "A"), first);
    }
}

#[test]
#[should_panic(expected = "must exist")]
fn panics_on_an_unknown_constant() {
    eval_threshold_const("const A: u64 = 1;", "NOPE");
}

#[test]
#[should_panic(expected = "must exist")]
fn panics_when_a_named_term_does_not_resolve() {
    // `A` references `GHOST`, which is not defined → recursive lookup panics.
    eval_threshold_const("const A: u64 = 2 * GHOST;", "A");
}

#[test]
fn real_mib_unit_is_one_mebibyte() {
    assert_eq!(threshold_u64("MIB"), MIB_LITERAL);
}

#[test]
fn real_gpu_min_high_tier_is_128_mib() {
    assert_eq!(threshold_u64("GPU_MIN_BYTES_HIGH_TIER"), 128 * MIB_LITERAL);
}

#[test]
fn real_gpu_breakeven_solo_high_tier_is_256_mib() {
    assert_eq!(
        threshold_u64("GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER"),
        256 * MIB_LITERAL
    );
}

#[test]
fn real_breakeven_solo_cap_exceeds_the_min_dispatch_threshold() {
    assert!(
        threshold_u64("GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER")
            > threshold_u64("GPU_MIN_BYTES_HIGH_TIER"),
        "solo breakeven cap must exceed the min dispatch threshold"
    );
}
