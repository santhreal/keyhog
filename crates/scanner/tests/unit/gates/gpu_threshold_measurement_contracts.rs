#[derive(serde::Deserialize)]
struct HistoricalGpuArtifact {
    notes: String,
    #[serde(default)]
    production_comparable: Option<bool>,
}

/// Evaluate a `u64` constant from `hw_probe/thresholds.rs` by name.
///
/// The thresholds are `pub(crate)`, so they are invisible to this external
/// integration test; the gate reads the source and evaluates the constant's
/// right-hand side instead. The RHS is a `*`-product of terms where each term is
/// either a `u64` literal (with optional `_` digit separators) OR the name of
/// another `u64` constant defined in the same file, most importantly the shared
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
fn historical_gpu_artifacts_cannot_support_current_crossover_claims() {
    for (name, raw) in [
        (
            "single-chunk crossover",
            include_str!(
                "../../../../../benchmarks/baselines/gpu_region_crossover_rtx5090_2026-06-19.toml"
            ),
        ),
        (
            "removed-route perf trace",
            include_str!(
                "../../../../../benchmarks/baselines/gpu_region_perf_trace_rtx5090_2026-06-20.toml"
            ),
        ),
        (
            "per-chunk SIMD crossover",
            include_str!(
                "../../../../../benchmarks/baselines/gpu_8mib_crossover_rtx5090_2026-07-10.toml"
            ),
        ),
    ] {
        let artifact: HistoricalGpuArtifact =
            toml::from_str(raw).unwrap_or_else(|error| panic!("parse {name}: {error}"));
        assert!(
            artifact.notes.to_ascii_uppercase().contains("HISTORICAL")
                || artifact.production_comparable == Some(false),
            "{name} must state that it is historical or explicitly set production_comparable=false"
        );
        assert_ne!(
            artifact.production_comparable,
            Some(true),
            "{name} must never be accepted as current production crossover evidence"
        );
    }
}

#[test]
fn fixed_high_tier_threshold_does_not_claim_an_unproven_8mib_crossover() {
    const MIB: u64 = 1024 * 1024;
    let gpu_min_bytes_high_tier = threshold_u64("GPU_MIN_BYTES_HIGH_TIER");
    let gpu_bytes_breakeven_solo_high_tier = threshold_u64("GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER");
    let eight_mib_bytes = 8 * MIB;
    assert!(
        gpu_min_bytes_high_tier > eight_mib_bytes,
        "fixed high-tier minimum must stay above the unproven 8 MiB crossover: threshold={} 8mib={}",
        gpu_min_bytes_high_tier,
        eight_mib_bytes
    );
    assert!(
        gpu_bytes_breakeven_solo_high_tier > eight_mib_bytes,
        "fixed solo threshold must stay above the unproven 8 MiB crossover: threshold={} 8mib={}",
        gpu_bytes_breakeven_solo_high_tier,
        eight_mib_bytes
    );
}

// ── threshold-constant evaluator contract ────────────────────────────────────
//
// `eval_threshold_const` is the part that silently broke CI when a threshold was
// refactored from `128 * 1024 * 1024` to `128 * MIB`: the old literal-only parser
// panicked on the `MIB` term. These tests pin every term form the evaluator must
// handle, literals, underscores, named-unit resolution, visibility prefixes,
// nesting, plus the real constant values, so the gate's own parser can never
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
