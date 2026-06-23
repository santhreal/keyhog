use crate::args::ScanArgs;
use keyhog_scanner::ScannerConfig;

use super::runtime::ML_THRESHOLD_DEFAULT;

#[derive(Debug, Clone)]
pub(super) struct ScannerConfigInput {
    precision: bool,
    fast: bool,
    deep: bool,
    decode_depth: Option<usize>,
    no_decode: bool,
    decode_size_limit: Option<usize>,
    min_confidence: Option<f64>,
    ml_threshold: f64,
    no_suppress_test_fixtures: bool,
    no_entropy: bool,
    entropy_threshold: Option<f64>,
    min_secret_len: Option<usize>,
    per_chunk_timeout_ms: Option<u64>,
    profile: bool,
    perf_trace: bool,
    entropy_source_files: bool,
    no_entropy_ml_scoring: bool,
    no_keyword_low_entropy: bool,
    scan_comments: bool,
    no_ml: bool,
    ml_weight: Option<f64>,
    no_unicode_norm: bool,
    known_prefixes: Vec<String>,
    secret_keywords: Vec<String>,
    test_keywords: Vec<String>,
    placeholder_keywords: Vec<String>,
}

impl ScannerConfigInput {
    pub(super) fn from_scan_args(args: &ScanArgs) -> Self {
        Self {
            precision: args.precision,
            fast: args.fast,
            deep: args.deep,
            decode_depth: args.decode_depth,
            no_decode: args.no_decode,
            decode_size_limit: args.decode_size_limit,
            min_confidence: args.min_confidence,
            ml_threshold: args.ml_threshold,
            no_suppress_test_fixtures: args.no_suppress_test_fixtures,
            no_entropy: args.no_entropy,
            entropy_threshold: args.entropy_threshold,
            min_secret_len: args.min_secret_len,
            per_chunk_timeout_ms: args.per_chunk_timeout_ms,
            profile: args.profile,
            perf_trace: args.perf_trace,
            entropy_source_files: args.entropy_source_files,
            no_entropy_ml_scoring: args.no_entropy_ml_scoring,
            no_keyword_low_entropy: args.no_keyword_low_entropy,
            scan_comments: args.scan_comments,
            no_ml: args.no_ml,
            ml_weight: args.ml_weight,
            no_unicode_norm: args.no_unicode_norm,
            known_prefixes: args.known_prefixes.clone(),
            secret_keywords: args.secret_keywords.clone(),
            test_keywords: args.test_keywords.clone(),
            placeholder_keywords: args.placeholder_keywords.clone(),
        }
    }
}

pub(crate) fn build_scanner_config(args: &ScanArgs) -> ScannerConfig {
    let input = ScannerConfigInput::from_scan_args(args);
    build_scanner_config_from_input(&input)
}

pub(super) fn build_scanner_config_from_input(input: &ScannerConfigInput) -> ScannerConfig {
    // The preset (`--fast` / `--deep`) is a BASE, not a terminal state. It
    // seeds decode-depth / entropy / ml defaults; the per-flag overrides below
    // then layer on top. Pre-fix this function early-returned at the preset, so
    // `--deep --min-confidence 0.9` (or `--deep --entropy-threshold 5.0`, or any
    // `--known-prefixes` / keyword list) silently dropped the explicit override
    // - a coherence leak where "what the operator asked for" != "what ran". Only
    // `--no-decode` / `--no-entropy` are clap-conflicting with the presets
    // (`conflicts_with_all` on the `fast`/`deep` flags), so every other override
    // is a legitimate refinement of the preset base and must take effect.
    let mut config = if input.precision {
        ScannerConfig::high_precision()
    } else if input.fast {
        ScannerConfig::fast()
    } else if input.deep {
        ScannerConfig::thorough()
    } else {
        ScannerConfig::default()
    };

    if let Some(depth) = input.decode_depth {
        config.max_decode_depth = depth;
    }
    if input.no_decode {
        config.max_decode_depth = 0;
    }
    if let Some(size) = input.decode_size_limit {
        config.max_decode_bytes = size;
    }
    if let Some(conf) = input.min_confidence {
        // Under `--precision` the 0.85 floor is a MINIMUM the operator may
        // raise but not lower: `--precision --min-confidence 0.9` tightens to
        // 0.9, while `--precision --min-confidence 0.3` stays at 0.85 (the
        // documented "`--min-confidence` still overrides the floor on top"
        // contract is one-directional - it cannot punch a hole in the precision
        // bar). Every other mode lets the operator set the floor outright.
        config.min_confidence = if input.precision {
            conf.max(ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE)
        } else {
            conf
        };
    }
    // `--ml-threshold` is the documented "minimum ML confidence score for
    // generic entropy secrets" knob. Pre-fix it was parsed + range-validated
    // but never read by any non-test path, so `--ml-threshold 0.9` silently did
    // nothing (M21: a dead precision lever giving false confidence). Wire it as
    // a confidence FLOOR composed with `.max()` - mirroring the precision-mode
    // composition just above and the "minimum score" wording of the flag - so a
    // raised threshold tightens the bar a generic/entropy finding must clear,
    // while a lowered one can never punch below an operator's `--min-confidence`
    // (or the precision floor). Gated on a real move off the declared default
    // (`ML_THRESHOLD_DEFAULT`): an unset flag leaves the canonical 0.40 floor
    // untouched, so behaviour off the bug path is unchanged.
    if input.ml_threshold != ML_THRESHOLD_DEFAULT {
        config.min_confidence = config.min_confidence.max(input.ml_threshold);
    }
    // Keep the fixture opt-out coherent: skip both value suppressions and the
    // test/example path confidence penalty.
    config.penalize_test_paths = !input.no_suppress_test_fixtures;

    // `--no-entropy` conflicts with the presets at the clap layer, so under a
    // preset this is always `true` (entropy stays whatever the preset set). For
    // the no-preset path it honours the flag. Likewise `--no-decode` is preset-
    // conflicting; decode-depth above still applies for the no-preset path.
    if !(input.fast || input.deep || input.precision) {
        config.entropy_enabled = !input.no_entropy;
    }
    if let Some(threshold) = input.entropy_threshold {
        config.entropy_threshold = threshold;
    }
    if let Some(min_secret_len) = input.min_secret_len {
        config.min_secret_len = min_secret_len;
    }
    config.per_chunk_timeout_ms = input.per_chunk_timeout_ms;
    config.profile = input.profile;
    config.perf_trace = input.perf_trace;
    config.entropy_in_source_files = input.entropy_source_files;
    // Entropy candidates are scored through the MoE (model authoritative) by
    // default; `--no-entropy-ml-scoring` restores the legacy heuristic emit.
    // No-op unless entropy + ML are both on (gated in scan_entropy_fallback).
    config.entropy_ml_authoritative = !input.no_entropy_ml_scoring;
    // Keyword-anchored generic values use the relaxed entropy floor by default
    // (the keyword key is the evidence; precision carried by the MoE);
    // `--no-keyword-low-entropy` restores the high-entropy-only generic gate.
    // No-op unless the generic keyword bridge fires (scan_generic_assignments).
    // Composed with `&&` (not assigned) so the flag is one-directional: it can
    // only DISABLE the relaxed floor, never re-enable it under a preset that
    // turned it off (e.g. `--precision`, whose high_precision() base sets it
    // false). Mirrors the one-directional precision min_confidence contract.
    config.generic_keyword_low_entropy =
        config.generic_keyword_low_entropy && !input.no_keyword_low_entropy;
    config.scan_comments = input.scan_comments;
    config.ml_enabled = !input.fast && !input.no_ml;
    if let Some(weight) = input.ml_weight {
        config.ml_weight = weight;
    }
    config.unicode_normalization = !input.no_unicode_norm;
    if !input.known_prefixes.is_empty() {
        config.known_prefixes = input.known_prefixes.clone();
    }
    if !input.secret_keywords.is_empty() {
        config.secret_keywords = input.secret_keywords.clone();
    }
    if !input.test_keywords.is_empty() {
        config.test_keywords = input.test_keywords.clone();
    }
    if !input.placeholder_keywords.is_empty() {
        config.placeholder_keywords = input.placeholder_keywords.clone();
    }
    // Re-run the NaN/range safety net AFTER every CLI flag and `.keyhog.toml`
    // override has been merged in. `From<ScanConfig>` sanitises once at
    // construction time, but the overrides above (e.g. `config.ml_weight =
    // weight`, `config.entropy_threshold = threshold`) mutate the numeric
    // fields directly afterwards and would otherwise smuggle out-of-range
    // values straight to the engine: `--ml-weight 5.0` / `-1.0` (the ML blend
    // `w*ml + (1-w)*heuristic` in scan_postprocess relies on `w in [0,1]`) and
    // `--entropy-threshold 99` / `-5` (a threshold > 8.0 can never fire,
    // disabling the entropy detector; a negative one makes `entropy >= thr`
    // always true). Neither `--ml-weight` nor `--entropy-threshold` has a
    // clamping clap value_parser, so this is the only place the override layer
    // can honour the same invariant the `From` path enforces. Idempotent.
    config.sanitise();
    config
}
