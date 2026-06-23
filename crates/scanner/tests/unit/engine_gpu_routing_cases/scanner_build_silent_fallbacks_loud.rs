//! Law 10 guard: scanner compile-time optimizations (RegexSet/AC/suffix-gate
//! builds and prefilter truncation) must never silently degrade. A build failure
//! that disables an optimization must emit a `tracing::warn!` so the operator can
//! see the perf regression, not assume the fast path is active.

use std::fs;
use std::path::PathBuf;

fn engine_src(name: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/engine")
            .join(name),
    )
    .unwrap_or_else(|_| panic!("{name} should be readable"))
}

#[test]
fn phase2_prefilter_compile_failures_warn() {
    let src = engine_src("phase2_prefilter.rs");
    assert!(
        src.contains("phase-2 RegexSet batch compile failed"),
        "RegexSet batch compile failure must warn"
    );
    assert!(
        src.contains("phase-2 RegexSet batch received out-of-range pattern index")
            && src.contains("phase-2 always-active prefilter received out-of-range pattern index")
            && src.contains("ASCII-folded phase-2 RegexSet received out-of-range pattern index")
            && src.contains("let mut valid_indices = Vec::with_capacity(chunk.len())")
            && src.contains("phase2_indices: valid_indices")
            && !src.contains(
                ".filter_map(|&i| phase2_patterns.get(i).map(|(p, _)| p.regex.as_str()))"
            ),
        "RegexSet batch source entries and stored phase-2 indices must stay aligned"
    );
    assert!(
        src.matches("crate::telemetry::record_invalid_pattern_index_skip()")
            .count()
            >= 3,
        "phase2 prefilter corrupt pattern-index skips must count typed scanner coverage gaps"
    );
    assert!(
        !src.contains(".filter_map(|&i| phase2_patterns.get(i))"),
        "ASCII-folded alternate RegexSets must not filter-map corrupt indices out of alignment"
    );
    assert!(
        src.contains("truncated phase-2 RegexSet batch failed to compile"),
        "truncated RegexSet batch compile failure must warn"
    );
    assert!(
        src.contains("phase-2 prefix-gate Aho-Corasick build failed"),
        "combined prefix-gate AC build failure must warn"
    );
    assert!(
        src.contains("ASCII-folded phase-2 RegexSet failed to compile"),
        "ASCII-folded RegexSet compile failure must warn"
    );
    let phase2_hs = engine_src("phase2_hs.rs");
    assert!(
        phase2_hs.contains("HS always-active prefilter received out-of-range phase-2 index"),
        "Hyperscan always-active prefilter must warn before ignoring corrupt phase-2 indices"
    );
    let phase2_gpu_dfa = [
        engine_src("phase2_gpu_dfa.rs"),
        engine_src("phase2_gpu_dfa/candidates.rs"),
    ]
    .join("\n");
    assert!(
        phase2_gpu_dfa.contains(
            "phase-2 GPU regex-DFA admission received out-of-range always-active pattern index"
        ) && phase2_gpu_dfa.contains(
            "phase-2 GPU regex-DFA candidate selection received out-of-range pattern index"
        ) && phase2_gpu_dfa.contains(
            "phase-2 GPU regex-DFA candidate append received out-of-range pattern index"
        ),
        "GPU regex-DFA admission must warn before ignoring corrupt always-active or candidate indices"
    );
    // Every warn site must use tracing::warn!, not debug!/silent drop.
    assert!(
        src.contains("tracing::warn!("),
        "phase2_prefilter.rs must contain tracing::warn! calls"
    );
}

#[test]
fn phase2_gpu_admission_loss_is_operator_visible() {
    let helper_src = engine_src("gpu_region_dispatch_helpers.rs");
    let dispatch_src = engine_src("gpu_region_dispatch.rs");
    assert!(
        helper_src.contains("fn report_phase2_gpu_admission_loss")
            && helper_src.contains("PHASE2_GPU_ADMISSION_LOSS_WARNED")
            && helper_src.contains("eprintln!(")
            && helper_src.contains("GPU speed evidence is incomplete")
            && helper_src.contains("CPU admission remains authoritative"),
        "phase-2 GPU regex-DFA admission loss must be visible to normal CLI stderr, not only tracing"
    );
    assert!(
        dispatch_src
            .matches("report_phase2_gpu_admission_loss(error);")
            .count()
            >= 2,
        "both full-batch and subset phase-2 GPU admission failures must route through the visible reporter"
    );
}

#[test]
fn phase2_gpu_catalog_loss_is_operator_visible() {
    let src = engine_src("phase2_gpu_dfa.rs");
    assert!(
        src.contains("fn report_phase2_gpu_catalog_loss")
            && src.contains("PHASE2_GPU_CATALOG_LOSS_WARNED")
            && src.contains("eprintln!(")
            && src.contains("phase-2 GPU regex-DFA catalog incomplete")
            && src.contains("GPU speed evidence is incomplete")
            && src.contains("CPU admission remains"),
        "phase-2 GPU regex-DFA catalog incompleteness must be visible to normal CLI stderr, not only tracing"
    );
    assert!(
        src.contains("candidate budget reached: selected")
            && src.contains("no lowerable prefixless always-active pattern")
            && src.contains("prefixless always-active pattern(s) uncovered after lowering"),
        "candidate budget, no-lowerable-catalog, and uncovered-pattern catalog gaps must describe the lost GPU evidence"
    );
    assert!(
        src.matches("report_phase2_gpu_catalog_loss(format!(")
            .count()
            >= 3,
        "every phase-2 GPU catalog incompleteness branch must route through the visible reporter"
    );
}

#[test]
fn phase2_anchor_ac_build_failures_warn() {
    let src = engine_src("phase2_anchor.rs");
    assert!(
        src.contains("phase-2 shared-anchor Aho-Corasick build failed"),
        "shared-anchor AC build failure must warn"
    );
    assert!(
        src.contains("phase-2 plain-anchor Aho-Corasick build failed"),
        "plain-anchor AC build failure must warn"
    );
    assert!(
        src.contains("tracing::warn!("),
        "phase2_anchor.rs must contain tracing::warn! calls"
    );
}

#[test]
fn confirmed_suffix_gate_build_failure_warns() {
    let src = engine_src("scan_postprocess/suffix_gate.rs");
    assert!(
        src.contains("confirmed-pass suffix-gate Aho-Corasick build failed"),
        "suffix-gate AC build failure must warn"
    );
    assert!(
        src.contains("tracing::warn!("),
        "scan_postprocess/suffix_gate.rs must contain tracing::warn! calls"
    );
}

#[test]
fn prefilter_truncation_parse_failures_warn() {
    let src = engine_src("phase2_truncate.rs");
    assert!(
        src.contains("prefilter regex truncation parse failed"),
        "truncation parse failure must warn"
    );
    assert!(
        src.contains("prefilter regex truncation compile failed"),
        "truncation compile failure must warn"
    );
    assert!(
        src.contains("tracing::warn!("),
        "phase2_truncate.rs must contain tracing::warn! calls"
    );
}

fn scanner_src(name: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(name),
    )
    .unwrap_or_else(|_| panic!("{name} should be readable"))
}

fn core_src(name: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../core/src")
            .join(name),
    )
    .unwrap_or_else(|_| panic!("{name} should be readable"))
}

#[test]
fn phase2_keyword_ac_build_failure_warns() {
    let src = scanner_src("compiler/compiler_compile.rs");
    assert!(
        src.contains("phase-2 keyword Aho-Corasick build failed"),
        "phase-2 keyword AC build failure must warn"
    );
    assert!(
        src.contains("tracing::warn!"),
        "compiler_compile.rs must contain tracing::warn! calls"
    );
}

#[test]
fn static_prefilter_regexes_warn_on_compile_failure() {
    // Every build-from-constant LazyLock regex/AC must call warn_prefilter_disabled
    // on compile failure, not silently return None via .ok().
    let files = [
        "multiline/structural.rs",
        "multiline/config.rs",
        "shared_regexes.rs",
        "checksum/slack.rs",
        "unicode_hardening.rs",
    ];
    for file in files {
        let src = scanner_src(file);
        assert!(
            src.contains("prefilter_degrade::warn_prefilter_disabled"),
            "{file} must call warn_prefilter_disabled on static prefilter build failure"
        );
    }
}

#[test]
fn static_prefilter_regexes_no_raw_ok_swallow() {
    let files = [
        "multiline/structural.rs",
        "multiline/config.rs",
        "shared_regexes.rs",
        "checksum/slack.rs",
        "unicode_hardening.rs",
    ];
    for file in files {
        let src = scanner_src(file);
        // Heuristic: a Regex::new(...) or AhoCorasick::new(...) immediately followed by .ok()
        // is a silent swallow. After the fix each failure path must branch on match/Err.
        let danger = regex::Regex::new(r"(Regex::new|AhoCorasick::new)\([^;]+\)\.ok\(\)").unwrap();
        assert!(
            !danger.is_match(&src),
            "{file} contains a silent .ok() swallow on a static prefilter build"
        );
    }
}

#[test]
fn structured_parser_parse_failures_warn() {
    // A matched structured file (tfstate, notebook, k8s Secret, docker-compose)
    // that fails to parse loses decode-through coverage; that must be a warning,
    // not a debug-only line that default logs never show.
    let json = scanner_src("structured/parsers/json.rs");
    assert!(
        json.contains("tfstate JSON parse failed"),
        "tfstate parse failure must be logged"
    );
    assert!(
        json.contains("Jupyter notebook JSON parse failed"),
        "jupyter parse failure must be logged"
    );
    assert!(
        json.contains("tracing::warn!(target: \"keyhog::structured\""),
        "json structured parsers must warn on parse failure"
    );

    let yaml = scanner_src("structured/parsers/yaml.rs");
    assert!(
        yaml.contains("k8s secret YAML parse failed"),
        "k8s secret parse failure must be logged"
    );
    assert!(
        yaml.contains("docker-compose YAML parse failed"),
        "docker-compose parse failure must be logged"
    );
    assert!(
        yaml.contains("tracing::warn!(target: \"keyhog::structured\""),
        "yaml structured parsers must warn on parse failure"
    );
}

#[test]
fn backend_affecting_config_parse_failures_are_loud() {
    let core_env_config =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/src/env_config.rs");
    let core_lib = core_src("lib.rs");
    assert!(
        !core_env_config.exists() && !core_lib.contains("env_config"),
        "numeric env parser helpers must not exist in production; config is explicit TOML/CLI"
    );

    let engine = engine_src("compiled_api.rs");
    let scanner_config = scanner_src("scanner_config.rs");
    assert!(
        engine.matches("self.config.per_chunk_deadline()").count() == 2
            && scanner_config.contains("pub per_chunk_timeout_ms: Option<u64>")
            && scanner_config.contains("per_chunk_deadline(&self)")
            && !engine.contains("crate::env_config::per_chunk_deadline")
            && !scanner_config.contains("KEYHOG_PER_CHUNK_TIMEOUT_MS"),
        "per-chunk deadlines must be explicit scanner config, not ambient env"
    );

    let tuning = scanner_src("tuning.rs");
    assert!(
        tuning.contains("ScannerTuningConfig::HS_PREFILTER_MAX_LEN_DEFAULT")
            && tuning.contains("apply_config")
            && !tuning.contains("std::env::var")
            && scanner_config.contains("pub hs_prefilter_max_len: Option<usize>")
            && scanner_config.contains("const HS_PREFILTER_MAX_LEN_DEFAULT: usize = 4096"),
        "HS prefilter max-length must be explicit scanner tuning config, not ambient env"
    );

    let gpu = scanner_src("gpu/backend.rs");
    assert!(
        gpu.contains("readback_timeout: Duration")
            && gpu.contains("let timeout = readback_timeout")
            && !gpu.contains("KEYHOG_GPU_MOE_TIMEOUT_MS")
            && !gpu.contains("u64_at_least_or_default")
            && scanner_config.contains("pub gpu_moe_timeout_ms: Option<u64>")
            && scanner_config.contains("const GPU_MOE_TIMEOUT_MS_DEFAULT: u64 = 30_000")
            && tuning.contains("set_gpu_moe_timeout_ms")
            && scanner_config.contains("gpu_moe_timeout(&self) -> Duration"),
        "GPU MoE timeout must be explicit scanner tuning config, not ambient env"
    );

    let simd = scanner_src("simd/backend.rs");
    let backend_prepared = scanner_src("engine/backend_prepared.rs");
    assert!(
        !simd.contains("KEYHOG_SHARD_TARGET")
            && !simd.contains("keyhog_core::env_config")
            && backend_prepared.contains("shard_target: tuning.hs_shard_target")
            && scanner_config.contains("pub hs_shard_target: Option<usize>")
            && scanner_config.contains("const HS_SHARD_TARGET_DEFAULT: usize = 80"),
        "Hyperscan shard target must be explicit compile tuning config, not ambient env"
    );
}
