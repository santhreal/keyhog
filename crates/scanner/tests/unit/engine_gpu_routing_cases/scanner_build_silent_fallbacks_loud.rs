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
fn fallback_prefilter_compile_failures_warn() {
    let src = engine_src("fallback_prefilter.rs");
    assert!(
        src.contains("fallback RegexSet batch compile failed"),
        "RegexSet batch compile failure must warn"
    );
    assert!(
        src.contains("truncated fallback RegexSet batch failed to compile"),
        "truncated RegexSet batch compile failure must warn"
    );
    assert!(
        src.contains("fallback prefix-gate Aho-Corasick build failed"),
        "combined prefix-gate AC build failure must warn"
    );
    assert!(
        src.contains("ASCII-folded fallback RegexSet failed to compile"),
        "ASCII-folded RegexSet compile failure must warn"
    );
    // Every warn site must use tracing::warn!, not debug!/silent drop.
    assert!(
        src.contains("tracing::warn!("),
        "fallback_prefilter.rs must contain tracing::warn! calls"
    );
}

#[test]
fn fallback_anchor_ac_build_failures_warn() {
    let src = engine_src("fallback_anchor.rs");
    assert!(
        src.contains("fallback shared-anchor Aho-Corasick build failed"),
        "shared-anchor AC build failure must warn"
    );
    assert!(
        src.contains("fallback plain-anchor Aho-Corasick build failed"),
        "plain-anchor AC build failure must warn"
    );
    assert!(
        src.contains("tracing::warn!("),
        "fallback_anchor.rs must contain tracing::warn! calls"
    );
}

#[test]
fn confirmed_suffix_gate_build_failure_warns() {
    let src = engine_src("scan_postprocess_suffix_gate.rs");
    assert!(
        src.contains("confirmed-pass suffix-gate Aho-Corasick build failed"),
        "suffix-gate AC build failure must warn"
    );
    assert!(
        src.contains("tracing::warn!("),
        "scan_postprocess_suffix_gate.rs must contain tracing::warn! calls"
    );
}

#[test]
fn prefilter_truncation_parse_failures_warn() {
    let src = engine_src("fallback_truncate.rs");
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
        "fallback_truncate.rs must contain tracing::warn! calls"
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
fn fallback_keyword_ac_build_failure_warns() {
    let src = scanner_src("compiler/compiler_compile.rs");
    assert!(
        src.contains("fallback keyword Aho-Corasick build failed"),
        "fallback keyword AC build failure must warn"
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
fn backend_affecting_env_parse_failures_are_loud() {
    let env_config = scanner_src("env_config.rs");
    let core_env_config = core_src("env_config.rs");
    assert!(
        core_env_config.contains("invalid {name}={raw:?}")
            && core_env_config.contains("invalid non-UTF-8 {name}")
            && core_env_config.contains("expected an integer >=")
            && env_config.contains("per_chunk_deadline")
            && env_config.contains(
                "keyhog_core::env_config::optional_u64_at_least(\"KEYHOG_PER_CHUNK_TIMEOUT_MS\", 1)",
            ),
        "scanner env parsing must warn visibly on malformed backend-affecting knobs"
    );

    let engine = engine_src("compiled_api.rs");
    assert!(
        engine
            .matches("crate::env_config::per_chunk_deadline()")
            .count()
            == 2
            && !engine.contains("env_per_chunk_deadline"),
        "scan entry points must use the centralized loud env parser for per-chunk deadlines"
    );

    let tuning = scanner_src("tuning.rs");
    let scanner_config = scanner_src("scanner_config.rs");
    assert!(
        tuning.contains("ScannerTuningConfig::HS_PREFILTER_MAX_LEN_DEFAULT")
            && tuning.contains("apply_config")
            && !tuning.contains("std::env::var")
            && scanner_config.contains("pub hs_prefilter_max_len: Option<usize>")
            && scanner_config.contains("pub const HS_PREFILTER_MAX_LEN_DEFAULT: usize = 4096"),
        "HS prefilter max-length must be explicit scanner tuning config, not ambient env"
    );

    let gpu = scanner_src("gpu/backend.rs");
    assert!(
        gpu.contains("readback_timeout: Duration")
            && gpu.contains("let timeout = readback_timeout")
            && !gpu.contains("KEYHOG_GPU_MOE_TIMEOUT_MS")
            && !gpu.contains("u64_at_least_or_default")
            && scanner_config.contains("pub gpu_moe_timeout_ms: Option<u64>")
            && scanner_config.contains("pub const GPU_MOE_TIMEOUT_MS_DEFAULT: u64 = 30_000")
            && tuning.contains("set_gpu_moe_timeout_ms")
            && tuning.contains("gpu_moe_timeout(&self) -> Duration"),
        "GPU MoE timeout must be explicit scanner tuning config, not ambient env"
    );

    let simd = scanner_src("simd/backend.rs");
    assert!(
        simd.contains("keyhog_core::env_config::usize_at_least_or_default")
            && simd.contains("\"KEYHOG_SHARD_TARGET\"")
            && !simd.contains("KEYHOG_SHARD_TARGET\") {\n            Ok(raw) => match raw.parse"),
        "Hyperscan shard-target env parse failures must be loud"
    );
}
