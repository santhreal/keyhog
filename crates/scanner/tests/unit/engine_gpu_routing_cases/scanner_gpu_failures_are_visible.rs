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

fn compiled_scanner_src(name: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/compiled_scanner")
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
        src.contains(
            "compiled scanner invariant violation: phase-2 always-active index out of range"
        ) && src.contains("phase2_indices: chunk.to_vec()")
            && !src.contains(
                ".filter_map(|&i| phase2_patterns.get(i).map(|(p, _)| p.regex.as_str()))"
            )
            && !src.contains("record_invalid_pattern_index_skip()")
            && !src.contains("out-of-range pattern index"),
        "RegexSet batch source entries and stored phase-2 indices must stay construction-owned and aligned"
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
        !phase2_hs.contains("out-of-range phase-2 index")
            && !phase2_hs.contains("phase2_patterns.get(idx)"),
        "Hyperscan always-active prefilter must consume construction-owned phase-2 indices directly"
    );
    let phase2_gpu_dfa = [
        engine_src("phase2_gpu_dfa.rs"),
        engine_src("phase2_gpu_dfa/candidates.rs"),
    ]
    .join("\n");
    assert!(
        !phase2_gpu_dfa.contains("out-of-range always-active pattern index")
            && !phase2_gpu_dfa.contains("out-of-range pattern index")
            && !phase2_gpu_dfa.contains("valid_phase2_gpu_dfa_candidates")
            && !phase2_gpu_dfa.contains("phase2_patterns.get(idx)"),
        "GPU regex-DFA admission must consume construction-owned phase-2 indices directly"
    );
    // Every warn site must use tracing::warn!, not debug!/silent drop.
    assert!(
        src.contains("tracing::warn!("),
        "phase2_prefilter.rs must contain tracing::warn! calls"
    );
}

#[test]
fn phase2_gpu_admission_loss_terminates_selected_route() {
    let dispatch_src = engine_src("gpu_region_dispatch.rs");
    assert!(
        dispatch_src.contains("fail_selected_gpu_dispatch_error(self, error)")
            && dispatch_src.contains("SelectedGpuDispatchError::new(reason)")
            && dispatch_src
                .matches("return dispatch_failure(reason);")
                .count()
                >= 2
            && !dispatch_src.contains("CPU admission remains authoritative"),
        "full-batch and subset phase-2 GPU failures must terminate the selected route instead of substituting CPU admission"
    );
}

#[test]
fn positioned_gpu_candidate_loss_updates_runtime_status() {
    let src = engine_src("gpu_region_dispatch.rs");
    assert!(
        src.contains("self.record_gpu_runtime_fault(format!(")
            && src.contains("fail_selected_gpu_dispatch_error(self, error)"),
        "recall-floor recovery and hard GPU dispatch failures must both update runtime status"
    );
    assert!(
        !src.contains("positioned literal matcher not built for this scanner")
            && !src.contains("positioned GPU candidate collection failed")
            && src.contains("GPU region-presence under-fire recovered"),
        "the redundant positioned-literal dispatch must stay retired while real GPU under-fire remains visible"
    );
    let forced = engine_src("gpu_forced.rs");
    assert!(
        forced.contains("fn record_gpu_runtime_fault(&self")
            && forced.contains("gpu_last_degrade_reason")
            && forced.contains("gpu_degrade_count"),
        "GPU degradation status accounting must have one owner"
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
fn gpu_matcher_loss_is_operator_visible() {
    let src = engine_src("gpu_lazy.rs");
    let helpers = engine_src("gpu_lazy_helpers.rs");
    assert!(
        helpers.contains("fn report_gpu_literal_matcher_unavailable")
            && helpers.contains("GPU_LITERAL_MATCHER_UNAVAILABLE_WARNED")
            && helpers.contains("eprintln!(")
            && helpers.contains("Use --require-gpu when GPU acceleration is mandatory"),
        "GPU matcher compile loss must be visible to normal CLI stderr"
    );
    assert!(
        src.contains("report_gpu_literal_matcher_unavailable(&error)")
            && !src.contains("gpu_position_matcher"),
        "the single live literal matcher compile failure must route through the visible reporter"
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
fn static_prefilter_regexes_handle_build_failure_loudly() {
    // Every static (LazyLock/OnceLock) regex/AC prefilter must handle a build
    // failure LOUDLY, never silently return None via `.ok()` (that path is
    // separately banned by `static_prefilter_regexes_no_raw_ok_swallow`). TWO
    // loud forms qualify, and each file must exhibit exactly the one that fits
    // its prefilter:
    //  - WARN + recall-preserving degrade (`prefilter_degrade::warn_prefilter_disabled`),
    //    correct ONLY when the prefilter is a superset filter whose absence loses
    //    speed but not recall (the full scan still runs). `checksum/slack.rs`.
    //  - Fail-closed PANIC (Law 10), correct for a compile-time-constant pattern
    //    or embedded Tier-B automaton whose only failure mode is a build/data bug
    //    AND whose absence would SILENTLY drop recall, so degrading is not an
    //    option and it must refuse to run. `shared_regexes.rs` (ASSIGN_RE),
    //    `unicode_hardening.rs` (evasion-anchor AC). `multiline/structural.rs`
    //    also fail-closes; it is pinned precisely by
    //    `structural_constant_regexes_fail_closed`.
    // (`multiline/config.rs` was previously listed but builds NO static prefilter
    // its "prefilter" is a memchr2 fast-path, nothing fallible to guard, so
    // requiring a loud handler there was a stale contract.)
    let warn_degrade = ["checksum/slack.rs"];
    let fail_closed = ["shared_regexes.rs", "unicode_hardening.rs"];
    for file in warn_degrade {
        let src = scanner_src(file);
        assert!(
            src.contains("prefilter_degrade::warn_prefilter_disabled"),
            "{file} builds a recall-preserving prefilter, so it must call \
             warn_prefilter_disabled (loud degrade) on build failure"
        );
    }
    for file in fail_closed {
        let src = scanner_src(file);
        assert!(
            src.contains("panic!"),
            "{file} builds a recall-load-bearing static prefilter whose absence \
             would silently drop recall, so it must FAIL CLOSED with a panic on \
             build failure, never warn+degrade or silently return None"
        );
    }
}

/// `multiline/structural.rs` is exempt from the warn+degrade gate above BECAUSE
/// it takes the stronger fail-closed path: its compile-time-constant CONCAT_RE /
/// TVAR_RE can only fail to build on a bad literal (a build defect, never a
/// runtime condition), so each `Regex::new` match branches its `Err` arm into a
/// `panic!` with a fix-the-pattern message instead of silently disabling
/// multiline scanning. This pins that contract so the exemption can never decay
/// into a silent `.ok()` (the companion `no_raw_ok_swallow` gate still covers it).
#[test]
fn structural_constant_regexes_fail_closed() {
    // Strip full-line `//` comments so the rationale comment (which names
    // `warn_prefilter_disabled`) cannot satisfy the "must not warn" assertion.
    let raw = scanner_src("multiline/structural.rs");
    let src: String = raw
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    // Both constant regexes must branch their build-error arm into a hard panic.
    let panic_arms = src.matches("Err(error) => panic!").count();
    assert!(
        panic_arms >= 2,
        "structural.rs must fail closed (panic) on CONCAT_RE and TVAR_RE build \
         failure: found {panic_arms} `Err(error) => panic!` arms, expected >= 2"
    );
    // And it must NOT reintroduce the warn+degrade path it deliberately dropped:
    // a compile-time constant has no recall-preserving degrade, so warn+None here
    // would silently disable multiline scanning on a build defect.
    assert!(
        !src.contains("warn_prefilter_disabled"),
        "structural.rs constants must fail closed, not warn+degrade, remove the \
         warn_prefilter_disabled call and keep the panic"
    );
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
        yaml.contains("tracing::warn!") && yaml.contains("target: \"keyhog::structured\""),
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

    let engine = compiled_scanner_src("runtime.rs");
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
            && scanner_config.contains("const HS_SHARD_TARGET_DEFAULT: usize = 320"),
        "Hyperscan shard target must be explicit compile tuning config, not ambient env"
    );
}
