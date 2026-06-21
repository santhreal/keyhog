//! Dogfood precision regression: policy/config prose and public schema/template
//! identifiers must not surface as `entropy-*` or `generic-secret` findings
//! merely because the surrounding key contains `token`, `secret`, or `key`.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn findings_for(scanner: &CompiledScanner, text: &str) -> Vec<(String, String)> {
    findings_for_path(scanner, text, "policy.toml")
}

fn findings_for_path(scanner: &CompiledScanner, text: &str, path: &str) -> Vec<(String, String)> {
    let chunk: Chunk = make_chunk(text, "filesystem", path);
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

fn assert_no_exact_credential(scanner: &CompiledScanner, line: &str, credential: &str) {
    let findings = findings_for(scanner, line);
    assert!(
        findings.iter().all(|(_, found)| found != credential),
        "dogfood precision value {credential:?} must not surface from {line:?}; findings: {findings:#?}"
    );
}

fn assert_no_exact_credential_at_path(
    scanner: &CompiledScanner,
    line: &str,
    credential: &str,
    path: &str,
) {
    let findings = findings_for_path(scanner, line, path);
    assert!(
        findings.iter().all(|(_, found)| found != credential),
        "dogfood precision value {credential:?} must not surface from {path}:{line:?}; findings: {findings:#?}"
    );
}

fn assert_no_credential_prefix(scanner: &CompiledScanner, line: &str, prefix: &str) {
    let findings = findings_for(scanner, line);
    assert!(
        findings.iter().all(|(_, found)| !found.starts_with(prefix)),
        "template prefix {prefix:?} must not surface from {line:?}; findings: {findings:#?}"
    );
}

#[test]
fn policy_train_case_strings_do_not_surface_as_entropy_or_generic_secrets() {
    let scanner = scanner();
    for value in [
        "ExecStart-points-to-public-vyre-binary-or-verified-install-path",
        "ConfigMap-values-carry-non-secret-Tier-A-runtime-knobs-only",
        "CPUWeight-MemoryMax-TasksMax-and-runtime-timeout-declared",
        "package-files-and-postinstall-behavior-exclude-private-Santh-and-secrets",
        "DynamicUser-or-dedicated-unprivileged-user-required-for-daemon-mode",
    ] {
        assert_no_exact_credential(&scanner, &format!("api_key_policy = \"{value}\""), value);
    }
}

#[test]
fn public_schema_version_identifiers_do_not_surface_as_generic_secrets() {
    let scanner = scanner();
    for value in [
        "vyre-archive-replay-audits:v1",
        "vyre-runtime-release-policy:v2",
        "santh-install-contract:v12",
    ] {
        assert_no_exact_credential(&scanner, &format!("schema_token = \"{value}\""), value);
    }
}

#[test]
fn public_source_reference_selectors_do_not_surface_as_entropy() {
    let scanner = scanner();
    for value in [
        "[sources.LINUX_OPENAT2][sources.BLAKE3_SPEC]",
        "[sources.BLAKE3_SPEC][sources.LSP_SEMANTIC_TOKENS_3_17]",
    ] {
        assert_no_exact_credential(&scanner, &format!("api_key = \"{value}\""), value);
    }
}

#[test]
fn public_metadata_taxonomy_values_do_not_surface_as_generic_secrets() {
    let scanner = scanner();
    for value in [
        "official-author-documentation",
        "primary-protocol-specification",
        "source-available",
    ] {
        assert_no_exact_credential(&scanner, &format!("api_key = \"{value}\""), value);
    }
}

#[test]
fn public_evidence_and_planning_identifiers_do_not_surface_as_secrets() {
    let scanner = scanner();
    for value in [
        "CWE_400_RESOURCE_CONSUMPTIONRFC_9457_PROBLEM_DETAILS",
        "RFC_9457_PROBLEM_DETAILSCWE_400_RESOURCE_CONSUMPTION",
        "row-range-vx-1001-through-vx-1020gate-evidence-consumption",
        "gate-evidence-consumptionrow-range-vx-1001-through-vx-1020",
        "dedup-authority-attestationgate-evidence-consumption",
        "prov-specialization-plus-authority-mapgate-evidence-consumption",
        "duplicate-authority-eliminationgate-evidence-consumption",
        "PW.8-protect-code-from-vulnerabilities-and-verify-release",
    ] {
        assert_no_exact_credential(&scanner, &format!("api_key = \"{value}\""), value);
    }
}

#[test]
fn public_artifact_references_do_not_surface_as_secrets() {
    let scanner = scanner();
    for value in [
        "vyre-conform/src/corpus/witness.rs:160-163",
        "$OUT_DIR/gates_registry.rs:17-19NullBackend",
        "PERF_ROADMAP_2026-05-01.mdB13B14",
        "SEPARATION_AUDIT_2026-05-01.md",
        "docs/optimization/ROADMAP.mdPERF_ROADMAP_2026-05-01.md",
        "PERF_ROADMAP_2026-05-01.mdB13B14f70c42299fVALIDATOR_ERRORS.md",
        "SEPARATION_AUDIT_2026-05-01.mdPERF_ROADMAP_2026-05-01.mdf70c42299fVALIDATOR_ERRORS.md",
        "#[allow(clippy::all)]vyre-conform/src/generated.rs:5vyre-conform/src/runtime/cache/tests/mod.rsunit/e67267d47d",
    ] {
        assert_no_exact_credential_at_path(
            &scanner,
            &format!("api_key = \"{value}\""),
            value,
            "docs/archive/ROADMAP_APPEND_ONLY_2026-05-22.md",
        );
    }
    let bare_artifact_lines = concat!(
        "PERF_ROADMAP_2026-05-01.mdB13B14\n",
        "SEPARATION_AUDIT_2026-05-01.md\n",
        "docs/optimization/ROADMAP.mdPERF_ROADMAP_2026-05-01.md\n",
    );
    let findings = findings_for_path(
        &scanner,
        bare_artifact_lines,
        "docs/archive/ROADMAP_APPEND_ONLY_2026-05-22.md",
    );
    for value in [
        "PERF_ROADMAP_2026-05-01.mdB13B14",
        "SEPARATION_AUDIT_2026-05-01.md",
        "docs/optimization/ROADMAP.mdPERF_ROADMAP_2026-05-01.md",
    ] {
        assert!(
            findings.iter().all(|(_, found)| found != value),
            "bare public artifact reference {value:?} must not surface; findings: {findings:#?}"
        );
    }
}

#[test]
fn shell_template_values_do_not_surface_as_literal_secrets() {
    let scanner = scanner();
    assert_no_credential_prefix(
        &scanner,
        r#"VYRE_RELEASE_PUBLISH_APPROVAL_TOKEN="publish-vyre-${VERSION}-weir-${BUILD}""#,
        "publish-vyre",
    );
    assert_no_credential_prefix(
        &scanner,
        r#"LAUNCH_APPROVAL_TOKEN="launch-vyre-$(date +%s)""#,
        "launch-vyre",
    );
}

#[test]
fn encoded_markup_and_html_event_fragments_do_not_surface_as_secrets() {
    let scanner = scanner();
    for value in [
        "%253Cscript%253E",
        "%3Cimg%20src=x%20onerror=alert%281%29%3E",
    ] {
        assert_no_exact_credential(&scanner, &format!("payload = \"{value}\""), value);
    }
    assert_no_exact_credential(&scanner, r#"token = "onfocus=""#, "onfocus=");
}

#[test]
fn source_code_expressions_do_not_surface_as_entropy_or_generic_secrets() {
    let scanner = scanner();
    for value in [
        "TokenizationScratch::default()bucket_pow2(n_tokens.max(1)",
        "c11_lexer_regular_sparse_u8_haystack_with_flags.unwrap_or(u32::MAX)",
        "c11_lexer_regular_sparse_u8_haystack_with_flags",
        "gpu_directive_metadata_u8(n_bucket",
        ":from_partsunpack_u32_words_prefix_exact(",
        ":from_parts`]c11_lexer_regular_sparse_u8_haystack_with_flags",
        "inclusive_prefix_scan_u32_into(",
        "unpack_u32_words_prefix_exact(",
        "PtxMmaSyncAlignedM16N8K16F16PtxMmaSyncAlignedM16N8K4Tf32",
        "1+(total_width+2-btns_width)/2)1+(total_width+2-msg_width)/2)",
    ] {
        assert_no_exact_credential_at_path(
            &scanner,
            &format!("api_key = \"{value}\""),
            value,
            "src/parsing/c/preprocess/gpu_pipeline/tokenization.rs",
        );
    }
}

#[test]
fn source_symbols_literals_and_string_fragments_do_not_surface_as_secrets() {
    let scanner = scanner();
    for (line, credential, path) in [
        (
            "let mut seed = 0x51_53_45_e2_b4_9f_c3_aa_u64;",
            "0x51_53_45_e2_b4_9f_c3_aa_u64",
            "src/graph/csr_frontier_queue_batch_memory.rs",
        ),
        (
            "value_salt: 0x3141_5926,",
            "0x3141_5926",
            "tests/common/generated_atomic_matrix.rs",
        ),
        (
            "api_key = 0x3141_5926;",
            "0x3141_5926",
            "tests/common/generated_atomic_matrix.rs",
        ),
        (
            r#"printf("KCONFIG_SEED=0x%X\n", seed);"#,
            "KCONFIG_SEED=0x%X\\n",
            "tests/corpus/r2_kernel_scripts/kconfig/conf.c",
        ),
        (
            r#"graph_source.contains("pub(crate) cached_input_key: ExactInputKey")"#,
            "ExactInputKey\")",
            "src/backend/cuda_graph_replay.rs",
        ),
        (
            r#"pipeline.contains("ptx_source_key: PtxSourceCacheKey")"#,
            "PtxSourceCacheKey\")",
            "tests/module_cache_contracts.rs",
        ),
        (
            r#"pipeline.contains("ptx_source_key: PtxSourceCacheKey")"#,
            "ptx_source_key:",
            "tests/module_cache_contracts.rs",
        ),
        (
            r#"assert!(tokens.iter().any(|token| token == "const:TOK_IDENTIFIER"))"#,
            "const:TOK_IDENTIFIER",
            "xtask/src/source_similar.rs",
        ),
        (
            r#"assert!(tokens.iter().any(|token| token == "const:VAST_DECL_CONTEXT_STRIDE_U32"))"#,
            "const:VAST_DECL_CONTEXT_STRIDE_U32",
            "xtask/src/source_similar.rs",
        ),
        (
            "let token_count = u32::try_from(words[1]).ok()?;",
            "u32::try_from(words[1]).ok()?",
            "src/pipeline/parse_cache.rs",
        ),
        (
            "cache_key: *cache_key,",
            "*cache_key",
            "src/pipeline/disk_cache.rs",
        ),
        (
            "if cached.cached_input_key != *input_key {",
            "*input_key",
            "src/backend/cuda_graph_replay.rs",
        ),
        (
            "if cached.cached_input_key != *input_keyexact_input_key {",
            "*input_keyexact_input_key",
            "src/backend/cuda_graph_replay.rs",
        ),
        (
            "let gen_key = block_idx(p, src_b);",
            "block_idx",
            "src/graph/exploded/cpu_ref.rs",
        ),
        (
            "let mut best_delta_by_pass: FxHashMap<&'static str, i128> = FxHashMap::default();",
            "FxHashMap",
            "src/optimizer/pass_selection.rs",
        ),
        (
            r#"let unit: &[u8] = b"api_key = \"AKIA0123token\";";"#,
            "\\\"AKIA0123token\\",
            "tests/literal_set_presence_gpu.rs",
        ),
    ] {
        assert_no_exact_credential_at_path(&scanner, line, credential, path);
    }
}

#[test]
fn public_evidence_ids_algorithms_and_metrics_do_not_surface_as_secrets() {
    let scanner = scanner();
    for (line, credential, path) in [
        (
            r#"algorithm = "argon2id""#,
            "argon2id",
            "docs/optimization/PASSWORD_HASHING_DERIVATION_POLICY.toml",
        ),
        (
            r#""A15-bank-conflict-fixture","#,
            "A15-bank-conflict-fixture",
            "release/evidence/optimization/optimization-analysis-fixtures.json",
        ),
        (
            r#"right_metric: "tokens=129:bytes=2050".to_string(),"#,
            "129:bytes=2050",
            "xtask/src/dedup_report.rs",
        ),
        (
            r#"subject.fingerprint.as_deref(), Some("source-token-fingerprint:v1:abc")"#,
            "v1:abc\")",
            "xtask/src/dedup_report.rs",
        ),
        (
            r#"Some("source-token-fingerprint:v1:abc")"#,
            "v1:abc\")",
            "xtask/src/dedup_report.rs",
        ),
        (
            r#"ffi_or_component_policy = "FFI_ABI_BOUNDARY_CONTRACTS.toml-remains-raw-pointer-and-unwind-authority""#,
            "FFI_ABI_BOUNDARY_CONTRACTS.toml-remains-raw-pointer-and-unwind-authority",
            "docs/optimization/LANGUAGE_BINDING_SURFACE_MATRIX.toml",
        ),
    ] {
        assert_no_exact_credential_at_path(&scanner, line, credential, path);
    }

    scanner.clear_fragment_cache();
    let findings = findings_for_path(
        &scanner,
        r#"
source_key = "dead-pass-no-capability"
hypothesis = "mlir-transform-fusion"
"#,
        "docs/optimization/PASS_RESEARCH_TRACE_ARTIFACTS.toml",
    );
    assert!(
        findings
            .iter()
            .all(|(_, found)| found != "dead-pass-no-capabilitymlir-transform-fusion"),
        "public pass trace labels must not reassemble as secrets; findings: {findings:#?}"
    );
}

#[test]
fn caesar_decoded_comment_prose_does_not_surface_as_entropy() {
    let scanner = scanner();
    let findings = findings_for_path(
        &scanner,
        "# Constant-time crypto contracts for VX-889 through VX-890 and VX-895 through VX-897.\n",
        "docs/optimization/CONSTANT_TIME_CRYPTO_CONTRACTS.toml",
    );
    let decoded_comment =
        "Zlkpqxkq-qfjbzovmqlzlkqoxzqpcloSU-889qeolrdeSU-890xkaSU-895qeolrdeSU-897";
    assert!(
        findings.iter().all(|(_, found)| found != decoded_comment),
        "Caesar-decoded public comment prose must not surface as entropy; findings: {findings:#?}"
    );
}

#[test]
fn caesar_decoded_evidence_chunks_do_not_use_entropy_fallback() {
    let scanner = scanner();
    let chunk: Chunk = make_chunk(
        r#"
schema_token = "VYDTYDW-1000xqideudjhoydvydtydwi.jecb"
route_token = "ktbXAYZ_SOT_YZGIQ=67108864IGXMU_HAORJ_PUHY=1igxmuzkyz-vbexk-xatzosk----tuigvzaxk"
hygiene_token = "ohw_=uhihuhqfh_f11_fodvvlib_ydvw_qrgh_nlqgv(&[0x8;14])"
"#,
        "filesystem/caesar",
        "release/evidence/hygiene/test-hygiene-scan.json",
    );
    scanner.clear_fragment_cache();
    let findings: Vec<(String, String)> = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect();
    for credential in [
        "VYDTYDW-1000xqideudjhoydvydtydwi.jecb",
        "ktbXAYZ_SOT_YZGIQ=67108864IGXMU_HAORJ_PUHY=1igxmuzkyz-vbexk-xatzosk----tuigvzaxk",
        "ohw_=uhihuhqfh_f11_fodvvlib_ydvw_qrgh_nlqgv(&[0x8;14])",
    ] {
        assert!(
            findings.iter().all(|(_, found)| found != credential),
            "Caesar evidence chunk value {credential:?} must not surface via entropy fallback; findings: {findings:#?}"
        );
    }
}

#[test]
fn toml_metadata_fragments_do_not_reassemble_into_generic_secrets() {
    let scanner = scanner();
    scanner.clear_fragment_cache();
    let findings = findings_for(
        &scanner,
        r#"
[[sources]]
source_class = "official-open-source-security-health-tool"
baseline_type = "repository-security-posture-checks"
reproducibility_class = "official-spec"
artifact_state = "documentation-only"
vx_rows = ["VX-701", "VX-704", "VX-707", "VX-708"]

[[sources]]
source_class = "official-static-analysis-results-standard"
baseline_type = "finding-result-interchange"
reproducibility_class = "official-doc"
artifact_state = "source-available"
vx_rows = ["VX-721", "VX-722", "VX-723", "VX-728"]

[[target]]
crash_dedup_key = "stack-input-digest"

[[target]]
crash_dedup_key = "diagnostic-partial-tree-digest"

[[target]]
crash_dedup_key = "report-rule-location-digest"
"#,
    );
    assert!(
        findings
            .iter()
            .all(|(id, _)| !id.ends_with(":reassembled")),
        "public TOML ledger fields must not enter secret-fragment reassembly; findings: {findings:#?}"
    );
}

#[test]
fn random_hyphenated_password_under_keyword_still_surfaces() {
    let scanner = scanner();
    let credential = "aapqhgn-qhuuc-trnmf";
    let findings = findings_for(&scanner, &format!("GRAPHITE_PASS={credential}"));
    assert!(
        findings
            .iter()
            .any(|(id, found)| id == "generic-secret" && found == credential),
        "random hyphenated password must still surface; findings: {findings:#?}"
    );
}
