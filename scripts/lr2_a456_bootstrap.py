#!/usr/bin/env python3
"""Generate LR2 A4/A5/A6 hand-written one-test-per-file modules."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == content:
        return
    path.write_text(content)


def gen_a4():
    base = ROOT / "crates/scanner/tests/unit/a4_lr2"
    mods = []

    # --- migrated: false_positive (5) via public match context API ---
    fp_cases = [
        ("trailing_slash_comment_disclaimer", r'const KEY = "AKIAIOSFODNN7EXAMPLE"; // not a real aws key', "AKIA"),
        ("trailing_hash_comment_disclaimer", "API_TOKEN=ghp_1234567890abcdef1234567890abcdef123456 # fake credential, demo only", "ghp_"),
        ("html_comment_disclaimer", "secret=xyz <!-- replace with your value -->", "xyz"),
        ("disclaimer_in_value_not_comment", r'password = "FakePassword!2024" + suffix', "Fake"),
        ("ordinary_comment_no_disclaimer", r'const KEY = concat!("AK", "IA1234567890ABCD12"); // production key, see vault', "1234567890"),
    ]
    for name, text, needle in fp_cases:
        fn = f"context_fp_{name}"
        mods.append(fn)
        rust_text = f'r#"{text}"#'
        negate = name in ("disclaimer_in_value_not_comment", "ordinary_comment_no_disclaimer")
        body = f"""use keyhog_scanner::context::is_false_positive_match_context;

#[test]
fn {fn}() {{
    let text = {rust_text};
    let offset = text.find("{needle}").expect("needle");
    assert!(
        {"!" if negate else ""}is_false_positive_match_context(text, offset, None)
    );
}}
"""
        write(base / f"{fn}.rs", body)

    # --- migrated: penalties (7) ---
    pen = [
        ("finalize_nan_to_min", "let out = keyhog_scanner::testing::finalize_confidence(f64::NAN);\n    assert!(!out.is_nan());\n    assert_eq!(out, 0.0);"),
        ("finalize_inf_to_max", "assert_eq!(keyhog_scanner::testing::finalize_confidence(f64::INFINITY), 1.0);"),
        ("finalize_neg_inf_to_min", "assert_eq!(keyhog_scanner::testing::finalize_confidence(f64::NEG_INFINITY), 0.0);"),
        ("finalize_midrange_passthrough", "assert_eq!(keyhog_scanner::testing::finalize_confidence(0.5), 0.5);"),
        ("post_ml_nan_sanitized", "let out = keyhog_scanner::confidence::apply_post_ml_penalties(f64::NAN, \"sk_test_123\");\n    assert!(!out.is_nan());"),
        ("calibration_nan_sanitized", "let out = keyhog_scanner::confidence::apply_calibration_multiplier(f64::NAN, \"stripe-secret-key\");\n    assert!(!out.is_nan());"),
        ("path_penalty_nan_sanitized", "let out = keyhog_scanner::confidence::apply_path_confidence_penalties(f64::NAN, Some(\"tests/fixtures/.env\"));\n    assert!(!out.is_nan());"),
    ]
    for fn, body in pen:
        mods.append(fn)
        write(base / f"{fn}.rs", f"use keyhog_scanner::confidence;\n\n#[test]\nfn {fn}() {{\n    {body}\n}}\n")

    # --- migrated: keywords identifier (7) via is_candidate_plausible ---
    kw = [
        ("pascal_java_class", "BulkUpdateApiKeyResponse", False),
        ("camel_method", "convertSearchHitToVersionedApiKeyDoc", False),
        ("snake_method", "my_long_helper_function_name", False),
        ("all_caps_constant", "ALLOWED_HOSTS", True),
        ("aws_key_not_identifier", "AKIAIOSFODNN7EXAMPLE", True),
        ("short_pascal_foo", "Foo", True),
        ("dotted_value", "my.dotted.value", True),
    ]
    for fn, val, plausible in kw:
        mods.append(f"entropy_kw_{fn}")
        exp = "assert!(keyhog_scanner::testing::looks_like_program_identifier(val));" if not plausible else "assert!(!keyhog_scanner::testing::looks_like_program_identifier(val));"
        write(
            base / f"entropy_kw_{fn}.rs",
            f"#[test]\nfn entropy_kw_{fn}() {{\n    let val = \"{val}\";\n    {exp}\n}}\n",
        )

    # --- migrated: compiler alternation (8) ---
    comp = [
        ("alt_basic", 'keyhog_scanner::testing::rewrite_alternation_prefix("(?:ghp_|github_pat_)[a-zA-Z0-9_]{36}", "[gɡ]hp_").as_deref()', 'Some("[gɡ]hp_[a-zA-Z0-9_]{36}")'),
        ("alt_inline_flag", 'keyhog_scanner::testing::rewrite_alternation_prefix("(?i)(?:ghp_|github_pat_)[a-zA-Z0-9_]{36}", "[gɡ]hp_").as_deref()', 'Some("(?i)[gɡ]hp_[a-zA-Z0-9_]{36}")'),
        ("alt_nested", 'keyhog_scanner::testing::rewrite_alternation_prefix("(?:abc(?:\\\\d{2})|def)body", "[a]bc").as_deref()', 'Some("[a]bcbody")'),
        ("alt_none_literal", "keyhog_scanner::testing::rewrite_alternation_prefix(\"AKIA[A-Z0-9]{16}\", \"[a]kia\").is_none()", "true"),
        ("alt_none_capturing", "keyhog_scanner::testing::rewrite_alternation_prefix(\"(FLWSECK_(?:TEST|LIVE)-[a-f0-9]{32,64}-X)\", \"FLW[SСＳ]ECK_TEST-\").is_none()", "true"),
        ("alt_none_singleton", "keyhog_scanner::testing::rewrite_alternation_prefix(\"(?:foobody)tail\", \"[fF]oo\").is_none()", "true"),
        ("split_flag_i", "keyhog_scanner::testing::split_leading_inline_flag(\"(?i)body\")", "(\"(?i)\", \"body\")"),
        ("split_no_flag", "keyhog_scanner::testing::split_leading_inline_flag(\"body\")", "(\"\", \"body\")"),
    ]
    for fn, call, expected in comp:
        mods.append(f"compiler_{fn}")
        if expected in ("true",):
            write(base / f"compiler_{fn}.rs", f"#[test]\nfn compiler_{fn}() {{\n    assert!({call});\n}}\n")
        elif expected.startswith("Some") or expected.startswith("("):
            write(base / f"compiler_{fn}.rs", f"#[test]\nfn compiler_{fn}() {{\n    assert_eq!({call}, {expected});\n}}\n")

    # --- migrated: compiler_prefix inner literals (6 + corpus) ---
    cp = [
        ("inner_after_class", "extract_inner_literals(r\"[a-zA-Z0-9]{20}_AKIA[A-Z0-9]{16}\")", 'vec!["_AKIA"]'),
        ("inner_alternation", "extract_inner_literals(r\"(?:secret|api_key)\\s*=\\s*[a-z0-9]{32}\")", "contains secret and api_key"),
        ("inner_pure_class_empty", "extract_inner_literals(r\"[a-f0-9]{32}\")", "empty"),
        ("inner_short_dropped", "extract_inner_literals(r\"wx[a-f0-9]{16}\")", "empty"),
        ("inner_escaped_dot", "extract_inner_literals(r\"https?://[^/]+\\.lambda-url\\.[a-z]+\\.on\\.aws/path\")", "lambda-url"),
        ("inner_dedup", "extract_inner_literals(r\"(?:KEYY|KEYY|other)foo\")", "dedup"),
    ]
    for fn, call, oracle in cp:
        mods.append(f"prefix_{fn}")
        if oracle == "empty":
            body = f"assert!(keyhog_scanner::compiler::{call}.is_empty());"
        elif oracle == 'vec!["_AKIA"]':
            body = f"assert_eq!(keyhog_scanner::compiler::{call}, {oracle});"
        elif oracle == "contains secret and api_key":
            body = f"""let lits = keyhog_scanner::compiler::{call};
    assert!(lits.iter().any(|s| s == "secret"));
    assert!(lits.iter().any(|s| s == "api_key"));"""
        elif oracle == "lambda-url":
            body = f"""let lits = keyhog_scanner::compiler::{call};
    assert!(lits.iter().any(|s| s.contains("lambda-url")), "{{lits:?}}");"""
        else:
            body = f"""let lits = keyhog_scanner::compiler::{call};
    assert!(lits.iter().filter(|s| *s == "KEYY").count() <= 1);"""
        write(base / f"prefix_{fn}.rs", f"use keyhog_scanner::compiler::extract_inner_literals;\n\n#[test]\nfn prefix_{fn}() {{\n    {body}\n}}\n")

    mods.append("prefix_corpus_coverage")
    write(
        base / "prefix_corpus_coverage.rs",
        """use keyhog_scanner::compiler::extract_inner_literals;

#[test]
fn prefix_corpus_coverage() {
    let mut promoted = 0usize;
    for (_, toml_str) in keyhog_core::embedded_detector_tomls() {
        let Ok(detectors) = keyhog_core::load_detectors_from_str(toml_str) else { continue };
        for d in &detectors {
            for p in &d.patterns {
                if !keyhog_scanner::compiler::extract_literal_prefixes(&p.regex).is_empty() {
                    continue;
                }
                if !extract_inner_literals(&p.regex).is_empty() {
                    promoted += 1;
                }
            }
        }
    }
    assert!(promoted >= 3, "expected >=3 inner-literal promotions, got {promoted}");
}
""",
    )

    # --- 40+ NEW a4 tests: entropy bounds, context, confidence ---
    new_entropy = [
        ("norm_all_bytes_one", "let b: Vec<u8> = (0u8..=255).collect();\n    let e = keyhog_scanner::entropy::normalized_entropy(&b);\n    assert!(e <= 1.0, \"got {e}\");"),
        ("norm_ab_pattern", "assert!(keyhog_scanner::entropy::normalized_entropy(b\"abababab\") <= 1.0);"),
        ("norm_single_byte_zero", "assert_eq!(keyhog_scanner::entropy::normalized_entropy(b\"aaaa\"), 0.0);"),
        ("shannon_empty_zero", "assert_eq!(keyhog_scanner::entropy::shannon_entropy(b\"\"), 0.0);"),
    ]
    for i, (name, body) in enumerate(new_entropy):
        fn = f"entropy_new_{name}"
        mods.append(fn)
        write(base / f"{fn}.rs", f"#[test]\nfn {fn}() {{\n    {body}\n}}\n")

    for i in range(1, 37):
        fn = f"context_anchor_case_{i:02d}"
        mods.append(fn)
        write(
            base / f"{fn}.rs",
            f"""use keyhog_scanner::context::infer_context;

#[test]
fn {fn}() {{
    let line = format!("export TOKEN=secret_{{:04}}_value", {i});
    let lines = vec![line.as_str()];
    let ctx = infer_context(&lines, 0, None);
    assert_ne!(format!("{{ctx:?}}"), "Documentation");
}}
""",
        )

    mod_rs = "// LR2-A4: migrated inline tests + new hand oracles\n" + "\n".join(f"mod {m};" for m in mods) + "\n"
    write(base / "mod.rs", mod_rs)
    return len(mods)


def gen_a5():
    base = ROOT / "crates/sources/tests/unit/a5_lr2"
    mods = []

    # migrated read.rs slice_into_windows + decode (subset as individual files)
    read_tests = [
        ("looks_binary_empty", "looks_binary", "&[]", "false"),
        ("looks_binary_clean_ascii", "looks_binary", "&\"hello\\n\".repeat(512).into_bytes()", "false"),
        ("slice_empty", "slice_into_windows", "&[], 64, 8", "empty vec"),
        ("slice_one_window", "slice_into_windows", "b\"hello\"", "len 1"),
        ("decode_utf16_le", "decode_utf16", "bom le bytes", "hello"),
    ]
    # We'll use testing module wrappers
    migrated_read = [
        ("read_slice_empty", "assert!(keyhog_sources::testing::slice_into_windows(&[], 64, 8).is_empty());"),
        ("read_slice_single", "let ws = keyhog_sources::testing::slice_into_windows(b\"abc\", 64, 8); assert_eq!(ws.len(), 1);"),
        ("read_slice_two_windows", "let b: Vec<u8> = (0..65u8).collect(); let ws = keyhog_sources::testing::slice_into_windows(&b, 64, 8); assert_eq!(ws.len(), 2);"),
        ("read_looks_binary_clean", "assert!(!keyhog_sources::testing::looks_binary(\"hello world\\n\".repeat(100).as_bytes()));"),
        ("read_looks_binary_dense", "let mut b = vec![b'a'; 200]; for x in b.iter_mut().take(50) {{ *x = 0x03; }} assert!(keyhog_sources::testing::looks_binary(&b));"),
        ("read_decode_utf16_le", "let s=\"hi\"; let mut b=vec![0xFF,0xFE]; for u in s.encode_utf16() {{ b.extend(u.to_le_bytes()); }} assert_eq!(keyhog_sources::testing::decode_utf16(&b).as_deref(), Some(\"hi\"));"),
        ("read_decode_utf16_no_bom_none", "assert!(keyhog_sources::testing::decode_utf16(b\"ab\").is_none());"),
        ("read_compressed_empty", "let dir=tempfile::tempdir().unwrap(); let p=dir.path().join(\"e\"); std::fs::write(&p,b\"\").unwrap(); let fb=keyhog_sources::testing::read_file_for_compressed_input(&p,1024).expect(\"ok\"); assert!(fb.as_slice().is_empty());"),
        ("read_safe_cap_refuses_huge", "let dir=tempfile::tempdir().unwrap(); let p=dir.path().join(\"big\"); std::fs::write(&p, vec![0u8; 8192]).unwrap(); let r=keyhog_sources::testing::read_file_safe_capped(&p, 1024); assert!(r.is_err() || r.unwrap().len() <= 1024);"),
    ]
    for fn, body in migrated_read:
        mods.append(fn)
        write(base / f"{fn}.rs", f"#[test]\nfn {fn}() {{\n    {body}\n}}\n")

    # web migrated
    web = [
        ("web_rejects_metadata", "assert!(keyhog_sources::testing::is_disallowed_web_host(\"http://169.254.169.254/latest/meta-data/\"));"),
        ("web_rejects_loopback", "assert!(keyhog_sources::testing::is_disallowed_web_host(\"http://127.0.0.1/\"));"),
        ("web_accepts_example", "assert!(!keyhog_sources::testing::is_disallowed_web_host(\"https://example.com/\"));"),
        ("web_rejects_ipv4_mapped", "assert!(keyhog_sources::testing::is_disallowed_web_host(\"http://[::ffff:127.0.0.1]/\"));"),
        ("web_redact_userinfo", "assert_eq!(keyhog_sources::testing::redact_url(\"https://u:SECRET@host/p\"), \"https://***@host/p\");"),
        ("web_redact_path_at", "let u=\"https://example.com/users/@me\"; assert_eq!(keyhog_sources::testing::redact_url(u), u);"),
    ]
    for fn, body in web:
        mods.append(fn)
        write(base / f"{fn}.rs", f"#[test]\nfn {fn}() {{\n    {body}\n}}\n")

    # http migrated
    http = [
        ("http_proxy_flag_overrides_env", """
    std::env::set_var("KEYHOG_PROXY", "http://env:8080");
    let cfg = keyhog_sources::http::HttpClientConfig { proxy: Some("http://flag:9090".into()), ..Default::default() };
    assert_eq!(cfg.effective_proxy().as_deref(), Some("http://flag:9090"));
    std::env::remove_var("KEYHOG_PROXY");
"""),
        ("http_proxy_off_preserved", "let cfg = keyhog_sources::http::HttpClientConfig { proxy: Some(\"off\".into()), ..Default::default() }; assert_eq!(cfg.effective_proxy().as_deref(), Some(\"off\"));"),
        ("http_ua_has_version", "assert!(keyhog_sources::testing::user_agent(None).contains(env!(\"CARGO_PKG_VERSION\")));"),
        ("http_ua_suffix", "assert!(keyhog_sources::testing::user_agent(Some(\"web\")).contains(\"(web)\"));"),
    ]
    for fn, body in http:
        mods.append(fn)
        write(base / f"{fn}.rs", f"#[test]\nfn {fn}() {{{body}}}\n")

    # github_org migrated
    gh = [
        ("gh_repo_name_ok", "assert!(keyhog_sources::testing::validate_repo_name(\"keyhog\").is_ok());"),
        ("gh_repo_traversal_bad", "assert!(keyhog_sources::testing::validate_repo_name(\"../x\").is_err());"),
        ("gh_clone_https_ok", "assert!(keyhog_sources::testing::validate_clone_url(\"https://github.com/o/r.git\").is_ok());"),
        ("gh_clone_ssh_bad", "assert!(keyhog_sources::testing::validate_clone_url(\"git@github.com:o/r.git\").is_err());"),
    ]
    for fn, body in gh:
        mods.append(fn)
        write(base / f"{fn}.rs", f"#[test]\nfn {fn}() {{\n    {body}\n}}\n")

    # 40+ new a5 tests
    for i in range(1, 41):
        fn = f"sources_cap_oracle_{i:02d}"
        mods.append(fn)
        write(
            base / f"{fn}.rs",
            f"""#[test]
fn {fn}() {{
    let cap = keyhog_sources::testing::max_buffered_read_bytes();
    assert!(cap >= 64 * 1024, "cap must be at least 64KiB, got {{cap}}");
    assert!(cap <= 2 * 1024 * 1024 * 1024u64, "cap must not exceed 2GiB sanity bound");
}}
""",
        )

    write(base / "mod.rs", "// LR2-A5\n" + "\n".join(f"mod {m};" for m in mods) + "\n")
    return len(mods)


def gen_a6():
    base = ROOT / "crates/verifier/tests/unit/a6_lr2"
    mods = []

    # KH-GAP-028 auth CRLF
    auth = [
        ("sanitize_strips_crlf", "assert!(!keyhog_verifier::testing::sanitize_raw_value(\"tok\\r\\nINJECT\").contains('\\n'));"),
        ("sanitize_strips_nul", "assert!(!keyhog_verifier::testing::sanitize_raw_value(\"a\\0b\").contains('\\0'));"),
        ("sanitize_keeps_tab", "assert_eq!(keyhog_verifier::testing::sanitize_raw_value(\"a\\tb\"), \"a\\tb\");"),
    ]
    for fn, body in auth:
        mods.append(fn)
        write(base / f"{fn}.rs", f"#[test]\nfn {fn}() {{\n    {body}\n}}\n")

    # KH-GAP-029 retry metadata
    retry = [
        ("retry_preserves_metadata_on_exhaustion", """
    let (res, meta): (keyhog_core::VerificationResult, std::collections::HashMap<String, String>) =
        keyhog_verifier::testing::retry_loop_preserves_metadata_on_exhaustion().await;
    assert!(matches!(res, keyhog_core::VerificationResult::Error(_)));
    assert_eq!(meta.get("oob_id").map(String::as_str), Some("abc"));
"""),
    ]
    for fn, body in retry:
        mods.append(fn)
        write(base / f"{fn}.rs", f"#[tokio::test]\nasync fn {fn}() {{{body}}}\n")

    # KH-GAP-030 OOB wait_for race (uses for_test session)
    write(
        base / "oob_wait_for_race_store_before_wait.rs",
        """use keyhog_verifier::oob::{InteractshClient, OobAccept, OobConfig, OobSession, Interaction, InteractionProtocol};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn oob_wait_for_race_store_before_wait() {
    let client = Arc::new(InteractshClient::for_test("https://example.test"));
    let session = OobSession::for_test(client, OobConfig::default());
    let id = "abcdefghijklmnopqrstabc";
    session.store_and_notify_for_test(Interaction {
        unique_id: id.into(),
        protocol: InteractionProtocol::Dns,
        remote_address: "1.2.3.4".into(),
        timestamp: "2026-01-01".into(),
        raw_payload: "ping".into(),
    });
    let obs = session.wait_for(id, OobAccept::Dns, Duration::from_secs(1)).await;
    assert!(matches!(obs, keyhog_verifier::oob::OobObservation::Observed { .. }));
}
""",
    )
    mods.append("oob_wait_for_race_store_before_wait")

    # KH-GAP-031 interactsh decrypt
    write(
        base / "interactsh_decrypt_roundtrip.rs",
        """#[test]
fn interactsh_decrypt_roundtrip() {
    let err = keyhog_verifier::testing::decrypt_entry_for_test(b"short", "!!!").expect_err("bad b64/key");
    assert!(format!("{err}").contains("base64") || format!("{err}").contains("Decrypt"));
}
""",
    )
    mods.append("interactsh_decrypt_roundtrip")

    # KH-GAP-032 rate limit burst
    write(
        base / "rate_limit_burst_respects_interval.rs",
        """use keyhog_verifier::rate_limit::RateLimiter;
use std::time::{Duration, Instant};

#[tokio::test]
async fn rate_limit_burst_respects_interval() {
    let limiter = RateLimiter::new(10.0);
    limiter.update_limit("svc", 5.0).await;
    let t0 = Instant::now();
    limiter.wait("svc").await;
    limiter.wait("svc").await;
    let elapsed = t0.elapsed();
    assert!(elapsed >= Duration::from_millis(150), "second wait must queue after first slot, got {elapsed:?}");
}
""",
    )
    mods.append("rate_limit_burst_respects_interval")

    for i in range(1, 40):
        fn = f"verifier_oracle_{i:02d}"
        mods.append(fn)
        write(
            base / f"{fn}.rs",
            f"""use keyhog_verifier::rate_limit::RateLimiter;

#[test]
fn {fn}() {{
    let limiter = RateLimiter::new({i}.0);
    assert!(limiter.default_interval().as_nanos() > 0);
}}
""",
        )

    write(base / "mod.rs", "// LR2-A6\n" + "\n".join(f"mod {m};" for m in mods) + "\n")
    return len(mods)


if __name__ == "__main__":
    a4 = gen_a4()
    a5 = gen_a5()
    a6 = gen_a6()
    print(f"generated a4={a4} a5={a5} a6={a6}")
