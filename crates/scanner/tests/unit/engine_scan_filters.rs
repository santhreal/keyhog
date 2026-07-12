// `tests/gap/no_inline_tests_in_src.rs`).
use super::{
    has_generic_assignment_keyword, has_high_entropy_run_at_least, has_high_entropy_run_fast,
    has_secret_keyword_fast, DEFAULT_ENTROPY_RUN_BYTES,
};

#[derive(serde::Deserialize)]
struct CuratedPrefixes {
    prefixes: Vec<String>,
}

/// The EXACT set of distinctive vendor prefixes `has_secret_keyword_fast`
/// treats as split-across-lines secret anchors. This is the contract: the fn
/// must fire for every one of these, so if a future edit drops one the
/// `every_curated_prefix_triggers` test fails loudly. Ordered by vendor to
/// mirror the source list.
static CURATED_PREFIXES: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    let raw = include_str!("../../../../rules/curated-prefixes.toml");
    match toml::from_str::<CuratedPrefixes>(raw) {
        Ok(parsed) => parsed.prefixes,
        Err(error) => panic!(
            "rules/curated-prefixes.toml is invalid: {error}. \
                     Fix the bundled Tier-B curated prefixes list."
        ),
    }
});

#[test]
fn curated_prefix_list_has_exactly_twenty_five_entries() {
    // Fast tripwire on the size of the recall-critical list. If the source
    // list grows/shrinks, update this AND `every_curated_prefix_triggers`
    // together so the count and the behavior stay in lockstep.
    assert_eq!(CURATED_PREFIXES.len(), 25);
}

#[test]
fn every_curated_prefix_triggers() {
    for prefix in &*CURATED_PREFIXES {
        let line = format!("api_key = {prefix}A1b2C3d4E5f6");
        assert!(
            has_secret_keyword_fast(line.as_bytes()),
            "curated prefix {prefix:?} must route the chunk to phase-2 reassembly"
        );
    }
}

#[test]
fn openai_prefixes_trigger() {
    assert!(has_secret_keyword_fast(b"key=sk-proj-abcdef"));
    assert!(has_secret_keyword_fast(b"key=sk-svcacct-abcdef"));
    assert!(has_secret_keyword_fast(b"key=sk-admin-abcdef"));
}

#[test]
fn stripe_prefixes_trigger() {
    assert!(has_secret_keyword_fast(b"k=sk_live_abcdef"));
    assert!(has_secret_keyword_fast(b"k=sk_test_abcdef"));
    assert!(has_secret_keyword_fast(b"k=rk_live_abcdef"));
    assert!(has_secret_keyword_fast(b"k=pk_live_abcdef"));
}

#[test]
fn github_all_installation_variants_trigger() {
    for token in ["ghp_", "ghs_", "gho_", "ghu_", "ghr_", "github_pat_"] {
        let line = format!("gh={token}0123456789");
        assert!(
            has_secret_keyword_fast(line.as_bytes()),
            "GitHub variant {token:?} must trigger"
        );
    }
}

#[test]
fn slack_prefixes_trigger() {
    for token in ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xapp-"] {
        let line = format!("slack={token}0123456789");
        assert!(
            has_secret_keyword_fast(line.as_bytes()),
            "Slack prefix {token:?} must trigger"
        );
    }
}

#[test]
fn anthropic_prefix_triggers() {
    assert!(has_secret_keyword_fast(b"key=sk-ant-api03-abcdef"));
}

#[test]
fn huggingface_prefix_triggers() {
    assert!(has_secret_keyword_fast(b"HF_TOKEN=hf_abcdefghij"));
}

#[test]
fn gitlab_and_npm_prefixes_trigger() {
    assert!(has_secret_keyword_fast(b"token=glpat-abcdefghij"));
    assert!(has_secret_keyword_fast(b"//registry:_authToken=npm_abcdef"));
}

#[test]
fn heroku_prefix_triggers() {
    assert!(has_secret_keyword_fast(b"key=HRKU-9f8e7d6c5b4a"));
}

#[test]
fn gcp_service_account_shard_triggers() {
    assert!(has_secret_keyword_fast(
        b"client_email: svc@proj.iam.gserviceaccount.com"
    ));
}

#[test]
fn match_is_case_sensitive_unlike_the_generic_gate() {
    // `has_secret_keyword_fast` uses a case-SENSITIVE automaton (the prefixes
    // are exact vendor casings), so an uppercased OpenAI prefix must NOT
    // trigger. This is the deliberate contrast with the case-folding generic
    // gate asserted in `generic_gate_is_case_insensitive`.
    assert!(
        !has_secret_keyword_fast(b"KEY=SK-PROJ-ABCDEF"),
        "uppercased vendor prefix must not match the case-sensitive fast gate"
    );
}

#[test]
fn heroku_prefix_is_case_sensitive() {
    // `HRKU-` is stored uppercase; the lowercase spelling is not a real Heroku
    // key prefix and must not trigger (guards against a case-fold regression
    // silently widening this gate).
    assert!(has_secret_keyword_fast(b"key=HRKU-abcdef"));
    assert!(!has_secret_keyword_fast(b"key=hrku-abcdef"));
}

#[test]
fn deliberately_excluded_short_prefixes_do_not_trigger() {
    // AKIA (AWS access-key id) and eyJ (base64 `{"` JWT header) are SHORT and
    // appear constantly in fixtures/docs, so they are intentionally excluded
    // from this multiline gate. Pin that exclusion — re-adding them would flood
    // the phase-2 tail with fixture noise.
    assert!(
        !has_secret_keyword_fast(b"AKIAIOSFODNN7EXAMPLE"),
        "AKIA is deliberately excluded from the multiline fast gate"
    );
    assert!(
        !has_secret_keyword_fast(b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        "eyJ JWT header is deliberately excluded from the multiline fast gate"
    );
}

#[test]
fn prefix_anywhere_in_chunk_triggers() {
    // The gate is a substring scan, not line-anchored: a prefix buried in the
    // middle of a chunk still routes it to phase-2.
    assert!(has_secret_keyword_fast(
        b"noise noise ghp_abcdef trailing noise"
    ));
}

#[test]
fn prefix_at_chunk_end_triggers() {
    assert!(has_secret_keyword_fast(b"the value is glpat-"));
}

#[test]
fn empty_input_does_not_trigger() {
    assert!(!has_secret_keyword_fast(b""));
}

#[test]
fn plain_prose_without_any_prefix_does_not_trigger() {
    assert!(!has_secret_keyword_fast(
        b"the quick brown fox jumps over the lazy dog"
    ));
}

#[test]
fn truncated_prefixes_do_not_trigger() {
    // `ghp` without the `_`, and `sk-proj` without the trailing `-`, are not
    // the full curated prefixes — the gate must require the exact token so it
    // stays specific.
    assert!(!has_secret_keyword_fast(b"ghp is a common abbreviation"));
    assert!(!has_secret_keyword_fast(b"my sk-proj folder"));
}

#[test]
fn generic_gate_is_case_insensitive() {
    // Contrast with the vendor-prefix gate: `has_generic_assignment_keyword`
    // folds case, so an all-caps assignment keyword still triggers.
    assert!(has_generic_assignment_keyword(b"PASSWORD=hunter2"));
    assert!(has_generic_assignment_keyword(b"Api_Key: xyz"));
}

#[test]
fn the_two_gates_cover_different_shapes() {
    // Separation of concerns: a bare `password=` line has NO vendor prefix, so
    // only the generic gate admits it; a bare `ghp_` token has no assignment
    // keyword, so only the fast gate admits it. Pin that neither gate silently
    // subsumes the other's job.
    assert!(!has_secret_keyword_fast(b"password: hunter2"));
    assert!(has_generic_assignment_keyword(b"password: hunter2"));
    assert!(has_secret_keyword_fast(b"ghp_0123456789abcdef"));
    assert!(!has_generic_assignment_keyword(b"ghp_0123456789abcdef"));
}

#[test]
fn generic_gate_rejects_a_non_credential_line() {
    assert!(!has_generic_assignment_keyword(
        b"the quick brown fox jumps over the lazy dog"
    ));
}

// ── has_high_entropy_run_fast: the keyword-free entropy admission gate ──
// Admits a chunk to the entropy fallback when it holds a contiguous run of >= 32
// credential-value bytes (alphanumerics + token separators + symbolic password
// punctuation). Recall-critical: without it, pure-entropy secrets with no keyword
// anchor bail (that regression pinned generic-high-entropy recall at 0.36). The
// gate is deliberately PERMISSIVE — UUID/hash-shaped false positives that pass here
// are suppressed downstream, so this pins the run/threshold contract, not precision.

#[test]
fn entropy_run_threshold_is_thirty_two() {
    assert_eq!(DEFAULT_ENTROPY_RUN_BYTES, 32);
}

#[test]
fn run_of_exactly_thirty_two_candidates_triggers() {
    assert!(has_high_entropy_run_fast(&[b'a'; 32]));
}

#[test]
fn run_of_thirty_one_candidates_does_not_trigger() {
    assert!(!has_high_entropy_run_fast(&[b'a'; 31]));
}

#[test]
fn a_non_candidate_byte_resets_the_run() {
    // 16 + space + 16 never reaches a contiguous 32.
    let mut data = vec![b'a'; 16];
    data.push(b' ');
    data.extend(std::iter::repeat(b'a').take(16));
    assert!(!has_high_entropy_run_fast(&data));
}

#[test]
fn run_resumes_after_a_break_and_can_still_trigger() {
    // Leading non-candidates do not prevent a later 32-run from firing.
    let mut data = vec![b' '; 8];
    data.extend(std::iter::repeat(b'z').take(32));
    assert!(has_high_entropy_run_fast(&data));
}

#[test]
fn every_allowed_symbol_byte_is_a_candidate() {
    for sym in [
        b'-', b'_', b'+', b'/', b'=', b'.', b':', b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*',
    ] {
        assert!(
            has_high_entropy_run_fast(&[sym; 32]),
            "symbol {:?} must count as an entropy-candidate byte",
            sym as char
        );
    }
}

#[test]
fn base64ish_mixed_run_triggers() {
    // A realistic base64/token run mixing alnum + `+/=._:-` is one contiguous run.
    let data = b"aB3+/=._:-aB3+/=._:-aB3+/=._:-aB3+"; // 33 candidate bytes
    assert!(has_high_entropy_run_fast(data));
}

#[test]
fn whitespace_and_structural_bytes_are_not_candidates() {
    assert!(!has_high_entropy_run_fast(&[b' '; 40]), "spaces");
    assert!(!has_high_entropy_run_fast(&[b'\n'; 40]), "newlines");
    assert!(!has_high_entropy_run_fast(&[b'"'; 40]), "double quotes");
    assert!(!has_high_entropy_run_fast(&[b'('; 40]), "parens");
}

#[test]
fn entropy_gate_empty_input_does_not_trigger() {
    assert!(!has_high_entropy_run_fast(b""));
}

#[test]
fn realistic_64_char_sha_hex_triggers() {
    let sha = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // 64 hex
    assert!(has_high_entropy_run_fast(sha));
}

#[test]
fn realistic_40_char_base62_token_triggers() {
    let token = b"ghp01234567890abcdefABCDEF0123456789wxyz"; // 40 alnum
    assert_eq!(token.len(), 40);
    assert!(has_high_entropy_run_fast(token));
}

#[test]
fn uuid_shaped_string_reaches_the_run_threshold() {
    // A 36-char UUID is one contiguous run because `-` is a candidate byte, so it
    // DOES pass this permissive gate (36 >= 32). The UUID-shaped false positive is
    // killed downstream by is_uuid_v4_shape, not here — pin that division of labor.
    let uuid = b"550e8400-e29b-41d4-a716-446655440000";
    assert_eq!(uuid.len(), 36);
    assert!(has_high_entropy_run_fast(uuid));
}

#[test]
fn natural_prose_never_reaches_the_threshold() {
    // Real words cap well under 32 and spaces reset the run.
    assert!(!has_high_entropy_run_fast(
        b"the quick brown fox jumps over the lazy dog again and again"
    ));
}

#[test]
fn at_least_helper_respects_a_custom_min_run() {
    assert!(has_high_entropy_run_at_least(&[b'a'; 16], 16));
    assert!(!has_high_entropy_run_at_least(&[b'a'; 15], 16));
}

#[test]
fn at_least_min_run_zero_clamps_to_one() {
    // min_run is clamped to >= 1: a single candidate byte satisfies min_run 0,
    // but empty data still cannot (there is no candidate byte at all).
    assert!(has_high_entropy_run_at_least(b"a", 0));
    assert!(!has_high_entropy_run_at_least(b"", 0));
}
