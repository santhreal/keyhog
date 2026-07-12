//! Regression contract for the MoE ML scorer's feature extractor and score path.
//!
//! These tests pin CONCRETE expected values of the 43-dimensional feature vector
//! (`ml_scorer::compute_features_with_config`) and of the observable score path
//! (`testing::ml_score`, which routes through the memoized `score` → forward pass
//! → rational sigmoid). Every assertion is an exact value: an f32 within a tight
//! epsilon, an exact `0.0`/`1.0` binary feature, a monotone ordering, or an exact
//! score-cache equality. No `is_empty()`/`len()>0`-only assertions.
//!
//! Feature-index map (mirrored from `ml_scorer/ml_features.rs`):
//!   [0]=len/200 clamp1  [1]=len>=20 [2]=len>=40 [3]=len>=100
//!   [4]=entropy/8  [5]=entropy>=3.5 [6]=entropy>=4.5 [7]=entropy>=5.8
//!   [8]=upper [9]=lower [10]=digit [11]=symbol
//!   [12]=known_prefix>0 [13]=prefix_len/10 clamp1 [14]="sk-" [15]="AKIA"
//!   [16]=ctx assignment [17]=secret_kw [18]=test_kw [19]=ctx comment
//!   [20]=placeholder_kw [21]=low-variety [22]=hex-placeholder [23]="://"
//!   [24]=unique_chars/40 [25]=unique_bigram ratio [26]=dots/5 [27]=dashes/10
//!   [32..37]=file-type one-hot (config,source,ci,infra,other,binary)
//!   [38]=comment [39]=assignment [40]=test-file [41]=decode-structure binary
//!   [42]=service-context (DET-1: context names a specific service from the
//!        detector-corpus-derived vocab, vs a generic api_key/secret/token role word)

const EPS: f32 = 1e-6;

fn feats(text: &str, ctx: &str) -> [f32; 43] {
    keyhog_scanner::ml_scorer::compute_features_with_config(text, ctx, &[], &[], &[], &[])
}

fn feats_cfg(
    text: &str,
    ctx: &str,
    prefixes: &[String],
    secret_kw: &[String],
    test_kw: &[String],
    placeholder_kw: &[String],
) -> [f32; 43] {
    keyhog_scanner::ml_scorer::compute_features_with_config(
        text,
        ctx,
        prefixes,
        secret_kw,
        test_kw,
        placeholder_kw,
    )
}

fn close(actual: f32, expected: f32, label: &str) {
    assert!(
        (actual - expected).abs() < EPS,
        "{label}: expected {expected}, got {actual}"
    );
}

#[test]
fn length_features_hit_exact_thresholds_and_clamp() {
    // len 19 -> just below the medium threshold (20); f[1]=0.
    let f19 = feats(&"e".repeat(19), "");
    close(f19[0], 19.0 / 200.0, "f0@19");
    assert_eq!(f19[1], 0.0, "f1@19 must be below medium threshold 20");
    assert_eq!(f19[2], 0.0);
    assert_eq!(f19[3], 0.0);

    // len 20 -> exactly medium threshold; f[1]=1, f[2]=0.
    let f20 = feats(&"b".repeat(20), "");
    close(f20[0], 20.0 / 200.0, "f0@20"); // 0.1
    assert_eq!(f20[1], 1.0);
    assert_eq!(f20[2], 0.0);
    assert_eq!(f20[3], 0.0);

    // len 40 -> exactly long threshold; f[2]=1, f[3]=0.
    let f40 = feats(&"c".repeat(40), "");
    close(f40[0], 40.0 / 200.0, "f0@40"); // 0.2
    assert_eq!(f40[1], 1.0);
    assert_eq!(f40[2], 1.0);
    assert_eq!(f40[3], 0.0);

    // len 100 -> exactly very-long threshold; all three fire.
    let f100 = feats(&"d".repeat(100), "");
    close(f100[0], 0.5, "f0@100");
    assert_eq!(f100[1], 1.0);
    assert_eq!(f100[2], 1.0);
    assert_eq!(f100[3], 1.0);

    // len 250 -> f[0] clamps to 1.0 (250/200 = 1.25 -> min(1.0)).
    let f250 = feats(&"z".repeat(250), "");
    close(f250[0], 1.0, "f0@250 clamp");
}

#[test]
fn entropy_features_match_canonical_shannon_and_buckets() {
    // "abcd": 4 distinct bytes, uniform -> Shannon entropy = log2(4) = 2.0.
    // 2.0 < 3.5 -> none of the entropy buckets fire.
    let low = feats("abcd", "");
    let ent_low = keyhog_scanner::entropy::shannon_entropy(b"abcd");
    close(low[4], ent_low as f32 / 8.0, "f4 parity low"); // ~0.25
    assert_eq!(low[5], 0.0, "entropy 2.0 is below 3.5 bucket");
    assert_eq!(low[6], 0.0);
    assert_eq!(low[7], 0.0);

    // 64 distinct bytes, uniform -> entropy = log2(64) = 6.0, above every bucket.
    let alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
    assert_eq!(alphabet.len(), 64);
    let hi = feats(alphabet, "");
    let ent_hi = keyhog_scanner::entropy::shannon_entropy(alphabet.as_bytes());
    close(hi[4], ent_hi as f32 / 8.0, "f4 parity hi"); // ~0.75
    assert_eq!(hi[5], 1.0, "entropy ~6.0 clears 3.5 bucket");
    assert_eq!(hi[6], 1.0, "entropy ~6.0 clears 4.5 bucket");
    assert_eq!(hi[7], 1.0, "entropy ~6.0 clears 5.8 bucket");
}

#[test]
fn character_class_features_are_exact() {
    // Mixed: upper, lower, digit, and symbols ('-','#').
    let mixed = feats("Abc123-#", "");
    assert_eq!(mixed[8], 1.0, "has_upper");
    assert_eq!(mixed[9], 1.0, "has_lower");
    assert_eq!(mixed[10], 1.0, "has_digit");
    assert_eq!(mixed[11], 1.0, "has_symbol");

    // All uppercase letters only.
    let upper = feats("ABCDEF", "");
    assert_eq!(upper[8], 1.0);
    assert_eq!(upper[9], 0.0, "no lowercase");
    assert_eq!(upper[10], 0.0, "no digit");
    assert_eq!(upper[11], 0.0, "no symbol");

    // Digits only.
    let digits = feats("123456", "");
    assert_eq!(digits[8], 0.0);
    assert_eq!(digits[9], 0.0);
    assert_eq!(digits[10], 1.0);
    assert_eq!(digits[11], 0.0);

    // Plain prose text (spaces are outside any base64/hex alphabet, so no decode
    // is attempted) is not a decode-structure binary payload.
    let plain = feats("hello world value", "");
    assert_eq!(
        plain[41], 0.0,
        "non-encoded text -> decode-structure feature 0.0"
    );
}

#[test]
fn builtin_openai_and_aws_prefix_features_are_exact() {
    let openai = feats("sk-abcdefghij", "");
    assert_eq!(openai[14], 1.0, "starts with sk-");
    assert_eq!(openai[15], 0.0, "not AKIA");

    let aws = feats("AKIAIOSFODNN7EXAMPLE", "");
    assert_eq!(aws[14], 0.0, "not sk-");
    assert_eq!(aws[15], 1.0, "starts with AKIA");

    let neither = feats("hello", "");
    assert_eq!(neither[14], 0.0);
    assert_eq!(neither[15], 0.0);
}

#[test]
fn known_prefix_length_feature_scales_and_clamps() {
    let prefixes = vec!["glpat-".to_string(), "ghp_".to_string()];

    // "glpat-" is 6 chars -> f[13] = 6/10 = 0.6.
    let glpat = feats_cfg("glpat-XYZABC", "", &prefixes, &[], &[], &[]);
    assert_eq!(glpat[12], 1.0, "known prefix present");
    close(glpat[13], 0.6, "prefix_len 6 -> 0.6");

    // "ghp_" is 4 chars -> f[13] = 0.4.
    let ghp = feats_cfg("ghp_abcdef", "", &prefixes, &[], &[], &[]);
    assert_eq!(ghp[12], 1.0);
    close(ghp[13], 0.4, "prefix_len 4 -> 0.4");

    // No configured prefix matches.
    let none = feats_cfg("nomatchhere", "", &prefixes, &[], &[], &[]);
    assert_eq!(none[12], 0.0);
    close(none[13], 0.0, "no prefix -> 0.0");

    // A 13-char prefix clamps f[13] to 1.0 (13/10 = 1.3 -> min(1.0)).
    let long_prefix = vec!["0123456789ABC".to_string()];
    let clamped = feats_cfg("0123456789ABCXY", "", &long_prefix, &[], &[], &[]);
    assert_eq!(clamped[12], 1.0);
    close(clamped[13], 1.0, "13-char prefix clamps to 1.0");
}

#[test]
fn low_variety_placeholder_feature_respects_length_and_variety_bounds() {
    // len 6 > 5 AND unique 1 <= 3 -> fires.
    assert_eq!(feats("aaaaaa", "")[21], 1.0);
    // len 5 is NOT > MIN_LOW_VARIETY_LENGTH(5) -> does not fire (boundary).
    assert_eq!(feats("aaaaa", "")[21], 0.0, "len 5 fails strict > 5");
    // unique 3 <= 3 -> still fires.
    assert_eq!(feats("aabbcc", "")[21], 1.0, "unique 3 is <= threshold 3");
    // unique 4 > 3 -> does not fire.
    assert_eq!(feats("aabbcd", "")[21], 0.0, "unique 4 exceeds threshold 3");
    // len 2 too short even though unique 1.
    assert_eq!(feats("aa", "")[21], 0.0);
}

#[test]
fn hex_placeholder_feature_requires_all_hex_and_length_over_ten() {
    // 12 hex chars, len > 10 -> fires.
    assert_eq!(feats("0123456789ab", "")[22], 1.0);
    // Exactly 10 hex chars -> 10 is NOT > 10 (boundary) -> does not fire.
    assert_eq!(feats("0123456789", "")[22], 0.0, "len 10 fails strict > 10");
    // 13 hex chars -> fires.
    assert_eq!(feats("0123456789abc", "")[22], 1.0);
    // Contains non-hex chars (X,Y) -> does not fire.
    assert_eq!(
        feats("0123456789abXY", "")[22],
        0.0,
        "non-hex char blocks feature"
    );
}

#[test]
fn url_scheme_feature_is_exact() {
    assert_eq!(feats("https://example.com/x", "")[23], 1.0, "'://' present");
    assert_eq!(feats("noscheme", "")[23], 0.0, "no '://'");
    assert_eq!(feats("ftp://host", "")[23], 1.0);
}

#[test]
fn unique_bigram_ratio_matches_exact_distinct_count() {
    // "abcd": windows ab,bc,cd -> 3 distinct of 3 -> 1.0.
    close(feats("abcd", "")[25], 1.0, "abcd bigram ratio");
    // "abcabc": windows ab,bc,ca,ab,bc -> distinct {ab,bc,ca}=3 of 5 -> 0.6.
    close(feats("abcabc", "")[25], 3.0 / 5.0, "abcabc bigram ratio");
    // "aaaa": windows aa,aa,aa -> 1 distinct of 3 -> 1/3.
    close(feats("aaaa", "")[25], 1.0 / 3.0, "aaaa bigram ratio");
    // "ab": single window -> 1/1 -> 1.0.
    close(feats("ab", "")[25], 1.0, "ab bigram ratio");
    // Single char: fewer than 2 bytes -> denominator 0 -> ratio 0.0.
    close(feats("a", "")[25], 0.0, "single char -> 0.0 ratio");
}

#[test]
fn structure_features_unique_chars_and_punctuation_counts() {
    // "a.b.c-d-e": distinct {a,.,b,c,-,d,e}=7; dots=2; dashes=2.
    let f = feats("a.b.c-d-e", "");
    close(f[24], 7.0 / 40.0, "unique_chars 7 -> 0.175");
    close(f[26], 2.0 / 5.0, "dot_count 2 -> 0.4");
    close(f[27], 2.0 / 10.0, "dash_count 2 -> 0.2");

    // 6 dots -> dot_count/5 = 1.2 clamps to 1.0; single distinct char '.'.
    let dots = feats("......", "");
    close(dots[26], 1.0, "6 dots clamp to 1.0");
    close(dots[24], 1.0 / 40.0, "unique_chars 1 -> 0.025");

    // 15 dashes -> dash_count/10 = 1.5 clamps to 1.0.
    let dashes = feats(&"-".repeat(15), "");
    close(dashes[27], 1.0, "15 dashes clamp to 1.0");
}

#[test]
fn file_type_one_hot_is_exactly_one_and_priority_ordered() {
    // Helper: sum of the six one-hot slots must always be exactly 1.0.
    let one_hot_sum = |f: &[f32; 43]| f[32] + f[33] + f[34] + f[35] + f[36] + f[37];

    // Empty context -> OTHER (index 4 -> slot 36).
    let other = feats("secret", "");
    assert_eq!(other[36], 1.0, "empty ctx -> OTHER");
    close(one_hot_sum(&other), 1.0, "exactly one file-type set");

    // Unquoted '=' -> CONFIG (index 0 -> slot 32).
    let config = feats("secret", "KEY=val");
    assert_eq!(config[32], 1.0, "unquoted equals -> CONFIG");
    close(one_hot_sum(&config), 1.0, "one file-type");

    // "def " source marker -> SOURCE (index 1 -> slot 33).
    let source = feats("secret", "def foo");
    assert_eq!(source[33], 1.0, "def marker -> SOURCE");
    close(one_hot_sum(&source), 1.0, "one file-type");

    // "jobs:" CI marker -> CI (index 2 -> slot 34).
    let ci = feats("secret", "jobs:");
    assert_eq!(ci[34], 1.0, "jobs: -> CI");
    close(one_hot_sum(&ci), 1.0, "one file-type");

    // "from " infra marker -> INFRA (index 3 -> slot 35).
    let infra = feats("secret", "from base");
    assert_eq!(infra[35], 1.0, "from -> INFRA");
    close(one_hot_sum(&infra), 1.0, "one file-type");

    // ".rodata" binary marker -> BINARY (index 5 -> slot 37), highest priority.
    let binary = feats("secret", ".rodata section");
    assert_eq!(binary[37], 1.0, ".rodata -> BINARY");
    close(one_hot_sum(&binary), 1.0, "one file-type");
}

#[test]
fn extra_context_features_comment_assignment_and_testfile() {
    // Comment start + unquoted equals -> comment (38) and assignment (39) both fire.
    let comment_assign = feats("secret", "# api_key = value");
    assert_eq!(comment_assign[38], 1.0, "comment prefix '#'");
    assert_eq!(comment_assign[39], 1.0, "unquoted '=' assignment");
    assert_eq!(comment_assign[40], 0.0, "not a test-file context");

    // Test-file fragment "test" present, no assignment, no comment.
    let testfile = feats("secret", "value in test_helper module");
    assert_eq!(testfile[40], 1.0, "'test' fragment -> test-file context");
    assert_eq!(testfile[39], 0.0, "no assignment operator");
    assert_eq!(testfile[38], 0.0, "not a comment");

    // ": " colon-space is treated as an assignment operator.
    let colon = feats("secret", "field: value");
    assert_eq!(colon[39], 1.0, "': ' -> assignment");
    assert_eq!(colon[38], 0.0);
    assert_eq!(colon[40], 0.0);

    // Plain prose -> none of the three fire.
    let plain = feats("secret", "just some prose here");
    assert_eq!(plain[38], 0.0);
    assert_eq!(plain[39], 0.0);
    assert_eq!(plain[40], 0.0);
}

#[test]
fn context_keyword_features_use_supplied_lists() {
    let secret_kw = vec!["password".to_string()];
    let test_kw = vec!["dummy".to_string()];

    // Secret keyword present in context -> f[17]=1, f[18]=0.
    let secret = feats_cfg(
        "s3cr3t",
        "the password field",
        &[],
        &secret_kw,
        &test_kw,
        &[],
    );
    assert_eq!(secret[17], 1.0, "secret keyword matched");
    assert_eq!(secret[18], 0.0, "no test keyword");

    // Test keyword present -> f[18]=1, f[17]=0.
    let test = feats_cfg(
        "s3cr3t",
        "a dummy value here",
        &[],
        &secret_kw,
        &test_kw,
        &[],
    );
    assert_eq!(test[17], 0.0);
    assert_eq!(test[18], 1.0, "test keyword matched");

    // Comment context sets f[19] (context comment) and f[16] assignment via '='.
    let assign = feats_cfg("s3cr3t", "x = 1", &[], &[], &[], &[]);
    assert_eq!(assign[16], 1.0, "context assignment operator");
    assert_eq!(assign[19], 0.0, "not a comment");

    // Placeholder keyword in the TEXT sets f[20].
    let placeholder_kw = vec!["changeme".to_string()];
    let ph = feats_cfg("changeme", "", &[], &[], &[], &placeholder_kw);
    assert_eq!(ph[20], 1.0, "placeholder keyword in text");
}

#[test]
fn service_context_feature_reflects_named_service_vs_generic() {
    // Feature 42 (DET-1 keyword specificity): the full feature vector's slot [42]
    // must be WIRED to `service_vocab::context_names_service` on the context — a
    // context that names a specific service from the detector-corpus-derived vocab
    // makes an otherwise-generic value credible (fires), while a purely generic
    // role-word context (api_key/secret/token — excluded from the vocab) does not.
    // The token value is held constant; ONLY the context varies, isolating slot 42.
    let value = "gH7kLmN9pQ2rS4tV6wX8yZ0aB1cD3eF5";

    // A named service ("zendesk" is pinned in-vocab by tests/unit/service_vocab.rs)
    // -> slot 42 fires. Uses a realistic assignment context.
    let named = feats(
        value,
        "zendesk_api_token = gH7kLmN9pQ2rS4tV6wX8yZ0aB1cD3eF5",
    );
    assert_eq!(
        named[42], 1.0,
        "a service-named context must set the DET-1 service-context feature"
    );

    // Case-fold: the vocab match is ASCII case-insensitive, so an uppercased
    // service name fires identically (guards against a case-sensitive regression).
    let named_upper = feats(value, "ZENDESK_API_TOKEN = xyz");
    assert_eq!(
        named_upper[42], 1.0,
        "service match must be case-insensitive"
    );

    // A generic role-word-only context (no service in the vocab) -> slot 42 is 0.0.
    // This is the exact confusion DET-1 exists to resolve: generic-keyword+opaque
    // value is an identifier (reject), service-keyword+opaque value is a credential.
    let generic = feats(value, "api_key = gH7kLmN9pQ2rS4tV6wX8yZ0aB1cD3eF5");
    assert_eq!(
        generic[42], 0.0,
        "a generic-role-word-only context must NOT set the service-context feature"
    );

    // Empty context short-circuits to 0.0 (context_names_service empty-guard).
    let no_context = feats(value, "");
    assert_eq!(no_context[42], 0.0, "empty context -> no service named");

    // Slot 42 is binary: every observed value is exactly 0.0 or 1.0.
    for f in [&named, &named_upper, &generic, &no_context] {
        assert!(f[42] == 0.0 || f[42] == 1.0, "feature 42 must be binary");
    }
}

#[test]
fn ml_score_is_deterministic_bounded_and_zero_on_empty() {
    // Empty text short-circuits to exactly 0.0.
    assert_eq!(keyhog_scanner::testing::ml_score("", ""), 0.0);
    assert_eq!(keyhog_scanner::testing::ml_score("", "context"), 0.0);

    // A real-looking token: score is a sigmoid output, always within [0, 1].
    let text = "gH7kLmN9pQ2rS4tV6wX8yZ0aB1cD3eF5";
    let ctx = "api_key = gH7kLmN9pQ2rS4tV6wX8yZ0aB1cD3eF5";
    let first = keyhog_scanner::testing::ml_score(text, ctx);
    assert!(
        (0.0..=1.0).contains(&first),
        "sigmoid score must lie in [0,1], got {first}"
    );

    // Memoized cache: identical (text, context) yields a bit-identical score.
    let second = keyhog_scanner::testing::ml_score(text, ctx);
    assert_eq!(first, second, "score cache must be deterministic");

    // Force the 256-entry cache past its wholesale-clear cap, then re-score the
    // original input: eviction must not change the recomputed score.
    for i in 0..300u32 {
        let filler = format!("filler-token-{i:04}-padding");
        let _ = keyhog_scanner::testing::ml_score(&filler, "");
    }
    let after_evict = keyhog_scanner::testing::ml_score(text, ctx);
    assert_eq!(
        first, after_evict,
        "score must be identical after cache eviction (recompute is stable)"
    );
}

#[test]
fn high_entropy_token_scores_above_obvious_placeholder() {
    // A diverse, high-entropy 32-char token vs. a degenerate all-'x' placeholder.
    let strong = keyhog_scanner::testing::ml_score("Xq7pL2mZ9kR4tW6vB8nC1dF3gH5jK0aS", "");
    let placeholder = keyhog_scanner::testing::ml_score(&"x".repeat(32), "");

    assert!(
        (0.0..=1.0).contains(&strong) && (0.0..=1.0).contains(&placeholder),
        "both scores must be valid sigmoid outputs: strong={strong}, placeholder={placeholder}"
    );
    assert!(
        strong > placeholder,
        "high-entropy token ({strong}) must outrank low-variety placeholder ({placeholder})"
    );
}
