use keyhog_scanner::entropy::{shannon_entropy, VERY_HIGH_ENTROPY_THRESHOLD};
use keyhog_scanner::testing::{
    ml_default_config_lists_for_test, ml_features_for_test, ml_score_default_config_for_test,
    ml_score_with_config_for_test,
};

const FILE_TYPE_OFFSET: usize = 32;
const CONFIG_FILE_TYPE_INDEX: usize = FILE_TYPE_OFFSET;
const CI_FILE_TYPE_INDEX: usize = FILE_TYPE_OFFSET + 2;
const VERY_HIGH_ENTROPY_FEATURE_INDEX: usize = 7;

fn test_score(text: &str, context: &str) -> f64 {
    ml_score_with_config_for_test(
        text,
        context,
        &["ghp_".to_string(), "sk-".to_string()],
        &["TOKEN".to_string(), "API_KEY".to_string()],
        &["test".to_string()],
        &["YOUR_".to_string()],
    )
}

#[test]
fn real_secret_scores_high() {
    let text = concat!("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
    let context = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    let s = test_score(text, context);
    assert!(s > 0.7, "Real GitHub PAT should score high, got {:.3}", s);
}

#[test]
fn hash_scores_low() {
    let text = "d41d8cd98f00b204e9800998ecf8427e";
    let context = "checksum = d41d8cd98f00b204e9800998ecf8427e";
    let s = test_score(text, context);
    assert!(s < 0.5, "MD5 hash should score low, got {:.3}", s);
}

#[test]
fn placeholder_scores_low() {
    let text = "YOUR_API_KEY_HERE";
    let context = "API_KEY=YOUR_API_KEY_HERE";
    let s = test_score(text, context);
    assert!(s < 0.3, "Placeholder should score very low, got {:.3}", s);
}

#[test]
fn empty_string_scores_zero() {
    assert_eq!(test_score("", "API_KEY="), 0.0);
}

#[test]
fn openai_key_scores_high() {
    // sk-proj- is a top-shelf provider prefix anchored to OPENAI_API_KEY=;
    // a "scores high" assertion below 0.5 is meaningless because the empty
    // string in the sibling test already scores 0.0. Real bar: a known
    // provider-prefixed credential under its env-var context must land
    // above 0.5 - otherwise the ML scorer is barely lifting confidence at
    // all over the no-info baseline.
    let key = "sk-proj-EXAMPLE000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let context = format!("OPENAI_API_KEY={key}");
    let s = test_score(key, &context);
    assert!(
        s > 0.5,
        "Realistic OpenAI key scored {:.3}, expected > 0.5 \
         (provider-prefixed credential under explicit env-var context)",
        s
    );
}

#[test]
fn base64_binary_scores_below_real_secret() {
    use base64::Engine;
    // Decode-structure feature (#41) in action through the real MoE forward
    // pass: a base64 blob that decodes to a PNG (magic bytes) is an embedded
    // asset, not a credential, even when it sits under a secret keyword. A real
    // high-entropy token of similar length under the SAME context must score
    // strictly higher - the only difference the model can see is the decode
    // verdict. This is the supervised "filter out base64" result.
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]);
    png.extend_from_slice(&[0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03]);
    let png_b64 = base64::engine::general_purpose::STANDARD.encode(&png);
    let secret = "Xk9Lm2Pq7Rs4Tv8Wy1Zb3Cd6Ef0Gh5IjKl7Mn";

    let png_ctx = format!("API_KEY={png_b64}");
    let secret_ctx = format!("API_KEY={secret}");
    let png_score = test_score(&png_b64, &png_ctx);
    let secret_score = test_score(secret, &secret_ctx);

    assert!(
        png_score < secret_score,
        "base64-of-PNG scored {png_score:.3}; a real secret scored {secret_score:.3} - \
         the decode-structure feature should push the binary blob lower"
    );
    assert!(
        png_score < 0.3,
        "base64-of-PNG must score below the report floor, got {png_score:.3}"
    );
}

#[test]
fn file_type_context_markers_are_ascii_case_insensitive() {
    let ci = ml_features_for_test(
        concat!("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"),
        "path=.GITHUB/WORKFLOWS/build.yml\nJOBS:\n  scan:",
    );
    assert_eq!(
        ci[CI_FILE_TYPE_INDEX], 1.0,
        "mixed-case CI markers must classify as CI context"
    );

    let config = ml_features_for_test(
        "sk-proj-EXAMPLE000000000000000000000000000000000000000000000000000000000000",
        "OPENAI_API_KEY=value\nsource=SETTINGS.YAML",
    );
    assert_eq!(
        config[CONFIG_FILE_TYPE_INDEX], 1.0,
        "mixed-case config markers must classify as config context"
    );
}

#[test]
fn very_high_entropy_feature_uses_canonical_scanner_threshold() {
    let text = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let entropy = shannon_entropy(text.as_bytes());
    assert!(
        (5.5..VERY_HIGH_ENTROPY_THRESHOLD).contains(&entropy),
        "fixture entropy {entropy:.4} must sit between the old drifted 5.5 cutoff and canonical {VERY_HIGH_ENTROPY_THRESHOLD}"
    );

    let features = ml_features_for_test(text, "API_KEY=");
    assert_eq!(
        features[VERY_HIGH_ENTROPY_FEATURE_INDEX], 0.0,
        "ML feature[7] must use canonical VERY_HIGH_ENTROPY_THRESHOLD={VERY_HIGH_ENTROPY_THRESHOLD}, not the old private 5.5 cutoff"
    );
}

#[test]
fn inference_is_fast() {
    let text = concat!("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
    let context = "TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    let start = std::time::Instant::now();
    for _ in 0..10000 {
        let _ = test_score(text, context);
    }
    let elapsed = start.elapsed();
    let per_call = elapsed / 10000;
    assert!(
        per_call.as_micros() < 100,
        "Inference too slow: {:?} per call",
        per_call
    );
}

// ── shipped-model separation contract ───────────────────────────────────────
//
// The MoE is AUTHORITATIVE for entropy-fallback candidates by default
// (`entropy_ml_authoritative` defaults on — core/config.rs), so its ability to
// score real high-entropy SECRETS high and structured high-entropy NON-secrets
// (hashes, UUIDs, JWT headers, mime types, dotted class names) low IS the
// recall/precision contract: a retrain that erodes that gap silently flips
// entropy-fallback behavior with no other gate to catch it.
//
// `ml/probe_entropy_separation.py` is the go/no-go oracle: it reconstructs the
// shipped `weights.bin` forward pass in numpy and scores a battery of real
// secrets vs. structured non-secrets through the Rust serve-path feature
// extractor with `config_lists.DEFAULT_LISTS` (which mirror
// `ScanConfig::default()`), reporting clean separation (real secrets ~0.98,
// non-secrets ~0.02, gap ~0.95). These tests are the CI mirror of that oracle:
// the SAME battery and the SAME default-config scoring path
// (`ml_score_default_config_for_test`), so the property the probe validates
// once cannot regress unnoticed.
//
// Two deliberate fidelity choices keep this honest:
//  * scoring goes through the real default keyword/prefix lists, NOT the
//    restricted `test_score` lists above — the model is context-sensitive by
//    design (a hash assigned to `api_key =` SHOULD raise suspicion), so the
//    separation is only meaningful under the production config, exactly as the
//    probe measures it; and
//  * each non-secret sits in its natural, non-credential context and each
//    secret under its real assignment prefix — the discrimination is the
//    model's, on the value, not an artifact of a hand-picked context.
//
// Each secret value is assembled from two fragments so this file holds no full
// credential-shaped literal (dogfood self-scan / push-protection clean).

/// Real high-entropy secrets under their natural secret-keyword assignment
/// prefixes — must score HIGH. Mirrors `probe_entropy_separation.py::TP`. The
/// context is the assignment prefix only (e.g. `token = "`), matching the
/// probe's feature inputs; the value is passed separately as the candidate.
fn real_secret_battery() -> Vec<(&'static str, String, &'static str)> {
    vec![
        ("aws_secret", format!("wJalrXUtnFEMI7K8{}", "MDfNGbPxRziCY3p9qLm2vK4"), "aws_secret_access_key = \""),
        ("client_secret", format!("xK9mPq2vL8nR4wT6{}", "yU3zA1bC5dE7fG0hJ2kM4nP"), "client_secret: "),
        ("password", format!("Atr0xK9mPq2vL8nR{}", "4wT6yU3zHc1bC5dE7fG"), "password = \""),
        ("secret_key", format!("4eC39HqLyjWDar{}", "jtT1zdp7dcQm8nZx2vL5"), "secret_key = \""),
        ("api_secret", format!("aB3xY7zQ9mK2pL5n{}", "R8wT6vU1jH4kM0nP7qR"), "api_secret: "),
        ("token", format!("R8wT6vU1jH4kM0nP{}", "7qZx2vL5nDe9fG3hJ6k"), "token = \""),
    ]
}

/// Structured high-entropy NON-secrets in their natural, non-credential
/// contexts — must score LOW. Mirrors `probe_entropy_separation.py::FP`: a
/// sha256 digest, an md5 etag, a UUID, a JWT header envelope, a git sha1, a
/// Java class name, a mime type, and a hex constant.
fn structured_nonsecret_battery() -> Vec<(&'static str, String, &'static str)> {
    vec![
        (
            "sha256_digest",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string(),
            "image: nginx@sha256:",
        ),
        ("md5_etag", "d41d8cd98f00b204e9800998ecf8427e".to_string(), "etag = \""),
        ("uuid", "550e8400-e29b-41d4-a716-446655440000".to_string(), "request_id = \""),
        ("jwt_header", format!("eyJhbGciOiJIUzI1NiIs{}", "InR5cCI6IkpXVCJ9"), "jwt_header = "),
        ("git_sha1", "a3f5c8e1b9d7f2a6c4e8b1d5f9a2c6e4b8d1f5a9".to_string(), "commit = \""),
        ("class_name", "com.fasterxml.jackson.databind.ObjectMapper".to_string(), "class = "),
        ("mime_type", "application/vnd.github.v3+json".to_string(), "accept = "),
        ("hex_constant", "0123456789abcdef0123456789abcdef".to_string(), "build_id = \""),
    ]
}

/// Score a battery entry through the production default-config MoE path.
fn battery_score(value: &str, context: &str) -> f64 {
    ml_score_default_config_for_test(value, context)
}

/// Recall side: every real high-entropy secret scores above 0.5.
#[test]
fn every_real_secret_scores_above_half() {
    for (label, value, ctx) in real_secret_battery() {
        let s = battery_score(&value, ctx);
        assert!(s > 0.5, "real secret '{label}' scored {s:.3}, expected > 0.5");
    }
}

/// Precision side: every structured high-entropy non-secret scores below 0.5,
/// even though each sits under assignment syntax.
#[test]
fn every_structured_nonsecret_scores_below_half() {
    for (label, value, ctx) in structured_nonsecret_battery() {
        let s = battery_score(&value, ctx);
        assert!(s < 0.5, "structured non-secret '{label}' scored {s:.3}, expected < 0.5");
    }
}

/// The load-bearing property: clean separation — the lowest-scoring real secret
/// outranks the highest-scoring structured non-secret. A retrain that lets ANY
/// structured non-secret outscore ANY real secret fails here.
#[test]
fn real_secrets_cleanly_separate_from_structured_nonsecrets() {
    let tp_min = real_secret_battery()
        .into_iter()
        .map(|(_, v, ctx)| battery_score(&v, ctx))
        .fold(f64::INFINITY, f64::min);
    let fp_max = structured_nonsecret_battery()
        .into_iter()
        .map(|(_, v, ctx)| battery_score(&v, ctx))
        .fold(f64::NEG_INFINITY, f64::max);
    assert!(
        tp_min > fp_max,
        "no clean separation: lowest secret {tp_min:.3} <= highest non-secret {fp_max:.3}"
    );
}

/// The separation must be a real margin, not a hairline — guards against a slow
/// erosion that keeps ordering but collapses the gap. The probe measures ~0.95;
/// 0.5 is a conservative floor that still catches a halving of the gap.
#[test]
fn separation_margin_is_substantial() {
    let tp_min = real_secret_battery()
        .into_iter()
        .map(|(_, v, ctx)| battery_score(&v, ctx))
        .fold(f64::INFINITY, f64::min);
    let fp_max = structured_nonsecret_battery()
        .into_iter()
        .map(|(_, v, ctx)| battery_score(&v, ctx))
        .fold(f64::NEG_INFINITY, f64::max);
    assert!(
        tp_min - fp_max > 0.5,
        "separation margin {:.3} too small (secret_min={tp_min:.3}, nonsecret_max={fp_max:.3})",
        tp_min - fp_max
    );
}

/// Cluster-mean view: the average real-secret score sits far above the average
/// structured-non-secret score (the probe reports ~0.98 vs ~0.02).
#[test]
fn tp_cluster_mean_far_exceeds_fp_cluster_mean() {
    let mean = |b: Vec<(&'static str, String, &'static str)>| {
        let n = b.len() as f64;
        b.into_iter().map(|(_, v, ctx)| battery_score(&v, ctx)).sum::<f64>() / n
    };
    let tp_mean = mean(real_secret_battery());
    let fp_mean = mean(structured_nonsecret_battery());
    assert!(
        tp_mean - fp_mean > 0.5,
        "cluster-mean gap {:.3} too small (tp_mean={tp_mean:.3}, fp_mean={fp_mean:.3})",
        tp_mean - fp_mean
    );
}

// Per-class pairwise locks: each structured non-secret class scores strictly
// below a canonical real secret, and below the 0.5 bar. Individual tests so a
// regression names the exact class that broke.

fn canonical_secret_score() -> f64 {
    let (_, v, ctx) = &real_secret_battery()[5]; // token = "
    battery_score(v, ctx)
}

fn nonsecret_score(label: &str) -> f64 {
    let (_, v, ctx) = structured_nonsecret_battery()
        .into_iter()
        .find(|(l, _, _)| *l == label)
        .expect("label in battery");
    battery_score(&v, ctx)
}

#[test]
fn uuid_scores_below_a_real_secret() {
    let (n, s) = (nonsecret_score("uuid"), canonical_secret_score());
    assert!(n < s && n < 0.5, "uuid {n:.3} vs secret {s:.3}");
}

#[test]
fn sha256_digest_scores_below_a_real_secret() {
    let (n, s) = (nonsecret_score("sha256_digest"), canonical_secret_score());
    assert!(n < s && n < 0.5, "sha256 {n:.3} vs secret {s:.3}");
}

#[test]
fn git_sha1_scores_below_a_real_secret() {
    let (n, s) = (nonsecret_score("git_sha1"), canonical_secret_score());
    assert!(n < s && n < 0.5, "git sha1 {n:.3} vs secret {s:.3}");
}

#[test]
fn jwt_header_scores_below_a_real_secret() {
    let (n, s) = (nonsecret_score("jwt_header"), canonical_secret_score());
    assert!(n < s && n < 0.5, "jwt header {n:.3} vs secret {s:.3}");
}

#[test]
fn mime_type_scores_below_a_real_secret() {
    let (n, s) = (nonsecret_score("mime_type"), canonical_secret_score());
    assert!(n < s && n < 0.5, "mime type {n:.3} vs secret {s:.3}");
}

#[test]
fn class_name_scores_below_a_real_secret() {
    let (n, s) = (nonsecret_score("class_name"), canonical_secret_score());
    assert!(n < s && n < 0.5, "class name {n:.3} vs secret {s:.3}");
}

#[test]
fn hex_constant_scores_below_a_real_secret() {
    let (n, s) = (nonsecret_score("hex_constant"), canonical_secret_score());
    assert!(n < s && n < 0.5, "hex constant {n:.3} vs secret {s:.3}");
}

#[test]
fn md5_etag_scores_below_a_real_secret() {
    let (n, s) = (nonsecret_score("md5_etag"), canonical_secret_score());
    assert!(n < s && n < 0.5, "md5 etag {n:.3} vs secret {s:.3}");
}

// Per-secret-class recall locks: each real-secret shape clears the bar so a
// regression names the exact assignment context that stopped scoring high.

fn secret_score(label: &str) -> f64 {
    let (_, v, ctx) = real_secret_battery()
        .into_iter()
        .find(|(l, _, _)| *l == label)
        .expect("label in battery");
    battery_score(&v, ctx)
}

#[test]
fn aws_secret_shape_scores_above_half() {
    let s = secret_score("aws_secret");
    assert!(s > 0.5, "aws secret shape scored {s:.3}");
}

#[test]
fn client_secret_scores_above_half() {
    let s = secret_score("client_secret");
    assert!(s > 0.5, "client_secret scored {s:.3}");
}

#[test]
fn password_assignment_scores_above_half() {
    let s = secret_score("password");
    assert!(s > 0.5, "password scored {s:.3}");
}

#[test]
fn secret_key_assignment_scores_above_half() {
    let s = secret_score("secret_key");
    assert!(s > 0.5, "secret_key scored {s:.3}");
}

#[test]
fn api_secret_assignment_scores_above_half() {
    let s = secret_score("api_secret");
    assert!(s > 0.5, "api_secret scored {s:.3}");
}

#[test]
fn token_assignment_scores_above_half() {
    let s = secret_score("token");
    assert!(s > 0.5, "token scored {s:.3}");
}

/// The model's verdict is a pure function of (value, context): the same input
/// scores bit-identically across calls (no nondeterminism from the per-thread
/// score cache or expert-accumulation order).
#[test]
fn score_is_deterministic_across_calls() {
    let (_, v, ctx) = &real_secret_battery()[5];
    let first = battery_score(v, ctx);
    for _ in 0..50 {
        assert_eq!(battery_score(v, ctx), first, "score must be deterministic");
    }
}

/// Coherence guard tying the battery to the real shipped config: every
/// real-secret context is anchored by at least one keyword that is actually in
/// `ScanConfig::default().secret_keywords`. If a future config edit drops the
/// keyword a context relies on, the battery would stop exercising the shipped
/// list (train/serve drift vs. `ml/config_lists.py`) and this fails loudly
/// instead of the separation tests passing for the wrong reason.
#[test]
fn default_config_secret_keywords_anchor_every_real_secret_context() {
    let (_, secret_keywords, _, _) = ml_default_config_lists_for_test();
    for (label, _v, ctx) in real_secret_battery() {
        let lc = ctx.to_ascii_lowercase();
        assert!(
            secret_keywords.iter().any(|k| lc.contains(&k.to_ascii_lowercase())),
            "real-secret context for '{label}' ({ctx:?}) contains no default secret keyword - \
             battery no longer exercises the shipped keyword list"
        );
    }
}

/// Speed bound on the whole battery: scoring the full secret+non-secret set
/// stays well inside the per-call budget the `inference_is_fast` test pins, so
/// the authoritative-MoE path can never become a slow fallback (Law 10 speed
/// bound). Construct the lists once, time only the scoring.
#[test]
fn battery_scoring_is_fast() {
    let battery: Vec<(String, &'static str)> = real_secret_battery()
        .into_iter()
        .chain(structured_nonsecret_battery())
        .map(|(_, v, ctx)| (v, ctx))
        .collect();
    let start = std::time::Instant::now();
    for _ in 0..2000 {
        for (v, ctx) in &battery {
            let _ = battery_score(v, ctx);
        }
    }
    let calls = 2000 * battery.len() as u32;
    let per_call = start.elapsed() / calls;
    assert!(per_call.as_micros() < 100, "battery inference too slow: {per_call:?}/call");
}
