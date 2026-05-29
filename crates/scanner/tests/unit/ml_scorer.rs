use keyhog_scanner::ml_scorer::score_with_config;

fn test_score(text: &str, context: &str) -> f64 {
    score_with_config(
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
