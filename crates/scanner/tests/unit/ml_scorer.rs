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
    let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
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
    let key = "sk-proj-EXAMPLE000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let context = format!("OPENAI_API_KEY={key}");
    let s = test_score(key, &context);
    assert!(
        s > 0.01,
        "Realistic OpenAI key scored {:.3}, expected > 0.01",
        s
    );
}

#[test]
fn inference_is_fast() {
    let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
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
