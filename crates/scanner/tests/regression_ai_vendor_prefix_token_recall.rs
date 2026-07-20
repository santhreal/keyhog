//! AI/LLM inference-vendor credential recall + precision lock for the vendors
//! beyond OpenAI/Anthropic (which live in regression_ai_provider_key_recall.rs):
//! HuggingFace (`hf_`), Replicate (`r8_`), Groq (`gsk_`), OpenRouter
//! (`sk-or-v1-`), Perplexity (`pplx-`), Mistral (context 32-alnum), Together AI
//! (context 64-hex), and Cohere (`co_` bare + context 40-alnum). Most carry a
//! distinctive bare prefix; a few are context-anchored. This pins each form plus
//! the length boundaries. None is checksum-gated.
//!
//! NOTE: the three HuggingFace detectors (api-key exact `{34}`, org-token and
//! user-token `{34,}`) all match the same `hf_<34>` value at the same offset, so
//! value-dedup keeps just one of the three labels. The recall contract is "an
//! `hf_` token is detected as HuggingFace", not which of the overlapping labels
//! wins (the tests assert membership in the HuggingFace detector set).

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x77E1_4B93);
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            charset[((s >> 33) % m) as usize] as char
        })
        .collect()
}
fn hex(n: usize, seed: usize) -> String {
    gen(n, seed, b"0123456789abcdef")
}
fn alnum(n: usize, seed: usize) -> String {
    gen(
        n,
        seed,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    )
}

const HF: &[&str] = &[
    "huggingface-api-key",
    "huggingface-org-token",
    "huggingface-user-token",
];

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "ai.env");
    s.clear_fragment_cache();
    s.scan(&chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.as_str().to_string()))
        .collect()
}
fn surfaces_under(text: &str, detector: &str, needle: &str) -> bool {
    scan(text)
        .iter()
        .any(|(id, cred)| id == detector && cred.contains(needle))
}
fn surfaces_under_any(text: &str, detectors: &[&str], needle: &str) -> bool {
    scan(text)
        .iter()
        .any(|(id, cred)| detectors.contains(&id.as_str()) && cred.contains(needle))
}
fn fires(text: &str, detector: &str) -> bool {
    scan(text).iter().any(|(id, _)| id == detector)
}
fn fires_any(text: &str, detectors: &[&str]) -> bool {
    scan(text)
        .iter()
        .any(|(id, _)| detectors.contains(&id.as_str()))
}

// ── HuggingFace: hf_<34> ─────────────────────────────────────────────────────

#[test]
fn huggingface_token_surfaces() {
    let k = format!("hf_{}", alnum(34, 1));
    assert!(
        surfaces_under_any(&k, HF, &k),
        "hf_ token must surface as HuggingFace"
    );
}

#[test]
fn huggingface_33_body_does_not_fire() {
    let k = format!("hf_{}", alnum(33, 2)); // 33 < the required 34
    assert!(!fires_any(&k, HF));
}

// ── Replicate: r8_<37> ───────────────────────────────────────────────────────

#[test]
fn replicate_token_surfaces() {
    let k = format!("r8_{}", alnum(37, 3));
    assert!(
        surfaces_under(&k, "replicate-api-key", &k),
        "r8_ token must surface"
    );
}

#[test]
fn replicate_in_assignment_surfaces() {
    let k = format!("r8_{}", alnum(37, 4));
    assert!(surfaces_under(
        &format!("REPLICATE_API_TOKEN={k}"),
        "replicate-api-key",
        &k
    ));
}

#[test]
fn replicate_36_body_does_not_fire() {
    let k = format!("r8_{}", alnum(36, 5)); // 36 < the required 37
    assert!(!fires(&k, "replicate-api-key"));
}

// ── Groq: gsk_<52> ───────────────────────────────────────────────────────────

#[test]
fn groq_token_surfaces() {
    let k = format!("gsk_{}", alnum(52, 6));
    assert!(
        surfaces_under(&k, "groq-api-key", &k),
        "gsk_ token must surface"
    );
}

#[test]
fn groq_in_env_surfaces() {
    let k = format!("gsk_{}", alnum(52, 7));
    assert!(surfaces_under(
        &format!("GROQ_API_KEY={k}"),
        "groq-api-key",
        &k
    ));
}

#[test]
fn groq_51_body_does_not_fire() {
    let k = format!("gsk_{}", alnum(51, 8)); // 51 < the required 52
    assert!(!fires(&k, "groq-api-key"));
}

// ── OpenRouter: sk-or-v1-<48+ hex> ───────────────────────────────────────────

#[test]
fn openrouter_token_surfaces() {
    let k = format!("sk-or-v1-{}", hex(48, 9));
    assert!(
        surfaces_under(&k, "openrouter-api-key", &k),
        "sk-or-v1- token must surface"
    );
}

#[test]
fn openrouter_longer_body_surfaces() {
    let k = format!("sk-or-v1-{}", hex(60, 10)); // {48,} is open-ended
    assert!(surfaces_under(&k, "openrouter-api-key", &k));
}

#[test]
fn openrouter_47_body_does_not_fire() {
    let k = format!("sk-or-v1-{}", hex(47, 11)); // 47 < the required 48
    assert!(!fires(&k, "openrouter-api-key"));
}

// ── Perplexity: pplx-<32+> ───────────────────────────────────────────────────

#[test]
fn perplexity_token_surfaces() {
    let k = format!("pplx-{}", alnum(32, 12));
    assert!(
        surfaces_under(&k, "perplexity-api-key", &k),
        "pplx- token must surface"
    );
}

#[test]
fn perplexity_31_body_does_not_fire() {
    let k = format!("pplx-{}", alnum(31, 13)); // 31 < the required 32
    assert!(!fires(&k, "perplexity-api-key"));
}

// ── Mistral: context-anchored 32-alnum ───────────────────────────────────────

#[test]
fn mistral_api_key_surfaces() {
    let k = alnum(32, 14);
    assert!(surfaces_under(
        &format!("MISTRAL_API_KEY={k}"),
        "mistral-api-key",
        &k
    ));
}

#[test]
fn mistral_lowercase_anchor_surfaces() {
    let k = alnum(32, 15);
    assert!(surfaces_under(
        &format!("mistral_api_key={k}"),
        "mistral-api-key",
        &k
    ));
}

// ── Together AI: context-anchored 64-hex ─────────────────────────────────────

#[test]
fn togetherai_api_key_surfaces() {
    let k = hex(64, 16);
    assert!(surfaces_under(
        &format!("TOGETHER_API_KEY={k}"),
        "togetherai-api-key",
        &k
    ));
}

#[test]
fn togetherai_63_hex_does_not_fire() {
    let k = hex(63, 17); // 63 < the required 64
    assert!(!fires(
        &format!("TOGETHER_API_KEY={k}"),
        "togetherai-api-key"
    ));
}

// ── Cohere: co_ bare (case-sensitive) + context 40-alnum ─────────────────────

#[test]
fn cohere_context_api_key_surfaces() {
    let k = alnum(40, 18);
    assert!(surfaces_under(
        &format!("COHERE_API_KEY={k}"),
        "cohere-api-key",
        &k
    ));
}

#[test]
fn cohere_co_prefix_bare_surfaces() {
    let k = format!("co_{}", alnum(40, 19));
    assert!(
        surfaces_under(&k, "cohere-api-key", &k),
        "co_ bare token must surface"
    );
}

#[test]
fn cohere_uppercase_co_prefix_does_not_fire() {
    // Pattern 1 is `(?-i)co_...`, forcing a lowercase `co_`; an uppercase `CO_`
    // must not be matched as a Cohere key (precision lock on the case flag).
    let k = format!("CO_{}", alnum(40, 20));
    assert!(!fires(&k, "cohere-api-key"));
}

// ── cross: several AI vendor keys co-surface ─────────────────────────────────

#[test]
fn multiple_prefix_ai_keys_cosurface() {
    let hf = format!("hf_{}", alnum(34, 21));
    let gsk = format!("gsk_{}", alnum(52, 22));
    let pplx = format!("pplx-{}", alnum(32, 23));
    let text = format!("HF_TOKEN={hf}\nGROQ_API_KEY={gsk}\nPERPLEXITY_KEY={pplx}\n");
    assert!(surfaces_under_any(&text, HF, &hf));
    assert!(surfaces_under(&text, "groq-api-key", &gsk));
    assert!(surfaces_under(&text, "perplexity-api-key", &pplx));
}

#[test]
fn multiple_context_ai_keys_cosurface() {
    let mistral = alnum(32, 24);
    let together = hex(64, 25);
    let cohere = alnum(40, 26);
    let text = format!(
        "MISTRAL_API_KEY={mistral}\nTOGETHER_API_KEY={together}\nCOHERE_API_KEY={cohere}\n"
    );
    assert!(surfaces_under(&text, "mistral-api-key", &mistral));
    assert!(surfaces_under(&text, "togetherai-api-key", &together));
    assert!(surfaces_under(&text, "cohere-api-key", &cohere));
}
