//! LANE-4 detection-truth: a DATA-DRIVEN BOOL-ONLY suppression truth table over
//! the public `keyhog_scanner::testing::known_example_suppressed` entry
//! point (the gate every scan-path finding passes through).
//!
//! This file asserts ONLY the boolean decision — it never touches the
//! process-global dogfood telemetry, so every test fn here is fully
//! parallel-safe. The companion file `suppression_reason_trace.rs` (its own
//! test binary) pins the EXACT `reason` strings the cascade emits; keeping the
//! telemetry-dependent assertions out of this binary means these large matrices
//! can run concurrently without a global-state race.
//!
//! Two directions, both at scale:
//!   * SUPPRESS lanes: every generated placeholder / EXAMPLE / bare-hex / UUID
//!     shape MUST be suppressed (a disabled gate flips the offending input red).
//!   * RECALL lane: every generated random NON-HEX vendor-shaped secret MUST NOT
//!     be suppressed (a gate that widens to eat real secrets flips it red).
//!
//! Every assertion is exact (Law 6): the boolean for a concrete input, never
//! `is_ok`/`!is_empty`. Deterministic + host-independent (pure decision logic,
//! no GPU, no scan timing, no network); the random corpus is a seeded
//! xorshift64* stream so the same cases run on every host/CI.

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::confidence::placeholder_words;
use keyhog_scanner::testing::known_example_suppressed;

/// Decision under the default public entry point (no path, unknown context):
/// `bypass_shape_gates = false`, so the full shape cascade is engaged — exactly
/// the path a generic/entropy finding takes on a real scan.
fn suppressed(credential: &str) -> bool {
    known_example_suppressed(credential, None, CodeContext::Unknown)
}

/// Deterministic xorshift64* byte source — reproducible random bodies without
/// an RNG crate or non-determinism (same seed ⇒ same corpus every run/host).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    /// A random body from a charset, length `len`.
    fn body(&mut self, charset: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| charset[(self.next() % charset.len() as u64) as usize] as char)
            .collect()
    }
}

const HEX: &[u8] = b"0123456789abcdef";
// Alnum charset that deliberately includes letters g-z so a body is NEVER pure
// hex (the bare-hex gate must not fire on these).
const NONHEX_ALNUM: &[u8] = b"ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ0123456789";

// ─────────────────────────── SUPPRESS matrices ───────────────────────────

/// Every generated 32/40/64-char PURE-hex digest (no anchor) suppresses via the
/// bare-hex-digest gate. 1500 cases (500 per length). A bare-hex regression
/// (gate disabled) flips the offending hex string red.
#[test]
fn bare_hex_digests_all_suppress() {
    let mut rng = Rng(0xABCD_1234_5678_9F01);
    let mut cases = 0usize;
    for &len in &[32usize, 40, 64] {
        for _ in 0..500 {
            let hex = rng.body(HEX, len);
            assert!(
                suppressed(&hex),
                "pure {len}-hex digest {hex:?} must be suppressed by the bare-hex gate"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 1500, "expected 1500 hex cases, ran {cases}");
}

/// Every generated UUID-v4 (version nibble 4, variant 8/9/a/b) suppresses via
/// the uuid_v4_shape gate. 1000 cases. A UUID-gate regression flips the
/// offending UUID red.
#[test]
fn uuid_v4_all_suppress() {
    let mut rng = Rng(0x1357_9BDF_2468_ACE0);
    let mut cases = 0usize;
    for _ in 0..1000 {
        let p1 = rng.body(HEX, 8);
        let p2 = rng.body(HEX, 4);
        let p3 = rng.body(HEX, 3);
        let variant = [b'8', b'9', b'a', b'b'][(rng.next() % 4) as usize] as char;
        let p4 = rng.body(HEX, 3);
        let p5 = rng.body(HEX, 12);
        let uuid = format!("{p1}-{p2}-4{p3}-{variant}{p4}-{p5}");
        assert!(
            suppressed(&uuid),
            "UUID-v4 {uuid:?} must be suppressed by the uuid_v4_shape gate"
        );
        cases += 1;
    }
    assert_eq!(cases, 1000, "expected 1000 UUID cases, ran {cases}");
}

/// Every generated placeholder-word token from the shared Tier-B vocabulary
/// suppresses when embedded in a longer token, underscore-bounded. This pins
/// both vocabulary ownership and behavior: a new configured word that is not
/// wired into doc-marker suppression flips red here.
#[test]
fn placeholder_words_all_suppress() {
    let mut rng = Rng(0x0F1E_2D3C_4B5A_6978);
    let words = placeholder_words();
    assert_eq!(
        words,
        vec![
            "example".to_string(),
            "dummy".to_string(),
            "fake".to_string(),
            "mock".to_string(),
            "sample".to_string(),
            "placeholder".to_string(),
            "changeme".to_string(),
        ],
        "placeholder suppression vocabulary must come from the shared Tier-B data file"
    );
    let mut cases = 0usize;
    for word in words.iter().map(|word| word.to_ascii_uppercase()) {
        for _ in 0..200 {
            let prefix = rng.body(NONHEX_ALNUM, 6);
            let suffix = rng.body(NONHEX_ALNUM, 8);
            let token = format!("{prefix}_{word}_{suffix}");
            assert!(
                suppressed(&token),
                "token {token:?} carrying placeholder word {word:?} must be suppressed"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 1400, "expected 1400 placeholder cases, ran {cases}");
}

/// Every generated EXAMPLE-suffixed token suppresses (the EXAMPLE special-case
/// arm via `ends_with("EXAMPLE")`). 600 cases. A regression in the EXAMPLE arm
/// flips the offending token red.
#[test]
fn example_suffixed_tokens_all_suppress() {
    let mut rng = Rng(0x9988_7766_5544_3322);
    let mut cases = 0usize;
    for _ in 0..600 {
        let body = rng.body(NONHEX_ALNUM, 16);
        let token = format!("{body}EXAMPLE");
        assert!(
            suppressed(&token),
            "EXAMPLE-suffixed token {token:?} must be suppressed by the EXAMPLE arm"
        );
        cases += 1;
    }
    assert_eq!(cases, 600, "expected 600 EXAMPLE cases, ran {cases}");
}

/// Every generated 5×5 dashed-serial / product-key shape suppresses via the
/// dashed_serial_key gate. 800 cases. A regression flips the offending key red.
#[test]
fn dashed_serial_keys_all_suppress() {
    // 5 blocks of 5 uppercase-alnum, dash-separated.
    const BLOCK: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = Rng(0x4242_2424_8181_1818);
    let mut cases = 0usize;
    for _ in 0..800 {
        let blocks: Vec<String> = (0..5).map(|_| rng.body(BLOCK, 5)).collect();
        let key = blocks.join("-");
        assert!(
            suppressed(&key),
            "5x5 dashed serial {key:?} must be suppressed by the dashed_serial_key gate"
        );
        cases += 1;
    }
    assert_eq!(cases, 800, "expected 800 dashed-serial cases, ran {cases}");
}

// ─────────────────────────── RECALL matrix ───────────────────────────

/// Lengths that are `% 4 == 1`: a base64 payload length is ALWAYS `% 4 ∈
/// {0,2,3}`, so a `% 4 == 1` string can NEVER decode as base64. Constraining
/// the random-secret bodies to these lengths guarantees the suppression
/// cascade's base64-decode-and-recheck arm (`try_decode_b64_to_utf8`) returns
/// `None` for every one of them — so this negative-twin oracle is fully
/// deterministic (no rare "random body coincidentally decoded to a suppressible
/// payload" flake), not just "usually" clean.
const NONDECODABLE_LENS: &[usize] = &[29, 33, 37, 41, 45];

/// REAL-secret negative twin at scale: every generated random NON-HEX alnum
/// body (lengths chosen so they can never base64-decode, see
/// `NONDECODABLE_LENS`), with NO placeholder word and NO EXAMPLE/fake-sequence
/// marker, NOT a UUID, NOT pure hex, suppresses NOTHING. 2000 cases. A shape
/// gate that widens to eat real secrets flips the offending random body red.
#[test]
fn random_nonhex_secrets_never_suppress() {
    let mut rng = Rng(0x2718_2818_2845_9045);
    let placeholder_words_upper: Vec<String> = placeholder_words()
        .iter()
        .map(|word| word.to_ascii_uppercase())
        .collect();
    let mut cases = 0usize;
    let mut checked = 0usize;
    while cases < 2000 {
        checked += 1;
        assert!(
            checked < 100_000,
            "too many re-rolls ({checked}) to reach 2000 clean random bodies — a \
             shape gate is suppressing nearly all random alnum secrets (recall collapse)"
        );
        let len = NONDECODABLE_LENS[(rng.next() as usize) % NONDECODABLE_LENS.len()];
        let body = rng.body(NONHEX_ALNUM, len);
        // Guard: skip any coincidental suppressible substring (placeholder
        // word, EXAMPLE marker, or a fake-sequence run). With this charset and
        // these lengths a hit is astronomically rare, but keep the oracle
        // honest — these are the ONLY substrings the cascade keys on for a bare
        // alnum body, so filtering them makes "not suppressed" a sound recall
        // assertion rather than a probabilistic one.
        let upper = body.to_uppercase();
        let has_placeholder_word = placeholder_words_upper
            .iter()
            .any(|word| upper.contains(word));
        if has_placeholder_word
            || ["1234567890", "0123456789", "ABCDEFGH"]
                .iter()
                .any(|w| upper.contains(w))
        {
            continue;
        }
        assert!(
            !suppressed(&body),
            "random non-hex secret body {body:?} (len {len}) was WRONGLY suppressed — \
             a shape gate widened to eat real credentials (recall regression)"
        );
        cases += 1;
    }
    assert_eq!(
        cases, 2000,
        "expected 2000 clean random-secret cases, ran {cases}"
    );
}

/// Hand-picked REAL vendor-shaped secrets (random, high-entropy bodies behind a
/// real vendor prefix, or random passwords) that MUST NOT be suppressed by any
/// shape gate — the recall negative twin in concrete, named form. NB: these are
/// FABRICATED random strings of the right SHAPE, not live credentials. Each was
/// verified offline against the full cascade (not pure-hex, not a UUID, no
/// placeholder/EXAMPLE/fake-sequence marker, no 5+ repeat run, and not
/// base64-decodable to a suppressible payload).
const REAL_SECRET_TABLE: &[&str] = &[
    "xoxb-9f3K2pQ7mZ1tR8vN4wL6yH0cB5dG2jE",
    "sk_live_4eC39HqLyjWDarjtT1zdp7d2K9mNvB",
    "ghp_J8kZq2WxX9nP4rT6yV1bC3dF5gH7jKaLmNo",
    "Tr0ub4dor&3xK9!mZqWvP",
    "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9f",
    "zX9wY7vU5tS3rQ1pO9nM7lK5jH3gF1dS9aZ7xC5v",
];

#[test]
fn named_real_secrets_are_never_suppressed() {
    let mut checked = 0usize;
    for credential in REAL_SECRET_TABLE {
        assert!(
            !suppressed(credential),
            "REAL secret {credential:?} was WRONGLY suppressed — a recall regression: \
             a shape gate widened to eat a real credential"
        );
        checked += 1;
    }
    assert_eq!(
        checked, 6,
        "expected 6 named real-secret cases, ran {checked}"
    );
}
