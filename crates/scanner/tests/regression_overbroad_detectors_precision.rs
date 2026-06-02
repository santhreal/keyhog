//! Regression: over-broad detectors matching generic tokens.
//!
//! Four detectors shipped patterns that fired on generic, non-credential
//! tokens, producing false positives at (in three cases) `critical` severity:
//!
//!   * `transpose-api-key`  — `(?:TRANSPOSE|transpose)[_a-zA-Z0-9]*[=:\s"']+([a-f0-9]{32})`
//!     The `[_a-zA-Z0-9]*` let ANY identifier *starting* with "transpose"
//!     (e.g. `transposeMatrixChecksum=<32hex>`) anchor a generic 32-hex
//!     hash/digest.
//!   * `octopus-deploy-api-key` — `API-[A-Z0-9]{16,}` (compiled case-insensitive)
//!     matched generic uppercase tokens such as `API-DOCUMENTATIONREFERENCE`
//!     and lowercase `api-...` words; no digit was required.
//!   * `moralis-api-key` — a bare `X-API-Key[=:\s"']+([a-zA-Z0-9]{60,})` pattern.
//!     `X-API-Key` is a generic HTTP header shared by dozens of services and
//!     Moralis keys carry no distinctive prefix, so the pattern matched ANY
//!     service's 60+ char token as a critical Moralis key.
//!   * `pipedream-api-key` — `api_[a-zA-Z0-9]{40,}`. `api_` is a generic prefix,
//!     so any `api_<40+ alnum>` (lowercase identifiers, lowercase hex digests)
//!     matched.
//!
//! The fixes (in `detectors/*.toml`) tighten each pattern to its real,
//! service-specific shape WITHOUT losing the canonical-positive recall path.
//!
//! This test asserts the precision/recall behaviour DIRECTLY against the
//! shipped detector TOMLs, compiling each pattern exactly the way the engine
//! does (`RegexBuilder::new(p).case_insensitive(true).crlf(true)` — see
//! `crates/scanner/src/compiler_compile.rs::shared_regex_compile`). It FAILS on
//! the old over-broad regexes and PASSES on the tightened ones.

use std::path::PathBuf;

use keyhog_core::{load_detectors, DetectorSpec, PatternSpec};
use regex::Regex;

/// `crates/scanner/../../detectors` — the on-disk Tier-B detector directory.
fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/scanner -> crates
    d.pop(); // crates        -> repo root
    d.push("detectors");
    d
}

fn load_detector(id: &str) -> DetectorSpec {
    let detectors = load_detectors(&detector_dir())
        .unwrap_or_else(|e| panic!("load detectors from {}: {e}", detector_dir().display()));
    detectors
        .into_iter()
        .find(|d| d.id == id)
        .unwrap_or_else(|| panic!("detector `{id}` not found on disk"))
}

/// Compile a single pattern exactly as the scanner engine compiles it.
fn compile(pattern: &PatternSpec) -> Regex {
    regex::RegexBuilder::new(&pattern.regex)
        .case_insensitive(true)
        .crlf(true)
        .build()
        .unwrap_or_else(|e| panic!("compile `{}`: {e}", pattern.regex))
}

/// True iff ANY of the detector's patterns matches anywhere in `haystack`.
fn any_pattern_matches(spec: &DetectorSpec, haystack: &str) -> bool {
    spec.patterns.iter().any(|p| compile(p).is_match(haystack))
}

/// For a detector that captures into group 1, return the captured credential
/// from the first pattern that matches (or the whole match if no group).
fn captured(spec: &DetectorSpec, haystack: &str) -> Option<String> {
    for p in &spec.patterns {
        let re = compile(p);
        if let Some(caps) = re.captures(haystack) {
            let idx = p.group.unwrap_or(0);
            if let Some(m) = caps.get(idx) {
                return Some(m.as_str().to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// transpose-api-key
// ---------------------------------------------------------------------------

#[test]
fn transpose_keeps_canonical_recall() {
    let spec = load_detector("transpose-api-key");
    // Canonical contract positive (tests/contracts/transpose-api-key.toml).
    let cred = "cdce91dd51dd450d5b00d6009adc6429";
    assert_eq!(
        captured(&spec, "TRANSPOSE=cdce91dd51dd450d5b00d6009adc6429").as_deref(),
        Some(cred),
        "transpose must still fire on the bare `TRANSPOSE=<32hex>` anchor"
    );
    // Quoted variant + explicit key suffix must also fire.
    assert_eq!(
        captured(
            &spec,
            "TRANSPOSE_API_KEY=\"cdce91dd51dd450d5b00d6009adc6429\""
        )
        .as_deref(),
        Some(cred),
        "transpose must fire on the TRANSPOSE_API_KEY=... anchor"
    );
    assert_eq!(
        captured(&spec, "transpose_token: cdce91dd51dd450d5b00d6009adc6429").as_deref(),
        Some(cred),
        "transpose must fire on the lowercase transpose_token anchor"
    );
}

#[test]
fn transpose_rejects_generic_word_prefixed_hash() {
    let spec = load_detector("transpose-api-key");
    // OLD `[_a-zA-Z0-9]*` allowed any identifier STARTING WITH "transpose" to
    // anchor an unrelated 32-hex hash. These are NOT transpose credentials.
    let generic = [
        // a git-blob / checksum stored in a variable whose name merely begins
        // with the substring "transpose"
        "transposeMatrixChecksum = d41d8cd98f00b204e9800998ecf8427e",
        "transposeResultCacheKey=098f6bcd4621d373cade4e832627b4f6",
        "transposedImageHash: 5d41402abc4b2a76b9719d911017c592",
    ];
    for g in generic {
        assert!(
            !any_pattern_matches(&spec, g),
            "transpose-api-key must NOT fire on generic word-prefixed hash: {g:?}"
        );
    }
}

#[test]
fn transpose_boundary_hash_length() {
    let spec = load_detector("transpose-api-key");
    // 31 hex chars (one short) must not match; exactly 32 must.
    assert!(
        !any_pattern_matches(&spec, "TRANSPOSE=cdce91dd51dd450d5b00d6009adc642"),
        "31-hex body is below the 32-char floor"
    );
    assert!(
        any_pattern_matches(&spec, "TRANSPOSE=cdce91dd51dd450d5b00d6009adc6429"),
        "exactly 32-hex body must match"
    );
}

// ---------------------------------------------------------------------------
// octopus-deploy-api-key
// ---------------------------------------------------------------------------

#[test]
fn octopus_keeps_canonical_recall() {
    let spec = load_detector("octopus-deploy-api-key");
    // Canonical contract positive — bare key only matches the API- pattern.
    let key = "API-7X68S9206QLQW4S2FVP";
    assert!(
        any_pattern_matches(&spec, key),
        "octopus must still fire on the canonical bare `API-...` key"
    );
    // Env + header anchored variants must also fire.
    assert!(
        any_pattern_matches(&spec, "OCTOPUS_API_KEY=API-7X68S9206QLQW4S2FVP"),
        "octopus must fire on the OCTOPUS_API_KEY=... anchor"
    );
    assert!(
        any_pattern_matches(&spec, "X-Octopus-ApiKey: API-7X68S9206QLQW4S2FVP"),
        "octopus must fire on the X-Octopus-ApiKey header"
    );
    assert!(
        any_pattern_matches(&spec, "Authorization: Bearer API-7X68S9206QLQW4S2FVP"),
        "octopus must surface the credential inside an Authorization envelope"
    );
}

#[test]
fn octopus_rejects_generic_uppercase_words() {
    let spec = load_detector("octopus-deploy-api-key");
    // OLD `API-[A-Z0-9]{16,}` (compiled case-insensitive) matched generic
    // uppercase English words and lowercase `api-` slugs alike. None of these
    // are Octopus keys: pure-letter uppercase words (no digit) and lowercase
    // doc slugs.
    let generic = [
        "API-DOCUMENTATIONREFERENCE",   // pure uppercase letters, no digit
        "API-RESPONSEHANDLERINTERFACE", // pure uppercase letters, no digit
        "api-documentation-versioning", // lowercase slug
        "API-AUTHENTICATIONREQUIRED",   // pure uppercase letters, no digit
    ];
    for g in generic {
        assert!(
            !any_pattern_matches(&spec, g),
            "octopus-deploy must NOT fire on generic token: {g:?}"
        );
    }
}

#[test]
fn octopus_boundary_digit_and_length() {
    let spec = load_detector("octopus-deploy-api-key");
    // A trailing single digit on an otherwise all-letter word must not satisfy
    // the digit requirement (the digit cannot be followed by the required
    // 15+ char tail).
    assert!(
        !any_pattern_matches(&spec, "API-DOCUMENTATIONHANDLER1"),
        "a single trailing digit must not turn a generic word into a key"
    );
    // Real key with an early digit and a long uppercase tail matches.
    assert!(
        any_pattern_matches(&spec, "API-7X68S9206QLQW4S2FVP"),
        "digit-dense uppercase key must match"
    );
    // Just below the 16-char body floor must not match even with a digit.
    assert!(
        !any_pattern_matches(&spec, "API-1AB2CD3EF4GH5J"),
        "15-char body is below the 16-char floor"
    );
}

// ---------------------------------------------------------------------------
// moralis-api-key
// ---------------------------------------------------------------------------

#[test]
fn moralis_keeps_canonical_recall() {
    let spec = load_detector("moralis-api-key");
    let cred = "RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj";
    assert_eq!(
        captured(
            &spec,
            "MORALIS_API_KEY=RDcaN0CTOK20ayMWP8e33V2zt9U44WSIdDo1pT8f2R68ugXVO0Lu9kX854Uj"
        )
        .as_deref(),
        Some(cred),
        "moralis must still fire on the MORALIS_API_KEY=... context anchor"
    );
}

#[test]
fn moralis_rejects_generic_x_api_key_header() {
    let spec = load_detector("moralis-api-key");
    // OLD bare `X-API-Key[=:\s"']+([a-zA-Z0-9]{60,})` matched ANY service's
    // 60+ char token under the generic `X-API-Key` header. None of these are
    // Moralis credentials; the header alone is not a Moralis anchor.
    let generic = [
        // a 60+ char token belonging to some other service entirely
        "X-API-Key: Z9kQ2mWp7Lx4Tn8Rb1Hc6Vd3Fg5Js0Ay2Eu7Io4Pq9Mz8Xc1Vb6Nm3Kl5Tr2",
        "X-API-Key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];
    for g in generic {
        assert!(
            !any_pattern_matches(&spec, g),
            "moralis must NOT fire on a bare generic X-API-Key header: {g:?}"
        );
    }
    // Coherence: no surviving pattern is the bare X-API-Key shape, and the
    // generic header keyword was removed from the prefilter list.
    assert!(
        !spec.patterns.iter().any(|p| p.regex.contains("X-API-Key")),
        "the bare X-API-Key value pattern must be gone"
    );
    assert!(
        !spec.keywords.iter().any(|k| k == "X-API-Key"),
        "the orphaned generic X-API-Key keyword must be removed for coherence"
    );
}

// ---------------------------------------------------------------------------
// pipedream-api-key
// ---------------------------------------------------------------------------

#[test]
fn pipedream_keeps_canonical_recall() {
    let spec = load_detector("pipedream-api-key");
    let key = "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5";
    assert!(
        any_pattern_matches(&spec, key),
        "pipedream must still fire on the canonical mixed-case base62 key"
    );
    assert!(
        any_pattern_matches(&spec, &format!("Authorization: Bearer {key}")),
        "pipedream must surface the credential inside a Bearer envelope"
    );
}

#[test]
fn pipedream_rejects_generic_api_tokens() {
    let spec = load_detector("pipedream-api-key");
    // OLD `api_[a-zA-Z0-9]{40,}` matched any long `api_` token. These generic
    // shapes (all-lowercase identifier; all-lowercase hex digest) are NOT
    // Pipedream keys and lack the mixed-case base62 signature.
    let generic = [
        // 64-char lowercase hex digest behind a generic api_ prefix
        "api_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        // long all-lowercase identifier
        "api_responsehandlerimplementationconfigurationservicefactorybuilder",
        // 40 lowercase hex (exactly the old floor)
        "api_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];
    for g in generic {
        assert!(
            !any_pattern_matches(&spec, g),
            "pipedream must NOT fire on generic api_ token: {g:?}"
        );
    }
}

#[test]
fn pipedream_boundary_uppercase_and_length() {
    let spec = load_detector("pipedream-api-key");
    // Body needs an uppercase letter AND >= 40 body chars. A short mixed-case
    // token under the floor must not match.
    assert!(
        !any_pattern_matches(&spec, "api_kaxHrCz"),
        "short body below the length floor must not match"
    );
    // Exactly at the floor with an early uppercase letter must match.
    // body = 1 lowercase + 1 uppercase + 39 alnum = 41 chars total.
    let at_floor = "api_aBcccccccccccccccccccccccccccccccccccccccc";
    assert!(
        any_pattern_matches(&spec, at_floor),
        "mixed-case body at the length floor must match: {at_floor:?}"
    );
}

// ---------------------------------------------------------------------------
// Property-style adversarial loop: deterministic generated generic tokens.
// None of the four tightened detectors may fire on machine-generated generic
// tokens that lack the service-specific signature.
// ---------------------------------------------------------------------------

/// Tiny deterministic LCG so the loop is reproducible without a proptest dep.
struct Lcg(u64);
impl Lcg {
    fn next_u32(&mut self) -> u32 {
        // Numerical Recipes LCG constants.
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
}

#[test]
fn overbroad_detectors_reject_generic_tokens_proptest() {
    let transpose = load_detector("transpose-api-key");
    let octopus = load_detector("octopus-deploy-api-key");
    let moralis = load_detector("moralis-api-key");
    let pipedream = load_detector("pipedream-api-key");

    let lowers: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let hexdigits: &[u8] = b"0123456789abcdef";

    let mut rng = Lcg(0x5151_5151_DEAD_BEEF);
    let iters = 12_000;

    for _ in 0..iters {
        // 1) transpose: a variable whose name merely starts with "transpose"
        //    holding an unrelated 32-hex digest.
        let mut hex = String::new();
        for _ in 0..32 {
            hex.push(hexdigits[(rng.next_u32() as usize) % hexdigits.len()] as char);
        }
        let t = format!("transposeMatrix{}Cache = {hex}", (rng.next_u32() % 90) + 10);
        assert!(
            !any_pattern_matches(&transpose, &t),
            "transpose fired on generic word-prefixed hash: {t:?}"
        );

        // 2) octopus: a generic ALL-UPPERCASE-LETTER token under API- (no digit).
        let wlen = 16 + (rng.next_u32() as usize % 12);
        let mut word = String::from("API-");
        for _ in 0..wlen {
            // uppercase letters only -> no digit, must never match
            word.push((b'A' + (rng.next_u32() as u8 % 26)) as char);
        }
        assert!(
            !any_pattern_matches(&octopus, &word),
            "octopus fired on a pure-letter uppercase token: {word:?}"
        );

        // 3) moralis: a 60+ char token under the generic X-API-Key header.
        let tlen = 60 + (rng.next_u32() as usize % 40);
        let mut body = String::new();
        for _ in 0..tlen {
            let c = (rng.next_u32() % 62) as u8;
            let ch = match c {
                0..=25 => b'a' + c,
                26..=51 => b'A' + (c - 26),
                _ => b'0' + (c - 52),
            };
            body.push(ch as char);
        }
        let m = format!("X-API-Key: {body}");
        assert!(
            !any_pattern_matches(&moralis, &m),
            "moralis fired on a bare generic X-API-Key header: {m:?}"
        );

        // 4) pipedream: an all-lowercase identifier under api_ (no uppercase).
        let plen = 40 + (rng.next_u32() as usize % 40);
        let mut ident = String::from("api_");
        for _ in 0..plen {
            ident.push(lowers[(rng.next_u32() as usize) % lowers.len()] as char);
        }
        assert!(
            !any_pattern_matches(&pipedream, &ident),
            "pipedream fired on an all-lowercase api_ identifier: {ident:?}"
        );
    }
}
