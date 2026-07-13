use crate::entropy::unique_byte_count;
use crate::entropy::{shannon_entropy, HIGH_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD};

/// Feature vector dimensionality. Each feature captures one signal:
/// 4 length features + 4 entropy features + 4 character class features +
/// 4 prefix features + 4 context features + 4 placeholder features +
/// 4 structure features + 6 file-type one-hot features + 3 extra features
/// (comment, assignment, test-file) = 37 base + 4 padding = 41, plus the
/// decode-structure feature (#41) and the service-context feature (#42) = 43.
///
/// Feature 41 is keyhog's decode-through advantage fed to the model: 1.0 when
/// the candidate base64/hex-decodes to an identifiable binary asset (magic
/// bytes) or a full protobuf-wire message, else 0.0. Training showed it lifts
/// held-out F1 0.924 -> 0.964 and drives the base64-of-binary false-flag rate
/// from 18% to 0% with no recall loss (see ml/train_classifier.py).
///
/// Feature 42 is the keyword-specificity signal (DET-1): 1.0 when the ML
/// context window names a SPECIFIC service from the embedded detector corpus
/// (codecov, grafana, …), else 0.0. Combined with feature 17 (generic
/// credential word in context) it gives the model the split the shape features
/// cannot see: service-keyword + UUID (real secret) vs generic-keyword + UUID
/// (identifier) (the dominant CredData/mirror confusion. See `service_vocab`).
///
/// The value is owned once by `super::model_arch::INPUT_DIM` (the gate/expert
/// input width). This name is the feature-extraction view of that same owner.
pub(crate) const NUM_FEATURES: usize = super::model_arch::INPUT_DIM;

/// Offset into the feature vector where the one-hot file-type encoding starts.
const FILE_TYPE_OFFSET: usize = 32;

/// Normalization ceiling for text length feature (feature[0] = len / 200).
/// 200 chars covers the longest common credential format (JWT, SSH keys).
const MAX_NORMALIZED_TEXT_LENGTH: f32 = 200.0;

/// Length thresholds for binary features. Trained on the distribution of
/// real credentials (20-char API keys, 40-char tokens, 100-char JWTs).
const MEDIUM_LENGTH_THRESHOLD: usize = 20;
const LONG_LENGTH_THRESHOLD: usize = 40;
const VERY_LONG_LENGTH_THRESHOLD: usize = 100;

/// Normalization ceiling for Shannon entropy (max theoretical for ASCII = 8.0).
const MAX_NORMALIZED_ENTROPY: f32 = 8.0;

/// Model-specific low-entropy bucket from the training corpus: 3.5 separates
/// readable English from random-ish strings. The high and very-high buckets use
/// the scanner's canonical entropy thresholds, not private ML copies.
///
/// This intentionally does NOT share an owner with
/// `entropy::plausibility::SYMBOLIC_CREDENTIAL_ENTROPY_FLOOR` (also 3.5): that is
/// a hard recall floor on the deterministic path, this is a model INPUT bucket
/// boundary retuned with each `weights.bin`. They coincide today by coincidence,
/// not by contract: `entropy_feature_bucket_currently_matches_symbolic_floor`
/// pins that coincidence so a retune of either is a conscious, reviewed change.
pub(crate) const ML_LOW_ENTROPY_FEATURE_THRESHOLD: f64 = 3.5;

const MAX_PREFIX_LENGTH: f32 = 10.0;
const OPENAI_PREFIX: &str = "sk-";
const AWS_ACCESS_KEY_PREFIX: &str = "AKIA";
const LOW_VARIETY_BYTE_THRESHOLD: usize = 3;
const MIN_LOW_VARIETY_LENGTH: usize = 5;
const MIN_HEX_PLACEHOLDER_LENGTH: usize = 10;
const MAX_UNIQUE_CHAR_NORMALIZATION: f32 = 40.0;
const MAX_DOT_COUNT_NORMALIZATION: f32 = 5.0;
const MAX_DASH_COUNT_NORMALIZATION: f32 = 10.0;

/// `u64` words needed to hold a presence bit for every possible byte bigram:
/// 256 * 256 = 65_536 distinct bigrams, packed 64 per word => 1024 words. Named
/// so the bitset size stays tied to its derivation instead of a bare literal.
pub(crate) const BIGRAM_BITSET_WORDS: usize = (256 * 256) / 64;
const CONFIG_FILE_TYPE_INDEX: usize = 0;
const SOURCE_FILE_TYPE_INDEX: usize = 1;
const CI_FILE_TYPE_INDEX: usize = 2;
const INFRA_FILE_TYPE_INDEX: usize = 3;
const OTHER_FILE_TYPE_INDEX: usize = 4;
const BINARY_FILE_TYPE_INDEX: usize = 5;
const COMMENT_CONTEXT_FEATURE_INDEX: usize = 38;
const ASSIGNMENT_OPERATOR_FEATURE_INDEX: usize = 39;
const TEST_FILE_CONTEXT_FEATURE_INDEX: usize = 40;
/// Decode-structure verdict: candidate decodes to identifiable binary / protobuf.
const DECODE_STRUCTURE_FEATURE_INDEX: usize = 41;
/// Keyword-specificity verdict: context names a specific service (DET-1).
const SERVICE_CONTEXT_FEATURE_INDEX: usize = 42;

#[derive(Clone, serde::Deserialize)]
struct MlFeatureMarkers {
    comment_prefixes: Vec<String>,
    binary_markers: Vec<String>,
    ci_markers: Vec<String>,
    infra_markers: Vec<String>,
    source_markers: Vec<String>,
    source_extensions: Vec<String>,
    config_markers: Vec<String>,
}

/// Parse the bundled Tier-B ML-feature marker lists. Returns an error rather
/// than panicking so the `ML_FEATURE_MARKERS` owner below is the single
/// fail-closed site (the `no_unwrap_expect` gate bans `expect` in production).
fn parse_ml_feature_markers(raw: &str) -> Result<MlFeatureMarkers, String> {
    toml::from_str::<MlFeatureMarkers>(raw).map_err(|error| error.to_string())
}

static ML_FEATURE_MARKERS: std::sync::LazyLock<MlFeatureMarkers> = std::sync::LazyLock::new(|| {
    match parse_ml_feature_markers(include_str!("../../../../rules/ml-feature-markers.toml")) {
        Ok(parsed) => parsed,
        Err(error) => panic!(
            "rules/ml-feature-markers.toml is invalid: {error}. \
                 Fix the bundled Tier-B metadata file list."
        ),
    }
});

static COMMENT_PREFIXES: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| ML_FEATURE_MARKERS.comment_prefixes.clone());

static BINARY_MARKERS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| ML_FEATURE_MARKERS.binary_markers.clone());

static CI_MARKERS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| ML_FEATURE_MARKERS.ci_markers.clone());

static INFRA_MARKERS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| ML_FEATURE_MARKERS.infra_markers.clone());

static SOURCE_MARKERS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| ML_FEATURE_MARKERS.source_markers.clone());

static SOURCE_EXTENSIONS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| ML_FEATURE_MARKERS.source_extensions.clone());

static CONFIG_MARKERS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| ML_FEATURE_MARKERS.config_markers.clone());

/// Entry point for feature-extraction unit tests.
#[cfg(test)]
pub(crate) fn compute_features_public(text: &str, context: &str) -> [f32; NUM_FEATURES] {
    if text.is_empty() {
        return [0.0f32; NUM_FEATURES];
    }
    compute_features_with_config(text, context, &[], &[], &[], &[])
}

/// Compute the full feature vector with detector-config keyword lists.
///
/// Public so the ML training-pipeline parity harness (`ml/parity_check.py`,
/// driven by the `dump_features` example) can compute byte-identical features
/// to this serve path - a retrained `weights.bin` is only valid if the Python
/// feature port matches this function exactly.
pub fn compute_features_with_config(
    text: &str,
    context: &str,
    known_prefixes: &[String],
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
) -> [f32; NUM_FEATURES] {
    debug_assert!(
        !text.is_empty(),
        "compute_features_with_config requires non-empty text"
    );

    let mut f = [0.0f32; NUM_FEATURES];
    let len = text.len();
    let text_bytes = text.as_bytes();
    let context_bytes = context.as_bytes();
    let ent = shannon_entropy(text_bytes);
    let text_summary = summarize_text_bytes(text_bytes);
    apply_length_features(&mut f, len);
    apply_entropy_features(&mut f, ent);
    apply_character_features(&mut f, &text_summary);
    apply_prefix_features(&mut f, text, known_prefixes);
    apply_context_features(
        &mut f,
        context,
        context_bytes,
        secret_keywords,
        test_keywords,
    );
    apply_placeholder_features(
        &mut f,
        text,
        text_bytes,
        len,
        text_summary.unique_bytes,
        placeholder_keywords,
    );
    apply_structure_features(&mut f, &text_summary, text_bytes);
    apply_file_type_feature(&mut f, context, context_bytes);
    apply_extra_features(&mut f, context, context_bytes);
    apply_decode_structure_feature(&mut f, text);
    apply_service_context_feature(&mut f, context_bytes);
    f
}

/// Feature 41: keyhog's decode-through advantage as a model input. Fires when
/// the candidate base64/hex-decodes to an identifiable binary asset (PNG, gzip,
/// zip, ELF, ...) or a full protobuf-wire message - signals that a generic
/// high-entropy string is embedded data, not a credential. The model learns a
/// strong negative weight, so base64-of-binary is filtered while real base64
/// secrets (which carry no magic header and do not parse as protobuf) survive.
fn apply_decode_structure_feature(features: &mut [f32; NUM_FEATURES], text: &str) {
    features[DECODE_STRUCTURE_FEATURE_INDEX] =
        binary_feature(crate::decode_structure::evidence(text).is_binary_payload());
}

/// Feature 42: keyword specificity (DET-1). Fires when the ±5-line ML context
/// window (or the `file:` path line) names a specific service from the
/// detector-corpus-derived vocabulary. The model learns the interaction with
/// the UUID/opaque-shape features: a service-named context makes an
/// otherwise-generic value credible; a generic-role-word-only context
/// (feature 17 without this one) marks it an identifier.
fn apply_service_context_feature(features: &mut [f32; NUM_FEATURES], context_bytes: &[u8]) {
    features[SERVICE_CONTEXT_FEATURE_INDEX] =
        binary_feature(super::service_vocab::context_names_service(context_bytes));
}

/// File-context fragments that imply this match is in test/fixture code.
/// Hoisted to a `const` so we don't allocate four Strings on every ML call.
const TEST_FILE_CONTEXT_FRAGMENTS: &[&[u8]] = &[b"test", b"mock", b"fixture", b"spec"];

fn apply_extra_features(features: &mut [f32; NUM_FEATURES], context: &str, context_bytes: &[u8]) {
    let is_in_comment = context_starts_with_comment_prefix(context);
    let has_assignment = has_assignment_operator(context);
    let is_test_file_context = TEST_FILE_CONTEXT_FRAGMENTS
        .iter()
        .any(|needle| crate::ascii_ci::ci_find_nonempty(context_bytes, needle));

    features[COMMENT_CONTEXT_FEATURE_INDEX] = binary_feature(is_in_comment);
    features[ASSIGNMENT_OPERATOR_FEATURE_INDEX] = binary_feature(has_assignment);
    features[TEST_FILE_CONTEXT_FEATURE_INDEX] = binary_feature(is_test_file_context);
}

fn apply_length_features(features: &mut [f32; NUM_FEATURES], len: usize) {
    features[0] = (len as f32 / MAX_NORMALIZED_TEXT_LENGTH).min(1.0);
    features[1] = binary_feature(len >= MEDIUM_LENGTH_THRESHOLD);
    features[2] = binary_feature(len >= LONG_LENGTH_THRESHOLD);
    features[3] = binary_feature(len >= VERY_LONG_LENGTH_THRESHOLD);
}

fn apply_entropy_features(features: &mut [f32; NUM_FEATURES], entropy_value: f64) {
    features[4] = entropy_value as f32 / MAX_NORMALIZED_ENTROPY;
    features[5] = binary_feature(entropy_value >= ML_LOW_ENTROPY_FEATURE_THRESHOLD);
    features[6] = binary_feature(entropy_value >= HIGH_ENTROPY_THRESHOLD);
    features[7] = binary_feature(entropy_value >= VERY_HIGH_ENTROPY_THRESHOLD);
}

fn apply_character_features(features: &mut [f32; NUM_FEATURES], summary: &TextSummary) {
    features[8] = binary_feature(summary.has_upper);
    features[9] = binary_feature(summary.has_lower);
    features[10] = binary_feature(summary.has_digit);
    features[11] = binary_feature(summary.has_symbol);
}

fn apply_prefix_features(
    features: &mut [f32; NUM_FEATURES],
    text: &str,
    known_prefixes: &[String],
) {
    let prefix_len = longest_known_prefix(text, known_prefixes);
    features[12] = binary_feature(prefix_len > 0);
    features[13] = (prefix_len as f32 / MAX_PREFIX_LENGTH).min(1.0);
    features[14] = binary_feature(text.starts_with(OPENAI_PREFIX));
    features[15] = binary_feature(text.starts_with(AWS_ACCESS_KEY_PREFIX));
}

fn apply_context_features(
    features: &mut [f32; NUM_FEATURES],
    context: &str,
    context_bytes: &[u8],
    secret_keywords: &[String],
    test_keywords: &[String],
) {
    features[16] = binary_feature(has_assignment_operator(context));
    features[17] = binary_feature(contains_any_ascii_case_insensitive(
        context_bytes,
        secret_keywords,
    ));
    features[18] = binary_feature(contains_any_ascii_case_insensitive(
        context_bytes,
        test_keywords,
    ));
    features[19] = binary_feature(context_starts_with_comment_prefix(context));
}

fn apply_placeholder_features(
    features: &mut [f32; NUM_FEATURES],
    text: &str,
    text_bytes: &[u8],
    len: usize,
    unique_bytes: usize,
    placeholder_keywords: &[String],
) {
    features[20] = binary_feature(contains_any_ascii_case_insensitive(
        text_bytes,
        placeholder_keywords,
    ));
    features[21] =
        binary_feature(len > MIN_LOW_VARIETY_LENGTH && unique_bytes <= LOW_VARIETY_BYTE_THRESHOLD);
    features[22] = binary_feature(
        text_bytes.iter().all(|byte| byte.is_ascii_hexdigit()) && len > MIN_HEX_PLACEHOLDER_LENGTH,
    );
    features[23] = binary_feature(text.contains("://"));
}

fn apply_structure_features(
    features: &mut [f32; NUM_FEATURES],
    summary: &TextSummary,
    text_bytes: &[u8],
) {
    features[24] = (summary.unique_bytes as f32 / MAX_UNIQUE_CHAR_NORMALIZATION).min(1.0);
    let (unique_bigrams, bigram_count) = unique_bigram_stats(text_bytes);
    features[25] = normalized_ratio(unique_bigrams, bigram_count);
    features[26] = (summary.dot_count as f32 / MAX_DOT_COUNT_NORMALIZATION).min(1.0);
    features[27] = (summary.dash_count as f32 / MAX_DASH_COUNT_NORMALIZATION).min(1.0);
}

fn apply_file_type_feature(
    features: &mut [f32; NUM_FEATURES],
    context: &str,
    context_bytes: &[u8],
) {
    let file_type = infer_file_type(context, context_bytes);
    features[FILE_TYPE_OFFSET + file_type] = 1.0;
}

fn infer_file_type(context: &str, context_bytes: &[u8]) -> usize {
    if is_binary_context(context_bytes) {
        return BINARY_FILE_TYPE_INDEX;
    }
    if is_ci_context(context_bytes) {
        return CI_FILE_TYPE_INDEX;
    }
    if is_infra_context(context, context_bytes) {
        return INFRA_FILE_TYPE_INDEX;
    }
    if is_source_context(context, context_bytes) {
        return SOURCE_FILE_TYPE_INDEX;
    }
    if is_config_context(context, context_bytes) {
        return CONFIG_FILE_TYPE_INDEX;
    }
    OTHER_FILE_TYPE_INDEX
}

fn is_binary_context(context_bytes: &[u8]) -> bool {
    contains_any_ascii_case_insensitive(context_bytes, &BINARY_MARKERS)
}

fn is_ci_context(context_bytes: &[u8]) -> bool {
    contains_any_ascii_case_insensitive(context_bytes, &CI_MARKERS)
}

fn is_infra_context(context: &str, context_bytes: &[u8]) -> bool {
    context.contains("from ") || contains_any_ascii_case_insensitive(context_bytes, &INFRA_MARKERS)
}

fn is_source_context(context: &str, context_bytes: &[u8]) -> bool {
    contains_any(context, &SOURCE_MARKERS)
        || contains_any_ascii_case_insensitive(context_bytes, &SOURCE_EXTENSIONS)
}

fn is_config_context(context: &str, context_bytes: &[u8]) -> bool {
    has_unquoted_equals(context)
        || contains_any_ascii_case_insensitive(context_bytes, &CONFIG_MARKERS)
}

fn has_unquoted_equals(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (idx, byte) in bytes.iter().enumerate() {
        if *byte != b'=' {
            continue;
        }

        let prev = if idx > 0 { bytes[idx - 1] } else { 0 };
        let next = if idx + 1 < bytes.len() {
            bytes[idx + 1]
        } else {
            0
        };
        if prev != b'\'' && prev != b'"' && next != b'\'' && next != b'"' {
            return true;
        }
    }
    false
}

fn has_assignment_operator(value: &str) -> bool {
    if has_unquoted_equals(value) {
        return true;
    }
    value.contains(": ")
}

/// Whether `context`, trimmed, begins with one of the recognized comment
/// markers. Both the context-feature comment signal (feature 19) and the
/// extra-feature comment signal (feature 38, `COMMENT_CONTEXT_FEATURE_INDEX`)
/// derive from this same check; it lives in one place so the two features can
/// never drift to different comment definitions.
fn context_starts_with_comment_prefix(context: &str) -> bool {
    COMMENT_PREFIXES
        .iter()
        .any(|prefix| context.trim().starts_with(prefix.as_str()))
}

/// Per-thread scratch for [`unique_bigram_stats`]: the 8 KiB presence bitset is
/// allocated once per thread and reused, and only the words actually set are
/// zeroed after each call (via `touched`), so a per-candidate call no longer
/// memsets the whole 8 KiB. `seen` holds the invariant "all-zero between calls".
struct BigramScratch {
    seen: Box<[u64]>,
    touched: Vec<usize>,
}

pub(crate) fn unique_bigram_stats(bytes: &[u8]) -> (usize, usize) {
    if bytes.len() < 2 {
        return (0, 0);
    }

    thread_local! {
        static SCRATCH: std::cell::RefCell<BigramScratch> =
            std::cell::RefCell::new(BigramScratch {
                seen: vec![0u64; BIGRAM_BITSET_WORDS].into_boxed_slice(),
                touched: Vec::new(),
            });
    }

    SCRATCH.with(|cell| {
        let scratch = &mut *cell.borrow_mut();
        let BigramScratch { seen, touched } = scratch;
        touched.clear();
        let mut unique = 0usize;
        for window in bytes.windows(2) {
            let idx = ((window[0] as usize) << 8) | window[1] as usize;
            let word = idx / 64;
            let bit = 1u64 << (idx % 64);
            if seen[word] & bit == 0 {
                if seen[word] == 0 {
                    touched.push(word);
                }
                seen[word] |= bit;
                unique += 1;
            }
        }
        // Restore the all-zero invariant touching only the words we set.
        for &word in touched.iter() {
            seen[word] = 0;
        }
        (unique, bytes.len() - 1)
    })
}

fn contains_any_ascii_case_insensitive(haystack: &[u8], needles: &[String]) -> bool {
    needles
        .iter()
        .any(|needle| crate::ascii_ci::ci_find_nonempty(haystack, needle.as_bytes()))
}

fn contains_any(haystack: &str, needles: &[String]) -> bool {
    needles
        .iter()
        .any(|needle| haystack.contains(needle.as_str()))
}

fn binary_feature(value: bool) -> f32 {
    if value {
        1.0
    } else {
        0.0
    }
}

fn normalized_ratio(numerator: usize, denominator: usize) -> f32 {
    if denominator == 0 {
        0.0
    } else {
        (numerator as f32 / denominator as f32).min(1.0)
    }
}

fn longest_known_prefix(text: &str, known_prefixes: &[String]) -> usize {
    known_prefixes
        .iter()
        .filter(|prefix| text.starts_with(*prefix))
        .map(|prefix| prefix.len())
        .max()
        .unwrap_or(0) // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
}

struct TextSummary {
    has_upper: bool,
    has_lower: bool,
    has_digit: bool,
    has_symbol: bool,
    dot_count: usize,
    dash_count: usize,
    unique_bytes: usize,
}

fn summarize_text_bytes(text_bytes: &[u8]) -> TextSummary {
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut dot_count = 0usize;
    let mut dash_count = 0usize;
    for &byte in text_bytes {
        has_upper |= byte.is_ascii_uppercase();
        has_lower |= byte.is_ascii_lowercase();
        has_digit |= byte.is_ascii_digit();
        has_symbol |= !byte.is_ascii_alphanumeric();
        dot_count += usize::from(byte == b'.');
        dash_count += usize::from(byte == b'-');
    }
    TextSummary {
        has_upper,
        has_lower,
        has_digit,
        has_symbol,
        dot_count,
        dash_count,
        unique_bytes: unique_byte_count(text_bytes),
    }
}
