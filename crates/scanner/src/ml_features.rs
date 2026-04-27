use crate::entropy::shannon_entropy;

/// Feature vector dimensionality. Each feature captures one signal:
/// 4 length features + 4 entropy features + 4 character class features +
/// 4 prefix features + 4 context features + 4 placeholder features +
/// 4 structure features + 6 file-type one-hot features + 3 extra features
/// (comment, assignment, test-file) = 37 base + 4 padding = 41.
pub const NUM_FEATURES: usize = 41;

/// Offset into the feature vector where the one-hot file-type encoding starts.
const FILE_TYPE_OFFSET: usize = 32;

/// Number of mixture-of-experts specialists. Each expert sees the same input
/// but learns different aspects (one may specialize in cloud credentials,
/// another in short API keys, etc.). 6 experts balance capacity vs. inference
/// cost — trained via grid search over {4, 6, 8, 12}.
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

/// Entropy thresholds derived from the training corpus: 3.5 separates readable
/// English from random-ish strings, 4.5 separates structured tokens from high
/// entropy, and 5.0 flags near-random secrets.
const LOW_ENTROPY_THRESHOLD: f64 = 3.5;
const HIGH_ENTROPY_THRESHOLD: f64 = 4.5;
const VERY_HIGH_ENTROPY_THRESHOLD: f64 = 5.5;

const MAX_PREFIX_LENGTH: f32 = 10.0;
const OPENAI_PREFIX: &str = "sk-";
const AWS_ACCESS_KEY_PREFIX: &str = "AKIA";
const LOW_VARIETY_BYTE_THRESHOLD: usize = 3;
const MIN_LOW_VARIETY_LENGTH: usize = 5;
const MIN_HEX_PLACEHOLDER_LENGTH: usize = 10;
const MAX_UNIQUE_CHAR_NORMALIZATION: f32 = 40.0;
const MAX_DOT_COUNT_NORMALIZATION: f32 = 5.0;
const MAX_DASH_COUNT_NORMALIZATION: f32 = 10.0;
const CONFIG_FILE_TYPE_INDEX: usize = 0;
const SOURCE_FILE_TYPE_INDEX: usize = 1;
const CI_FILE_TYPE_INDEX: usize = 2;
const INFRA_FILE_TYPE_INDEX: usize = 3;
const OTHER_FILE_TYPE_INDEX: usize = 4;
const BINARY_FILE_TYPE_INDEX: usize = 5;
const COMMENT_CONTEXT_FEATURE_INDEX: usize = 38;
const ASSIGNMENT_OPERATOR_FEATURE_INDEX: usize = 39;
const TEST_FILE_CONTEXT_FEATURE_INDEX: usize = 40;

const COMMENT_PREFIXES: &[&str] = &["#", "//", "/*", "--"];
const BINARY_MARKERS: &[&str] = &[
    "load:",
    ".rodata",
    "xref",
    "lea rdi",
    "go.string",
    "core::str",
    "alloc::string",
    "objdump",
    "strings:",
    "symbol:",
];
const CI_MARKERS: &[&str] = &[
    "jobs:",
    "stages:",
    "pipeline",
    "jenkinsfile",
    ".gitlab-ci",
    "buildspec",
    ".github/workflows",
    ".github/actions",
    "circleci",
    ".travis.yml",
    "azure-pipelines",
    "bitbucket-pipelines",
    "semaphore",
    "concourse",
    "tekton",
    "argocd",
];
const INFRA_MARKERS: &[&str] = &[
    "resource ",
    "apiversion:",
    ".tf",
    ".tfvars",
    "dockerfile",
    "docker-compose",
    "k8s",
    "ansible",
    "helm",
    "kustomize",
    "cloudformation",
    "serverless.yml",
    "wrangler.toml",
    "pulumi",
    "vagrant",
];
const SOURCE_MARKERS: &[&str] = &["const ", "let ", "var ", "def ", "fn "];
const SOURCE_EXTENSIONS: &[&str] = &[
    ".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php", ".swift", ".kt",
];
const CONFIG_MARKERS: &[&str] = &[
    ".env",
    ".yaml",
    ".json",
    ".toml",
    ".properties",
    ".cfg",
    ".ini",
];

/// Public entry point for feature extraction (used by GPU batch inference).
pub fn compute_features_public(text: &str, context: &str) -> [f32; NUM_FEATURES] {
    if text.is_empty() {
        return [0.0f32; NUM_FEATURES];
    }
    compute_features_with_config(text, context, &[], &[], &[], &[])
}

/// Compute the 41-dimensional feature vector.
pub(crate) fn compute_features_with_config(
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
        text_summary.unique_chars,
        placeholder_keywords,
    );
    apply_structure_features(&mut f, &text_summary, text_bytes);
    apply_file_type_feature(&mut f, context);
    apply_extra_features(&mut f, context, context_bytes);
    f
}

/// File-context fragments that imply this match is in test/fixture code.
/// Hoisted to a `const` so we don't allocate four Strings on every ML call.
const TEST_FILE_CONTEXT_FRAGMENTS: &[&[u8]] = &[b"test", b"mock", b"fixture", b"spec"];

fn apply_extra_features(features: &mut [f32; NUM_FEATURES], context: &str, context_bytes: &[u8]) {
    let is_in_comment = COMMENT_PREFIXES
        .iter()
        .any(|prefix| context.trim().starts_with(prefix));
    let has_assignment = has_assignment_operator(context);
    let is_test_file_context = TEST_FILE_CONTEXT_FRAGMENTS
        .iter()
        .any(|needle| contains_ascii_case_insensitive(context_bytes, needle));

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
    features[5] = binary_feature(entropy_value >= LOW_ENTROPY_THRESHOLD);
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
    features[19] = binary_feature(
        COMMENT_PREFIXES
            .iter()
            .any(|prefix| context.trim().starts_with(prefix)),
    );
}

fn apply_placeholder_features(
    features: &mut [f32; NUM_FEATURES],
    text: &str,
    text_bytes: &[u8],
    len: usize,
    unique_chars: usize,
    placeholder_keywords: &[String],
) {
    features[20] = binary_feature(contains_any_ascii_case_insensitive(
        text_bytes,
        placeholder_keywords,
    ));
    features[21] =
        binary_feature(len > MIN_LOW_VARIETY_LENGTH && unique_chars <= LOW_VARIETY_BYTE_THRESHOLD);
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
    features[24] = (summary.unique_chars as f32 / MAX_UNIQUE_CHAR_NORMALIZATION).min(1.0);
    let (unique_bigrams, bigram_count) = unique_bigram_stats(text_bytes);
    features[25] = normalized_ratio(unique_bigrams, bigram_count);
    features[26] = (summary.dot_count as f32 / MAX_DOT_COUNT_NORMALIZATION).min(1.0);
    features[27] = (summary.dash_count as f32 / MAX_DASH_COUNT_NORMALIZATION).min(1.0);
}

fn apply_file_type_feature(features: &mut [f32; NUM_FEATURES], context: &str) {
    let file_type = infer_file_type(context);
    features[FILE_TYPE_OFFSET + file_type] = 1.0;
}

fn infer_file_type(context: &str) -> usize {
    let context_lower = context.to_ascii_lowercase();
    if is_binary_context(&context_lower) {
        return BINARY_FILE_TYPE_INDEX;
    }
    if is_ci_context(&context_lower) {
        return CI_FILE_TYPE_INDEX;
    }
    if is_infra_context(context, &context_lower) {
        return INFRA_FILE_TYPE_INDEX;
    }
    if is_source_context(context, &context_lower) {
        return SOURCE_FILE_TYPE_INDEX;
    }
    if is_config_context(context, &context_lower) {
        return CONFIG_FILE_TYPE_INDEX;
    }
    OTHER_FILE_TYPE_INDEX
}

fn is_binary_context(context_lower: &str) -> bool {
    contains_any(context_lower, BINARY_MARKERS)
}

fn is_ci_context(context_lower: &str) -> bool {
    contains_any(context_lower, CI_MARKERS)
}

fn is_infra_context(context: &str, context_lower: &str) -> bool {
    context.contains("from ") || contains_any(context_lower, INFRA_MARKERS)
}

fn is_source_context(context: &str, context_lower: &str) -> bool {
    contains_any(context, SOURCE_MARKERS) || contains_any(context_lower, SOURCE_EXTENSIONS)
}

fn is_config_context(context: &str, context_lower: &str) -> bool {
    has_unquoted_equals(context) || contains_any(context_lower, CONFIG_MARKERS)
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

fn unique_byte_count(bytes: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut count = 0usize;
    for byte in bytes {
        let slot = &mut seen[*byte as usize];
        if !*slot {
            *slot = true;
            count += 1;
        }
    }
    count
}

fn unique_bigram_stats(bytes: &[u8]) -> (usize, usize) {
    if bytes.len() < 2 {
        return (0, 0);
    }

    let mut seen = [0u64; 1024];
    let mut unique = 0usize;
    for window in bytes.windows(2) {
        let idx = ((window[0] as usize) << 8) | window[1] as usize;
        let word = idx / 64;
        let bit = 1u64 << (idx % 64);
        if seen[word] & bit == 0 {
            seen[word] |= bit;
            unique += 1;
        }
    }
    (unique, bytes.len() - 1)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn contains_any_ascii_case_insensitive(haystack: &[u8], needles: &[String]) -> bool {
    needles
        .iter()
        .any(|needle| contains_ascii_case_insensitive(haystack, needle.as_bytes()))
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
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
        .unwrap_or(0)
}

struct TextSummary {
    has_upper: bool,
    has_lower: bool,
    has_digit: bool,
    has_symbol: bool,
    dot_count: usize,
    dash_count: usize,
    unique_chars: usize,
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
        unique_chars: unique_byte_count(text_bytes),
    }
}
