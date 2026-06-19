"""Python parity/debug port of `crates/scanner/src/ml_scorer/ml_features.rs`.

Training uses `ml/rust_features.py`, which calls the Rust `dump_features`
serve-path extractor. This file exists only as a parity/debug oracle:
`ml/parity_check.py` drives a battery of inputs through both the Rust
`compute_features_with_config` and this module and asserts agreement to within
1e-5.

Base layout (indices, mirrors the Rust comment "37 base + 4 padding = 41"):
  0-3   length        4-7   entropy        8-11  char class
  12-15 prefix        16-19 context        20-23 placeholder
  24-27 structure     28-31 PADDING (always 0)
  32-37 file-type one-hot (config/source/ci/infra/other/binary)
  38    in-comment    39 assignment-op    40 test-file-context

Feature #41 (the 42nd, appended when the Rust scanner is bumped to 42 features):
  41    decode-structure is_binary_payload — keyhog's decode-through advantage
        fed into the model. Computed on the credential text via decode_structure.
"""

from __future__ import annotations

import math

import decode_structure

NUM_BASE_FEATURES = 41
DECODE_FEATURE_INDEX = 41
NUM_FEATURES = 42

FILE_TYPE_OFFSET = 32
MAX_NORMALIZED_TEXT_LENGTH = 200.0
MEDIUM_LENGTH_THRESHOLD = 20
LONG_LENGTH_THRESHOLD = 40
VERY_LONG_LENGTH_THRESHOLD = 100
MAX_NORMALIZED_ENTROPY = 8.0
LOW_ENTROPY_THRESHOLD = 3.5
HIGH_ENTROPY_THRESHOLD = 4.5
VERY_HIGH_ENTROPY_THRESHOLD = 5.5
MAX_PREFIX_LENGTH = 10.0
OPENAI_PREFIX = "sk-"
AWS_ACCESS_KEY_PREFIX = "AKIA"
LOW_VARIETY_BYTE_THRESHOLD = 3
MIN_LOW_VARIETY_LENGTH = 5
MIN_HEX_PLACEHOLDER_LENGTH = 10
MAX_UNIQUE_CHAR_NORMALIZATION = 40.0
MAX_DOT_COUNT_NORMALIZATION = 5.0
MAX_DASH_COUNT_NORMALIZATION = 10.0

CONFIG_FILE_TYPE_INDEX = 0
SOURCE_FILE_TYPE_INDEX = 1
CI_FILE_TYPE_INDEX = 2
INFRA_FILE_TYPE_INDEX = 3
OTHER_FILE_TYPE_INDEX = 4
BINARY_FILE_TYPE_INDEX = 5

COMMENT_CONTEXT_FEATURE_INDEX = 38
ASSIGNMENT_OPERATOR_FEATURE_INDEX = 39
TEST_FILE_CONTEXT_FEATURE_INDEX = 40

COMMENT_PREFIXES = ["#", "//", "/*", "--"]
BINARY_MARKERS = [
    "load:", ".rodata", "xref", "lea rdi", "go.string", "core::str",
    "alloc::string", "objdump", "strings:", "symbol:",
]
CI_MARKERS = [
    "jobs:", "stages:", "pipeline", "jenkinsfile", ".gitlab-ci", "buildspec",
    ".github/workflows", ".github/actions", "circleci", ".travis.yml",
    "azure-pipelines", "bitbucket-pipelines", "semaphore", "concourse",
    "tekton", "argocd",
]
INFRA_MARKERS = [
    "resource ", "apiversion:", ".tf", ".tfvars", "dockerfile", "docker-compose",
    "k8s", "ansible", "helm", "kustomize", "cloudformation", "serverless.yml",
    "wrangler.toml", "pulumi", "vagrant",
]
SOURCE_MARKERS = ["const ", "let ", "var ", "def ", "fn "]
SOURCE_EXTENSIONS = [
    ".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php", ".swift", ".kt",
]
CONFIG_MARKERS = [".env", ".yaml", ".json", ".toml", ".properties", ".cfg", ".ini"]

TEST_FILE_CONTEXT_FRAGMENTS = [b"test", b"mock", b"fixture", b"spec"]


def _binary(value: bool) -> float:
    return 1.0 if value else 0.0


def shannon_entropy(data: bytes) -> float:
    """Standard base-2 Shannon entropy over byte frequencies. Matches
    `entropy::fast::shannon_entropy_scalar` for credential strings (no NUL runs,
    so the Rust NUL fast-path is inert)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def _unique_byte_count(data: bytes) -> int:
    return len(set(data))


def _unique_bigram_stats(data: bytes) -> tuple[int, int]:
    if len(data) < 2:
        return 0, 0
    seen = set()
    for i in range(len(data) - 1):
        seen.add((data[i], data[i + 1]))
    return len(seen), len(data) - 1


def _normalized_ratio(num: int, den: int) -> float:
    if den == 0:
        return 0.0
    return min(num / den, 1.0)


def _ci_contains(haystack: bytes, needle: bytes) -> bool:
    if not needle:
        return False
    return haystack.lower().find(needle.lower()) != -1


def _ci_contains_any(haystack: bytes, needles: list[str]) -> bool:
    hl = haystack.lower()
    return any(n and hl.find(n.encode("utf-8").lower()) != -1 for n in needles)


def _has_unquoted_equals(value: str) -> bool:
    b = value.encode("utf-8")
    for idx, byte in enumerate(b):
        if byte != ord("="):
            continue
        prev = b[idx - 1] if idx > 0 else 0
        nxt = b[idx + 1] if idx + 1 < len(b) else 0
        if prev not in (ord("'"), ord('"')) and nxt not in (ord("'"), ord('"')):
            return True
    return False


def _has_assignment_operator(value: str) -> bool:
    if _has_unquoted_equals(value):
        return True
    return ": " in value


def _longest_known_prefix(text: str, known_prefixes: list[str]) -> int:
    best = 0
    for p in known_prefixes:
        if text.startswith(p):
            best = max(best, len(p.encode("utf-8")))
    return best


def _contains_any(haystack: str, needles: list[str]) -> bool:
    return any(n in haystack for n in needles)


def _infer_file_type(context: str) -> int:
    lower = context.lower()
    if _contains_any(lower, BINARY_MARKERS):
        return BINARY_FILE_TYPE_INDEX
    if _contains_any(lower, CI_MARKERS):
        return CI_FILE_TYPE_INDEX
    if "from " in context or _contains_any(lower, INFRA_MARKERS):
        return INFRA_FILE_TYPE_INDEX
    if _contains_any(context, SOURCE_MARKERS) or _contains_any(lower, SOURCE_EXTENSIONS):
        return SOURCE_FILE_TYPE_INDEX
    if _has_unquoted_equals(context) or _contains_any(lower, CONFIG_MARKERS):
        return CONFIG_FILE_TYPE_INDEX
    return OTHER_FILE_TYPE_INDEX


def compute_features(
    text: str,
    context: str,
    known_prefixes: list[str] | None = None,
    secret_keywords: list[str] | None = None,
    test_keywords: list[str] | None = None,
    placeholder_keywords: list[str] | None = None,
    with_decode: bool = True,
) -> list[float]:
    """Return the feature vector. `with_decode=False` returns the 41 base
    features (for parity against the current 41-feature Rust scanner);
    `with_decode=True` appends feature #41 (decode-structure)."""
    known_prefixes = known_prefixes or []
    secret_keywords = secret_keywords or []
    test_keywords = test_keywords or []
    placeholder_keywords = placeholder_keywords or []

    width = NUM_FEATURES if with_decode else NUM_BASE_FEATURES
    f = [0.0] * width
    if not text:
        return f

    tb = text.encode("utf-8")
    cb = context.encode("utf-8")
    length = len(tb)
    ent = shannon_entropy(tb)

    def _is_ascii_alnum(b: int) -> bool:
        return 48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122

    has_upper = any(65 <= b <= 90 for b in tb)
    has_lower = any(97 <= b <= 122 for b in tb)
    has_digit = any(48 <= b <= 57 for b in tb)
    has_symbol = any(not _is_ascii_alnum(b) for b in tb)
    dot_count = tb.count(ord("."))
    dash_count = tb.count(ord("-"))
    unique_chars = _unique_byte_count(tb)

    # length
    f[0] = min(length / MAX_NORMALIZED_TEXT_LENGTH, 1.0)
    f[1] = _binary(length >= MEDIUM_LENGTH_THRESHOLD)
    f[2] = _binary(length >= LONG_LENGTH_THRESHOLD)
    f[3] = _binary(length >= VERY_LONG_LENGTH_THRESHOLD)
    # entropy
    f[4] = ent / MAX_NORMALIZED_ENTROPY
    f[5] = _binary(ent >= LOW_ENTROPY_THRESHOLD)
    f[6] = _binary(ent >= HIGH_ENTROPY_THRESHOLD)
    f[7] = _binary(ent >= VERY_HIGH_ENTROPY_THRESHOLD)
    # char class
    f[8] = _binary(has_upper)
    f[9] = _binary(has_lower)
    f[10] = _binary(has_digit)
    f[11] = _binary(has_symbol)
    # prefix
    prefix_len = _longest_known_prefix(text, known_prefixes)
    f[12] = _binary(prefix_len > 0)
    f[13] = min(prefix_len / MAX_PREFIX_LENGTH, 1.0)
    f[14] = _binary(text.startswith(OPENAI_PREFIX))
    f[15] = _binary(text.startswith(AWS_ACCESS_KEY_PREFIX))
    # context
    f[16] = _binary(_has_assignment_operator(context))
    f[17] = _binary(_ci_contains_any(cb, secret_keywords))
    f[18] = _binary(_ci_contains_any(cb, test_keywords))
    f[19] = _binary(any(context.strip().startswith(p) for p in COMMENT_PREFIXES))
    # placeholder
    f[20] = _binary(_ci_contains_any(tb, placeholder_keywords))
    f[21] = _binary(length > MIN_LOW_VARIETY_LENGTH and unique_chars <= LOW_VARIETY_BYTE_THRESHOLD)
    f[22] = _binary(
        all(chr(b) in "0123456789abcdefABCDEF" for b in tb) and length > MIN_HEX_PLACEHOLDER_LENGTH
    )
    f[23] = _binary("://" in text)
    # structure
    f[24] = min(unique_chars / MAX_UNIQUE_CHAR_NORMALIZATION, 1.0)
    ub, bc = _unique_bigram_stats(tb)
    f[25] = _normalized_ratio(ub, bc)
    f[26] = min(dot_count / MAX_DOT_COUNT_NORMALIZATION, 1.0)
    f[27] = min(dash_count / MAX_DASH_COUNT_NORMALIZATION, 1.0)
    # 28-31 padding (left at 0.0)
    # file type one-hot
    f[FILE_TYPE_OFFSET + _infer_file_type(context)] = 1.0
    # extra
    f[COMMENT_CONTEXT_FEATURE_INDEX] = _binary(
        any(context.strip().startswith(p) for p in COMMENT_PREFIXES)
    )
    f[ASSIGNMENT_OPERATOR_FEATURE_INDEX] = _binary(_has_assignment_operator(context))
    f[TEST_FILE_CONTEXT_FEATURE_INDEX] = _binary(
        any(_ci_contains(cb, frag) for frag in TEST_FILE_CONTEXT_FRAGMENTS)
    )

    if with_decode:
        f[DECODE_FEATURE_INDEX] = _binary(decode_structure.is_encoded_binary(text))

    return f
