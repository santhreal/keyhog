//! Shape helpers used by the generic-secret value gauntlet.

/// Exact dotted credential shapes the generic fallback may treat as real
/// tokens. Property/method chains also use dots, so keep this as a tight
/// allowlist instead of a punctuation relaxation.
pub(crate) fn is_structured_dotted_token(value: &str) -> bool {
    if !value.contains('.') {
        return false;
    }
    let mut parts = value.split('.');
    let (Some(first), Some(second), Some(third), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let segments = [first, second, third];
    let is_jwt_like = first.starts_with("eyJ")
        && segments.iter().all(|segment| {
            segment.len() >= 4
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
                })
        });
    let is_discord_style = (23..=28).contains(&first.len())
        && (6..=8).contains(&second.len())
        && (27..=38).contains(&third.len())
        && segments.iter().all(|segment| {
            segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        });
    is_jwt_like || is_discord_style
}

/// Standard-base64-arbitrary-bytes shape detector for the
/// generic-secret path only. Returns true when `value` looks like
/// a protobuf wire dump / marshalled binary / k8s data field rather
/// than a credential token.
///
/// Why generic-path-only: named detectors with service-specific
/// keyword anchors (`AccountKey=...`, `AZURE_STORAGE_KEY=...`) cover
/// the legitimate ~88-char base64 cred families and skip this
/// fallback entirely. Suppressing on the generic path doesn't
/// touch their recall - verified by passing service-specific
/// fixtures through `engine/scan.rs`'s named-detector path which
/// runs before `scan_generic_assignments`.
///
/// Heuristics:
///   1. Length in `[40, 300]` (covers both the 40-80 protobuf
///      sweet spot and the longer 80-300 k8s `data:` blobs).
///   2. Alphabet is standard base64, not url-safe.
///   3. Contains both `+` and `/`, or has padding with at least one of
///      them, which is a stronger byte-level signal than pure text-like
///      pure-base62 strings.
///      Real provider tokens are pure base62 without padding
///      because their length isn't derived from base64 of bytes -
///      AKIA + 16, ghp_ + 36, sk_live_ + 24, etc. all land on
///      char counts that don't need `=` padding. Adding the
///      "padded" branch catches the residual ~862 FPs where the
///      payload happens to encode random bytes into pure-b62
///      characters but still needs the `==` padding to round out.
///   4. Length is a multiple of 4 OR ends with `=`/`==` padding.
pub(crate) fn generic_path_looks_like_random_base64_blob(value: &str, entropy: f64) -> bool {
    const HIGH_ENTROPY_BASE64_CUTOFF: f64 = 4.8;

    if entropy >= HIGH_ENTROPY_BASE64_CUTOFF {
        return false;
    }

    // Band 40..=300 (covers both the 40-80 protobuf sweet spot and the longer
    // 80-300 k8s `data:` blobs). The band + padding + standard-base64-alphabet +
    // BOTH-`+`-AND-`/` skeleton is the shared `is_byte_distribution_base64_blob`
    // canonical (MC-12); this path composes its entropy cutoff (above) and band
    // on top.
    crate::decode_structure::is_byte_distribution_base64_blob(value, 40, 300)
}

/// True when a generic assignment candidate is standard-base64-shaped but has
/// enough entropy and alphabet diversity that shape alone cannot prove it is
/// data rather than an opaque no-prefix credential. These candidates still flow
/// through the generic confidence penalties, so ordinary report-floor scans keep
/// random-byte blobs quiet while `min_confidence=0` target/audit scans can see
/// the candidate instead of losing it to a hard suppression cliff.
pub(crate) fn generic_path_allows_ambiguous_base64_candidate(value: &str, entropy: f64) -> bool {
    const HIGH_ENTROPY_BASE64_CUTOFF: f64 = 4.8;
    const MIN_DISTINCT_ALNUM: u32 = 32;

    if entropy < HIGH_ENTROPY_BASE64_CUTOFF {
        return false;
    }
    let Some(shape) = crate::decode::standard_base64_shape(value) else {
        return false;
    };
    shape.distinct_alnum >= MIN_DISTINCT_ALNUM
}

/// Random-byte base64 decoy detector for the generic-secret path only.
/// Returns true when `value` is a pure standard-base64-alphabet blob in the
/// 40-80-char decoy band that base64-decodes to bytes which are neither valid
/// UTF-8 text nor a recognizable binary magic - i.e. the SecretBench
/// `negatives.py` base64-of-random-protobuf-bytes decoy class.
///
/// Why this exists alongside [`generic_path_looks_like_random_base64_blob`] and
/// `decode_structure::is_encoded_binary`:
///   * `is_encoded_binary` only fires on a recognizable magic header OR a clean
///     multi-field protobuf-wire parse. Random wire bytes parse as a full
///     protobuf message < 0.5% of the time, so the 30-80-random-byte decoy
///     slips both checks.
///   * `generic_path_looks_like_random_base64_blob` requires `+`/`/` or `=`
///     padding; a random-byte payload that happens to encode into pure base62
///     without padding evades it.
///   * `looks_like_uniform_base64_blob` (penalty path) floors at 44 chars and
///     only multiplies confidence by 0.02 - it does not hard-drop, and the
///     generic emit path bypasses the penalty path entirely.
///
/// This gate closes the family with a decode-through: pure standard-base64
/// alphabet (no `-`/`_`/`.`, so url-safe-prefixed service tokens are already
/// excluded), no service-prefix anchor, length in the decoy band, decoding to
/// non-text non-magic bytes. Named-detector matches anchor on a service prefix
/// and run before this fallback, so a real 40-char anchored secret still fires.
pub(crate) fn generic_path_looks_like_random_byte_blob(value: &str) -> bool {
    // Decoy band: SecretBench `negatives.py` emits base64 of 30-80 random
    // protobuf-wire bytes, which encodes to ~40-108 base64 chars. Cap at 80
    // to stay inside the band the audit measured (longer pure-base64 blobs are
    // already slammed by the penalty path's `looks_like_uniform_base64_blob`).
    if !(40..=80).contains(&value.len()) {
        return false;
    }
    // Pure STANDARD base64 alphabet only. Any `-`/`_`/`.` (base64url, JWT,
    // Slack, dotted property) rejects, which also clears every url-safe
    // service-prefixed token.
    // Require at least one pure-base62 path here: this branch is for the
    // long tail of random-binary decoys that missed the punct/pad gate.
    // Strings with `+`/`/` are already covered by the random-base64 gate
    // once both punctuation marks are present.
    if value.bytes().any(|b| matches!(b, b'+' | b'/')) {
        return false;
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'=')
    {
        return false;
    }
    // Decode-through: the value must base64/hex-decode, and the decoded bytes
    // must be neither a recognizable binary magic nor predominantly printable
    // text. Random wire bytes land around a 0.30 printable ratio; real
    // base64-wrapped text (which decodes near 1.0 printable) stays out of the
    // drop while random bytes are caught. A magic header is already handled by
    // `is_encoded_binary`, but re-checking here keeps the gate self-contained
    // and correct if call order ever changes.
    let structure = crate::decode_structure::analyze(value);
    if !structure.decodable {
        return false;
    }
    if structure.magic.is_some() {
        return true;
    }
    structure.printable_ratio < 0.85
}

/// IAM-ARN-trimmed-prefix gate for the generic-secret path.
/// Recognizes `aws:iam::...` shapes without `arn:` prefix.
pub(crate) fn generic_path_looks_like_trimmed_aws_arn(value: &str) -> bool {
    let prefixes = ["aws:iam::", "aws-cn:iam::", "aws-us-gov:iam::"];
    let Some(body) = prefixes.iter().find_map(|&p| value.strip_prefix(p)) else {
        return false;
    };
    let targets = [
        ":role/",
        ":user/",
        ":group/",
        ":policy/",
        ":instance-profile/",
    ];
    targets.iter().any(|&t| body.contains(t))
}
