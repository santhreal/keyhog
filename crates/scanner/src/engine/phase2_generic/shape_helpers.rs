//! Shape helpers used by the generic-secret value gauntlet.

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
