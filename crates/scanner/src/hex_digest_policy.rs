//! Tier-B hex-digest recognition and fragment-boundary policy.
//!
//! One owner for the four hex widths/bounds the shape gates and the
//! digest-fragment adjudicator consult. The values live in
//! `rules/hex-digest-policy.toml` so a new digest family (or a corrected
//! truncation boundary) is a data edit, and the three width lists cannot drift
//! into contradicting each other: the loader proves the containment relations
//! the doc comments used to assert only in prose.

/// Recognized hex-digest widths and the fragment-run boundary, in hex chars.
pub(crate) struct HexDigestPolicy {
    canonical_lengths: Box<[usize]>,
    bare_digest_lengths: Box<[usize]>,
    service_key_lengths: Box<[usize]>,
    /// Contiguous hex run at or above which a match is a digest fragment.
    pub(crate) fragment_run_min_length: usize,
    /// `min_len` used when the detector declares none.
    pub(crate) fragment_default_min_len: usize,
}

#[derive(serde::Deserialize)]
struct HexDigestPolicyFile {
    hex_digest_policy: HexDigestPolicySection,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HexDigestPolicySection {
    canonical_lengths: Vec<usize>,
    bare_digest_lengths: Vec<usize>,
    service_key_lengths: Vec<usize>,
    fragment_run_min_length: usize,
    fragment_default_min_len: usize,
}

/// Parse + validate the bundled policy. Returns an error rather than panicking
/// so the [`POLICY`] owner below is the single fail-closed site (the
/// `no_unwrap_expect` gate bans `expect` in production source).
pub(crate) fn parse_policy(raw: &str) -> Result<HexDigestPolicy, String> {
    let parsed: HexDigestPolicyFile =
        toml::from_str(raw).map_err(|error| format!("invalid hex-digest-policy.toml: {error}"))?;
    let section = parsed.hex_digest_policy;
    let canonical_lengths = validate_lengths("canonical_lengths", section.canonical_lengths)?;
    let bare_digest_lengths =
        validate_lengths("bare_digest_lengths", section.bare_digest_lengths)?;
    let service_key_lengths =
        validate_lengths("service_key_lengths", section.service_key_lengths)?;
    require_subset("canonical_lengths", &canonical_lengths, &bare_digest_lengths)?;
    require_subset(
        "service_key_lengths",
        &service_key_lengths,
        &bare_digest_lengths,
    )?;
    if section.fragment_run_min_length == 0 {
        return Err("fragment_run_min_length must be greater than zero".to_string());
    }
    if section.fragment_default_min_len == 0 {
        return Err("fragment_default_min_len must be greater than zero".to_string());
    }
    if section.fragment_default_min_len > section.fragment_run_min_length {
        return Err(format!(
            "fragment_default_min_len {} exceeds fragment_run_min_length {}; the fragment check \
             could never fire",
            section.fragment_default_min_len, section.fragment_run_min_length
        ));
    }
    Ok(HexDigestPolicy {
        canonical_lengths: canonical_lengths.into_boxed_slice(),
        bare_digest_lengths: bare_digest_lengths.into_boxed_slice(),
        service_key_lengths: service_key_lengths.into_boxed_slice(),
        fragment_run_min_length: section.fragment_run_min_length,
        fragment_default_min_len: section.fragment_default_min_len,
    })
}

/// A width list must be non-empty, positive, and strictly ascending. Requiring
/// ascending order rejects duplicates and keeps the file readable as one
/// ordered width ladder.
fn validate_lengths(field: &str, lengths: Vec<usize>) -> Result<Vec<usize>, String> {
    if lengths.is_empty() {
        return Err(format!("{field} must contain at least one width"));
    }
    let mut previous = 0usize;
    for &length in &lengths {
        if length == 0 {
            return Err(format!("{field} widths must be greater than zero"));
        }
        if length <= previous {
            return Err(format!(
                "{field} must be strictly ascending; {length} follows {previous}"
            ));
        }
        previous = length;
    }
    Ok(lengths)
}

fn require_subset(field: &str, subset: &[usize], superset: &[usize]) -> Result<(), String> {
    for length in subset {
        if !superset.contains(length) {
            return Err(format!(
                "{field} width {length} is missing from bare_digest_lengths; a width the shape \
                 gates recognize must also be a bare-digest width"
            ));
        }
    }
    Ok(())
}

static POLICY: std::sync::LazyLock<HexDigestPolicy> = std::sync::LazyLock::new(|| {
    match parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/rules/hex-digest-policy.toml"
    ))) {
        Ok(policy) => policy,
        Err(error) => panic!(
            "rules/hex-digest-policy.toml is invalid: {error}. \
             Fix the bundled Tier-B hex-digest policy."
        ),
    }
});

pub(crate) fn policy() -> &'static HexDigestPolicy {
    &POLICY
}

/// `true` iff `len` (in hex chars) is a canonical cryptographic digest width.
#[inline]
pub(crate) fn is_canonical_length(len: usize) -> bool {
    POLICY.canonical_lengths.contains(&len)
}

/// `true` iff `len` is a width the bare-hex-digest shape gate recognizes.
#[inline]
pub(crate) fn is_bare_digest_length(len: usize) -> bool {
    POLICY.bare_digest_lengths.contains(&len)
}

/// `true` iff `len` is a width a service-anchored detector may own.
#[inline]
pub(crate) fn is_service_key_length(len: usize) -> bool {
    POLICY.service_key_lengths.contains(&len)
}
