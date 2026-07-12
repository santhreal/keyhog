use crate::suppression::token_randomness::TokenRandomness;

/// Public schema/policy identifiers often look like
/// `product-area-contract:v1`. Under keys such as `schema_token` the generic
/// bridge used to report them as credentials; a versioned kebab identifier is a
/// public contract name, not a secret.
pub(crate) fn looks_like_public_version_identifier_with_randomness(
    value: &str,
    randomness: &TokenRandomness<'_>,
) -> bool {
    let Some((name, version)) = value.split_once(':') else {
        return false;
    };
    let Some(version_digits) = version.strip_prefix('v') else {
        return false;
    };
    if version_digits.is_empty()
        || version_digits.len() > 3
        || !version_digits.bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    if name.len() < 8 || name.len() > 96 || !name.contains('-') {
        return false;
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return false;
    }
    let mut part_count = 0usize;
    for part in name.split('-') {
        if part.is_empty() || part.len() > 24 {
            return false;
        }
        part_count += 1;
    }
    if part_count < 3 {
        return false;
    }
    !randomness.is_random_token(name)
}

/// TOML/source-ledger selectors such as `[sources.LINUX_OPENAT2]` and glued
/// pairs like `[sources.LINUX_OPENAT2][sources.BLAKE3_SPEC]` are public
/// references, not credentials.
pub(crate) fn looks_like_public_reference_selector(value: &str) -> bool {
    if value.len() < 12 || value.len() > 160 {
        return false;
    }
    let mut rest = value;
    let mut count = 0usize;
    while let Some(after_prefix) = rest.strip_prefix("[sources.") {
        let Some(end) = after_prefix.find(']') else {
            return false;
        };
        let ident = &after_prefix[..end];
        if ident.len() < 3
            || ident.len() > 80
            || !ident
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return false;
        }
        count += 1;
        rest = &after_prefix[end + 1..];
    }
    count >= 1 && rest.is_empty()
}

#[derive(serde::Deserialize)]
struct PublicWords {
    words: Vec<String>,
}

fn parse_public_words(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<PublicWords>(raw)
        .map(|parsed| parsed.words)
        .map_err(|error| error.to_string())
}

static PUBLIC_WORDS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_public_words(include_str!("../../../../../rules/public-words.toml")) {
        Ok(words) => words,
        Err(error) => panic!(
            "rules/public-words.toml is invalid: {error}. \
             Fix the bundled Tier-B public words list."
        ),
    }
});

#[derive(serde::Deserialize)]
struct PublicShapeLists {
    algorithms: Vec<String>,
    extensions: Vec<String>,
    html_events: Vec<String>,
}

fn parse_public_shape_lists(raw: &str) -> Result<PublicShapeLists, String> {
    toml::from_str::<PublicShapeLists>(raw).map_err(|error| error.to_string())
}

/// Single parse of the public-shape Tier-B lists: the three field statics below
/// each read one list from this owner instead of re-`include_str!`'ing and
/// re-parsing the whole file three times at startup. Fail-closed (Law 10):
/// invalid bundled metadata panics loudly at first use.
static PUBLIC_SHAPE_LISTS: std::sync::LazyLock<PublicShapeLists> = std::sync::LazyLock::new(|| {
    match parse_public_shape_lists(include_str!("../../../../../rules/public-shape-lists.toml")) {
        Ok(lists) => lists,
        Err(error) => panic!(
            "rules/public-shape-lists.toml is invalid: {error}. \
             Fix the bundled public shape lists."
        ),
    }
});

static ALGORITHMS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| PUBLIC_SHAPE_LISTS.algorithms.clone());

static EXTENSIONS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| PUBLIC_SHAPE_LISTS.extensions.clone());

static HTML_EVENTS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| PUBLIC_SHAPE_LISTS.html_events.clone());

/// Public taxonomy / provenance labels used in source ledgers:
/// `official-author-documentation`, `primary-protocol-specification`,
/// `source-available`, etc.
pub(crate) fn looks_like_public_metadata_identifier_with_randomness(
    value: &str,
    randomness: &TokenRandomness<'_>,
) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 12 || bytes.len() > 128 || !bytes.contains(&b'-') {
        return false;
    }
    if !bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return false;
    }
    let mut parts = 0usize;
    let mut public_parts = 0usize;
    for part in value.split('-') {
        if part.is_empty() || part.len() > 24 {
            return false;
        }
        parts += 1;
        for word in &*PUBLIC_WORDS {
            if word == part {
                public_parts += 1;
                break;
            }
        }
    }
    parts >= 2 && public_parts >= 1 && !randomness.is_random_token(value)
}

/// Public planning/evidence identifiers from audit ledgers and control
/// matrices: CWE/RFC/OWASP labels, VX row ranges, and project issue IDs.
pub(crate) fn looks_like_public_evidence_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 6 || bytes.len() > 220 {
        return false;
    }
    if bytes.iter().any(|&b| {
        !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'/' | b'='))
    }) {
        return false;
    }

    if looks_like_public_crypto_algorithm_identifier(value)
        || looks_like_public_fixture_identifier(value)
        || looks_like_public_metric_fragment(value)
    {
        return true;
    }

    // Case-insensitive byte scans instead of allocating BOTH an uppercased AND a
    // lowercased copy of every candidate (Law 7). `value` is already constrained
    // to the ASCII alphabet [A-Za-z0-9_-.:/=] by the guard above, so `ci_find`
    // (case-insensitive, pre-lowered needles) is byte-identical to the prior
    // to_ascii_uppercase()/to_ascii_lowercase()-then-contains form. The OR arms
    // all short-circuit to `true`, so reordering the upper/lower checks into one
    // pass does not change the boolean result.
    use crate::ascii_ci::{ci_find, starts_with_ignore_ascii_case};
    if ci_find(bytes, b"cwe_")
        || ci_find(bytes, b"rfc_")
        || ci_find(bytes, b"owasp_")
        || ci_find(bytes, b"nist_")
        || ci_find(bytes, b"cisa_")
    {
        return true;
    }
    if ci_find(bytes, b"-issue-") || ci_find(bytes, b"_issue_") {
        return true;
    }
    if looks_like_caesar_shifted_public_issue_reference(value) {
        return true;
    }

    if ci_find(bytes, b"gate-evidence-consumption")
        || ci_find(bytes, b"authority-attestation")
        || ci_find(bytes, b"authority-elimination")
        || ci_find(bytes, b"authority-map")
        || (ci_find(bytes, b"dead-pass")
            && ci_find(bytes, b"capability")
            && ci_find(bytes, b"transform"))
    {
        return true;
    }
    ci_find(bytes, b"row-range-vx-")
        || ci_find(bytes, b"through-vx-")
        || (starts_with_ignore_ascii_case(bytes, b"pw.") && bytes.contains(&b'-'))
}

fn looks_like_public_crypto_algorithm_identifier(value: &str) -> bool {
    // Case-insensitive exact match without allocating a lowercased copy (Law 7).
    // `eq_ignore_ascii_case` is byte-identical to the prior
    // `value.to_ascii_lowercase().as_str() == <lowercase literal>` form.
    ALGORITHMS
        .iter()
        .any(|algo| value.eq_ignore_ascii_case(algo.as_str()))
}

fn looks_like_public_fixture_identifier(value: &str) -> bool {
    // Zero-alloc: the `-fixture` suffix is a case-insensitive byte compare and
    // the `-` presence is case-irrelevant, so neither needs the prior
    // `value.to_ascii_lowercase()` allocation (Law 7). The rest of the function
    // already reads `value`, not the lowered copy.
    let bytes = value.as_bytes();
    if !crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b"-fixture") || !bytes.contains(&b'-') {
        return false;
    }
    let mut parts = value.split('-');
    let Some(prefix) = parts.next() else {
        return false;
    };
    if prefix.len() < 2
        || prefix.len() > 8
        || !prefix.as_bytes()[0].is_ascii_uppercase()
        || !prefix.as_bytes()[1..].iter().any(|b| b.is_ascii_digit())
    {
        return false;
    }
    parts.all(|part| {
        !part.is_empty()
            && part.len() <= 24
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    })
}

fn looks_like_public_metric_fragment(value: &str) -> bool {
    let Some((left, right)) = value.split_once(":bytes=") else {
        return false;
    };
    !left.is_empty()
        && left.len() <= 6
        && !right.is_empty()
        && right.len() <= 12
        && left.bytes().all(|b| b.is_ascii_digit())
        && right.bytes().all(|b| b.is_ascii_digit())
}

fn looks_like_caesar_shifted_public_issue_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    let lower = bytes.iter().filter(|b| b.is_ascii_lowercase()).count();
    let hyphens = bytes.iter().filter(|&&b| b == b'-').count();
    if lower < 16 || hyphens < 2 {
        return false;
    }
    bytes.windows(6).any(|window| {
        window[0].is_ascii_uppercase()
            && window[1].is_ascii_uppercase()
            && window[2] == b'-'
            && window[3].is_ascii_digit()
            && window[4].is_ascii_digit()
            && window[5].is_ascii_digit()
    })
}

/// Public source/doc/build artifact references often get concatenated by
/// markdown/TOML extraction into dense strings (`src/foo.rs:1-3docs/bar.md`).
pub(crate) fn looks_like_public_artifact_reference_with_randomness(
    value: &str,
    randomness: &TokenRandomness<'_>,
) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 8 || bytes.len() > 360 {
        return false;
    }
    if bytes
        .iter()
        .any(|&b| b < 0x20 || b == 0x7f || matches!(b, b'\'' | b'"'))
    {
        return false;
    }

    use crate::ascii_ci::{ci_find, ci_find_at, ends_with_ignore_ascii_case};

    // Single guided pass over the value per extension: derive the total hit
    // count AND the filename-shape verdict from the same scan (each extension's
    // occurrences are found once, not recomputed by a separate `ci_find_at`).
    let mut extension_hits = 0usize;
    let mut filename_shape = false;
    for extension in EXTENSIONS.iter() {
        let ext = extension.as_bytes();
        let mut first_idx = None;
        let mut start = 0usize;
        while start + ext.len() <= bytes.len() {
            let Some(rel) = ci_find_at(&bytes[start..], ext) else {
                break;
            };
            let idx = start + rel;
            first_idx.get_or_insert(idx);
            extension_hits += 1;
            start = idx + ext.len();
        }
        if filename_shape {
            continue;
        }
        if ends_with_ignore_ascii_case(bytes, ext) {
            filename_shape = true;
            continue;
        }
        if let Some(idx) = first_idx {
            let after = &value[idx + ext.len()..];
            if after.is_empty() {
                continue;
            }
            if after.len() <= 16
                && after
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                filename_shape = true;
                continue;
            }
            if let Some(prose_suffix) = after.strip_prefix('-') {
                let mut parts = 0usize;
                let prose_ok = prose_suffix.split('-').all(|part| {
                    if part.is_empty()
                        || part.len() > 24
                        || !part.bytes().all(|b| b.is_ascii_lowercase())
                    {
                        return false;
                    }
                    parts += 1;
                    true
                }) && parts >= 3
                    && !randomness.is_random_token(prose_suffix);
                if prose_ok {
                    filename_shape = true;
                }
            }
        }
    }
    if extension_hits == 0 {
        return false;
    }

    let has_path_or_build_marker = bytes.contains(&b'/')
        || bytes.contains(&b'\\')
        || ci_find(bytes, b"$out_dir")
        || ci_find(bytes, b"src")
        || ci_find(bytes, b"docs")
        || ci_find(bytes, b"tests")
        || ci_find(bytes, b"target")
        || ci_find(bytes, b"#[")
        || ci_find(bytes, b"#!");
    let has_line_marker = ci_find(bytes, b":{") || bytes.contains(&b':') && bytes.contains(&b'-');
    let has_multiple_artifacts = extension_hits >= 2;
    let has_public_filename_shape = filename_shape && (value.contains('_') || value.contains('-'));

    has_path_or_build_marker
        || has_line_marker
        || has_multiple_artifacts
        || has_public_filename_shape
}

/// Shell/template values are assembled at runtime. The generic bridge may see
/// either the full `${VAR}` / `$(cmd)` form or a regex-truncated prefix ending
/// in `$`; both are source templates, not literal credentials.
pub(crate) fn looks_like_shell_template_value_with_randomness(
    value: &str,
    randomness: &TokenRandomness<'_>,
) -> bool {
    if value.contains("${") || value.contains("$(") {
        return true;
    }
    let Some(prefix) = value.strip_suffix('$') else {
        return false;
    };
    let prefix = prefix.trim_end_matches('-');
    if prefix.len() < 8 || prefix.len() > 80 || !prefix.contains('-') {
        return false;
    }
    if !prefix.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-') {
        return false;
    }
    let mut part_count = 0usize;
    for part in prefix.split('-') {
        if part.is_empty() || part.len() > 18 {
            return false;
        }
        part_count += 1;
    }
    part_count >= 2 && !randomness.is_random_token(prefix)
}

/// URL-encoded markup/XSS probes (`%3Cscript%3E`, double-encoded
/// `%253Cscript%253E`, etc.) are payload examples, not credentials.
pub(crate) fn looks_like_percent_encoded_markup(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 8 || !bytes.contains(&b'%') {
        return false;
    }
    let has_encoded_open = crate::ascii_ci::ci_find(bytes, b"%3c")
        || crate::ascii_ci::ci_find(bytes, b"%253c")
        || crate::ascii_ci::ci_find(bytes, b"%26lt%3b");
    let has_encoded_close = crate::ascii_ci::ci_find(bytes, b"%3e")
        || crate::ascii_ci::ci_find(bytes, b"%253e")
        || crate::ascii_ci::ci_find(bytes, b"%26gt%3b");
    if !(has_encoded_open && has_encoded_close) {
        return false;
    }
    [
        b"script".as_slice(),
        b"iframe".as_slice(),
        b"svg".as_slice(),
        b"img".as_slice(),
        b"onerror".as_slice(),
        b"onfocus".as_slice(),
        b"onclick".as_slice(),
    ]
    .iter()
    .any(|needle| crate::ascii_ci::ci_find(bytes, needle))
}

/// HTML event-handler attribute fragments such as `onfocus=` are executable
/// payload grammar, not secret material.
pub(crate) fn looks_like_html_event_handler_fragment(value: &str) -> bool {
    let Some(event) = value.strip_suffix('=') else {
        return false;
    };
    if event.len() < 5 || event.len() > 24 || !event.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    HTML_EVENTS
        .iter()
        .any(|known| event.eq_ignore_ascii_case(known.as_str()))
}

#[cfg(test)]
mod artifact_reference_tests {
    use super::looks_like_public_artifact_reference_with_randomness;
    use crate::suppression::token_randomness::TokenRandomness;

    fn is_artifact(value: &str) -> bool {
        let randomness = TokenRandomness::for_candidate(value);
        looks_like_public_artifact_reference_with_randomness(value, &randomness)
    }

    #[test]
    fn single_pass_shape_detection_matches_expected() {
        // Two artifacts + a path marker (single guided pass counts both hits).
        assert!(is_artifact("src/foo.rs:1-3docs/bar.md"));
        // Single filename shape with an underscore, no other marker.
        assert!(is_artifact("my_module.rs"));
        // No extension at all => the extension_hits==0 guard rejects it even
        // though it is otherwise opaque.
        assert!(!is_artifact("AKIAIOSFODNN7EXAMPLE"));
    }
}
