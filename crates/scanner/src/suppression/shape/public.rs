/// Public schema/policy identifiers often look like
/// `product-area-contract:v1`. Under keys such as `schema_token` the generic
/// bridge used to report them as credentials; a versioned kebab identifier is a
/// public contract name, not a secret.
pub(crate) fn looks_like_public_version_identifier(value: &str) -> bool {
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
    !crate::suppression::token_randomness::is_random_token(name)
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

/// Public taxonomy / provenance labels used in source ledgers:
/// `official-author-documentation`, `primary-protocol-specification`,
/// `source-available`, etc.
pub(crate) fn looks_like_public_metadata_identifier(value: &str) -> bool {
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
    const PUBLIC_WORDS: &[&str] = &[
        "advisory",
        "api",
        "archive",
        "artifact",
        "author",
        "benchmark",
        "capability",
        "classification",
        "coding",
        "control",
        "dead",
        "documentation",
        "fixture",
        "format",
        "framework",
        "fusion",
        "guidance",
        "guide",
        "handbook",
        "implementation",
        "language",
        "ledger",
        "manual",
        "metadata",
        "mlir",
        "model",
        "official",
        "paper",
        "pass",
        "policy",
        "primary",
        "project",
        "protocol",
        "provenance",
        "public",
        "recommendation",
        "reference",
        "repository",
        "research",
        "security",
        "source",
        "spec",
        "specification",
        "standard",
        "taxonomy",
        "technical",
        "toolchain",
        "transform",
        "vendor",
        "versioning",
        "vulnerability",
        "weakness",
    ];
    let mut parts = 0usize;
    let mut public_parts = 0usize;
    for part in value.split('-') {
        if part.is_empty() || part.len() > 24 {
            return false;
        }
        parts += 1;
        if PUBLIC_WORDS.contains(&part) {
            public_parts += 1;
        }
    }
    parts >= 2 && public_parts >= 1 && !crate::suppression::token_randomness::is_random_token(value)
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

    let upper = value.to_ascii_uppercase();
    if upper.contains("CWE_")
        || upper.contains("RFC_")
        || upper.contains("OWASP_")
        || upper.contains("NIST_")
        || upper.contains("CISA_")
    {
        return true;
    }
    if upper.contains("-ISSUE-") || upper.contains("_ISSUE_") {
        return true;
    }
    if looks_like_caesar_shifted_public_issue_reference(value) {
        return true;
    }

    let lower = value.to_ascii_lowercase();
    if lower.contains("gate-evidence-consumption")
        || lower.contains("authority-attestation")
        || lower.contains("authority-elimination")
        || lower.contains("authority-map")
        || (lower.contains("dead-pass")
            && lower.contains("capability")
            && lower.contains("transform"))
    {
        return true;
    }
    lower.contains("row-range-vx-")
        || lower.contains("through-vx-")
        || (lower.starts_with("pw.") && lower.contains('-'))
}

fn looks_like_public_crypto_algorithm_identifier(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "argon2" | "argon2d" | "argon2i" | "argon2id" | "bcrypt" | "scrypt" | "pbkdf2"
    )
}

fn looks_like_public_fixture_identifier(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if !lower.ends_with("-fixture") || !lower.contains('-') {
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
pub(crate) fn looks_like_public_artifact_reference(value: &str) -> bool {
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

    let lower = value.to_ascii_lowercase();
    const EXTENSIONS: &[&str] = &[
        ".rs", ".md", ".json", ".toml", ".yaml", ".yml", ".c", ".h", ".hpp", ".cpp", ".py", ".go",
        ".ts", ".tsx", ".js", ".jsx", ".sh", ".lock", ".log",
    ];
    let extension_hits: usize = EXTENSIONS
        .iter()
        .map(|extension| lower.matches(extension).count())
        .sum();
    if extension_hits == 0 {
        return false;
    }

    let has_path_or_build_marker = lower.contains('/')
        || lower.contains('\\')
        || lower.contains("$out_dir")
        || lower.contains("src")
        || lower.contains("docs")
        || lower.contains("tests")
        || lower.contains("target")
        || lower.contains("#[")
        || lower.contains("#![");
    let has_line_marker =
        lower.contains(":{") || lower.bytes().any(|b| b == b':') && lower.contains('-');
    let has_multiple_artifacts = extension_hits >= 2;
    let has_public_filename_shape = EXTENSIONS.iter().any(|extension| {
        if lower.ends_with(extension) {
            return true;
        }
        lower.find(extension).is_some_and(|idx| {
            let after = &lower[idx + extension.len()..];
            if after.is_empty() {
                return false;
            }
            if after.len() <= 16
                && after
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return true;
            }
            if let Some(prose_suffix) = after.strip_prefix('-') {
                let mut parts = 0usize;
                return prose_suffix.split('-').all(|part| {
                    if part.is_empty()
                        || part.len() > 24
                        || !part.bytes().all(|b| b.is_ascii_lowercase())
                    {
                        return false;
                    }
                    parts += 1;
                    true
                }) && parts >= 3
                    && !crate::suppression::token_randomness::is_random_token(prose_suffix);
            }
            false
        })
    }) && (value.contains('_') || value.contains('-'));

    has_path_or_build_marker
        || has_line_marker
        || has_multiple_artifacts
        || has_public_filename_shape
}

/// Shell/template values are assembled at runtime. The generic bridge may see
/// either the full `${VAR}` / `$(cmd)` form or a regex-truncated prefix ending
/// in `$`; both are source templates, not literal credentials.
pub(crate) fn looks_like_shell_template_value(value: &str) -> bool {
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
    part_count >= 2 && !crate::suppression::token_randomness::is_random_token(prefix)
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
    const HTML_EVENTS: &[&str] = &[
        "onblur",
        "onchange",
        "onclick",
        "onerror",
        "onfocus",
        "oninput",
        "onkeydown",
        "onkeypress",
        "onkeyup",
        "onload",
        "onmouseover",
        "onsubmit",
    ];
    HTML_EVENTS
        .iter()
        .any(|known| event.eq_ignore_ascii_case(known))
}
