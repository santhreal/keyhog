//! Doc / placeholder / instructional marker substring scans. Extracted
//! from `should_suppress_inner` so documentation-marker handling has one
//! focused boundary. Returns a tri-state verdict that the decision tree consumes
//! verbatim - `Allow` means "this is a known
//! service-prefixed token, do NOT suppress and skip the shape gates";
//! `Suppress` means "this is a documentation specimen, suppress now";
//! `KeepChecking` means "fall through to the rest of the decision tree".

use super::shape::{looks_like_prefixed_masked_sequence, RFC7519_EXAMPLE_JWT_PREFIX};

fn record_marker_suppression(path: Option<&str>, credential: &str, reason: &'static str) {
    crate::adjudicate::record_stage_suppression(
        path,
        credential,
        crate::adjudicate::StageId::ShapeGate(reason),
    );
}

/// Outcome of the doc/placeholder/marker pre-checks.
pub(super) enum MarkerVerdict {
    /// The credential matched a documentation marker or known FP shape -
    /// the caller should return `true` (suppress) immediately.
    Suppress,
    /// The credential is a known service-prefixed token (e.g. `ghp_…`,
    /// `AKIA…`) whose body does NOT match a masked-sequence shape. The
    /// caller should return `false` immediately - the prefix is positive
    /// evidence and downstream shape gates would generate FPs.
    Allow,
    /// No marker matched. The caller should continue with the remaining
    /// suppression checks (PEM, repetitive masking, hash/UUID, etc.).
    KeepChecking,
}

/// Case-insensitive word-boundary token-contains. The previous implementation
/// mixed byte- and char-indexing (`upper.chars().nth(byte_idx - 1)`) which,
/// for any credential containing non-ASCII bytes before the match, returned
/// the wrong character and silently let placeholder tokens slip past. ASCII
/// inputs happened to work because `byte_idx == char_idx` for pure ASCII.
pub(super) fn upper_contains_token(upper: &str, token: &str) -> bool {
    upper.match_indices(token).any(|(idx, _)| {
        let before = upper[..idx].chars().next_back();
        let after = upper[idx + token.len()..].chars().next();
        before.is_none_or(|c| !c.is_alphanumeric()) && after.is_none_or(|c| !c.is_alphanumeric())
    })
}

/// Run the doc/placeholder/marker pre-checks against `credential`. Caller
/// passes `upper` (already uppercased credential) to avoid re-allocating
/// and `from_evasion_decoder` so EXAMPLE-suppression can be skipped when
/// the value arrived through `/reverse` or `/caesar` (those are
/// adversarial decoders - an EXAMPLE marker in their output IS evidence
/// of a real leak, not a documentation specimen).
pub(super) fn check_markers(
    credential: &str,
    upper: &str,
    from_evasion_decoder: bool,
    path: Option<&str>,
    entropy_hint: Option<f64>,
) -> MarkerVerdict {
    // ── 1. Universal placeholder keywords (case-insensitive) ──
    if crate::placeholder_words::contains_non_example_placeholder_word_with_entropy_hint(
        credential,
        upper,
        entropy_hint,
    ) {
        record_marker_suppression(path, credential, "placeholder_word");
        return MarkerVerdict::Suppress;
    }
    // EXAMPLE is special: only suppress if it is in the credential value itself,
    // not in a URL domain (example.com is a reserved domain per RFC 2606).
    // Skip entirely when the credential arrived through an evasion decoder
    // (see fn-doc): an attacker reversing/ROTating an EXAMPLE-suffixed AWS
    // test key is exactly the kind of leak the engine should report.
    if let Some(example) = crate::placeholder_words::example_word() {
        if !from_evasion_decoder
            && (upper_contains_token(upper, example.upper())
                || upper.ends_with(example.upper())
                || upper_contains_token(upper, "EXAMPLEKEY")
                || upper.ends_with("EXAMPLEKEY"))
            && !credential.contains("example.com")
            && !credential.contains("example.org")
        {
            crate::telemetry::record_example_suppression(
                "pipeline",
                path,
                credential,
                "contains_EXAMPLE_token",
            );
            return MarkerVerdict::Suppress;
        }
    }

    // ── 2. Common instructional fragments ──
    const INSTRUCTIONAL_FRAGMENTS: &[&str] = &["YOUR_", "YOUR-", "INSERT", "CHANGE", "REPLACE"];
    for frag in INSTRUCTIONAL_FRAGMENTS {
        if upper.contains(frag) {
            // Require a word boundary before the fragment to avoid substring
            // false-positions in real secrets (e.g. "CHANGE" inside base64).
            // `match_indices` yields BYTE offsets, so the preceding character
            // must be read on a byte boundary (`upper[..idx].chars().next_back()`)
            // rather than via `chars().nth(idx - 1)` (a CHAR index): mixing the
            // two mis-reads the boundary char for any credential with a
            // multibyte char before the match - the same bug the module header
            // documents and `upper_contains_token` already avoids. Only the
            // *leading* boundary is checked here (instructional fragments like
            // `YOUR_API`, `CHANGEME`, `INSERTKEY` are normally followed by
            // alphanumerics, so a trailing-boundary requirement would miss them).
            let mut positions = upper.match_indices(frag);
            if positions.any(|(idx, _)| {
                upper[..idx]
                    .chars()
                    .next_back()
                    .is_none_or(|c| !c.is_alphanumeric())
            }) {
                record_marker_suppression(path, credential, "instructional_fragment");
                return MarkerVerdict::Suppress;
            }
        }
    }

    // Developer markers override provider-prefix trust.
    if upper_contains_token(upper, "TODO") || upper_contains_token(upper, "FIXME") {
        record_marker_suppression(path, credential, "dev_marker_todo_fixme");
        return MarkerVerdict::Suppress;
    }

    // The RFC 7519 specimen JWT must be checked BEFORE the
    // known-prefix bypass below - the specimen starts with `eyJ`
    // which IS a known-prefix (JWT header marker), so the
    // bypass would otherwise return Allow and let the
    // textbook-example token through as a real finding.
    // SecretBench-medium 15k seed-0: 142 leaked FPs on this
    // exact specimen pre-fix.
    // Prefix-or-substring match on the 61-char RFC7519 specimen JWT
    // (literal base64url encoding of
    // `{"alg":"HS256","typ":"JWT"}.{"sub":"1234567890`). Any token
    // containing those exact bytes IS the documentation specimen -
    // no production JWT in the wild uses the literal
    // `"sub":"1234567890` claim except cargo-culted from the spec.
    // `contains` (not just `starts_with`) is required because some
    // extractor paths capture surrounding context such as
    // `auth_token=eyJhbGci...` - `starts_with` misses every one of
    // those; `contains` catches them. SecretBench-medium 15k seed-0:
    // 349 leaked FPs in `jwt-rfc-example` category were the
    // `auth_token=…` log-line + `api.key=…` properties shape.
    if credential.contains(RFC7519_EXAMPLE_JWT_PREFIX) {
        record_marker_suppression(path, credential, "rfc7519_example_jwt");
        return MarkerVerdict::Suppress;
    }

    // Documentation/placeholder markers embedded *inside* a
    // known-prefix token (e.g. `ghp_EXAMPLE_TOKEN_FROM_DOCS`,
    // `AKIAEXAMPLEEXAMPLE12`, `sk_live_PLACEHOLDER_NOT_A_REAL_KEY`,
    // `xoxb-…-EXAMPLE-TOKEN`). The general EXAMPLE check at the
    // top requires a *word-boundary* token match, which misses
    // these because the marker is surrounded by alphanumerics
    // (camelCase or snake_case). This substring scan MUST run
    // BEFORE the known-prefix Allow fast-path below: otherwise a
    // doc marker buried inside a service-prefixed token would gain
    // immunity from the substring scan and leak through as a real
    // finding. SecretBench-medium 15k seed-0: 234 leaked FPs from
    // docs-example-marker pre-fix (145 of them this exact ordering
    // bug). Substring match is safe here because real secrets do
    // not contain these literal strings.
    //
    // `TESTKEY_*` adversarial fixtures carry the marker as their
    // prefix, so the `TESTKEY`/`TEST_KEY` markers are skipped for
    // them - they fall through to repetitive-mask gates instead.
    const DOC_MARKER_SUBSTRINGS: &[&str] = &[
        "EXAMPLE",
        "PLACEHOLDER",
        "NOT_A_REAL",
        "NOTAREAL",
        "INSERT_TOKEN_HERE",
        "INSERT-TOKEN-HERE",
        "CHANGE-ME",
        "CHANGEME",
        "REPLACE_ME",
        "REPLACEME",
        "REDACTED",
        "FAKE_KEY",
        "FAKEKEY",
        "TEST_KEY",
        "TESTKEY",
        "SAMPLE_KEY",
        "SAMPLEKEY",
    ];
    if !from_evasion_decoder
        && !credential.contains("example.com")
        && !credential.contains("example.org")
    {
        for marker in DOC_MARKER_SUBSTRINGS {
            if upper.contains(marker) {
                if credential.starts_with("TESTKEY_")
                    && (*marker == "TESTKEY" || *marker == "TEST_KEY")
                {
                    continue;
                }
                record_marker_suppression(path, credential, "doc_marker_substring");
                return MarkerVerdict::Suppress;
            }
        }
    }

    // Known-prefix Allow fast-path. Runs AFTER the doc-marker substring
    // scan above so a marker buried inside a service-prefixed token
    // (`AKIAEXAMPLEEXAMPLE12`, `ghp_EXAMPLE_TOKEN_FROM_DOCS`) suppresses
    // first and never reaches this Allow. A clean known-prefix token whose
    // body does NOT match a masked-sequence shape is positive evidence -
    // downstream shape gates would only generate FPs, so we return early.
    // `TESTKEY_*` adversarial fixtures must not take this fast path; they
    // fall through to the repetitive-mask gates in the decision tree.
    let known_prefix_body = crate::confidence::known_prefix_body(credential);
    if let Some(body) = known_prefix_body {
        if looks_like_prefixed_masked_sequence(body) {
            record_marker_suppression(path, credential, "prefixed_masked_sequence");
            return MarkerVerdict::Suppress;
        }
        if !credential.starts_with("TESTKEY_") {
            return MarkerVerdict::Allow;
        }
    }

    MarkerVerdict::KeepChecking
}
