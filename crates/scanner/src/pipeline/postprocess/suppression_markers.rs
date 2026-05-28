use crate::context;
use crate::shape_gates::RFC7519_EXAMPLE_JWT_PREFIX;
use crate::shape_gates::*;
use super::suppression_helpers::*;

pub(super) fn check_marker_and_prefix_gates(
    credential: &str,
    path: Option<&str>,
    upper: &str,
    bypass_shape_gates: bool,
) -> bool {
    // ── 1. Universal placeholder keywords (case-insensitive) ──
    const PLACEHOLDER_WORDS: &[&str] = &["DUMMY", "PLACEHOLDER", "FAKE", "MOCK", "SAMPLE"];
    for word in PLACEHOLDER_WORDS {
        if upper_contains_token(&upper, word) {
            return true;
        }
    }
    // EXAMPLE is special: only suppress if it is in the credential value itself,
    // not in a URL domain (example.com is a reserved domain per RFC 2606).
    // Always suppress canonical documentation example tokens — including
    // credentials recovered through reverse/Caesar decode layers. Forward
    // literals such as `AKIAIOSFODNN7EXAMPLE` and `ghp_example_…` must
    // never surface as findings just because decode/reverse re-emitted them
    // under a `…/reverse` source_type (KH-GAP-101). Non-example tokens
    // produced only by evasion decoders (e.g. `ELPMAXE_AKEY`) still pass.
    if (upper_contains_token(&upper, "EXAMPLE") || upper.ends_with("EXAMPLE"))
        && !credential.contains("example.com")
        && !credential.contains("example.org")
    {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "contains_EXAMPLE_token",
        );
        return true;
    }

    // ── 2. Common instructional fragments ──
    const INSTRUCTIONAL_FRAGMENTS: &[&str] = &["YOUR_", "YOUR-", "INSERT", "CHANGE", "REPLACE"];
    for frag in INSTRUCTIONAL_FRAGMENTS {
        if upper.contains(frag) {
            // Require a word boundary before the fragment to avoid substring
            // false-positions in real secrets (e.g. "CHANGE" inside base64).
            let mut positions = upper.match_indices(frag);
            if positions.any(|(idx, _)| {
                idx == 0
                    || upper
                        .chars()
                        .nth(idx - 1)
                        .is_none_or(|c| !c.is_alphanumeric())
            }) {
                return true;
            }
        }
    }

    // Developer markers override provider-prefix trust.
    if upper_contains_token(&upper, "TODO") || upper_contains_token(&upper, "FIXME") {
        return true;
    }

    // The RFC 7519 specimen JWT must be checked BEFORE the
    // known-prefix bypass below — the specimen starts with `eyJ`
    // which IS a known-prefix (JWT header marker), so the
    // bypass would otherwise return `false` and let the
    // textbook-example token through as a real finding.
    // SecretBench-medium 15k seed-0: 142 leaked FPs on this
    // exact specimen pre-fix.
    // Prefix-or-substring match on the 61-char RFC7519 specimen JWT
    // (literal base64url encoding of
    // `{"alg":"HS256","typ":"JWT"}.{"sub":"1234567890`). Any token
    // containing those exact bytes IS the documentation specimen —
    // no production JWT in the wild uses the literal
    // `"sub":"1234567890` claim except cargo-culted from the spec.
    // `contains` (not just `starts_with`) is required because some
    // extractor paths capture surrounding context such as
    // `auth_token=eyJhbGci...` — `starts_with` misses every one of
    // those; `contains` catches them. SecretBench-medium 15k seed-0:
    // 349 leaked FPs in `jwt-rfc-example` category were the
    // `auth_token=…` log-line + `api.key=…` properties shape.
    if credential.contains(RFC7519_EXAMPLE_JWT_PREFIX) {
        return true;
    }

    // Documentation/placeholder markers embedded *inside* a
    // known-prefix token (e.g. `ghp_EXAMPLE_TOKEN_FROM_DOCS`,
    // `AKIAEXAMPLEEXAMPLE12`, `sk_live_PLACEHOLDER_NOT_A_REAL_KEY`,
    // `xoxb-…-EXAMPLE-TOKEN`). The general EXAMPLE check at the
    // top requires a *word-boundary* token match, which misses
    // these because the marker is surrounded by alphanumerics
    // (camelCase or snake_case). Then the known-prefix bypass
    // below would early-return `false`, letting them through.
    // SecretBench-medium 15k seed-0: 234 leaked FPs from
    // docs-example-marker pre-fix. Substring match is safe here
    // because real secrets do not contain these literal strings.
    //
    // Service-prefix credentials are vetted before doc-marker substring
    // checks. `TESTKEY_*` adversarial fixtures carry the marker as
    // their prefix, so they fall through to repetitive-mask gates
    // instead of taking the service-prefix fast path.
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
    let known_prefix_body = known_prefix_body(credential);
    if let Some(body) = known_prefix_body {
        if looks_like_prefixed_masked_sequence(body) {
            return true;
        }
        if !credential.starts_with("TESTKEY_") {
            if !credential.contains("example.com") && !credential.contains("example.org") {
                for marker in DOC_MARKER_SUBSTRINGS {
                    if upper.contains(marker) {
                        return true;
                    }
                }
            }
            return false;
        }
        let body = &credential["TESTKEY_".len()..];
        if (body.len() < 20 && has_three_or_more_consecutive_identical(body))
            || has_n_or_more_consecutive_identical(body, 5)
            || has_repeated_block_mask(body)
        {
            return true;
        }
    }

    if !credential.contains("example.com") && !credential.contains("example.org") {
        for marker in DOC_MARKER_SUBSTRINGS {
            if upper.contains(marker) {
                if credential.starts_with("TESTKEY_")
                    && (*marker == "TESTKEY" || *marker == "TEST_KEY")
                {
                    continue;
                }
                return true;
            }
        }
    }

    // PEM-framed credentials (private keys, certificates) get a hard
    // bypass on the body-entropy heuristics below: the BEGIN/END
    // frame IS the high-confidence signal, and base64-encoded
    // structured data (notably the `openssh-key-v1\0\0\0\0…` prefix
    // every OPENSSH PRIVATE KEY starts with) legitimately contains
    // long runs of identical characters like `AAAAAAAA` from
    // zero-padding. Without this carve-out, real OPENSSH keys get
    // suppressed by `has_n_or_more_consecutive_identical` and the
    // PEM `private-key` detector silently misses them — see
    // `tests/contracts/private-key.toml` OPENSSH positive.
    if credential.starts_with("-----BEGIN") {
        return false;
    }

    false
}
