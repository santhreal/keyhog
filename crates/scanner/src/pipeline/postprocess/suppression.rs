use super::shape_gates::RFC7519_EXAMPLE_JWT_PREFIX;
use super::shape_gates::*;
use crate::context;

fn upper_contains_token(upper: &str, token: &str) -> bool {
    upper.match_indices(token).any(|(idx, _)| {
        // `idx` is a BYTE index from `match_indices`; use byte-index slicing
        // for both sides. The previous `upper.chars().nth(idx - 1)` mixed
        // byte- and char-indexing — for any credential with non-ASCII bytes
        // before `idx`, `nth(byte_idx - 1)` returned the wrong character
        // (sometimes a character INSIDE the match), miscomputing the
        // word-boundary check and silently letting placeholder tokens slip
        // past the suppression. ASCII inputs happened to work because
        // byte_idx == char_idx for pure ASCII.
        let before = upper[..idx].chars().next_back();
        let after = upper[idx + token.len()..].chars().next();
        before.is_none_or(|c| !c.is_alphanumeric()) && after.is_none_or(|c| !c.is_alphanumeric())
    })
}

/// Check if a credential should be suppressed (e.g., if it is a known example token).
pub fn should_suppress_known_example_credential(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
) -> bool {
    should_suppress_known_example_credential_with_source(credential, path, context, None)
}

/// Variant of [`should_suppress_known_example_credential`] that also takes the
/// chunk's `source_type`. When the credential arrived through an
/// **adversarial-evasion decoder** (reverse, Caesar/ROT-N), the EXAMPLE-token
/// suppression is skipped — legitimate test fixtures don't typically reverse
/// or rotate their EXAMPLE markers; only attackers building evasions do, so
/// the marker becomes evidence FOR a real leak rather than against it.
///
/// Other decoders (base64, hex, URL) decode legitimate transport encodings
/// where EXAMPLE-suppression remains appropriate, so we don't blanket-bypass
/// the rule on every decoder origin.
pub fn should_suppress_known_example_credential_with_source(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
) -> bool {
    should_suppress_inner(credential, path, context, source_type, false, false)
}

/// Variant for named-detector findings that have already matched a
/// service-specific anchor (e.g. `ALGOLIA_ADMIN_KEY=<32hex>`). When set,
/// the shape-based gates (pure-hash-digest, UUID, b64-blob, dashed-serial,
/// hex-uniformity) are bypassed because the regex anchor IS the positive
/// evidence — a 32-hex value after `ALGOLIA_ADMIN_KEY=` is an Algolia key,
/// NOT an MD5. Use ONLY from detector paths whose regex requires a
/// service-keyword anchor in the alternation list.
pub fn should_suppress_named_detector_finding(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
    detector_id: &str,
) -> bool {
    // Generic-password / generic-secret FP on C/Rust function call
    // shapes. The TOML regex for generic-password (and similar generic
    // assignment-shape detectors) captures `[a-zA-Z0-9_-]{12,80}` after
    // a `_pwd = ` / `password: ` match. In source code that captures
    // function names like `sk_SRP_user_pwd_new_null` (openssl srp_vfy.c)
    // because the regex stops at `(`. Pure alphanumeric+underscore
    // captures with NO digit and 2+ underscores are C-identifier-shaped,
    // not passwords. Real passwords almost always have digits, special
    // chars, or are not so heavily underscored.
    //
    // Limit to generic-* and entropy-* detectors so service-anchored
    // detectors (which already have provider-specific shape gates) keep
    // their existing behaviour.
    if (detector_id.starts_with("generic-") || detector_id.starts_with("entropy-"))
        && looks_like_pure_identifier(credential)
    {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "pure_identifier_no_digit",
        );
        return true;
    }
    // Generic detectors (generic-secret, generic-private-key, entropy-*)
    // never use this bypass — their anchor is keyword-class, not
    // service-specific, and shape gates are load-bearing for them.
    let bypass_shape_gates = !detector_id.starts_with("generic-")
        && !detector_id.starts_with("entropy-")
        && detector_id != "private-key";
    should_suppress_inner(
        credential,
        path,
        context,
        source_type,
        false,
        bypass_shape_gates,
    )
}

/// True if `credential` is an identifier / natural-language shape rather
/// than a real credential. Covers three FP families seen in dogfood:
///   * snake_case-no-digit (≥ 2 underscores) — C/Rust function names like
///     `sk_SRP_user_pwd_new_null` (openssl) captured by `_pwd = ` regexes.
///   * CamelCase-no-digit alphabetic — Java/JS method references like
///     `getParameter` captured by `password = getParameter(...)` shapes
///     (webgoat WebgoatContext.java, line 93).
///   * Pure-alphabetic words ≥ 8 chars — natural-language strings like
///     German "Benutzername" or English "yourpasswordisbasic" captured
///     by `(?i)password[=:]<word>` shapes in i18n .properties files.
/// Real credentials almost always have a digit, hyphen, slash, or other
/// non-letter byte — this filter never trips on those.
pub(crate) fn looks_like_pure_identifier(credential: &str) -> bool {
    let bytes = credential.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut underscore_count = 0usize;
    let mut hyphen_count = 0usize;
    let mut has_digit = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut alpha_count = 0usize;
    for &b in bytes {
        if b == b'_' {
            underscore_count += 1;
        } else if b == b'-' {
            hyphen_count += 1;
        } else if b.is_ascii_digit() {
            has_digit = true;
        } else if b.is_ascii_uppercase() {
            has_upper = true;
            alpha_count += 1;
        } else if b.is_ascii_lowercase() {
            has_lower = true;
            alpha_count += 1;
        } else {
            // Any byte outside `[A-Za-z0-9_-]` means this is NOT a
            // pure identifier: real credentials reach here through `!`,
            // `=`, `/`, `+`, `:`, etc. in the value alphabet.
            return false;
        }
    }
    if has_digit {
        return false;
    }
    // snake_case_no_digit: ≥ 2 underscores. Covers `sk_SRP_user_pwd_new_null`
    // (openssl), `auth_decoders`, `gss_token`-style C/Rust identifiers.
    if underscore_count >= 2 {
        return true;
    }
    // CamelCase / pure-alphabetic / single-separator identifier: bytes
    // are all `[A-Za-z_-]` (no digit), length 8..=40, ≤ 1 underscore,
    // ≤ 1 hyphen, ≥ 8 alphabetic characters. Covers:
    //   * `getParameter`, `Benutzername` — pure alphabetic CamelCase
    //     or natural-language word
    //   * `curlx_strdup`, `auth_decoders` — single-underscore C names
    //   * `user-password`, `aria-secret`, `Get-Function` — kebab-case
    //     / PowerShell verb-noun identifiers
    // Bounded above 40 so a real long random alpha-only credential
    // (rare) isn't suppressed. Real credentials have at least one
    // digit / symbol — none of the FP shapes do.
    if (underscore_count + hyphen_count) <= 1
        && alpha_count >= 8
        && alpha_count <= 40
        && (has_upper || has_lower)
    {
        return true;
    }
    false
}

fn should_suppress_inner(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
    skip_b64_decode_recheck: bool,
    bypass_shape_gates: bool,
) -> bool {
    let from_evasion_decoder =
        source_type.is_some_and(|s| s.contains("/reverse") || s.contains("/caesar"));
    let upper = credential.to_uppercase();

    // ── 1. Universal placeholder keywords (case-insensitive) ──
    const PLACEHOLDER_WORDS: &[&str] = &["DUMMY", "PLACEHOLDER", "FAKE", "MOCK", "SAMPLE"];
    for word in PLACEHOLDER_WORDS {
        if upper_contains_token(&upper, word) {
            return true;
        }
    }
    // EXAMPLE is special: only suppress if it is in the credential value itself,
    // not in a URL domain (example.com is a reserved domain per RFC 2606).
    // Skip entirely when the credential arrived through an evasion decoder
    // (see fn-doc): an attacker reversing/ROTating an EXAMPLE-suffixed AWS
    // test key is exactly the kind of leak the engine should report.
    if !from_evasion_decoder
        && (upper_contains_token(&upper, "EXAMPLE") || upper.ends_with("EXAMPLE"))
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
    let known_prefix_body = known_prefix_body(credential);
    if let Some(body) = known_prefix_body {
        if looks_like_prefixed_masked_sequence(body) {
            return true;
        }
        if !credential.starts_with("TESTKEY_") {
            return false;
        }
    }

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

    // ── 3. Repetitive masking patterns ──
    // These all gate on !bypass_shape_gates: a named detector whose
    // regex specifically requested e.g. `[A-Z0-9]{5,10}` for a
    // Paylocity company ID has already vetted that the credential
    // shape is real; suppressing `AAA12345` on a "three identical
    // leading chars" heuristic silently drops the company ID for
    // any tenant whose ID starts with a triple. Kimi-suppress
    // findings #2-5. Generic / entropy detectors (bypass_shape_gates
    // = false) keep the gates because their anchor is keyword-class,
    // not vendor-fingerprint, and the masks DO catch real noise on
    // those paths.
    // 5+ consecutive 'x' or 'X' (e.g., xxxxx, XXXXXXX) — masks and placeholders.
    // 3x can appear in real base64/hex, so only suppress longer runs.
    if !bypass_shape_gates && upper.contains("XXXXX") {
        return true;
    }
    // 5+ consecutive identical characters in any credential, or 3+ in short credentials.
    // Real secrets can have short runs (e.g., "000" in base64) but rarely 5+.
    if !bypass_shape_gates
        && credential.len() < 20
        && has_three_or_more_consecutive_identical(credential)
    {
        return true;
    }
    if !bypass_shape_gates && has_n_or_more_consecutive_identical(credential, 5) {
        return true;
    }
    if !bypass_shape_gates && has_repeated_block_mask(credential) {
        return true;
    }
    // Entirely filler symbols
    if !bypass_shape_gates
        && credential
            .chars()
            .all(|c| c == 'x' || c == 'X' || c == '*' || c == '-' || c == '.')
    {
        return true;
    }
    // Purely symbolic strings that look like filler/placeholder
    // (e.g., "********", "--------") — NOT real passwords like "!@#$%^&*()"
    // Check for ≤2 unique chars without heap allocation.
    if !bypass_shape_gates
        && credential.len() >= 8
        && credential.chars().all(|c| !c.is_alphanumeric())
    {
        let bytes = credential.as_bytes();
        let first = bytes[0];
        let mut second = first;
        let mut distinct = 1u32;
        for &b in &bytes[1..] {
            if b != first && b != second {
                distinct += 1;
                if distinct > 2 {
                    break;
                }
                second = b;
            }
        }
        if distinct <= 2 {
            return true;
        }
    }

    // ── 4. Known fake sequences ──
    // Only suppress if the fake sequence is a DOMINANT part of the credential
    // (>50% of the non-prefix content). Substring matches in long credentials
    // produce false suppressions on real secrets.
    const FAKE_SEQUENCES: &[&str] = &["1234567890", "0123456789", "ABCDEFGH", "ABCDEFGHIJ"];
    for seq in FAKE_SEQUENCES {
        if upper.contains(seq) {
            // Only suppress short credentials dominated by the fake sequence,
            // not long ones where it's a small substring.
            let seq_ratio = seq.len() as f64 / credential.len().max(1) as f64;
            if seq_ratio > 0.4 {
                return true;
            }
        }
    }

    // ── 5b. Bare hash digest / UUID shape suppression ──
    // Values whose entire body is an MD5 (32-hex), SHA1 (40-hex),
    // SHA256 (64-hex), SHA512 (128-hex) or RFC-4122 UUID-v4
    // (8-4-4-4-12 with version-4 nibble) are almost never secrets in
    // practice — they're git commit IDs, npm-lock integrity hashes,
    // requirements.txt --hash entries, docker image digests, and
    // k8s resource UIDs. Surfaced by the secretbench mirror corpus
    // as the dominant FP class.
    // Known-prefix credentials bypass this (a 64-char hex AWS key
    // shouldn't be filtered) — we already returned `false` above
    // when known_prefix_body matched.
    // Split the old "hash digest OR UUID" gate by *which side* is
    // load-bearing. Both are gated by `bypass_shape_gates` — the
    // comment used to say the hash-digest side was always-on, which
    // contradicted the code (kimi-suppress audit caught the mismatch).
    // The code is correct: gate both, because ~30 named detectors
    // (Algolia 32-hex, New Relic 40-hex, Redis Labs 64-hex, AlienVault
    // OTX, Splunk HEC, Rollbar, etc.) explicitly request pure-hex
    // credentials in their regexes. Suppressing those would tank recall
    // for every hex-shaped service-specific secret.
    //
    //   - Hash digest (32/40/48/56/64/72/128-char uniform hex, plus
    //     `sha256:` / `sha512:` prefixed forms): bench v18 showed
    //     unbounded suppression of bare hex added 3304 FPs
    //     (sha256-hex 1460 + sha1-hex 1027 + git-commit-sha 817) on
    //     generic / entropy detectors. Gate keeps generic FPs out
    //     while letting named hex-anchored detectors fire.
    //
    //   - UUID v4 (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`): Heroku
    //     API key, Cypress record key, the body of many license-server
    //     tokens use UUID v4. A named detector with a service-specific
    //     anchor is positive evidence the UUID is a credential, NOT a
    //     docker image digest or k8s resource ID. Generic / entropy
    //     detectors stay gated because for them a bare UUID is noise.
    //
    // Bench v19 confirmed both gates close the FP regression without
    // losing recall; the contracts_runner test caught the earlier
    // UUID over-suppression that prompted the split.
    if !bypass_shape_gates && looks_like_hash_digest(credential) {
        return true;
    }
    if !bypass_shape_gates && is_uuid_v4_shape(credential) {
        return true;
    }

    // ── 5c. License-key / serial shape: 5 blocks of 5 alnum chars,
    //         dash-separated (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX). Used
    //         by Microsoft Office / Adobe / Atlassian license keys
    //         and a thousand similar product-key surfaces. Real
    //         credentials almost never carry this shape. From
    //         secretbench-medium-15k: 464 FPs (3rd-largest cluster).
    if !bypass_shape_gates && looks_like_dashed_serial_key(credential) {
        return true;
    }

    // ── 5d. The well-known RFC 7519 example JWT (specimen token
    //         from the spec, copy-pasted into thousands of docs).
    //         Conservative literal-prefix match so we don't
    //         accidentally suppress real JWTs that begin with the
    //         same header.
    // Prefix-only match: the 61-char RFC7519_EXAMPLE_JWT_PREFIX is
    // the literal base64url encoding of
    // `{"alg":"HS256","typ":"JWT"}.{"sub":"1234567890`. Any token
    // beginning with those exact bytes IS the documentation
    // specimen — no production JWT in the wild uses the literal
    // `"sub":"1234567890` claim except cargo-culted from the spec.
    // (The previous belt-and-suspenders `contains(signature)`
    // check failed when an upstream regex value-extractor
    // truncated the captured credential before the signature
    // segment — the prefix-only check is sufficient and survives
    // truncation.)
    if credential.starts_with(RFC7519_EXAMPLE_JWT_PREFIX) {
        return true;
    }

    // ── 5e0. Credentials never contain interior whitespace runs.
    //          The dotenv/properties/log-line extractors sometimes
    //          capture the entire RHS as the credential when the
    //          source line is `TOKEN=Session opened with handle
    //          XYZ. See documentation.` — multi-word English
    //          prose with a high-entropy substring is never a
    //          real credential. SecretBench-medium 15k seed-0:
    //          68 FPs from lorem-with-high-entropy.
    if credential.len() > 30 && credential.chars().filter(|c| c.is_whitespace()).count() >= 2 {
        // Cheap English-word sanity check: at least one lowercase
        // alphabetic run of length 3+ between whitespace tokens —
        // characteristic of prose, not credentials.
        let has_word_run = credential
            .split_whitespace()
            .any(|tok| tok.len() >= 3 && tok.chars().all(|c| c.is_ascii_lowercase()));
        if has_word_run {
            return true;
        }
    }

    // ── 5e1. AWS IAM resource ARNs (`arn:aws:iam::ACCT:role/...`,
    //          `:user/`, `:group/`, `:policy/`, `:instance-profile/`)
    //          are identifiers, not credentials — they only name a
    //          resource, they don't authenticate against it.
    //          Other ARN namespaces (e.g. `secretsmanager:*:secret:*`,
    //          `rds:*:cluster:*`) ARE credential REFERENCES that
    //          downstream detectors should keep firing on, so the
    //          gate is intentionally narrow to the IAM namespace.
    //          SecretBench-medium 15k seed-0: 27 FPs from aws-arn
    //          (all IAM role ARNs).
    if (credential.starts_with("arn:aws:iam::")
        || credential.starts_with("arn:aws-cn:iam::")
        || credential.starts_with("arn:aws-us-gov:iam::"))
        && (credential.contains(":role/")
            || credential.contains(":user/")
            || credential.contains(":group/")
            || credential.contains(":policy/")
            || credential.contains(":instance-profile/"))
    {
        return true;
    }

    // ── 5e2. HTML colour codes (`#RRGGBB`, `#RGB`). 6-or-3 hex
    //          digits prefixed by `#`. Real credentials are never
    //          prefixed with `#`. SecretBench-medium 15k seed-0:
    //          22 FPs from html-color.
    if let Some(body) = credential.strip_prefix('#') {
        if (body.len() == 3 || body.len() == 6 || body.len() == 8)
            && body.chars().all(|c| c.is_ascii_hexdigit())
        {
            return true;
        }
    }

    // ── 5e3. Template placeholders wrapped in `{...}`, `<...>`,
    //          `${...}`, `{{...}}`. Real credentials are never
    //          delivered wrapped in brace/angle markers. The
    //          dotenv/yaml extractor sometimes preserves these
    //          wrappers when the placeholder is the entire RHS.
    //          SecretBench-medium 15k seed-0: 41 FPs from
    //          template-placeholder.
    {
        let trimmed = credential.trim();
        let bracketed = (trimmed.starts_with('{') && trimmed.ends_with('}'))
            || (trimmed.starts_with('<') && trimmed.ends_with('>'))
            || (trimmed.starts_with("${") && trimmed.ends_with('}'));
        if bracketed && trimmed.len() <= 80 {
            return true;
        }
    }

    // ── 5f. base64-of-arbitrary-bytes (e.g. protobuf wire dumps,
    //         random binary blobs encoded for transport). Real
    //         credential tokens almost never use standard base64
    //         with `+/` punctuation AND `=` padding AND lack a
    //         known prefix; they're either base64URL (`-_` instead
    //         of `+/`) or pure alphanumeric. SecretBench-medium
    //         15k seed-0: 705 leaked FPs from base64-protobuf
    //         (largest single FP class).
    //
    //         Gate: standard-base64 alphabet only, contains at
    //         least one of `+/`, ends in `=` padding, length ≥ 40,
    //         and is NOT preceded by a known hash-algo label
    //         (already handled above by the prefixed-hash gate).
    //
    //         BYPASS LIST: detectors whose regex anchors on a
    //         service-specific keyword (AWS_SECRET_ACCESS_KEY,
    //         AccountKey=, etc.) carry positive evidence strong
    //         enough that the b64 shape is irrelevant. Those
    //         findings come through `engine/scan.rs` and don't
    //         pass this gate when `bypass_b64_blob_suppression`
    //         is set in the source_type. The default is to apply
    //         the gate (keeps base64-protobuf FP suppression).
    // Named detectors with service-specific anchors bypass the b64-blob
    // gate too (e.g. AWS_SECRET_ACCESS_KEY=<40b64> would otherwise be
    // dropped as a protobuf-shaped blob).
    if !bypass_shape_gates && looks_like_standard_base64_blob(credential) {
        return true;
    }

    // ── 6. Algorithmic placeholder detection ──
    // Credentials dominated by filler after stripping known prefixes.
    if crate::context::is_known_example_credential(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "algorithmic_placeholder",
        );
        return true;
    }

    // ── 7. Context-based suppression for docs/comments ──
    // Only suppress in docs/comments if the credential IS a placeholder word
    // (not if it merely contains one as a substring of a longer value).
    if matches!(
        context,
        context::CodeContext::Documentation | context::CodeContext::Comment
    ) {
        let trimmed = credential.trim_matches(|c: char| !c.is_alphanumeric());
        let trimmed_upper = trimmed.to_uppercase();
        if trimmed_upper == "TOKEN"
            || trimmed_upper == "KEY"
            || trimmed_upper == "SECRET"
            || trimmed_upper == "PASSWORD"
            || trimmed_upper == "API_KEY"
            || trimmed_upper == "API_TOKEN"
            || trimmed_upper == "YOUR_TOKEN"
            || trimmed_upper == "YOUR_API_KEY"
        {
            return true;
        }
    }

    // ── 8. Path-based heuristic ──
    if let Some(path) = path {
        // ASCII case-insensitive segment compare — no per-call lowercase
        // alloc of the full path. Hot path during placeholder rejection.
        let is_example_path = path.split(['/', '\\']).any(|component| {
            component.eq_ignore_ascii_case("example")
                || component.eq_ignore_ascii_case("examples")
                || component.eq_ignore_ascii_case("test")
                || component.eq_ignore_ascii_case("tests")
                || component.eq_ignore_ascii_case("fixture")
                || component.eq_ignore_ascii_case("fixtures")
        });
        if is_example_path && upper_contains_token(&upper, "EXAMPLE") {
            return true;
        }
    }

    // ── 9. Base64-decode-and-recheck ──
    //          Bench fixtures (notably kubernetes-secret-shape yaml in
    //          the SecretBench mirror) wrap placeholder/hash/UUID/ARN
    //          payloads in base64 inside `data:` fields. A k8s-secret
    //          detector match on the outer base64 wrapper bypasses the
    //          inner gates above because the OUTER token is just
    //          opaque base64 — none of the EXAMPLE / PLACEHOLDER /
    //          hash / UUID / IAM-ARN substrings appear in it.
    //          Decoding the wrapper once and re-running the core
    //          suppression on the decoded UTF-8 catches all of them:
    //            • `Z2hwX0VYQU1QTEVfVE9LRU5fRlJPTV9ET0NT`
    //                → `ghp_EXAMPLE_TOKEN_FROM_DOCS` (EXAMPLE marker)
    //            • `YXJuOmF3czppYW06Ojc4MzY2NDQ5MjgxNjpyb2xlL1JlYWRlc...`
    //                → `arn:aws:iam::...:role/ReaderRole` (IAM gate)
    //            • `Y2U3ZWUxZDAtZThiNi00ZDNmLTk2YjAtYmU3YjBiZDdiOGFj`
    //                → uuid v4 shape (UUID gate)
    //            • `MzRiNTIyOWY5NDdlZGZjOTIxMzVlZDNiMWU0MjE1Y2NlNm...`
    //                → 64-char sha256 hex (hash gate)
    //          The `skip_b64_decode_recheck` flag prevents recursion
    //          when called from a previously-decoded payload.
    //          SecretBench-medium 15k seed-0: estimated 3000-5000 of
    //          the 14k FPs come from this exact path.
    if !skip_b64_decode_recheck {
        if let Some(decoded) = try_decode_b64_to_utf8(credential) {
            // Sanity bound: the decoded text must look like a sensible
            // payload (printable, not too long, not empty). Random
            // bytes that happen to base64-decode to UTF-8 of pure
            // garbage shouldn't trigger gates that rely on shape.
            if !decoded.is_empty()
                && decoded.len() <= credential.len()
                && decoded
                    .chars()
                    .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
                && should_suppress_inner(
                    &decoded,
                    path,
                    context,
                    source_type,
                    true,
                    bypass_shape_gates,
                )
            {
                return true;
            }
        }
    }
    false
}

/// Try to decode `credential` as standard or url-safe base64 and
/// return the result as UTF-8 if successful. Returns `None` on any
/// decode failure or non-UTF-8 payload.
///
/// Used by the suppression gate to peek inside base64-wrapped
/// fixtures whose outer shape looks generic but whose decoded
/// content is a known placeholder / hash / ARN / UUID.
fn try_decode_b64_to_utf8(credential: &str) -> Option<String> {
    // Cheap shape gate before paying for the decode allocation.
    // Standard base64 alphabet (`[A-Za-z0-9+/=]`) and url-safe
    // (`[A-Za-z0-9_\-=]`). Length must be ≥ 8 so we don't waste
    // cycles on every 4-char identifier we see.
    if credential.len() < 8 || credential.len() > 4096 {
        return None;
    }
    let valid = credential.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
    });
    if !valid {
        return None;
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    // Try standard, url-safe, and their no-pad variants in order.
    // A no-trait-object array sidesteps the `base64::Engine` non-
    // dyn-compatible trait bound.
    if let Ok(bytes) = STANDARD.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    if let Ok(bytes) = URL_SAFE.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    if let Ok(bytes) = STANDARD_NO_PAD.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    None
}
