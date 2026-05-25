use crate::context;
use crate::types::*;
use keyhog_core::{Chunk, MatchLocation, RawMatch};
use std::borrow::Cow;
use std::collections::HashMap;

pub fn build_raw_match(
    detector: &keyhog_core::DetectorSpec,
    chunk: &Chunk,
    credential: &str,
    companions: HashMap<String, String>,
    offset: usize,
    line: usize,
    ent: f64,
    confidence: f64,
    scan_state: &mut ScanState,
) -> RawMatch {
    // Diff-aware severity: a credential whose only sighting is in non-HEAD
    // git history (the developer already removed it from `main`) is still
    // a leak — but it's strictly less urgent than a credential live in HEAD
    // that an attacker can grep right now. Drop one tier when the source
    // backend tagged this chunk as `git/history`. Everything else (live
    // filesystem, `git/head`, S3/Docker/Web/etc) keeps the detector's
    // declared severity.
    let severity = if chunk.metadata.source_type == "git/history" {
        detector.severity.downgrade_one()
    } else {
        detector.severity
    };
    RawMatch {
        detector_id: scan_state.intern_metadata(&detector.id),
        detector_name: scan_state.intern_metadata(&detector.name),
        service: scan_state.intern_metadata(&detector.service),
        severity,
        credential_hash: crate::sha256_hash(credential),
        credential: scan_state.intern_credential(credential),
        companions,
        location: MatchLocation {
            source: scan_state.intern_metadata(&chunk.metadata.source_type),
            file_path: chunk
                .metadata
                .path
                .as_ref()
                .map(|p| scan_state.intern_metadata(p)),
            line: Some(line),
            offset: offset + chunk.metadata.base_offset,
            commit: chunk
                .metadata
                .commit
                .as_ref()
                .map(|c| scan_state.intern_metadata(c)),
            author: chunk
                .metadata
                .author
                .as_ref()
                .map(|a| scan_state.intern_metadata(a)),
            date: chunk
                .metadata
                .date
                .as_ref()
                .map(|d| scan_state.intern_metadata(d)),
        },
        entropy: Some(ent),
        confidence: Some(confidence),
    }
}

pub fn local_context_window(text: &str, line: usize, radius: usize) -> String {
    // Avoid collecting all lines just to slice 2*radius. Iterator-based
    // approach skips lines before the window and takes only what's needed.
    let start = line.saturating_sub(radius).saturating_sub(1);
    let end = line + radius;
    let window: Vec<&str> = text.lines().skip(start).take(end - start).collect();
    window.join("\n")
}

/// Compute the byte offsets for every line in a string.
///
/// Uses `memchr` for SIMD-accelerated newline scanning (~4x faster
/// than `str::match_indices` on inputs > 1 KiB).
pub fn compute_line_offsets(text: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    // Pre-size: average line length ~40 chars is typical for source code.
    let estimated_lines = bytes.len() / 40 + 1;
    let mut offsets = Vec::with_capacity(estimated_lines);
    offsets.push(0);
    let mut start = 0;
    while let Some(pos) = memchr::memchr(b'\n', &bytes[start..]) {
        offsets.push(start + pos + 1);
        start += pos + 1;
    }
    offsets
}

pub fn match_line_number(
    preprocessed: &ScannerPreprocessedText,
    line_offsets: &[usize],
    offset: usize,
) -> usize {
    preprocessed.line_for_offset(offset).unwrap_or_else(|| {
        // `line_offsets` holds the byte offset of each line start in
        // ascending order. The first offset strictly greater than
        // `offset` is its line index — which is what
        // `partition_point` returns directly. Binary search collapses
        // the prior O(L) `position()` walk into O(log L); on a 10k-
        // line file with N matches we go from N × 10k compares to
        // N × ~14.
        line_offsets.partition_point(|&lo| lo <= offset)
    })
}

pub fn normalize_scannable_chunk<'a>(chunk: &'a Chunk, owned: &'a mut Option<Chunk>) -> &'a Chunk {
    let normalized = crate::normalize_chunk_data(&chunk.data);
    if let Cow::Owned(data) = normalized {
        *owned = Some(Chunk {
            data: data.into(),
            metadata: chunk.metadata.clone(),
        });
        owned.as_ref().unwrap_or(chunk)
    } else {
        chunk
    }
}

fn upper_contains_token(upper: &str, token: &str) -> bool {
    upper.match_indices(token).any(|(idx, _)| {
        let before = idx.checked_sub(1).and_then(|i| upper.chars().nth(i));
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
    // Generic detectors (generic-secret, generic-private-key, entropy-*)
    // never use this bypass — their anchor is keyword-class, not
    // service-specific, and shape gates are load-bearing for them.
    let bypass_shape_gates = !detector_id.starts_with("generic-")
        && !detector_id.starts_with("entropy-")
        && detector_id != "private-key";
    should_suppress_inner(credential, path, context, source_type, false, bypass_shape_gates)
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
                return true;
            }
        }
    }

    let known_prefix_body = known_prefix_body(credential);
    if let Some(body) = known_prefix_body {
        if looks_like_prefixed_masked_sequence(body) {
            return true;
        }
        return false;
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
    // load-bearing:
    //
    //   - Hash digest (32/40/48/56/64/72/128-char uniform hex, plus
    //     `sha256:` / `sha512:` prefixed forms) → ALWAYS on. Real
    //     secrets at these lengths use base64 (+/=/mixed case), not
    //     pure hex. Bench v18 proved bypassing this added 3304 FPs
    //     (sha256-hex 1460 + sha1-hex 1027 + git-commit-sha 817) with
    //     zero recall gain.
    //
    //   - UUID v4 (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`) → gated by
    //     `bypass_shape_gates`. Several real services (Heroku API key,
    //     Cypress record key, the body of many license-server tokens)
    //     use UUID v4 as their credential format. A named detector
    //     with a service-specific anchor (`HEROKU_API_KEY=<uuid>`) is
    //     positive evidence the UUID is a credential, NOT a docker
    //     image digest or k8s resource ID. Generic / entropy detectors
    //     stay gated because for them a bare UUID is always noise.
    //
    // Bench v19 confirmed the hash gate side closes the FP regression
    // without losing recall; the contracts_runner test caught the UUID
    // over-suppression that prompted the split.
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
    if credential.len() > 30
        && credential.chars().filter(|c| c.is_whitespace()).count() >= 2
    {
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
                && should_suppress_inner(&decoded, path, context, source_type, true, bypass_shape_gates)
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
    use base64::engine::general_purpose::{
        STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
    };
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

/// Prefix of the RFC 7519 specimen JWT — the example token from the
/// JWT spec, copy-pasted into thousands of "how to use JWTs" blog
/// posts and docs. NOT a real secret.
const RFC7519_EXAMPLE_JWT_PREFIX: &str =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw";

/// True if `credential` matches the XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
/// dashed-serial / license-key shape: exactly 5 dash-separated
/// blocks, each exactly 5 alphanumeric characters. Microsoft Office,
/// Adobe, Atlassian, JetBrains and many other product-key surfaces
/// use this shape; real credentials almost never do.
pub(crate) fn looks_like_dashed_serial_key(credential: &str) -> bool {
    if credential.len() != 29 {
        return false;
    }
    let parts: Vec<&str> = credential.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    parts.iter().all(|p| p.len() == 5 && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// True if `credential` is a bare cryptographic hash digest
/// (MD5/SHA1/SHA256/SHA512) or an RFC-4122 UUID-v4. These are the
/// dominant false-positive class in the SecretBench mirror corpus.
///
/// Strictness: the entire credential must be only hex (or, for UUIDs,
/// hex + dashes in the canonical 8-4-4-4-12 shape with version-4
/// nibble). Mixed-case is tolerated only when uniform — `Abcd1234`
/// in a real secret would NOT match because it's not all-lower or
/// all-upper hex. A scanner that already coincidentally classifies
/// the credential as a known-prefix secret (AKIA…, ghp_… etc.) has
/// already returned `false` upstream of this function.
#[cfg(test)]
pub(crate) fn looks_like_pure_hash_digest_or_uuid(credential: &str) -> bool {
    // Combined-shape helper retained for test scaffolding that asserts the
    // pre-split behavior. Production paths call `is_uuid_v4_shape` and
    // `looks_like_hash_digest` individually because the UUID arm is gated
    // by `bypass_shape_gates` while the hash arm is always-on.
    is_uuid_v4_shape(credential) || looks_like_hash_digest(credential)
}

/// Hash-digest sub-check of [`looks_like_pure_hash_digest_or_uuid`].
/// Always safe to apply (real secrets at these lengths use base64, not
/// uniform hex). Exposed so the named-detector path can apply it
/// without the UUID arm.
pub(crate) fn looks_like_hash_digest(credential: &str) -> bool {
    // Prefixed-hash forms emitted by docker (`sha256:<64-hex>`), npm
    // package-lock integrity (`sha512-<base64>`), python requirements
    // (`sha256:<64-hex>`) and git-LFS pointers (`sha256:<64-hex>`).
    // These are very common FP shapes — see secretbench mirror per-
    // category FP counts (docker-image-digest, npm-lock-integrity,
    // python-requirements-hash).
    if let Some(body) = strip_hash_algo_prefix(credential) {
        // Stripped body must itself be a hash digest of the
        // corresponding length OR a base64 blob (npm-style).
        if body.len() == 64 && is_uniform_hex(body) {
            return true;
        }
        if body.len() == 128 && is_uniform_hex(body) {
            return true;
        }
        if body.len() == 40 && is_uniform_hex(body) {
            return true;
        }
        if looks_like_base64_blob_with_padding(body) {
            return true;
        }
    }
    // Bare hash-digest hex. Lengths that real secrets use commonly
    // (e.g. 40-char AWS secret-access-key body) DON'T match because
    // those are base64, not pure hex.
    //
    // The 48-char length is included because several detector
    // regexes (e.g. honeybadger-api-key `[a-f0-9]{32,48}`) greedy-
    // capture the FIRST 48 chars of a 64-char sha256 hex span,
    // producing a 48-char credential that is the prefix of a hash
    // and not a real key. Same for 56 and 72 — common boundary
    // lengths produced by detectors that quantify hex spans without
    // a non-hex terminator. The 64/128 already-covered cases catch
    // the full-length hash; the 48/56/72 extension covers the
    // truncated-prefix variants. Each added length is justified by
    // a SecretBench-medium FP cluster.
    matches!(credential.len(), 32 | 40 | 48 | 56 | 64 | 72 | 128)
        && is_uniform_hex(credential)
}

/// If `credential` begins with — OR contains — one of the well-known
/// hash-algorithm labels (`sha256:`, `sha512:`, `sha512-`, `sha1:`,
/// `md5:`), return the body after the label. Otherwise None.
///
/// Substring match (not prefix-only) is intentional. Docker image
/// digests are commonly written `nginx@sha256:<64-hex>`, python
/// requirements as `--hash=sha256:<64-hex>`, both of which keyhog's
/// value extractor surfaces as one credential string that doesn't
/// START with the algo label.
fn strip_hash_algo_prefix(credential: &str) -> Option<&str> {
    const LABELS: &[&str] = &["sha256:", "sha512:", "sha512-", "sha256-", "sha1:", "md5:"];
    for label in LABELS {
        if let Some(idx) = credential.find(label) {
            return Some(&credential[idx + label.len()..]);
        }
    }
    None
}

/// True if `s` looks like a base64-encoded blob with one or two
/// trailing `=` padding chars (the canonical shape of npm package-
/// lock `integrity` values after stripping `sha512-`). Conservative
/// length floor of 40 chars to avoid catching short base64 tokens
/// that might be real secrets.
fn looks_like_base64_blob_with_padding(s: &str) -> bool {
    if s.len() < 40 {
        return false;
    }
    if !(s.ends_with("==") || s.ends_with('=')) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// True if `credential` is a standard-base64-encoded arbitrary-bytes
/// blob (protobuf wire format, marshalled binary, etc.) rather than
/// a credential token.
///
/// Heuristics (all required):
///   1. Length in `[40, 80]` chars — the window where the SecretBench
///      protobuf negatives concentrate (30-60 random bytes → 40-80
///      base64 chars). Above 80 we leave to the decode-and-recheck
///      gate (random binary doesn't decode to UTF-8 — no recheck
///      fires — and real long-form positives like Azure storage key
///      (88 chars) keep their recall). Below 40 we'd over-suppress
///      short tokens that happen to contain `+/`.
///   2. Alphabet limited to `[A-Za-z0-9+/=]` (standard base64).
///   3. Contains at least one of `+` or `/` — the chars that
///      distinguish standard base64 from base64url. Real provider
///      tokens use base64url (`-_`) or pure alphanumeric, never
///      standard `+/` in the bare-token form.
///   4. Either ends in `=`/`==` padding OR length is a multiple of
///      4 (proper base64 of byte-aligned data). 40 % 4 == 0 so the
///      40-char unpadded case is admitted; previously the gate
///      rejected those, leaking thousands of FPs from the no-pad
///      40-char `generic-password`/`generic-secret` shape in the
///      SecretBench mirror corpus.
///
/// Why this is safe for recall: PEM-framed credentials get the
/// hard bypass above (they start with `-----BEGIN`), so
/// EC/RSA/PGP/OpenSSH private keys are unaffected even though
/// their bodies are standard base64. The 86/88-char Azure storage
/// key sits OUTSIDE the [40, 80] window — recall preserved.
#[allow(dead_code)]
fn looks_like_standard_base64_blob(credential: &str) -> bool {
    if !(40..=80).contains(&credential.len()) {
        return false;
    }
    let has_padding = credential.ends_with("==") || credential.ends_with('=');
    let length_multiple_of_4 = credential.len() % 4 == 0;
    if !has_padding && !length_multiple_of_4 {
        return false;
    }
    let mut has_b64_punct = false;
    for c in credential.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '=' => {}
            '+' | '/' => has_b64_punct = true,
            _ => return false,
        }
    }
    has_b64_punct
}

fn is_uniform_hex(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut saw_lower = false;
    let mut saw_upper = false;
    for &b in bytes {
        match b {
            b'0'..=b'9' => {}
            b'a'..=b'f' => saw_lower = true,
            b'A'..=b'F' => saw_upper = true,
            _ => return false,
        }
    }
    // Reject MiXeD-case hex (real hash digests are emitted by every
    // standard library in one case or the other, never mixed). The
    // mixed-case bar saves recall on Base16-ish secrets that happen
    // to look hex-shaped.
    !(saw_lower && saw_upper)
}

pub(crate) fn is_uuid_v4_shape(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return false;
    }
    // Version-4 marker at position 14, variant marker at position 19
    // (8/9/a/b) per RFC 4122. We don't require the version digit so
    // we also catch v1/v3/v5 — every standard-shaped UUID is FP.
    let mut saw_lower = false;
    let mut saw_upper = false;
    for (i, &c) in b.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            continue;
        }
        match c {
            b'0'..=b'9' => {}
            b'a'..=b'f' => saw_lower = true,
            b'A'..=b'F' => saw_upper = true,
            _ => return false,
        }
    }
    !(saw_lower && saw_upper)
}

/// Return true if the credential contains three or more consecutive identical characters.
fn has_three_or_more_consecutive_identical(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let mut run = 1usize;
        while i + run < bytes.len() && bytes[i + run] == b {
            run += 1;
        }
        if run >= 3 {
            return true;
        }
        i += run;
    }
    false
}

fn known_prefix_body(credential: &str) -> Option<&str> {
    // Single source of truth: crate::confidence::KNOWN_PREFIXES.
    // Pre-2026-05-24 this function carried a hand-curated 27-entry list
    // that drifted from the canonical 38-entry KNOWN_PREFIXES. Missing
    // entries (sk-, xoxs-, glcbt-, glrt-, vercel_, sbp_, 0x, rk_test_,
    // -----BEGIN, TESTKEY_) meant credentials with those prefixes
    // bypassed the early-return-false fast path and fell into the
    // repetitive-mask/filler gates below, where a legitimate
    // `sk-abcdefghijklmnopqrstuvwxyz...` OpenAI key with naturally-
    // occurring repeated characters would be dropped. Kimi-suppress
    // audit finding #1.
    crate::confidence::KNOWN_PREFIXES
        .iter()
        .find_map(|prefix| credential.strip_prefix(prefix))
}

fn looks_like_prefixed_masked_sequence(body: &str) -> bool {
    // Trailing-ellipsis is an unambiguous placeholder signal: real secrets
    // never end in `...`. UI prompt strings like `ghp_1a2b3c4...` (vscode
    // input-box placeholder) and docs snippets like `sk_live_abcd1234...`
    // are the dominant failure mode. Same for unicode horizontal ellipsis.
    if body.ends_with("...") || body.ends_with('…') {
        return true;
    }
    let upper = body.to_ascii_uppercase();
    let starts_with_mask = upper.starts_with("XXX") || upper.starts_with("***");
    let contains_fake_sequence = ["1234567890", "0123456789", "ABCDEFGH", "ABCDEFGHIJ"]
        .iter()
        .any(|seq| upper.contains(seq));
    starts_with_mask && contains_fake_sequence
}

fn has_repeated_block_mask(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut long_runs = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let mut run = 1usize;
        while i + run < bytes.len() && bytes[i + run] == b {
            run += 1;
        }
        if run >= 4 && b.is_ascii_alphanumeric() {
            long_runs += 1;
            if long_runs >= 3 {
                return true;
            }
        }
        i += run;
    }
    false
}

fn has_n_or_more_consecutive_identical(s: &str, n: usize) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let mut run = 1usize;
        while i + run < bytes.len() && bytes[i + run] == b {
            run += 1;
        }
        // Dashes are legitimate delimiters in structured formats (PEM headers,
        // UUIDs, JWT separators). Don't count them as repetitive masking.
        if run >= n && b != b'-' {
            return true;
        }
        i += run;
    }
    false
}

pub fn find_companion(
    preprocessed: &ScannerPreprocessedText,
    primary_line: usize,
    companion: &CompiledCompanion,
) -> Option<String> {
    // `primary_line` is 1-based (the return of `match_line_number` is
    // a 1-based partition_point index). Clamp the lower bound at
    // FIRST_LINE_NUMBER so a primary on line 1 with within=3 starts
    // at line 1, not line -2 (which saturates to 0 and would silently
    // shift the whole window off by one).
    let start = primary_line
        .saturating_sub(companion.within_lines)
        .max(FIRST_LINE_NUMBER);
    let end = primary_line.saturating_add(companion.within_lines);
    let (window_start, window_end) = line_window_offsets(preprocessed, start, end)?;
    // Defensive: `line_window_offsets` returns offsets relative to the
    // line index, but the underlying text may have been truncated
    // mid-scan (windowed mode, decoded chunk shorter than original)
    // so the offsets can exceed `text.len()`. Use `get` to bail out
    // cleanly instead of panicking on a `&str[..]` slice — a single
    // bogus companion lookup must never crash a worker.
    let haystack = preprocessed.text.get(window_start..window_end)?;
    let group = companion.capture_group.unwrap_or(FIRST_CAPTURE_GROUP_INDEX);
    let line_range = start..=end;

    // Capture-group fast path: when the regex has no groups, `find_iter` is
    // strictly cheaper than `captures_iter` — `find` allocates no
    // `Captures` object per iteration. The previous unconditional
    // `captures_iter` paid for that allocation on every match across every
    // companion lookup in every scan.
    if companion.capture_group.is_none() {
        for m in companion.regex.find_iter(haystack) {
            if m.len() > 4096 {
                continue;
            }
            if let Some(line) = preprocessed.line_for_offset(window_start + m.start()) {
                if line_range.contains(&line) {
                    return Some(m.as_str().to_string());
                }
            }
        }
        return None;
    }

    // Capture-group path: reuse one `CaptureLocations` buffer across every
    // iter tick. `captures_iter` allocates a fresh `Captures` per match;
    // `captures_read_at` writes into the borrowed buffer instead.
    let mut locs = companion.regex.capture_locations();
    let mut cursor = 0usize;
    let bytes_total = haystack.len();
    while cursor <= bytes_total {
        let Some(whole) = companion
            .regex
            .captures_read_at(&mut locs, haystack, cursor)
        else {
            break;
        };
        // Advance the cursor before any branch that might `continue`, to
        // keep the loop monotonic. Zero-width matches bump by one byte
        // and we then align onto a UTF-8 boundary — `captures_read_at`'s
        // behavior is unspecified at non-boundary positions, so we must
        // never feed it one.
        let mut next = if whole.end() == cursor {
            cursor + 1
        } else {
            whole.end()
        };
        while next < bytes_total && !haystack.is_char_boundary(next) {
            next += 1;
        }
        let prev_cursor = cursor;
        cursor = next;

        if let Some((s, e)) = locs.get(group) {
            if e.saturating_sub(s) <= 4096 {
                if let Some(line) = preprocessed.line_for_offset(window_start + s) {
                    if line_range.contains(&line) {
                        return Some(haystack[s..e].to_string());
                    }
                }
            }
        }
        let _ = prev_cursor; // borrowck scope marker; cursor is already updated
    }
    None
}

pub fn line_window_offsets(
    preprocessed: &ScannerPreprocessedText,
    start_line: usize,
    end_line: usize,
) -> Option<(usize, usize)> {
    let mut start_offset = None;
    let mut end_offset = None;

    for mapping in &preprocessed.mappings {
        if start_offset.is_none() && mapping.line_number >= start_line {
            start_offset = Some(mapping.start_offset);
        }
        if mapping.line_number <= end_line {
            end_offset = Some(mapping.end_offset);
        }
    }

    Some((start_offset?, end_offset?))
}

pub fn is_within_hex_context(data: &str, match_start: usize, match_end: usize) -> bool {
    if !valid_match_bounds(data, match_start, match_end) {
        return false;
    }
    let matched = &data[match_start..match_end];
    // Cheap rejects FIRST. The earlier flow always walked the
    // matched-string to count hex digits before checking the length
    // floor — wasted work for the (very common) sub-16-byte AC
    // matches that can't possibly meet the threshold. Reordering
    // skips the count entirely on those.
    if matched.len() < MIN_HEX_MATCH_LEN {
        return false;
    }
    if !has_at_least_n_hex_digits(matched, MIN_HEX_DIGITS_IN_MATCH) {
        return false;
    }
    let (before, after) = surrounding_hex_context(data, match_start, match_end);
    let hex_before = formatted_hex_run(before.chars().rev());
    let hex_after = formatted_hex_run(after.chars());
    hex_before >= MIN_HEX_CONTEXT_DIGITS && hex_after >= MIN_HEX_CONTEXT_DIGITS
}

/// Returns true as soon as `n` ASCII hex digits have been seen in `s`.
/// Walking the full string just to compare a count to a threshold is
/// wasted — for matches with no hex shape at all we exit after a
/// handful of bytes; for hex-heavy matches the threshold is cleared
/// long before the end of the credential.
fn has_at_least_n_hex_digits(s: &str, n: usize) -> bool {
    if n == 0 {
        return true;
    }
    let mut seen = 0usize;
    for &b in s.as_bytes() {
        if b.is_ascii_hexdigit() {
            seen += 1;
            if seen >= n {
                return true;
            }
        }
    }
    false
}

fn valid_match_bounds(data: &str, match_start: usize, match_end: usize) -> bool {
    match_end > match_start
        && data.is_char_boundary(match_start)
        && data.is_char_boundary(match_end)
}

fn surrounding_hex_context(data: &str, match_start: usize, match_end: usize) -> (&str, &str) {
    let context_start = crate::engine::floor_char_boundary(
        data,
        match_start.saturating_sub(HEX_CONTEXT_RADIUS_CHARS),
    );
    let context_end = {
        let mut end = (match_end + HEX_CONTEXT_RADIUS_CHARS).min(data.len());
        while end < data.len() && !data.is_char_boundary(end) {
            end += 1;
        }
        end.min(data.len())
    };
    (
        &data[context_start..match_start],
        &data[match_end..context_end],
    )
}

fn formatted_hex_run(iter: impl Iterator<Item = char>) -> usize {
    let mut hex_digits = 0usize;
    let mut separators = 0usize;
    let mut seen_hex = false;

    for ch in iter {
        if ch.is_ascii_hexdigit() {
            hex_digits += 1;
            seen_hex = true;
            continue;
        }
        if matches!(ch, ' ' | '\t' | ':' | '-')
            && (!seen_hex || separators < MAX_HEX_CONTEXT_SEPARATORS)
        {
            separators += 1;
            continue;
        }
        break;
    }

    hex_digits
}

pub fn match_entropy(data: &[u8]) -> f64 {
    #[cfg(feature = "entropy")]
    {
        crate::entropy::shannon_entropy(data)
    }

    #[cfg(not(feature = "entropy"))]
    {
        fallback_entropy(data)
    }
}

#[cfg(not(feature = "entropy"))]
fn fallback_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // 4-way parallel histogram: same strategy as entropy_fast.rs
    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];

    let chunks = data.chunks_exact(4);
    let remainder = chunks.remainder();
    for chunk in chunks {
        c0[chunk[0] as usize] += 1;
        c1[chunk[1] as usize] += 1;
        c2[chunk[2] as usize] += 1;
        c3[chunk[3] as usize] += 1;
    }
    for &byte in remainder {
        c0[byte as usize] += 1;
    }

    let mut counts = [0u32; 256];
    for j in 0..256 {
        counts[j] = c0[j] + c1[j] + c2[j] + c3[j];
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod placeholder_suppression_tests {
    //! Regression coverage for the prefix-trust suppression carve-outs.
    //! Without these, vscode/ide UI strings like `ghp_1a2b3c4...` get
    //! reported as critical findings (kimi dogfood-2 finding #4) — see
    //! task #82 for the original repro.
    use super::*;

    #[test]
    fn ascii_ellipsis_in_body_suppresses_ghp_placeholder() {
        // body of `ghp_1a2b3c4...` after stripping the known prefix.
        assert!(looks_like_prefixed_masked_sequence("1a2b3c4..."));
        assert!(looks_like_prefixed_masked_sequence("sk_live_abcd1234..."));
    }

    #[test]
    fn unicode_ellipsis_in_body_suppresses_placeholder() {
        // Real-world placeholder forms — some IDEs / Word-style autocorrect
        // emit U+2026 (HORIZONTAL ELLIPSIS) instead of three ASCII dots.
        assert!(looks_like_prefixed_masked_sequence("1a2b3c4\u{2026}"));
    }

    #[test]
    fn dot_inside_body_does_not_suppress_real_credential() {
        // Negative: a real token body that happens to contain a dot in
        // the middle (e.g. some JWT-style structured tokens) must NOT
        // be suppressed by the trailing-ellipsis carve-out.
        assert!(!looks_like_prefixed_masked_sequence(
            "eyJhbGciOiJIUzI1NiJ9.payloadX"
        ));
    }

    // ── hash-digest / UUID suppression unit tests ────────────────────

    #[test]
    fn sha256_hex_lowercase_is_suppressed() {
        // git commit SHA, npm-lock integrity body, requirements.txt
        // --hash entry, etc. — all 64 lowercase hex.
        let sha256 = "2c0fa7a26774e22af3993a69e2ca7956518f2244aabbccddeeff001122334455";
        assert_eq!(sha256.len(), 64);
        assert!(looks_like_pure_hash_digest_or_uuid(sha256));
    }

    #[test]
    fn sha256_hex_uppercase_is_suppressed() {
        let sha256 = "2C0FA7A26774E22AF3993A69E2CA7956518F2244AABBCCDDEEFF001122334455";
        assert_eq!(sha256.len(), 64);
        assert!(looks_like_pure_hash_digest_or_uuid(sha256));
    }

    #[test]
    fn sha1_md5_sha512_lengths_are_suppressed() {
        assert!(looks_like_pure_hash_digest_or_uuid(
            "d41d8cd98f00b204e9800998ecf8427e"          // MD5: 32
        ));
        assert!(looks_like_pure_hash_digest_or_uuid(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"  // SHA1: 40
        ));
        // SHA-512: 128 hex chars
        let sha512 = "abcdef0123456789".repeat(8);
        assert_eq!(sha512.len(), 128);
        assert!(looks_like_pure_hash_digest_or_uuid(&sha512));
    }

    #[test]
    fn uuid_v4_canonical_shape_is_suppressed() {
        assert!(looks_like_pure_hash_digest_or_uuid(
            "550e8400-e29b-41d4-a716-446655440000"
        ));
    }

    #[test]
    fn mixed_case_hex_is_not_suppressed() {
        // Real secret coincidentally looks hex-shaped but is mixed
        // case — keyhog should NOT silently drop it as a digest.
        assert!(!looks_like_pure_hash_digest_or_uuid(
            "AbCdEf0123456789abCdEf0123456789"  // MiXeD 32-hex
        ));
    }

    #[test]
    fn aws_secret_access_key_shape_is_not_suppressed() {
        // 40-char AWS secret-access-key body — NOT all hex (uses
        // base64 alphabet incl. `/` and `+`), so the hex-shape gate
        // must NOT fire on it.
        assert!(!looks_like_pure_hash_digest_or_uuid(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ));
    }

    #[test]
    fn docker_image_digest_sha256_prefix_is_suppressed() {
        let sha = "abcdef0123456789".repeat(4);
        assert_eq!(sha.len(), 64);
        let docker = format!("sha256:{sha}");
        assert!(looks_like_pure_hash_digest_or_uuid(&docker));
    }

    #[test]
    fn npm_integrity_sha512_dash_prefix_is_suppressed() {
        // npm package-lock.json integrity body: sha512-<base64>==
        let body = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/AAAA==";
        let npm = format!("sha512-{body}");
        assert!(looks_like_pure_hash_digest_or_uuid(&npm));
    }

    #[test]
    fn python_requirements_hash_sha256_prefix_is_suppressed() {
        // python --hash=sha256:<64-hex> value
        let sha = "0123456789abcdef".repeat(4);
        assert_eq!(sha.len(), 64);
        let py = format!("sha256:{sha}");
        assert!(looks_like_pure_hash_digest_or_uuid(&py));
    }

    #[test]
    fn docker_image_digest_embedded_sha256_is_suppressed() {
        // Docker image-digest commonly written as
        // `nginx@sha256:<64-hex>` — keyhog's value extractor surfaces
        // the whole right-hand side as one credential, so the
        // sha-algo label sits MID-string, not at the start.
        let sha = "abcdef0123456789".repeat(4);
        assert_eq!(sha.len(), 64);
        let digest = format!("nginx@sha256:{sha}");
        assert!(looks_like_pure_hash_digest_or_uuid(&digest));
    }

    #[test]
    fn python_pip_hash_embedded_sha256_is_suppressed() {
        // pip requirements.txt: `--hash=sha256:<64-hex>`
        let sha = "0123456789abcdef".repeat(4);
        let pip = format!("--hash=sha256:{sha}");
        assert!(looks_like_pure_hash_digest_or_uuid(&pip));
    }

    #[test]
    fn dashed_serial_license_key_shape_is_suppressed() {
        assert!(looks_like_dashed_serial_key("ABCDE-12345-FGHIJ-67890-KLMNO"));
    }

    #[test]
    fn dashed_serial_off_block_shape_is_not_suppressed() {
        // Real keyhog AKIA key shape has no internal hyphens
        assert!(!looks_like_dashed_serial_key("AKIAIOSFODNN7EXAMPLE"));
        // Heroku UUID has different block sizes (8-4-4-4-12), must not match
        assert!(!looks_like_dashed_serial_key(
            "12345678-1234-1234-1234-123456789012"
        ));
        // 4 blocks of 5 → 24 chars (incl 3 dashes) doesn't match 29-char rule
        assert!(!looks_like_dashed_serial_key("ABCDE-12345-FGHIJ-67890"));
    }

    #[test]
    fn substring_hash_label_in_real_token_does_not_suppress() {
        // Adversarial: a real token that happens to embed the substring
        // `md5:` in its body but whose body after the label isn't a
        // hash-shape length. Must NOT suppress.
        assert!(!looks_like_pure_hash_digest_or_uuid("user_md5:not_a_hash_body"));
    }

    #[test]
    fn near_hash_lengths_off_by_one_are_not_suppressed() {
        // 31, 33, 39, 41, 63, 65 hex chars are NOT recognised hash
        // sizes — the precision win is from the EXACT length match,
        // so off-by-one variants stay surfaced for the entropy gate.
        assert!(!looks_like_pure_hash_digest_or_uuid(&"a".repeat(31)));
        assert!(!looks_like_pure_hash_digest_or_uuid(&"f".repeat(33)));
        assert!(!looks_like_pure_hash_digest_or_uuid(&"0".repeat(65)));
    }
}

#[cfg(test)]
mod hex_context_tests {
    //! Coverage for the reordered + short-circuited hex-context check.
    //! The walk now exits as soon as the hex-digit threshold is met,
    //! so we have to prove both the cheap-rejection case and the
    //! parity-with-full-walk case.

    use super::*;

    #[test]
    fn has_at_least_n_hex_digits_threshold_zero_always_true() {
        assert!(has_at_least_n_hex_digits("", 0));
        assert!(has_at_least_n_hex_digits("xyz", 0));
    }

    #[test]
    fn has_at_least_n_hex_digits_short_circuits_after_threshold() {
        // 16 hex digits at the start, then garbage. The walk should
        // exit before reaching the garbage — if it didn't, this would
        // still pass, but the SAFETY of the change is that walking
        // the full string is allowed, just not required.
        let s = format!("{}{}", "deadbeefcafef00d", "non-hex tail goes here");
        assert!(has_at_least_n_hex_digits(&s, 16));
    }

    #[test]
    fn has_at_least_n_hex_digits_returns_false_when_insufficient() {
        // 8 hex digits; threshold 16. Must walk the whole string and
        // conclude false. Includes non-hex bytes interspersed to
        // confirm the count only increments on hexdigits.
        let s = "xx12 yy34 zz56 ww78 NO";
        assert!(!has_at_least_n_hex_digits(s, 16));
    }

    #[test]
    fn is_within_hex_context_short_match_skips_count() {
        // Match shorter than MIN_HEX_MATCH_LEN must return false
        // WITHOUT walking the credential — the order swap is what
        // makes that observable. We just verify the answer.
        let data = "deadbeef cafef00d AKIA1234 deadbeef cafef00d";
        // Position the match on "AKIA1234" (8 chars — well below the
        // 16-byte floor).
        let start = data.find("AKIA1234").unwrap();
        let end = start + "AKIA1234".len();
        assert!(!is_within_hex_context(data, start, end));
    }

    #[test]
    fn is_within_hex_context_hex_match_in_hex_surroundings_returns_true() {
        // A 16+ char hex match inside a hex-stuffed line should
        // trigger the false-positive guard.
        let data = "deadbeef-cafef00d-0123456789abcdef-deadbeef-cafef00d-cafef00d";
        let target = "0123456789abcdef";
        let start = data.find(target).unwrap();
        let end = start + target.len();
        assert!(is_within_hex_context(data, start, end));
    }

    #[test]
    fn is_within_hex_context_hex_match_in_plain_surroundings_returns_false() {
        // Same long-hex match but with non-hex prose around it; the
        // surrounding-context check fails so we don't suppress.
        let data = "the value of the field is 0123456789abcdef and that's it";
        let target = "0123456789abcdef";
        let start = data.find(target).unwrap();
        let end = start + target.len();
        assert!(!is_within_hex_context(data, start, end));
    }

    #[test]
    fn is_within_hex_context_invalid_bounds_returns_false() {
        // start >= end, or non-char-boundary indices, must short-
        // circuit cleanly without panicking.
        let data = "hello";
        assert!(!is_within_hex_context(data, 3, 3));
        assert!(!is_within_hex_context(data, 4, 2));
    }

    #[test]
    fn is_within_hex_context_count_short_circuit_matches_full_walk() {
        // Property check: across a randomised but fixed-seed mix of
        // strings, the early-exit count must agree with the prior
        // `chars().filter().count() >= n` formulation. Locked in so
        // a future "optimisation" can't silently regress.
        for n in [0, 1, 5, 16, 64] {
            for s in [
                "",
                "deadbeef",
                "0123456789abcdef0123456789abcdef",
                "Pin verify token 12 ab cd 34",
                "AKIAIOSFODNN7EXAMPLE",
                "xx 0011 22 33 44 55 66 77 88 99 aa bb cc dd ee ff",
                "non-hex content with letters g h i j k l m n o p",
            ] {
                let early = has_at_least_n_hex_digits(s, n);
                let full = s.chars().filter(|c| c.is_ascii_hexdigit()).count() >= n;
                assert_eq!(early, full, "mismatch for n={n}, s={s:?}");
            }
        }
    }
}

#[cfg(test)]
mod line_lookup_tests {
    //! Correctness coverage for the binary-search line-number lookup.
    //! The whole point of swapping `iter().position()` → `partition_point`
    //! is invisible perf — it has to round-trip exactly the same answer
    //! the linear walk did, on every offset including the boundaries.

    use super::*;
    use crate::types::ScannerPreprocessedText;

    fn preprocess(text: &str) -> ScannerPreprocessedText {
        ScannerPreprocessedText::passthrough(text)
    }

    fn linear_position(line_offsets: &[usize], offset: usize) -> usize {
        line_offsets
            .iter()
            .position(|&lo| lo > offset)
            .unwrap_or(line_offsets.len())
    }

    #[test]
    fn line_for_offset_returns_correct_line_in_passthrough_text() {
        // Three lines, offsets 0..7 ("line 1\n"), 7..14 ("line 2\n"),
        // 14..20 ("line 3"). The lookup is line_number for the byte
        // offset of the first character of each line.
        let pp = preprocess("line 1\nline 2\nline 3");
        assert_eq!(pp.line_for_offset(0), Some(1));
        assert_eq!(pp.line_for_offset(3), Some(1));
        assert_eq!(pp.line_for_offset(6), Some(1)); // newline byte
        assert_eq!(pp.line_for_offset(7), Some(2)); // start of line 2
        assert_eq!(pp.line_for_offset(13), Some(2));
        assert_eq!(pp.line_for_offset(14), Some(3));
        assert_eq!(pp.line_for_offset(19), Some(3));
    }

    #[test]
    fn line_for_offset_returns_none_past_end() {
        let pp = preprocess("hello\nworld");
        // Offsets beyond the text fall outside the last mapping and
        // must report None — callers fall back to the line_offsets
        // search path which has its own bound check.
        assert_eq!(pp.line_for_offset(11), None);
        assert_eq!(pp.line_for_offset(99), None);
    }

    #[test]
    fn match_line_number_partition_point_matches_linear_position() {
        // Property: for every offset within and around a synthetic
        // line_offsets vector, the new partition_point must return the
        // exact same line index the prior `position()` walk did.
        let line_offsets = vec![0, 12, 30, 31, 100, 250, 1000];
        for offset in 0..1100 {
            let bin = line_offsets.partition_point(|&lo| lo <= offset);
            let lin = linear_position(&line_offsets, offset);
            assert_eq!(
                bin, lin,
                "binary vs linear mismatch at offset {offset}: bin={bin} lin={lin}"
            );
        }
    }

    #[test]
    fn match_line_number_handles_empty_line_offsets() {
        // Edge case: passthrough on a single-line chunk has one
        // mapping; line_offsets fallback may still be empty under
        // some preprocessor configurations. Both paths must agree.
        let pp = preprocess("oneline");
        let line_offsets: Vec<usize> = vec![];
        assert_eq!(match_line_number(&pp, &line_offsets, 0), 1);
        // Offset past end falls through to the empty fallback → 0.
        assert_eq!(match_line_number(&pp, &line_offsets, 99), 0);
    }

    #[test]
    fn line_counting_is_consistent_across_line_endings() {
        // Cross-platform robustness: a file with CRLF (Windows-authored)
        // line endings must produce the same line count + line-for-offset
        // mapping as the same content with LF-only endings. `str::lines()`
        // recognises both \n and \r\n, and `match_indices('\n')` catches
        // the \n half of every \r\n — so the two stay consistent. Lock
        // it in with a regression test so a future refactor that switches
        // to a different separator detector can't silently break it.

        let lf_text = "line one\nline two\nline three";
        let crlf_text = "line one\r\nline two\r\nline three";

        // Same number of lines either way.
        let lf_lines: Vec<&str> = lf_text.lines().collect();
        let crlf_lines: Vec<&str> = crlf_text.lines().collect();
        assert_eq!(lf_lines.len(), 3);
        assert_eq!(crlf_lines.len(), 3);
        // Decoded lines are identical (the \r is stripped by str::lines).
        assert_eq!(lf_lines, crlf_lines);

        // line_offsets count is the same (both have 3 line starts: the
        // first byte + after each \n).
        assert_eq!(compute_line_offsets(lf_text).len(), 3);
        assert_eq!(compute_line_offsets(crlf_text).len(), 3);

        // For a match in line 2: the byte offset depends on encoding,
        // but the LINE NUMBER must be 2 in both cases.
        let lf_offsets = compute_line_offsets(lf_text);
        let crlf_offsets = compute_line_offsets(crlf_text);
        let lf_line2_start = lf_offsets[1];
        let crlf_line2_start = crlf_offsets[1];
        let pp_lf = ScannerPreprocessedText::passthrough(lf_text);
        let pp_crlf = ScannerPreprocessedText::passthrough(crlf_text);
        assert_eq!(match_line_number(&pp_lf, &lf_offsets, lf_line2_start), 2);
        assert_eq!(
            match_line_number(&pp_crlf, &crlf_offsets, crlf_line2_start),
            2
        );
    }

    #[test]
    fn line_counting_handles_no_trailing_newline() {
        // Single-line files with no terminator at all — common for
        // programmatically-generated configs and test fixtures.
        let text = "AKIAIOSFODNN7EXAMPLE";
        let offsets = compute_line_offsets(text);
        assert_eq!(offsets, vec![0]);
        let pp = ScannerPreprocessedText::passthrough(text);
        // Any byte offset within the line resolves to line 1.
        for offset in [0, 1, 5, text.len() - 1] {
            assert_eq!(match_line_number(&pp, &offsets, offset), 1);
        }
    }

    #[test]
    fn line_counting_handles_empty_text() {
        // Defensive: empty text → no offsets but the function must not
        // panic. `passthrough` builds a one-mapping (start=0, end=0)
        // entry; partition_point on `[0]` for offset 0 returns 1, but
        // `line_for_offset` returns None for an empty range, so the
        // fallback fires and yields 1 (zero-indexed line 0 + 1).
        let text = "";
        let offsets = compute_line_offsets(text);
        assert_eq!(offsets, vec![0]);
        let pp = ScannerPreprocessedText::passthrough(text);
        // Result is 1 (the fallback's partition_point on [0] for offset 0).
        // We don't care exactly what — just that it doesn't panic.
        let _ = match_line_number(&pp, &offsets, 0);
    }

    #[test]
    fn match_line_number_uses_fallback_when_offset_past_preprocessed() {
        // Construct a chunk where `line_for_offset` returns None for
        // an out-of-range offset; the binary-search fallback must
        // fire and return the right line index.
        let pp = preprocess("a\nb");
        // Line offsets vector covers offsets up to 100.
        let line_offsets = vec![0, 2, 4, 8, 16, 32, 64];
        let offset = 50;
        // Linear answer for reference.
        let expected = linear_position(&line_offsets, offset);
        // pp's internal mappings only go up to its own text length
        // (3), so offset 50 should hit the fallback path.
        assert_eq!(match_line_number(&pp, &line_offsets, offset), expected);
    }
}
