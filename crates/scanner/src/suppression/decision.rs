//! The unified suppression decision tree. Public entry points in
//! [`super::api`] delegate to [`suppression_stage_inner`], which walks a
//! linear cascade of shape / context / path / decode gates and returns the
//! exact adjudicator stage that suppresses a candidate.

use super::decode::try_decode_b64_to_utf8;
use super::doc_markers::{check_markers, MarkerVerdict};
use super::shape::{
    has_n_or_more_consecutive_identical, has_repeated_block_mask,
    has_three_or_more_consecutive_identical, is_uuid_v4_shape, looks_like_bare_hex_digest,
    looks_like_base64_integrity_body, looks_like_bracketed_template_placeholder,
    looks_like_dashed_serial_key, looks_like_prefixed_hash_digest, looks_like_standard_base64_blob,
    looks_like_truncated_uuid_v4_suffix, HASH_ALGO_INTEGRITY_LABELS, HIGH_ENTROPY_BASE64_CUTOFF,
    RFC7519_EXAMPLE_JWT_PREFIX,
};
use crate::{adjudicate::StageId, context};

#[derive(serde::Deserialize)]
struct FakeSequences {
    sequences: Vec<String>,
}

fn parse_fake_sequences(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<FakeSequences>(raw)
        .map(|parsed| parsed.sequences)
        .map_err(|error| error.to_string())
}

static FAKE_SEQUENCES: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_fake_sequences(include_str!("../../../../rules/fake-sequences.toml")) {
        Ok(sequences) => sequences,
        Err(error) => panic!(
            "rules/fake-sequences.toml is invalid: {error}. \
             Fix the bundled Tier-B fake sequences list."
        ),
    }
});

#[derive(serde::Deserialize)]
struct ExamplePathComponents {
    components: Vec<String>,
}

fn parse_example_path_components(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<ExamplePathComponents>(raw)
        .map(|parsed| parsed.components)
        .map_err(|error| error.to_string())
}

static EXAMPLE_PATH_COMPONENTS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_example_path_components(include_str!(
        "../../../../rules/example-path-components.toml"
    )) {
        Ok(components) => components,
        Err(error) => panic!(
            "rules/example-path-components.toml is invalid: {error}. \
             Fix the bundled Tier-B example path components list."
        ),
    }
});

#[inline]
fn suppress(reason: &'static str) -> Option<StageId> {
    Some(StageId::ShapeGate(reason))
}

/// If `source_type` came from an adversarial evasion decoder, return the
/// generic-fallback suppression reason for that decoder. `/caesar` and
/// `/reverse` are the two evasion decoders; ONE owner so the decision tree
/// (which only needs "is this evasion output?" to skip EXAMPLE-marker
/// suppression) and `api.rs` (which suppresses coincidental GENERIC / weak-anchor
/// matches on that output) can never check divergent decoder sets. The api
/// gate previously checked `/caesar` alone and silently let `/reverse`
/// generic-fallback noise through.
pub(super) fn evasion_decoder_reason(source_type: Option<&str>) -> Option<&'static str> {
    let s = source_type?;
    if s.contains("/caesar") {
        Some("caesar_generic_fallback")
    } else if s.contains("/reverse") {
        Some("reverse_generic_fallback")
    } else {
        None
    }
}

/// True when `s` is multi-word English prose carrying an interior whitespace run
/// the dotenv/properties/log-line extractor sometimes captures an entire RHS
/// like `Session opened with handle XYZ. See documentation.` as the credential.
/// Cheap word-run sanity check: >30 bytes, ≥2 whitespace chars, and at least one
/// 3+ char all-lowercase token between spaces, characteristic of prose, not a
/// credential.
///
/// ONE definition shared by the direct gate (5e0) and the base64-decoded twin
/// (`decoded_benign_text_reason`), which previously carried byte-identical copies
/// of this predicate that could silently drift apart (DEDUP, µ-dcn-12). This is
/// deliberately NOT the same as `shape::looks_like_english_prose` (that one has a
/// 16-byte floor and an all-lowercase arm) (the two thresholds differ by design).
pub(crate) fn looks_like_prose_whitespace_run(s: &str) -> bool {
    s.len() > 30
        && s.chars().filter(|c| c.is_whitespace()).count() >= 2
        && s.split_whitespace()
            .any(|tok| tok.len() >= 3 && tok.chars().all(|c| c.is_ascii_lowercase()))
}

pub(super) fn suppression_stage_inner(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
    skip_b64_decode_recheck: bool,
    bypass_shape_gates: bool,
    entropy_hint: Option<f64>,
    // Bridge-path-only exemption (KH-L-0110): the caller has proven this is a
    // COMPLETE, delimiter-terminated pure-hex value of canonical key length
    // (32/48) anchored by a STRONG credential keyword, a real key on CredData
    // (hex48+kw 1033 POS / 0 NEG; hex32+kw 0.976), invisible to the mirror's
    // len-40/64 hash negatives. When set, skip the bare-hex-digest arm and the
    // later pairwise sequential-hex placeholder arm. The earlier fake-sequence,
    // repetitive-run, repeated-block, prefixed-hash, UUID, and serial gates still
    // run, so explicit decoys do not surface.
    allow_canonical_hex_key: bool,
    allow_base64_blob_shape: bool,
    allow_encoded_text_secret: bool,
) -> Option<StageId> {
    let from_evasion_decoder = evasion_decoder_reason(source_type).is_some();
    // ASCII uppercase: every marker/needle compared against `upper` is ASCII, so
    // this is byte-identical for matching yet avoids the full Unicode case-fold
    // (allocation + length changes like `ß`→`SS`) on the suppression hot path.
    let upper = credential.to_ascii_uppercase();

    // ── 1-2. Doc / placeholder / instructional / RFC7519 / known-prefix /
    //         DOC_MARKER substring scans.
    match check_markers(credential, &upper, from_evasion_decoder, path, entropy_hint) {
        MarkerVerdict::Suppress(reason) => return suppress(reason),
        MarkerVerdict::Allow => return None,
        MarkerVerdict::KeepChecking => {}
    }

    // PEM-framed credentials (private keys, certificates) get a hard
    // bypass on the body-entropy heuristics below: the BEGIN/END
    // frame IS the high-confidence signal, and base64-encoded
    // structured data (notably the `openssh-key-v1\0\0\0\0…` prefix
    // every OPENSSH PRIVATE KEY starts with) legitimately contains
    // long runs of identical characters like `AAAAAAAA` from
    // zero-padding. Without this carve-out, real OPENSSH keys get
    // suppressed by `has_n_or_more_consecutive_identical` and the
    // PEM `private-key` detector silently misses them - see
    // `tests/contracts/private-key.toml` OPENSSH positive.
    if crate::credential_shapes::is_pem_block(credential) {
        return None;
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
    // 5+ consecutive 'x' or 'X' (e.g., xxxxx, XXXXXXX) - masks and placeholders.
    // 3x can appear in real base64/hex, so only suppress longer runs.
    if !bypass_shape_gates && upper.contains("XXXXX") {
        return suppress("mask_run_xxxxx");
    }
    // 5+ consecutive identical characters in any credential, or 3+ in short credentials.
    // Real secrets can have short runs (e.g., "000" in base64) but rarely 5+.
    if !bypass_shape_gates
        && credential.len() < 20
        && has_three_or_more_consecutive_identical(credential)
    {
        return suppress("short_repetitive_run");
    }
    let has_n_plus = has_n_or_more_consecutive_identical(credential, 5);
    let suppresses_repetitive_run = has_n_plus
        && !entropy_hint
            .is_some_and(|entropy| entropy >= HIGH_ENTROPY_BASE64_CUTOFF && credential.len() >= 40);
    let high_entropy_base64_candidate = entropy_hint.is_some_and(|entropy| {
        entropy >= HIGH_ENTROPY_BASE64_CUTOFF
            && credential.len() >= 40
            && (credential.contains('+') || credential.contains('/'))
    });
    if !bypass_shape_gates && suppresses_repetitive_run {
        return suppress("repetitive_run");
    }
    if !bypass_shape_gates && has_repeated_block_mask(credential) {
        return suppress("repeated_block_mask");
    }
    // Entirely filler symbols
    if !bypass_shape_gates
        && credential
            .chars()
            .all(|c| c == 'x' || c == 'X' || c == '*' || c == '-' || c == '.')
    {
        return suppress("filler_symbols");
    }
    // Purely symbolic strings that look like filler/placeholder
    // (e.g., "********", "--------") - NOT real passwords like "!@#$%^&*()"
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
            return suppress("low_distinct_symbolic");
        }
    }

    // ── 4. Known fake sequences ──
    // Only suppress if the fake sequence is a DOMINANT part of the credential:
    // its length must exceed 40% of the FULL credential length (no prefix
    // stripping). Substring matches in long credentials produce false
    // suppressions on real secrets.
    if !bypass_shape_gates {
        for seq in &*FAKE_SEQUENCES {
            if upper.contains(seq.as_str()) {
                // Only suppress short credentials dominated by the fake sequence,
                // not long ones where it's a small substring.
                let seq_ratio = seq.len() as f64 / credential.len().max(1) as f64;
                if seq_ratio > 0.4 {
                    return suppress("fake_sequence");
                }
            }
        }
    }

    // ── 5b. Bare hash digest / UUID shape suppression ──
    // Values whose entire body is an MD5 (32-hex), SHA1 (40-hex),
    // SHA256 (64-hex), SHA512 (128-hex) or RFC-4122 UUID-v4
    // (8-4-4-4-12 with version-4 nibble) are almost never secrets in
    // practice - they're git commit IDs, npm-lock integrity hashes,
    // requirements.txt --hash entries, docker image digests, and
    // k8s resource UIDs. Surfaced by the mirror bench corpus
    // as the dominant FP class.
    // Known-prefix credentials bypass this (a 64-char hex AWS key
    // shouldn't be filtered) - we already returned Allow above
    // when known_prefix_body matched.
    // Split the old "hash digest OR UUID" gate by *which side* is
    // load-bearing. Both are gated by `bypass_shape_gates` - the
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
    //   - UUID v4 (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`): Heroku,
    //     Braze, Codecov, Consul, Cypress record keys, and license-server
    //     tokens use UUID v4 bodies. A named detector with a service-specific
    //     anchor is positive evidence the UUID is a credential, NOT a
    //     docker image digest or k8s resource ID. Generic / entropy
    //     detectors stay gated because for them a bare UUID is noise.
    //
    // Bench v19 confirmed both gates close the FP regression without
    // losing recall; the contracts_runner test caught the earlier
    // UUID over-suppression that prompted the split.
    //
    // Anchor-class split (recovers v32's 0-FP on these classes without
    // the +60-TP regression of a blanket revert - see 19c9d668):
    //
    //   * ALWAYS-FIRE sub-shapes (even with `bypass_shape_gates` set):
    //     algo-labelled digests (`sha256:`/`sha512-`/…) and 5x5 dashed
    //     serials. Service-specific UUID detectors stay alive under
    //     `bypass_shape_gates`; generic keyword captures of a bare UUID
    //     still suppress.
    //
    //   * BARE uniform-hex (32/40/48/56/64/72/128-hex) stays gated on
    //     `!bypass_shape_gates`: it is shape-indistinguishable from real
    //     service-anchored hex keys (Algolia admin 32-hex, New Relic
    //     40-hex, Redis Labs 64-hex). Dropping it under a service anchor
    //     would tank recall (the +60 TP). The bare-hex-under-a-generic-
    //     keyword case (`api_key=<64-hex>` git SHA) is handled upstream
    //     in `suppression/api.rs`, which reclassifies generic-keyword
    //     pure-hex captures as `weak_anchor` → `!bypass_shape_gates`
    //     here, so this arm still fires for them.
    if looks_like_prefixed_hash_digest(credential) {
        return suppress("labelled_hash_digest");
    }
    if !bypass_shape_gates && !allow_canonical_hex_key && looks_like_bare_hex_digest(credential) {
        return suppress("bare_hex_digest");
    }
    if !bypass_shape_gates && is_uuid_v4_shape(credential) {
        return suppress("uuid_v4_shape");
    }
    if !bypass_shape_gates && looks_like_truncated_uuid_v4_suffix(credential) {
        return suppress("truncated_uuid_v4_suffix");
    }

    // ── 5c. License-key / serial shape: 5 blocks of 5 alnum chars,
    //         dash-separated (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX). Used
    //         by Microsoft Office / Adobe / Atlassian license keys
    //         and a thousand similar product-key surfaces. Real
    //         credentials almost never carry this shape. From
    //         secretbench-medium-15k: 464 FPs (3rd-largest cluster).
    //
    //         Always-fire (like the labelled-digest / UUID arms above):
    //         the exact 5x5 dash-separated shape (`JQQJN-XXXXX-XXXXX-
    //         XXXXX-XXXXX` Windows/Office/Adobe license keys) is never
    //         the body a service-specific detector regex requests, so a
    //         bare `secret=` keyword anchor cannot override it. A real
    //         service-anchored credential carries a known prefix and has
    //         already exited via `Allow` in `check_markers`.
    if looks_like_dashed_serial_key(credential) {
        return suppress("dashed_serial_key");
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
    // specimen - no production JWT in the wild uses the literal
    // `"sub":"1234567890` claim except cargo-culted from the spec.
    // (The previous belt-and-suspenders `contains(signature)`
    // check failed when an upstream regex value-extractor
    // truncated the captured credential before the signature
    // segment - the prefix-only check is sufficient and survives
    // truncation.)
    if credential.starts_with(RFC7519_EXAMPLE_JWT_PREFIX) {
        return suppress("rfc7519_example_jwt");
    }

    // ── 5e0. Credentials never contain interior whitespace runs.
    //          The dotenv/properties/log-line extractors sometimes
    //          capture the entire RHS as the credential when the
    //          source line is `TOKEN=Session opened with handle
    //          XYZ. See documentation.` - multi-word English
    //          prose with a high-entropy substring is never a
    //          real credential. SecretBench-medium 15k seed-0:
    //          68 FPs from lorem-with-high-entropy.
    if looks_like_prose_whitespace_run(credential) {
        return suppress("prose_whitespace");
    }

    // ── 5e1. AWS IAM resource ARNs (`arn:aws:iam::ACCT:role/...`,
    //          `:user/`, `:group/`, `:policy/`, `:instance-profile/`)
    //          are identifiers, not credentials - they only name a
    //          resource, they don't authenticate against it.
    //          Other ARN namespaces (e.g. `secretsmanager:*:secret:*`,
    //          `rds:*:cluster:*`) ARE credential REFERENCES that
    //          downstream detectors should keep firing on, so the
    //          gate is intentionally narrow to the IAM namespace.
    //          SecretBench-medium 15k seed-0: 27 FPs from aws-arn
    //          (all IAM role ARNs).
    if crate::suppression::shape::looks_like_aws_iam_arn(credential) {
        return suppress("aws_iam_arn");
    }

    // ── 5e2. HTML colour codes (`#RGB`, `#RRGGBB`, `#RRGGBBAA`). 3, 6,
    //          or 8 hex digits prefixed by `#`. Real credentials are
    //          never prefixed with `#`. SecretBench-medium 15k seed-0:
    //          22 FPs from html-color.
    if let Some(body) = credential.strip_prefix('#') {
        if (body.len() == 3 || body.len() == 6 || body.len() == 8)
            && body.chars().all(|c| c.is_ascii_hexdigit())
        {
            return suppress("html_color");
        }
    }

    // ── 5e3. Template placeholders wrapped in `{...}`, `<...>`,
    //          `${...}`, `{{...}}`. Real credentials are never
    //          delivered wrapped in brace/angle markers. The
    //          dotenv/yaml extractor sometimes preserves these
    //          wrappers when the placeholder is the entire RHS.
    //          SecretBench-medium 15k seed-0: 41 FPs from
    //          template-placeholder.
    if looks_like_bracketed_template_placeholder(credential.trim()) {
        return suppress("template_placeholder");
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
    if !bypass_shape_gates
        && !high_entropy_base64_candidate
        && !allow_base64_blob_shape
        && !allow_encoded_text_secret
        && looks_like_standard_base64_blob(credential)
    {
        return suppress("base64_blob");
    }

    // ── 6. Algorithmic placeholder detection ──
    // Credentials dominated by filler after stripping known prefixes.
    if !allow_canonical_hex_key && crate::context::is_known_example_credential(credential) {
        if bypass_shape_gates && credential.chars().all(|c| c.is_ascii_hexdigit()) {
            // Keep named hex detectors alive (e.g. Algolia admin key)
        } else {
            return suppress("algorithmic_placeholder");
        }
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
            return suppress("doc_placeholder_word");
        }
    }

    // ── 8. Path-based heuristic ──
    if let Some(path) = path {
        let is_example_path =
            crate::platform_compat::path_has_any_component(path, &*EXAMPLE_PATH_COMPONENTS);
        if is_example_path && super::doc_markers::upper_contains_token(&upper, "EXAMPLE") {
            return suppress("example_path_marker");
        }
    }

    // ── 9. Base64-decode-and-recheck ──
    //          Bench fixtures (notably kubernetes-secret-shape yaml in
    //          the SecretBench mirror) wrap placeholder/hash/UUID/ARN
    //          payloads in base64 inside `data:` fields. A k8s-secret
    //          detector match on the outer base64 wrapper bypasses the
    //          inner gates above because the OUTER token is just
    //          opaque base64 - none of the EXAMPLE / PLACEHOLDER /
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
    if !skip_b64_decode_recheck && !allow_encoded_text_secret {
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
            {
                return suppression_stage_inner(
                    &decoded,
                    path,
                    context,
                    source_type,
                    true,
                    bypass_shape_gates,
                    None,
                    allow_canonical_hex_key,
                    false,
                    false,
                );
            }
        }
    }
    None
}

pub(crate) fn decoded_benign_text_reason(credential: &str) -> Option<&'static str> {
    let decoded = try_decode_b64_to_utf8(credential)?;
    let decoded = decoded.trim();
    if decoded.is_empty()
        || decoded.len() > credential.len()
        || !decoded
            .chars()
            .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
    {
        return None;
    }

    if decoded_looks_like_labelled_hash(decoded) {
        return Some("decoded_labelled_hash_digest");
    }
    // Same length set as the direct bare-hex arm (32/40/48/56/64/72/128) so a
    // base64-wrapped md5 (32) / sha1 (40) digest is suppressed too, the old
    // 56|64|72|128 gate here dropped the md5/sha1 lengths and leaked them.
    //
    // This is context-FREE (it only sees the base64 value): a decoded hex32 is
    // indistinguishable from an md5 here, so it CANNOT decide "AES key vs hash".
    // That discrimination is the CALLER's job, a decoded canonical hex key
    // assigned to a STRONG credential keyword (`api-key: <b64>`) is exempted
    // BEFORE this arm via `decoded_hex_key_is_strong_anchored`, mirroring the
    // direct path's `is_strong_keyword_anchored_hex_key`. Keeping this arm
    // unconditional preserves the bare-md5/sha1 suppression contract.
    if looks_like_bare_hex_digest(decoded) {
        return Some("decoded_bare_hash_digest");
    }
    if looks_like_dashed_serial_key(decoded) {
        return Some("decoded_dashed_serial_key");
    }
    if is_uuid_v4_shape(decoded) {
        return Some("decoded_uuid_v4_shape");
    }
    if decoded.contains(RFC7519_EXAMPLE_JWT_PREFIX) {
        return Some("decoded_rfc7519_example_jwt");
    }
    if crate::suppression::shape::looks_like_aws_iam_arn(decoded) {
        return Some("decoded_aws_iam_arn");
    }
    if looks_like_bracketed_template_placeholder(decoded) {
        return Some("decoded_template_placeholder");
    }
    if looks_like_prose_whitespace_run(decoded) {
        return Some("decoded_prose_whitespace");
    }
    if crate::context::is_known_example_credential(decoded)
        || crate::placeholder_words::contains_placeholder_word(decoded)
    {
        return Some("decoded_placeholder");
    }

    None
}

fn decoded_looks_like_labelled_hash(decoded: &str) -> bool {
    if looks_like_prefixed_hash_digest(decoded) {
        return true;
    }
    for &label in HASH_ALGO_INTEGRITY_LABELS {
        let Some(idx) = decoded.find(label) else {
            continue;
        };
        let body = &decoded[idx + label.len()..];
        // Same 40-char base64 integrity floor as the canonical owner: the two
        // sites carried divergent floors (32 here vs 40 there) for the same
        // labelled-integrity-body test.
        if looks_like_base64_integrity_body(body) {
            return true;
        }
    }
    false
}
