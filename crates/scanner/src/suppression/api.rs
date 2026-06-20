//! Public suppression entry points. The scanner calls one of these three
//! per finding; they apply the path / shape pre-checks unique to each
//! call site, then delegate the rest to [`super::decision::should_suppress_inner`].

use super::decision::should_suppress_inner;
use super::path_filter::{looks_like_secret_scanner_source, looks_like_vendored_minified_path};
use super::shape::{
    contains_uuid_v4_substring, looks_like_credential_colliding_punctuation,
    looks_like_email_address, looks_like_pure_identifier, looks_like_regex_literal_tail,
    looks_like_scheme_prefixed_uri, looks_like_syntactic_punctuation_marker,
    looks_like_url_or_path_segment, looks_like_word_separated_identifier,
};
use super::token_randomness::{keep_identifier_gate, keep_word_separated_gate};
use crate::context;

/// Check if a credential should be suppressed (e.g., if it is a known example token).
#[cfg(test)]
pub(crate) fn should_suppress_known_example_credential(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
) -> bool {
    should_suppress_known_example_credential_with_source(credential, path, context, None)
}

/// Variant of [`should_suppress_known_example_credential`] that also takes the
/// chunk's `source_type`. When the credential arrived through an
/// **adversarial-evasion decoder** (reverse, Caesar/ROT-N), the EXAMPLE-token
/// suppression is skipped - legitimate test fixtures don't typically reverse
/// or rotate their EXAMPLE markers; only attackers building evasions do, so
/// the marker becomes evidence FOR a real leak rather than against it.
///
/// Other decoders (base64, hex, URL) decode legitimate transport encodings
/// where EXAMPLE-suppression remains appropriate, so we don't blanket-bypass
/// the rule on every decoder origin.
#[cfg(any(feature = "entropy", feature = "simdsieve", test))]
pub(crate) fn should_suppress_known_example_credential_with_source(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
) -> bool {
    should_suppress_inner(
        credential,
        path,
        context,
        source_type,
        false,
        false,
        None,
        false,
        false,
        false,
    )
}

/// Entropy-aware variant for high-entropy generic/entropy fallbacks.
///
/// `allow_canonical_hex_key` (KH-L-0110): set by the generic keyword-bridge when
/// the value is a COMPLETE pure-hex value of canonical key length (32/48)
/// anchored by a STRONG credential keyword — exempts it from the bare-hex-digest
/// gate only (see [`super::decision::should_suppress_inner`]).
///
/// `allow_base64_blob_shape`: set only for the isolated full-line entropy lane.
/// It releases the shape-only random-base64 gate while keeping decoded-content
/// checks alive, so a standalone opaque token can surface but decoded examples,
/// hashes, UUIDs, prose, and placeholders still fail closed.
pub(crate) fn should_suppress_known_example_credential_with_source_and_entropy(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
    entropy: f64,
    allow_canonical_hex_key: bool,
    allow_base64_blob_shape: bool,
    allow_encoded_text_secret: bool,
) -> bool {
    should_suppress_inner(
        credential,
        path,
        context,
        source_type,
        false,
        false,
        Some(entropy),
        allow_canonical_hex_key,
        allow_base64_blob_shape,
        allow_encoded_text_secret,
    )
}

/// Variant for named-detector findings that have already matched a
/// service-specific anchor (e.g. `ALGOLIA_ADMIN_KEY=<32hex>`). When set,
/// the shape-based gates (pure-hash-digest, UUID, b64-blob, dashed-serial,
/// hex-uniformity) are bypassed because the regex anchor IS the positive
/// evidence - a 32-hex value after `ALGOLIA_ADMIN_KEY=` is an Algolia key,
/// NOT an MD5. Use ONLY from detector paths whose regex requires a
/// service-keyword anchor in the alternation list.
#[cfg(test)]
pub(crate) fn should_suppress_named_detector_finding(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
    detector_id: &str,
) -> bool {
    should_suppress_named_detector_finding_weak(
        credential,
        path,
        context,
        source_type,
        detector_id,
        false,
    )
}

/// Weak-anchor-aware variant of [`should_suppress_named_detector_finding`].
///
/// `weak_anchor` is the structural classification produced by
/// [`detector_weak_anchor`] at the scan call site (which has the full
/// [`keyhog_core::DetectorSpec`]). When `true`, the detector relies on a
/// generic keyword anchor with a broad / hash-shaped capture, so the
/// shape-suppression gates that protect the `generic-*` / `entropy-*`
/// fallbacks stay engaged instead of being bypassed. The id-only public
/// wrapper above passes `false` for callers that have not computed the
/// structural classification.
pub(crate) fn should_suppress_named_detector_finding_weak(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
    detector_id: &str,
    weak_anchor: bool,
) -> bool {
    // Shape filters split into two tiers based on whether the shape
    // can legitimately appear as the body of a real service-anchored
    // credential.
    //
    // **Tier A - applies to ALL detectors.** Only `punctuation_decorated`
    // stays universal - `--api-secret`, `&password`, `Password:` are
    // grammar / syntax markers, never the body of a real credential
    // regardless of which detector matched.
    //
    // **Tier B - generic-* / entropy-* only.** These shapes CAN appear
    // as legitimate credential bodies when paired with a service-
    // specific regex anchor. The anchor is positive evidence that the
    // value is a credential, so the shape filter would be wrong to drop
    // it. (Examples the contract corpus enforces:
    //   * `powerbi-credentials` - body IS a UUID
    //   * `mongodb-atlas-credentials` - body IS `mongodb://...` URI
    //   * `cockroachdb-api-key` - body has underscore-separated words
    //   * `avalanche-api-credentials` - body IS an RPC URL
    //   * `aws-secret-access-key` - body has `/+=` URL-segment chars
    // These all DROPPED when the Tier-B filters fired on named
    // detectors. The generic-* / entropy-* fallbacks have no anchor -
    // there the shape filter IS the only positive-evidence gate, so
    // it must stay.)
    //
    // The previous flow applied Tier B universally and dropped 400+
    // contract evasions. See task #41 + the 2026-05-27 audit.
    let apply_tier_b = is_generic_or_entropy(detector_id, weak_anchor);

    // KH-L-0414: the contiguous-identifier gate KH-L-0413 lifted on the
    // scan-time generic bridge also fired here on weakly-anchored named /
    // generic-* / entropy-* findings, dropping real random passwords a service
    // detector flagged. Gate it on the SHARED `keep_identifier_gate` so a random
    // token (`gjbubxsu`) is recovered while a dictionary reference
    // (`getUserName`) still suppresses — one discriminator, both paths.
    if apply_tier_b && keep_identifier_gate(credential) && looks_like_pure_identifier(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "pure_identifier_no_digit",
        );
        return true;
    }
    // The word-separated gate uses the STRICTER `keep_word_separated_gate`
    // (mirrors the generic-bridge path): the English bigram model mis-scores
    // acronym fragments (`d2i_PKCS7_bio`, `curlx_memdup0`) as random, so the lift
    // is trusted only for all-lowercase-letter random tokens. See the matching
    // note in `phase2_generic_shape::generic_value_shape_rejected`.
    if apply_tier_b
        && keep_word_separated_gate(credential)
        && looks_like_word_separated_identifier(credential)
    {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "word_separated_identifier",
        );
        return true;
    }
    if apply_tier_b && looks_like_scheme_prefixed_uri(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "scheme_prefixed_uri",
        );
        return true;
    }
    // Tier A: pure syntactic markers (`--flag`, `&ptr`, `@attr`, `$var`,
    // `Label:`) are never a credential body - suppress for every detector.
    if looks_like_syntactic_punctuation_marker(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "syntactic_punctuation_marker",
        );
        return true;
    }
    // Tier B: `/`-led base64, `!`-led / `!`-trailed secrets look decorated but
    // are valid credential bodies. Only an FP signal for unanchored generic/
    // entropy matches; a named service-anchored detector has already proven
    // these bytes are the credential, so DON'T suppress there.
    if apply_tier_b && looks_like_credential_colliding_punctuation(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "credential_colliding_punctuation",
        );
        return true;
    }
    if apply_tier_b && looks_like_url_or_path_segment(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "url_or_path_segment",
        );
        return true;
    }
    // Captured value contains a UUID v4 / RFC-4122 substring anywhere.
    // Tier B because many real credentials are UUIDs (powerbi
    // client_id, opsgenie heartbeat, docusign integration key,
    // launchdarkly sdk-key, etc.) - only suppress in generic/entropy
    // paths where there's no service anchor.
    if apply_tier_b && contains_uuid_v4_substring(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "contains_uuid_v4",
        );
        return true;
    }
    // Email-address shape: `noreply@gogs.localhost` (gogs golden test
    // ini), `bob.norman@mail.example.com` (shopify test response).
    // Email addresses are public identifiers, not credentials.
    if looks_like_email_address(credential) {
        crate::telemetry::record_example_suppression("pipeline", path, credential, "email_address");
        return true;
    }
    // Vendored 3rd-party minified bundle path: applies to ALL detectors,
    // not just generic-*. A "secret-like" sequence in a minified
    // codemirror/pdfjs/jquery/etc. bundle is never a real leak.
    if looks_like_vendored_minified_path(path) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "vendored_minified_path",
        );
        return true;
    }
    // Native-binary string extraction (`filesystem:binary-strings`,
    // `filesystem/archive-binary`): the file is an ELF / Mach-O / PE /
    // wasm / archived binary whose printable strings were extracted as
    // a fallback. Short-prefix detectors (openai `sk-`, stabilityai
    // `sk-`, helicone `sk-`/`pk-`/`eu-`, clickup `pk_`, AKIA / ASIA,
    // K00M, AIza, dn_, …) generate noise on random compiled-code byte
    // sequences that happen to start with the prefix. A real credential
    // embedded in a native binary is best caught via the optional
    // `binary` feature (Ghidra-based extraction with context), not via
    // brute-force strings. Skip every named-detector finding here so
    // we don't ship FPs from compiled apps' rodata.
    if source_type.is_some_and(|s| s.contains("binary-strings") || s.contains("archive-binary")) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "native_binary_strings",
        );
        return true;
    }
    // The file at `path` is itself a secret scanner - every detector
    // routinely matches its own regex definitions inside the source.
    if looks_like_secret_scanner_source(path) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "secret_scanner_source",
        );
        return true;
    }
    // Files explicitly marked as base64 (`.b64`, `.base64`, or basename
    // starting with `base64_` / containing `base64_string`) hold base64-
    // encoded blobs - usually images or binaries that the operator
    // wants the base64 decoder to handle. Raw text-mode hits inside the
    // base64 stream (AIza, sk-, ASIA, etc.) are alphabet coincidences,
    // not credentials. The base64-decoder pass produces a separate
    // `filesystem/base64` chunk with the decoded content; that chunk
    // hits `has_binary_magic` if it's image/binary, otherwise it's
    // scanned normally.
    if path.is_some_and(|p| {
        // Case-insensitive checks over raw bytes - avoids the per-match
        // `p.to_ascii_lowercase()` allocation. Endswith checks are also
        // case-insensitive so `.B64` / `.BASE64` extensions still suppress.
        let bytes = p.as_bytes();
        if crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b".b64")
            || crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b".base64")
        {
            return true;
        }
        let basename = crate::platform_compat::path_basename_bytes(bytes);
        basename
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"base64_"))
            || crate::ascii_ci::ci_find(basename, b"base64_string")
            || basename.eq_ignore_ascii_case(b"base64.txt")
    }) && source_type.is_some_and(|s| s == "filesystem")
    {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "raw_base64_file",
        );
        return true;
    }
    // Regex-literal tail: applies to ALL detectors. A capture ending
    // in `)/g`, `)/g,`, `]+`, `})\\b`, etc. is a JS/Go/Python regex
    // pattern definition (often in another secret-scanner's own
    // source code), not a credential. claude-code's Feedback.tsx
    // has 1 `hot-aws_key` finding on its own AWS regex definition
    // `/AKIA[A-Z0-9]{16,17}/g,`.
    if looks_like_regex_literal_tail(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "regex_literal_tail",
        );
        return true;
    }
    // Generic detectors (generic-secret, generic-private-key, entropy-*)
    // never use this bypass - their anchor is keyword-class, not
    // service-specific, and shape gates are load-bearing for them.
    // Weakly anchored named detectors (e.g. datadog-api-key) also do not
    // bypass shape gates to prevent false positive traps from triggering.
    let bypass_shape_gates = !detector_id.starts_with("generic-")
        && !detector_id.starts_with("entropy-")
        && !weak_anchor
        && detector_id != "private-key";
    let allow_encoded_text_secret = detector_id.starts_with("generic-")
        && crate::decode_structure::decodes_to_printable_text(credential);
    should_suppress_inner(
        credential,
        path,
        context,
        source_type,
        false,
        bypass_shape_gates,
        None,
        false,
        false,
        allow_encoded_text_secret,
    )
}

/// True if the detector that fired has no service-specific anchor -
/// the generic `generic-*` / `entropy-*` fallbacks, or a named detector
/// that the structural classifier flagged as weakly anchored
/// (`weak_anchor`). Used by [`should_suppress_named_detector_finding_weak`]
/// to decide whether the Tier-B shape filters apply: strongly anchored
/// detectors have positive evidence in their regex that the shape filter
/// would otherwise destroy.
fn is_generic_or_entropy(detector_id: &str, weak_anchor: bool) -> bool {
    detector_id.starts_with("generic-") || detector_id.starts_with("entropy-") || weak_anchor
}

/// Detectors that are weakly anchored but NOT caught by the structural
/// broad-identifier rule in [`detector_weak_anchor`], because their
/// capture is pure-hex (`[a-f0-9]{32}` / `{40}`) - structurally identical
/// to a legitimate hex API key such as `algolia-admin-api-key`, so shape
/// alone cannot tell them apart - or a high-minimum broad identifier
/// (`{20,}` / `{32}`). These were measured FP-prone on the SecretBench
/// mirror corpus and so remain an explicit, corpus-derived data set rather
/// than a structural derivation.
const RESIDUAL_WEAK_ANCHORED: &[&str] = &[
    "aerisweather-api-credentials",
    "base-api-credentials",
    "flickr-api-key",
    "census-api-key",
    "workato-api-credentials",
    "adobe-api-key",
    "alchemy-api-key",
    "azure-openai-api-key",
    "datadog-api-key",
    "etherscan-api-key",
    "spotify-client-credentials",
    "bamboohr-api-key",
    "calendly-api-key",
    "crowdin-api-token",
    "github-oauth-secret",
    "sonarcloud-token",
    "activecampaign-api-key",
    "chef-automate-token",
    "foundation-api-key",
    "getresponse-api-key",
    "rudder-api-token",
];

/// Structurally classify whether a named detector is *weakly anchored*:
/// it relies on a generic keyword anchor (`api_key=`, `token=`, …) with a
/// capture that can collide with non-secrets, so the shape-suppression
/// gates must stay engaged (it should be treated like a `generic-*`
/// fallback rather than a service-fingerprinted detector).
///
/// Derived at the scan call site from the detector's own regex shape so
/// every present and future detector with this shape is covered - this
/// replaces a hand-maintained ID allowlist that drifted out of sync with
/// the detector corpus. The broad-identifier class (Category C of
/// `docs/EXECUTION_PLAN.md`: a `[a-zA-Z0-9_-]`-style capture with a small
/// minimum length that matches any short identifier) is derived here; the
/// pure-hex class, which is shape-indistinguishable from real hex keys,
/// stays in [`RESIDUAL_WEAK_ANCHORED`].
pub(crate) fn detector_weak_anchor(spec: &keyhog_core::DetectorSpec) -> bool {
    let id = spec.id.as_str();
    if id.starts_with("generic-") || id.starts_with("entropy-") || id == "private-key" {
        return false;
    }
    if spec.min_confidence.is_some() {
        return false;
    }
    RESIDUAL_WEAK_ANCHORED.contains(&id)
        || spec
            .patterns
            .iter()
            .any(|p| has_broad_identifier_capture(&p.regex))
}

/// True if `regex` contains a capture group whose entire body is a single
/// full-alphabet identifier character class (`[a-zA-Z0-9_-]` and close
/// variants, NOT hex-only `[a-f0-9]`) with a minimum repeat of 0 or 1
/// (`+`, `*`, `{0,..}`, `{1,..}`, `{1}`). That is the broad-identifier
/// false-positive shape from Category C of `docs/EXECUTION_PLAN.md`: a
/// minimum length of one means the capture matches ANY short identifier
/// (function name, variable, kwarg default) sitting after the detector's
/// keyword anchor. Higher minimums (e.g. `{8,}`, `{16}`) describe real
/// fixed-shape keys and are deliberately NOT flagged.
fn has_broad_identifier_capture(regex: &str) -> bool {
    let mut search_from = 0;
    while let Some(rel) = regex[search_from..].find("([") {
        let class_open = search_from + rel + 1; // index of '['
        let Some(rel_close) = regex[class_open..].find(']') else {
            break;
        };
        let class_close = class_open + rel_close; // index of ']'
        let body = &regex[class_open + 1..class_close];
        if let Some(min_len) = group_capture_min_len(&regex[class_close + 1..]) {
            if min_len <= 1 && is_full_alpha_identifier_class(body) {
                return true;
            }
        }
        search_from = class_close + 1;
    }
    false
}

/// If `after` (the slice immediately following a class's closing `]`) is a
/// quantifier that closes the capture group right after it, return the
/// quantifier's minimum repeat count. `Some` only when the group is exactly
/// `([class]<quant>)`.
fn group_capture_min_len(after: &str) -> Option<usize> {
    let bytes = after.as_bytes();
    match bytes.first()? {
        b'+' if bytes.get(1) == Some(&b')') => Some(1),
        b'*' if bytes.get(1) == Some(&b')') => Some(0),
        b'{' => {
            let close = after.find('}')?;
            if after.as_bytes().get(close + 1) != Some(&b')') {
                return None;
            }
            after[1..close].split(',').next()?.parse::<usize>().ok() // LAW10: malformed input => None (fail-closed at the boundary; not a valid value), recall-safe
        }
        _ => None,
    }
}

/// True if `body` (a regex character-class body, without the brackets) is
/// composed only of identifier range/literal tokens AND includes a full
/// alphabetic range (`a-z`, `A-Z`, or `\w`). Hex-only classes (`a-f0-9`)
/// return false because `a-f` is not an accepted token.
fn is_full_alpha_identifier_class(body: &str) -> bool {
    const TOKENS: &[&str] = &["a-z", "A-Z", "0-9", "\\w", "\\d", "_", "-"];
    let mut full_alpha = false;
    let mut rest = body;
    while !rest.is_empty() {
        match TOKENS.iter().find(|t| rest.starts_with(**t)) {
            Some(t) => {
                if *t == "a-z" || *t == "A-Z" || *t == "\\w" {
                    full_alpha = true;
                }
                rest = &rest[t.len()..];
            }
            None => return false,
        }
    }
    full_alpha
}
