//! Public suppression entry points. The scanner calls one of these three
//! per finding; they apply the path / shape pre-checks unique to each
//! call site, then delegate the rest to [`super::decision::should_suppress_inner`].

use super::decision::should_suppress_inner;
use super::path_filter::{looks_like_secret_scanner_source, looks_like_vendored_minified_path};
use super::shape::{
    contains_uuid_v4_substring, looks_like_email_address,
    looks_like_punctuation_decorated_identifier, looks_like_pure_identifier,
    looks_like_regex_literal_tail, looks_like_scheme_prefixed_uri, looks_like_url_or_path_segment,
    looks_like_word_separated_identifier,
};
use crate::context;

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
/// suppression is skipped - legitimate test fixtures don't typically reverse
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
/// evidence - a 32-hex value after `ALGOLIA_ADMIN_KEY=` is an Algolia key,
/// NOT an MD5. Use ONLY from detector paths whose regex requires a
/// service-keyword anchor in the alternation list.
pub fn should_suppress_named_detector_finding(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
    detector_id: &str,
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
    let apply_tier_b = is_generic_or_entropy_detector(detector_id);

    if apply_tier_b && looks_like_pure_identifier(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "pure_identifier_no_digit",
        );
        return true;
    }
    if apply_tier_b && looks_like_word_separated_identifier(credential) {
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
    if looks_like_punctuation_decorated_identifier(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "punctuation_decorated_identifier",
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
        // Both `/` and `\` so Windows paths (`C:\foo\base64_x.txt`)
        // collapse to the same basename. Same rationale as the
        // fallback_entropy path-gate sibling.
        let basename = bytes
            .iter()
            .rposition(|&b| b == b'/' || b == b'\\')
            .map(|i| &bytes[i + 1..])
            .unwrap_or(bytes);
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

/// True if the detector that fired has no service-specific anchor -
/// only the generic `generic-password`, `generic-secret`,
/// `entropy-*` fallbacks. Used by [`should_suppress_named_detector_finding`]
/// to decide whether the Tier-B shape filters apply: anchored
/// detectors (everything else) have positive evidence in their regex
/// that the shape filter would otherwise destroy.
fn is_generic_or_entropy_detector(detector_id: &str) -> bool {
    detector_id.starts_with("generic-") || detector_id.starts_with("entropy-")
}
