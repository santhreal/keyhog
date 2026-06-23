//! Public suppression entry points. The scanner calls one of these three
//! per finding; they apply the path / shape pre-checks unique to each
//! call site, then delegate the rest to [`super::decision::suppression_stage_inner`].

use super::decision::suppression_stage_inner;
use super::path_filter::{
    looks_like_hot_pattern_base64_path, looks_like_raw_base64_file_path,
    looks_like_secret_scanner_source, looks_like_vendored_minified_path,
};
use super::shape::{
    contains_uuid_v4_substring, looks_like_credential_colliding_punctuation,
    looks_like_email_address, looks_like_pure_identifier, looks_like_regex_literal_tail,
    looks_like_scheme_prefixed_uri, looks_like_syntactic_punctuation_marker,
    looks_like_url_or_path_segment, looks_like_word_separated_identifier,
    public_noncredential_shape_with_randomness, PublicShapeScope,
};
use super::token_randomness::{
    keep_identifier_gate_with_randomness, keep_word_separated_gate_with_randomness, TokenRandomness,
};
use crate::context;

#[derive(Debug, Clone, Copy)]
pub(crate) struct KnownExampleSuppressionCtx<'a> {
    path: Option<&'a str>,
    context: context::CodeContext,
    source_type: Option<&'a str>,
    entropy: Option<f64>,
    allow_canonical_hex_key: bool,
    allow_base64_blob_shape: bool,
    allow_encoded_text_secret: bool,
}

impl<'a> KnownExampleSuppressionCtx<'a> {
    #[cfg(any(feature = "simdsieve", test))]
    pub(crate) fn new(
        path: Option<&'a str>,
        context: context::CodeContext,
        source_type: Option<&'a str>,
    ) -> Self {
        Self {
            path,
            context,
            source_type,
            entropy: None,
            allow_canonical_hex_key: false,
            allow_base64_blob_shape: false,
            allow_encoded_text_secret: false,
        }
    }

    pub(crate) fn with_entropy(
        path: Option<&'a str>,
        context: context::CodeContext,
        source_type: Option<&'a str>,
        entropy: f64,
        allow_canonical_hex_key: bool,
        allow_base64_blob_shape: bool,
        allow_encoded_text_secret: bool,
    ) -> Self {
        Self {
            path,
            context,
            source_type,
            entropy: Some(entropy),
            allow_canonical_hex_key,
            allow_base64_blob_shape,
            allow_encoded_text_secret,
        }
    }
}

pub(crate) fn suppress_known_example_credential_stage(
    credential: &str,
    ctx: KnownExampleSuppressionCtx<'_>,
) -> Option<crate::adjudicate::StageId> {
    suppression_stage_inner(
        credential,
        ctx.path,
        ctx.context,
        ctx.source_type,
        false,
        false,
        ctx.entropy,
        ctx.allow_canonical_hex_key,
        ctx.allow_base64_blob_shape,
        ctx.allow_encoded_text_secret,
    )
}

#[cfg(any(feature = "simdsieve", test))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct HotPatternSuppressionCtx<'a> {
    path: Option<&'a str>,
    source_type: &'a str,
    min_credential_len: usize,
}

#[cfg(any(feature = "simdsieve", test))]
impl<'a> HotPatternSuppressionCtx<'a> {
    pub(crate) fn new(
        path: Option<&'a str>,
        source_type: &'a str,
        min_credential_len: usize,
    ) -> Self {
        Self {
            path,
            source_type,
            min_credential_len,
        }
    }
}

#[cfg(feature = "simdsieve")]
pub(crate) fn hot_pattern_suppression_stage(
    credential: &str,
    ctx: HotPatternSuppressionCtx<'_>,
) -> Option<crate::adjudicate::HotPatternSignal> {
    if credential.len() < ctx.min_credential_len {
        return Some(crate::adjudicate::HotPatternSignal::ShapeGate(
            "hot_below_min_length",
        ));
    }
    let example_ctx = KnownExampleSuppressionCtx::new(
        ctx.path,
        context::CodeContext::Unknown,
        Some(ctx.source_type),
    );
    if let Some(stage_id) = suppress_known_example_credential_stage(credential, example_ctx) {
        return Some(crate::adjudicate::HotPatternSignal::SuppressionStage(
            stage_id,
        ));
    }
    if looks_like_regex_literal_tail(credential) {
        return Some(crate::adjudicate::HotPatternSignal::ShapeGate(
            "hot_regex_literal_tail",
        ));
    }
    if looks_like_vendored_minified_path(ctx.path) {
        return Some(crate::adjudicate::HotPatternSignal::ShapeGate(
            "hot_vendored_minified_path",
        ));
    }
    if ctx.source_type.contains("binary-strings") || ctx.source_type.contains("archive-binary") {
        return Some(crate::adjudicate::HotPatternSignal::ShapeGate(
            "hot_binary_source",
        ));
    }
    if looks_like_secret_scanner_source(ctx.path) {
        return Some(crate::adjudicate::HotPatternSignal::ShapeGate(
            "hot_secret_scanner_source",
        ));
    }
    if looks_like_hot_pattern_base64_path(ctx.path) {
        return Some(crate::adjudicate::HotPatternSignal::ShapeGate(
            "hot_base64_path",
        ));
    }
    None
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct NamedDetectorSuppressionCtx<'a> {
    path: Option<&'a str>,
    context: context::CodeContext,
    source_type: Option<&'a str>,
    detector_id: &'a str,
    weak_anchor: bool,
}

impl<'a> NamedDetectorSuppressionCtx<'a> {
    pub(crate) fn with_weak_anchor(
        path: Option<&'a str>,
        context: context::CodeContext,
        source_type: Option<&'a str>,
        detector_id: &'a str,
        weak_anchor: bool,
    ) -> Self {
        Self {
            path,
            context,
            source_type,
            detector_id,
            weak_anchor,
        }
    }
}

/// Named-detector suppression with explicit structural context.
///
/// `NamedDetectorSuppressionCtx::weak_anchor` is produced by
/// [`detector_weak_anchor`] at the scan call site, which has the full
/// [`keyhog_core::DetectorSpec`]. When it is true, the detector relies on a
/// generic keyword anchor with a broad / hash-shaped capture, so the
/// shape-suppression gates that protect the `generic-*` / `entropy-*`
/// fallbacks stay engaged instead of being bypassed.
pub(crate) fn suppress_named_detector_finding(
    credential: &str,
    ctx: NamedDetectorSuppressionCtx<'_>,
) -> bool {
    suppress_named_detector_finding_stage(credential, ctx).is_some()
}

pub(crate) fn suppress_named_detector_finding_stage(
    credential: &str,
    ctx: NamedDetectorSuppressionCtx<'_>,
) -> Option<crate::adjudicate::StageId> {
    let path = ctx.path;
    let context = ctx.context;
    let source_type = ctx.source_type;
    let detector_id = ctx.detector_id;
    let weak_anchor = ctx.weak_anchor;
    let randomness = TokenRandomness::for_candidate(credential);
    let shape_stage = |reason| Some(crate::adjudicate::StageId::ShapeGate(reason));

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

    if apply_tier_b && source_type.is_some_and(|source| source.contains("/caesar")) {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "caesar_generic_fallback",
        );
        return shape_stage("caesar_generic_fallback");
    }

    if apply_tier_b {
        if let Some(reason) = public_noncredential_shape_with_randomness(
            credential,
            PublicShapeScope::WeakAnchor,
            &randomness,
        ) {
            crate::adjudicate::record_example_suppression("pipeline", path, credential, reason);
            return shape_stage(reason);
        }
    }

    // KH-L-0414: the contiguous-identifier gate KH-L-0413 lifted on the
    // scan-time generic bridge also fired here on weakly-anchored named /
    // generic-* / entropy-* findings, dropping real random passwords a service
    // detector flagged. Gate it on the SHARED `keep_identifier_gate` so a random
    // token (`gjbubxsu`) is recovered while a dictionary reference
    // (`getUserName`) still suppresses — one discriminator, both paths.
    if apply_tier_b
        && keep_identifier_gate_with_randomness(credential, &randomness)
        && looks_like_pure_identifier(credential)
    {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "pure_identifier_no_digit",
        );
        return shape_stage("pure_identifier_no_digit");
    }
    // The word-separated gate uses the STRICTER `keep_word_separated_gate`
    // (mirrors the generic-bridge path): the English bigram model mis-scores
    // acronym fragments (`d2i_PKCS7_bio`, `curlx_memdup0`) as random, so the lift
    // is trusted only for all-lowercase-letter random tokens. See the matching
    // note in `phase2_generic_shape::generic_value_shape_rejected`.
    if apply_tier_b
        && keep_word_separated_gate_with_randomness(credential, &randomness)
        && looks_like_word_separated_identifier(credential)
    {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "word_separated_identifier",
        );
        return shape_stage("word_separated_identifier");
    }
    if apply_tier_b && looks_like_scheme_prefixed_uri(credential) {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "scheme_prefixed_uri",
        );
        return shape_stage("scheme_prefixed_uri");
    }
    // Tier A: pure syntactic markers (`--flag`, `&ptr`, `@attr`, `$var`,
    // `Label:`) are never a credential body - suppress for every detector.
    if looks_like_syntactic_punctuation_marker(credential) {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "syntactic_punctuation_marker",
        );
        return shape_stage("syntactic_punctuation_marker");
    }
    // Tier B: `/`-led base64, `!`-led / `!`-trailed secrets look decorated but
    // are valid credential bodies. Only an FP signal for unanchored generic/
    // entropy matches; a named service-anchored detector has already proven
    // these bytes are the credential, so DON'T suppress there.
    if apply_tier_b && looks_like_credential_colliding_punctuation(credential) {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "credential_colliding_punctuation",
        );
        return shape_stage("credential_colliding_punctuation");
    }
    if apply_tier_b && looks_like_url_or_path_segment(credential) {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "url_or_path_segment",
        );
        return shape_stage("url_or_path_segment");
    }
    // Captured value contains a UUID v4 / RFC-4122 substring anywhere.
    // Tier B because many real credentials are UUIDs (powerbi
    // client_id, opsgenie heartbeat, docusign integration key,
    // launchdarkly sdk-key, etc.) - only suppress in generic/entropy
    // paths where there's no service anchor.
    if apply_tier_b && contains_uuid_v4_substring(credential) {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "contains_uuid_v4",
        );
        return shape_stage("contains_uuid_v4");
    }
    // Email-address shape: `noreply@gogs.localhost` (gogs golden test
    // ini), `bob.norman@mail.example.com` (shopify test response).
    // Email addresses are public identifiers, not credentials.
    if looks_like_email_address(credential) {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "email_address",
        );
        return shape_stage("email_address");
    }
    // Vendored 3rd-party minified bundle path: applies to ALL detectors,
    // not just generic-*. A "secret-like" sequence in a minified
    // codemirror/pdfjs/jquery/etc. bundle is never a real leak.
    if looks_like_vendored_minified_path(path) {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "vendored_minified_path",
        );
        return shape_stage("vendored_minified_path");
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
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "native_binary_strings",
        );
        return shape_stage("native_binary_strings");
    }
    // The file at `path` is itself a secret scanner - every detector
    // routinely matches its own regex definitions inside the source.
    if looks_like_secret_scanner_source(path) {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "secret_scanner_source",
        );
        return shape_stage("secret_scanner_source");
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
    if looks_like_raw_base64_file_path(path) && source_type.is_some_and(|s| s == "filesystem") {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "raw_base64_file",
        );
        return shape_stage("raw_base64_file");
    }
    // Regex-literal tail: applies to ALL detectors. A capture ending
    // in `)/g`, `)/g,`, `]+`, `})\\b`, etc. is a JS/Go/Python regex
    // pattern definition (often in another secret-scanner's own
    // source code), not a credential. claude-code's Feedback.tsx
    // has 1 `hot-aws_key` finding on its own AWS regex definition
    // `/AKIA[A-Z0-9]{16,17}/g,`.
    if looks_like_regex_literal_tail(credential) {
        crate::adjudicate::record_example_suppression(
            "pipeline",
            path,
            credential,
            "regex_literal_tail",
        );
        return shape_stage("regex_literal_tail");
    }
    // Generic detectors (generic-secret, generic-private-key, entropy-*)
    // never use this bypass - their anchor is keyword-class, not
    // service-specific, and shape gates are load-bearing for them.
    // Weakly anchored named detectors (e.g. datadog-api-key) also do not
    // bypass shape gates to prevent false positive traps from triggering.
    let bypass_shape_gates =
        crate::detector_ids::is_service_anchored_detector(detector_id) && !weak_anchor;
    let allow_encoded_text_secret = crate::detector_ids::is_generic_detector(detector_id)
        && crate::decode_structure::decodes_to_printable_text(credential);
    suppression_stage_inner(
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
/// (`weak_anchor`). Used by [`suppress_named_detector_finding`]
/// to decide whether the Tier-B shape filters apply: strongly anchored
/// detectors have positive evidence in their regex that the shape filter
/// would otherwise destroy.
fn is_generic_or_entropy(detector_id: &str, weak_anchor: bool) -> bool {
    crate::detector_ids::is_generic_or_entropy_detector(detector_id) || weak_anchor
}

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
/// stays in `rules/detector-classification.toml`.
pub(crate) fn detector_weak_anchor(spec: &keyhog_core::DetectorSpec) -> Result<bool, String> {
    let id = spec.id.as_str();
    if crate::detector_ids::is_generic_or_entropy_detector(id)
        || crate::detector_ids::is_private_key_fallback(id)
    {
        return Ok(false);
    }
    if spec.min_confidence.is_some() {
        return Ok(false);
    }
    Ok(crate::detector_classification::is_residual_weak_anchor(id)?
        || spec
            .patterns
            .iter()
            .any(|p| has_broad_identifier_capture(&p.regex)))
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
