//! Public suppression entry points. The scanner calls one of these three
//! per finding; they apply the path / shape pre-checks unique to each
//! call site, then delegate the rest to [`super::decision::suppression_stage_inner`].

use super::decision::suppression_stage_inner;
use super::detector_policy::DetectorSuppressionPolicy;
use super::path_filter::{
    looks_like_raw_base64_file_path, looks_like_secret_scanner_source,
    looks_like_vendored_minified_path,
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
    reject_repeated_blocks: bool,
}

impl<'a> KnownExampleSuppressionCtx<'a> {
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
            reject_repeated_blocks: true,
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
            reject_repeated_blocks: true,
        }
    }

    pub(crate) fn with_repeated_block_policy(mut self, reject: bool) -> Self {
        self.reject_repeated_blocks = reject;
        self
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
        ctx.reject_repeated_blocks,
        ctx.entropy,
        ctx.allow_canonical_hex_key,
        ctx.allow_base64_blob_shape,
        ctx.allow_encoded_text_secret,
    )
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct NamedDetectorSuppressionCtx<'a> {
    path: Option<&'a str>,
    context: context::CodeContext,
    source_type: Option<&'a str>,
    detector_rules: Option<&'a DetectorSuppressionPolicy>,
    service_anchored: bool,
    weak_anchor: bool,
    structural_password_slot: bool,
    allow_canonical_hex_key_material: bool,
}

impl<'a> NamedDetectorSuppressionCtx<'a> {
    pub(crate) fn with_weak_anchor(
        path: Option<&'a str>,
        context: context::CodeContext,
        source_type: Option<&'a str>,
        detector_id: &'a str,
        service_anchored: bool,
        weak_anchor: bool,
        structural_password_slot: bool,
    ) -> Self {
        Self::with_weak_anchor_and_key_material_policy(
            path,
            context,
            source_type,
            test_detector_suppression_rules(detector_id),
            service_anchored,
            weak_anchor,
            structural_password_slot,
            false,
        )
    }

    pub(crate) fn with_weak_anchor_and_key_material_policy(
        path: Option<&'a str>,
        context: context::CodeContext,
        source_type: Option<&'a str>,
        detector_rules: Option<&'a DetectorSuppressionPolicy>,
        service_anchored: bool,
        weak_anchor: bool,
        structural_password_slot: bool,
        allow_canonical_hex_key_material: bool,
    ) -> Self {
        Self {
            path,
            context,
            source_type,
            detector_rules,
            service_anchored,
            weak_anchor,
            structural_password_slot,
            allow_canonical_hex_key_material,
        }
    }
}

/// Dedicated precision gate for syntactically proven password slots.
pub(crate) fn structural_password_slot_rejection(credential: &str) -> Option<&'static str> {
    if credential.bytes().all(|byte| byte.is_ascii_alphabetic())
        && super::token_randomness::is_confident_dictionary_word(credential)
    {
        Some("dictionary_word_placeholder")
    } else if super::token_randomness::has_low_letter_diversity(credential) {
        Some("low_letter_diversity_mask")
    } else {
        None
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
    let detector_rules = ctx.detector_rules;
    let service_anchored = ctx.service_anchored;
    let weak_anchor = ctx.weak_anchor;
    let structural_password_slot = ctx.structural_password_slot;
    let randomness = TokenRandomness::for_candidate(credential);
    let shape_stage = |reason| Some(crate::adjudicate::StageId::ShapeGate(reason));

    // Operator overrides (allowlisted path / value) win over every shape gate,
    // so they run FIRST. The broad per-detector STOPWORD substring heuristic is
    // the least-specific reason and runs LAST (just before `suppression_stage_inner`)
    // so a precise structural gate claims the drop with its own reason.
    if let Some(stage_id) = detector_rules.and_then(|rules| rules.allowlist_stage(path, credential))
    {
        return Some(stage_id);
    }

    // Tier A - universal exact-placeholder gate. A value that IS EXACTLY a
    // placeholder word (`password`, `secret`, `default`, `null`, `none`,
    // `undefined`, `empty`) is never a real credential on ANY detector. The
    // entropy/generic path drops these via `bytes_contain_entropy_placeholder_marker`
    // (Category 5), but NAMED/vendor detectors (e.g. `rabbitmq-management-credentials`
    // capturing `RABBITMQ_PASSWORD=password`) bypass that path, so apply the SAME
    // whole-value exact gate here through the shared `is_exact_entropy_placeholder`
    // owner. Whole-value only: a real credential that merely CONTAINS such a word
    // (`mysecretkey123`) is untouched.
    if crate::placeholder_words::is_exact_entropy_placeholder(credential.as_bytes()) {
        return shape_stage("exact_placeholder_value");
    }

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
    let apply_tier_b = (!service_anchored && !structural_password_slot) || weak_anchor;

    // A detector-wide or exact-pattern structural-password-slot policy proves
    // the slot even when its service is generic. Skipping Tier-B randomness
    // and mask gates keeps real random passwords, but requires two dedicated
    // placeholder checks:
    //   1. the literal dictionary word (`://user:password@host`, `IDENTIFIED BY
    //      'secret'`, `--password welcome`), caught by the bigram model being
    //      CONFIDENT the value is pronounceable English; never a random token
    //      (below the English threshold), a short fail-safe (model returns None),
    //      or a hex digest (no g..z letter);
    //   2. the repetitive / digit-only MASK (`--password xxxxxxxx`, `IDENTIFIED
    //      BY 'XXXXXXXX'`, `--password 12345678`), improbable bigrams, so the
    //      dictionary gate misses it, but fewer than `MIN_DISTINCT_LETTERS`
    //      distinct letters, the same floor `is_random_token` uses, so a genuine
    //      short random password (`i8cr1w!`, 4 distinct letters) is kept.
    // Scoped to this family: a service-anchored detector's structured capture
    // (hex / prefixed key) is never a free-form word, and applying the gate to
    // all strong anchors wrongly suppressed hex keys whose a..f bigrams read as
    // English (rollbar, steam, matomo, …).
    // Weak anchors retain Tier-B, but a declared structural slot must still pass
    // these mask and placeholder checks before the broader gates run.
    if structural_password_slot {
        if let Some(reason) = structural_password_slot_rejection(credential) {
            crate::adjudicate::record_example_suppression("pipeline", path, credential, reason);
            return shape_stage(reason);
        }
    }

    // A GENERIC / weak-anchor match on an evasion decoder's output (`/caesar`,
    // `/reverse`) is coincidental noise. Both decoders share ONE owner so this
    // gate can never diverge from the decision tree's set (was `/caesar`-only,
    // silently leaking `/reverse` generic-fallback noise).
    if apply_tier_b {
        if let Some(reason) = super::decision::evasion_decoder_reason(source_type) {
            crate::adjudicate::record_example_suppression("pipeline", path, credential, reason);
            return shape_stage(reason);
        }
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
    // (`getUserName`) still suppresses (one discriminator, both paths).
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
    // produces an AWS access-key candidate from its own regex definition
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
    // Per-detector STOPWORD substring heuristic runs LAST among the shape gates:
    // every structural gate above (email, exact placeholder, uuid, url segment,
    // …) yields a MORE specific reason, so a value that is really one of those
    // claims that reason instead of a coincidental `stopwords` hit. Set-preserving
    // vs. the old top-of-pipeline placement (a value a stopword would drop is
    // dropped here just the same, only later), except the randomness guard inside
    // deliberately RECOVERS random credentials that merely embed a stopword.
    if let Some(stage_id) =
        detector_rules.and_then(|rules| rules.stopword_stage(path, credential, &randomness))
    {
        return Some(stage_id);
    }
    // Generic detectors such as generic-secret, generic-api-key, and entropy-*
    // retain shape gates because a keyword class is not a structural anchor.
    // A strong service anchor or declared password slot bypasses them unless
    // the exact pattern is explicitly weak.
    let bypass_shape_gates = (service_anchored || structural_password_slot) && !weak_anchor;
    // Canonical pure-hex recall is an explicit detector-TOML decision. Strong
    // anchors already skip generic shape gates; weak anchors may bypass the
    // digest arms only when their compiled detector policy admits the length.
    // Missing policy therefore suppresses digest-shaped values instead of
    // inheriting a scanner-global width list.
    let allow_encoded_text_secret =
        !service_anchored && crate::decode_structure::decodes_to_printable_text(credential);
    let allow_canonical_hex_key = ctx.allow_canonical_hex_key_material;
    suppression_stage_inner(
        credential,
        path,
        context,
        source_type,
        false,
        bypass_shape_gates,
        true,
        None,
        allow_canonical_hex_key,
        false,
        allow_encoded_text_secret,
    )
}

/// Structurally classify whether a named detector is *weakly anchored*:
/// it relies on a generic keyword anchor (`api_key=`, `token=`, …) with a
/// capture that can collide with non-secrets, so the shape-suppression
/// gates must stay engaged (it should be treated like a `generic-*`
/// fallback rather than a service-fingerprinted detector).
///
/// Declared explicitly by detector or pattern `weak_anchor`.
/// Regex text, detector IDs, and confidence floors do not imply this policy.
pub(crate) fn detector_weak_anchor(spec: &keyhog_core::DetectorSpec) -> bool {
    match detector_weak_anchor_base(spec) {
        WeakAnchorBase::Always => true,
        WeakAnchorBase::Never => false,
        WeakAnchorBase::PerPattern => spec.patterns.iter().any(|pattern| pattern.weak_anchor),
    }
}

/// Detector-wide portion of the weak-anchor decision, separated from the
/// explicit per-pattern bit carried by `CompiledPattern`.
///
/// `weak_anchor` keeps the Tier-B shape gates engaged for collision-prone
/// captures. A detector like `servicenow-api-key` mixes a strong instance
/// pattern with a weak username pattern, so the strong one must not inherit the
/// weak sibling's gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WeakAnchorBase {
    /// Always weak regardless of which pattern matched (residual pure-hex list).
    Always,
    /// Never weak.
    Never,
    /// Weak iff the matched pattern declares `weak_anchor = true`.
    PerPattern,
}

pub(crate) fn detector_weak_anchor_base(spec: &keyhog_core::DetectorSpec) -> WeakAnchorBase {
    if spec.weak_anchor {
        return WeakAnchorBase::Always;
    }
    if spec.patterns.iter().any(|pattern| pattern.weak_anchor) {
        WeakAnchorBase::PerPattern
    } else {
        WeakAnchorBase::Never
    }
}

#[cfg(test)]
fn test_detector_suppression_rules(
    detector_id: &str,
) -> Option<&'static DetectorSuppressionPolicy> {
    static RULES: std::sync::LazyLock<DetectorSuppressionPolicy> =
        std::sync::LazyLock::new(DetectorSuppressionPolicy::test_fixture);
    (detector_id == "test-detector").then_some(&RULES)
}

#[cfg(not(test))]
const fn test_detector_suppression_rules(
    _detector_id: &str,
) -> Option<&'static DetectorSuppressionPolicy> {
    None
}

#[cfg(test)]
mod weak_anchor_shape_tests {
    #[test]
    fn test_per_detector_allowlist_and_stopwords() {
        use super::{suppress_named_detector_finding_stage, NamedDetectorSuppressionCtx};
        use crate::context::CodeContext;

        let ctx_allowlisted_path = NamedDetectorSuppressionCtx::with_weak_anchor(
            Some("src/allowlisted_path/file.rs"),
            CodeContext::Unknown,
            Some("filesystem"),
            "test-detector",
            true,
            false,
            false,
        );
        let res = suppress_named_detector_finding_stage("some_secret", ctx_allowlisted_path);
        assert_eq!(
            res,
            Some(crate::adjudicate::StageId::ShapeGate("allowlist_paths"))
        );

        let ctx_normal_path = NamedDetectorSuppressionCtx::with_weak_anchor(
            Some("src/other_path/file.rs"),
            CodeContext::Unknown,
            Some("filesystem"),
            "test-detector",
            true,
            false,
            false,
        );
        let res = suppress_named_detector_finding_stage("allowlisted_value_12345", ctx_normal_path);
        assert_eq!(
            res,
            Some(crate::adjudicate::StageId::ShapeGate("allowlist_values"))
        );

        let res =
            suppress_named_detector_finding_stage("contains_stopword_here_secret", ctx_normal_path);
        assert_eq!(
            res,
            Some(crate::adjudicate::StageId::ShapeGate("stopwords"))
        );

        let res =
            suppress_named_detector_finding_stage("contains_STOPWORD_HERE_secret", ctx_normal_path);
        assert_eq!(
            res,
            Some(crate::adjudicate::StageId::ShapeGate("stopwords"))
        );

        let incidental_stopword = "pxidztpv_stopword_here_nxruoapftabufvcsa";
        assert!(
            crate::suppression::token_randomness::is_random_token(incidental_stopword),
            "fixture must exercise the random-token bypass"
        );
        let res = suppress_named_detector_finding_stage(incidental_stopword, ctx_normal_path);
        assert_eq!(
            res, None,
            "a configured stopword inside a random credential must not suppress it"
        );

        let res = suppress_named_detector_finding_stage("normal_secret", ctx_normal_path);
        assert_eq!(res, None);
    }

    #[test]
    fn exact_placeholder_value_is_suppressed_for_named_detectors() {
        use super::{suppress_named_detector_finding_stage, NamedDetectorSuppressionCtx};
        use crate::adjudicate::StageId;
        use crate::context::CodeContext;

        // A real vendor detector (no configured allowlist/stopwords) so the
        // universal Tier-A exact-placeholder gate is what decides, this is the
        // `rabbitmq-management-credentials` FP class: `RABBITMQ_PASSWORD=password`
        // captured the bare word, which the entropy path drops but named
        // detectors previously bypassed.
        let ctx = NamedDetectorSuppressionCtx::with_weak_anchor(
            Some("config/rabbitmq.env"),
            CodeContext::Unknown,
            Some("filesystem"),
            "rabbitmq-management-credentials",
            true,
            false,
            false,
        );
        let exact = Some(StageId::ShapeGate("exact_placeholder_value"));
        for placeholder in [
            "password",
            "secret",
            "default",
            "null",
            "none",
            "undefined",
            "empty",
        ] {
            assert_eq!(
                suppress_named_detector_finding_stage(placeholder, ctx),
                exact,
                "named value {placeholder:?} must be suppressed as an exact placeholder",
            );
        }
        // Whole-value only: a strong credential is untouched, and a value that
        // merely starts with a placeholder word is NOT an exact match.
        assert_eq!(
            suppress_named_detector_finding_stage("xK9mP2qR7wZ4nBvT8", ctx),
            None,
            "a strong random credential must survive the exact-placeholder gate",
        );
        assert_ne!(
            suppress_named_detector_finding_stage("passwordX9mP2qR7wZ4", ctx),
            exact,
            "a value merely CONTAINING a placeholder word is not an exact match",
        );
    }
}
