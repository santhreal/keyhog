//! Generic-secret VALUE-SHAPE rejection gauntlet + its base64/ARN shape
//! helpers, extracted from `phase2_generic.rs` (Law 5).
//! `generic_value_shape_rejected` is the pure per-candidate predicate the
//! `scan_generic_assignments` loop calls after computing `(value, entropy)`: it
//! returns `Some(gate)` iff a precision shape gate would have `continue`d
//! (identifier / type-name / uri / base64-blob / encoded-binary / placeholder
//! families), naming the firing gate, else `None`. Behaviour-identical to the
//! former inline gauntlet, every gate is verbatim, each `continue` became
//! `return Some(GenericValueShapeStage::...)` (KH-L-0412: the name feeds the
//! `--dogfood` suppression trace; the caller records it, the predicate stays
//! pure). Recall is guarded by the generic-secret bench gates.
use super::*;
use crate::adjudicate::GenericValueShapeStage;

/// KH-L-0413: the identifier/type-name cluster (`pure_identifier_no_digit` /
/// `pure_identifier` / `type_name_shape` / `word_separated_identifier`) drops
/// code references (`password = getUserName`), but also ~1114 keyword-anchored
/// REAL random passwords (`GRAPHITE_PASS=gjbubxsu`) that are shape-identical
/// (lowercase, no digit). `keep_identifier_gate_with_randomness` returns false
/// (LIFT the gate, recover the value) ONLY when the value reads as a RANDOM
/// token under the English bigram model - a dictionary identifier still returns
/// true (stay suppressed). The gate is the SHARED context-aware function so this
/// scan-time path and the post-process weak-anchor path agree exactly.
use crate::suppression::token_randomness::{
    keep_identifier_gate_with_randomness, keep_word_separated_gate_with_randomness, TokenRandomness,
};

impl CompiledScanner {
    /// `Some(gate)` iff a generic-secret candidate `value` (with precomputed
    /// `entropy`) is rejected by a precision shape gate, the returned
    /// stage names the FIRING gate (for the `--dogfood` suppression trace);
    /// `None` means the value passes every gate. Pure: reads `value`, `entropy`,
    /// `chunk` metadata and `self.config` only, no side effects, no emission
    /// (the caller, `scan_generic_assignments`, records the telemetry).
    ///
    /// KH-L-0412: this gauntlet was the last SILENT suppression path, the caller
    /// did `if generic_value_shape_rejected(..) { continue }` with no telemetry,
    /// so every generic-bridge shape drop was invisible to `--dogfood` (a Law-10
    /// silent drop, and the bulk of the KH-L-0408 decomposition's never-candidate
    /// vs suppressed ambiguity). Returning the gate NAME keeps the predicate pure
    /// while making the drop loud and attributable.
    pub(crate) fn generic_value_shape_rejected(
        &self,
        value: &str,
        entropy: f64,
        chunk: &Chunk,
        // The keyword bridge proved this is complete pure-hex key material via
        // the owning detector's exact keyword/length policy, or via the legacy
        // structural 32/48 vendor-key family. Threaded into the placeholder/hash
        // suppression below to exempt only gates that confuse keys with digests.
        allow_canonical_hex_key: bool,
        allow_encoded_text_secret: bool,
        allow_decoded_hex_key_material: bool,
    ) -> Option<GenericValueShapeStage> {
        if chunk.metadata.source_type.contains("/caesar") {
            return Some(GenericValueShapeStage::CaesarGenericFallback);
        }

        // Generic-secret min length comes from adjudicate, which owns the
        // `GENERIC_SECRET` identity selection (this leaf never names the id
        // see suppression_named_detector_ctx_owner gate). The base64-shape gates
        // below take the RAW `entropy`: their boundary is the base64-blob shape
        // constant `HIGH_ENTROPY_BASE64_CUTOFF` (owned once inside the decoy
        // predicate), NOT generic-secret's confidence-boost `entropy_high`: those
        // are two distinct thresholds and must not be conflated (a marshalled-binary
        // blob is a blob regardless of the generic-secret confidence floor).
        let generic_secret_detector = self
            .generic_owning_detector
            .generic_secret_index()
            .and_then(|index| self.detectors.get(index));
        let generic_keyword_detector = self
            .generic_owning_detector
            .generic_keyword_secret_index()
            .and_then(|index| self.detectors.get(index));
        let crate::adjudicate::GenericSecretShapeFloors { min_len } =
            crate::adjudicate::generic_secret_shape_floors(generic_secret_detector);
        if !allow_encoded_text_secret
            && crate::adjudicate::generic_bridge_entropy_below_floor(
                entropy,
                self.config.entropy_threshold,
                self.config.generic_keyword_low_entropy,
                generic_secret_detector,
                generic_keyword_detector,
                value.len(),
            )
        {
            return Some(GenericValueShapeStage::EntropyBelowFloor);
        }

        // Length gate
        if value.len() < min_len {
            return Some(GenericValueShapeStage::ValueTooShort);
        }
        let randomness = TokenRandomness::for_candidate(value);
        let allow_ambiguous_base64_candidate =
            crate::suppression::shape::generic_base64_candidate_is_ambiguous(value, entropy);
        let high_entropy_punctuation_payload =
            crate::suppression::shape::looks_like_high_entropy_punctuation_payload(value, entropy);
        if let Some(reason) = crate::suppression::shape::public_noncredential_shape_with_randomness(
            value,
            crate::suppression::shape::PublicShapeScope::Full,
            &randomness,
        ) {
            return Some(GenericValueShapeStage::SharedShape(reason));
        }

        // Variable-name filter: real secrets have mixed character classes.
        // Reject code expressions and whitespace-bearing labels before they
        // can be scored as keyword-anchored generic credentials.
        if value.contains(' ') {
            return Some(GenericValueShapeStage::CodeExpressionChars);
        }
        if !high_entropy_punctuation_payload
            && crate::suppression::shape::looks_like_source_code_expression_with_randomness(
                value,
                &randomness,
            )
        {
            return Some(GenericValueShapeStage::SourceCodeExpression);
        }
        if crate::decode::caesar::is_source_code_path(chunk.metadata.path.as_deref())
            && crate::suppression::shape::looks_like_source_symbol_identifier_with_randomness(
                value,
                &randomness,
            )
        {
            return Some(GenericValueShapeStage::SourceSymbolIdentifier);
        }
        // C++ / Rust scope-resolution (`Class::Member`, `Etc::passwd`,
        // `PrivateKey::<T>`) is the dominant generic-secret FP class
        // in source-code scans. The first `:` slips because the bridge
        // already consumed one `:`; the second stays in-value because
        // `:` is in the alphabet to keep `nginx@sha256:<hex>` intact.
        // Two filters together cover the family:
        //   * value starts with `:` - jinja lexer enum-style captures
        //     like `:open_paren:` from `case token::open_paren:` (32+
        //     FPs in llama-cpp's jinja lexer).
        //   * value contains `::` - Rust scope captures like
        //     `PrivateKey::`, `Etc::passwd`, `K256Config::SigningKey`
        //     (malachite's signing-ecdsa had 6+ findings of this
        //     shape).  Real sha256 / git-blob digests never have
        //     `::`, so this never weakens digest recall.
        if value.starts_with(':') || value.contains("::") {
            return Some(GenericValueShapeStage::ScopeResolution);
        }
        // Type-name / fully-qualified-path shape: starts with an
        // uppercase letter, has ≥ 2 uppercase letters, has lowercase
        // letters, length 8..=40, pure ASCII alphanumeric. Catches
        // Rust/Java/C# type names like `K256SigningKey`,
        // `ShopifyToken`, `P256VerifyingKey` (the digit prevented
        // the suppression-pipeline pure-CamelCase filter from
        // firing, because that filter requires no-digit).  Real
        // credentials follow this regular alternating-case structure
        // only as a coincidence; a 14-char value with two upper-case
        // clusters and a digit triplet is overwhelmingly a type
        // identifier.
        if keep_identifier_gate_with_randomness(value, &randomness)
            && value.len() >= min_len
            && value.len() <= 40
            && value.as_bytes()[0].is_ascii_uppercase()
            && keyhog_core::ascii_ci::is_ascii_alphanumeric_str(value)
            && value.bytes().filter(u8::is_ascii_uppercase).count() >= 2
            && value.bytes().any(|b| b.is_ascii_lowercase())
        {
            return Some(GenericValueShapeStage::TypeNameShape);
        }
        // Allow dots ONLY in structured token patterns (exactly 2 dots
        // separating base64 segments). Reject other dotted values (method
        // chains, FQDNs).
        //
        // Defect #76: the old "is_jwt_like" check passed any
        // 3-segment dotted string where each segment was 4+
        // base64-alphabet chars - which matches every
        // `this.someService.copilotToken` property access in
        // TS/JS/Java/etc. Real JWTs always begin with `eyJ`
        // (base64 of `{"`, the first two bytes of a JSON
        // header); requiring that prefix on the first segment
        // eliminates property-access FPs without losing any
        // real JWT - the base64 alphabet only produces those
        // three characters from a `{"` header. Discord-style bot tokens are
        // the other bounded three-segment credential shape: 23-28, 6-8, and
        // 27-38 base64url chars. Keep that exact length profile alive while
        // leaving property access suppressed.
        if value.contains('.') && !crate::suppression::shape::is_structured_dotted_token(value) {
            return Some(GenericValueShapeStage::NonJwtDotted);
        }
        // Reject pure identifiers: only alphanumeric + underscore
        if value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            // Must have at least one digit AND one letter to not be a variable name
            let has_digit = value.chars().any(|c| c.is_ascii_digit());
            let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
            if keep_identifier_gate_with_randomness(value, &randomness)
                && !(has_digit && (has_upper || has_lower))
            {
                return Some(GenericValueShapeStage::PureIdentifierNoDigit);
            }
        }
        // Kebab-case / snake-case identifier shape: same filter the
        // named-detector path applies, just routed here too. Catches
        // `Get-Location` (PowerShell verb-noun), `user-password` (Go
        // config field), `curlx_strdup` (C single-underscore fn).
        // The `chars().all alphanumeric+_` branch above only covers
        // underscore separators; this extends coverage to hyphens.
        if keep_identifier_gate_with_randomness(value, &randomness)
            && crate::suppression::shape::looks_like_pure_identifier(value)
        {
            return Some(GenericValueShapeStage::PureIdentifier);
        }
        // Word-separated identifier with embedded digits. The stricter
        // context-aware gate owns the acronym/product-key carve-out and the
        // random lowercase-password lift in `token_randomness`.
        if keep_word_separated_gate_with_randomness(value, &randomness)
            && crate::suppression::shape::looks_like_word_separated_identifier(value)
        {
            return Some(GenericValueShapeStage::WordSeparatedIdentifier);
        }
        // Scheme-prefixed URI / URN: `urn:shopify:params:oauth:...`,
        // `secret-token:<base64>` (bat-go merchant README). Documented
        // OAuth grant types and protocol URIs that the regex captures
        // via the trailing `token-type:...token` keyword.
        if crate::suppression::shape::looks_like_scheme_prefixed_uri(value) {
            return Some(GenericValueShapeStage::SchemePrefixedUri);
        }
        // Punctuation-decorated identifier: `--api-secret` (CLI flag),
        // `&gss_recv_token` (C pointer), `@v_password` (SQL bind),
        // `!!apiKeyOrOAuthToken` (JS coercion), `Password:` (UI label),
        // `privateAccessToken!` (TS non-null assertion).
        if !high_entropy_punctuation_payload
            && crate::suppression::shape::looks_like_punctuation_decorated_identifier(value)
        {
            return Some(GenericValueShapeStage::PunctuationDecoratedIdentifier);
        }
        // URL / path-fragment shape: `user/settings/password` (gogs
        // template constants), `user/auth/forgot_passwd` (gogs auth
        // templates), `/api/v1/access_token` (alist OAuth URL). Keep the
        // adjacent high-entropy base64 exemption here too for long opaque
        // tokens that happen to contain `/`; keep the 40-char band on the
        // path gate because it still contains random-byte decoys.
        let high_entropy_long_punctuation_payload =
            high_entropy_punctuation_payload && value.len() > 40;
        if !high_entropy_long_punctuation_payload
            && crate::suppression::shape::looks_like_url_or_path_segment(value)
        {
            return Some(GenericValueShapeStage::UrlOrPathSegment);
        }
        // Vendored 3rd-party minified bundle: drop generic-secret
        // hits in vendored codemirror/pdfjs/wp-includes/etc. paths.
        if crate::suppression::path_filter::looks_like_vendored_minified_path(
            chunk.metadata.path.as_deref(),
        ) {
            return Some(GenericValueShapeStage::VendoredMinifiedPath);
        }
        // Regex-literal suppression: the fast-path hot patterns and
        // generic-secret regex sometimes capture rules being defined
        // in source code that itself implements a secret scanner.
        // Captures ending in regex metacharacters (`/g`, `})\b`,
        // `]+`, `]*`, `]?`, etc.) are regex pattern literals, not
        // credentials. Real credentials don't end in regex sigils.
        // Source: claude-code's teamMemorySync/secretScanner.ts had
        // 3 hot-aws_session_key / hot-slack_bot_token findings on
        // its own regex definitions.
        if crate::suppression::shape::looks_like_regex_literal_tail(value) {
            return Some(GenericValueShapeStage::RegexLiteralTail);
        }

        // Standard-base64-arbitrary-bytes suppression for generic
        // path only: any value 40-300 chars consisting solely of
        // `[A-Za-z0-9+/=]` with at least one `+/` and proper
        // base64 padding/byte-alignment is overwhelmingly a
        // protobuf wire dump, marshalled binary, or k8s base64
        // payload - not a real credential. Named-detector
        // matches with service-specific keyword anchors
        // (azure-storage-account-key etc.) take this path's
        // alternative route (engine/scan.rs) and don't pass
        // through this gate, so service-specific recall is
        // preserved. SecretBench-medium 15k seed-0: ~10 FPs/
        // shard × 256 shards = ~2.5k FPs from this path alone.
        if !allow_canonical_hex_key
            && !allow_encoded_text_secret
            && crate::suppression::shape::looks_like_generic_random_base64_blob_decoy(
                value, entropy,
            )
        {
            return Some(GenericValueShapeStage::Base64Blob);
        }

        // ARN-without-prefix suppression for generic path.
        // The generic-secret regex captures values starting
        // AFTER the keyword (`auth`/`secret`/`token`). For
        // an input `token = arn:aws:iam::ACCT:role/...`, the
        // `arn:` literal is consumed as part of the bridge
        // (it's the value separator's neighborhood), and the
        // captured value is the rest: `aws:iam::ACCT:role/...`.
        // The pipeline gate's IAM-ARN check requires the
        // `arn:` prefix; the trimmed form leaks here. The
        // dedicated trimmed-prefix gate catches it without
        // weakening the global gate.
        if crate::suppression::shape::looks_like_trimmed_aws_iam_arn(value) {
            return Some(GenericValueShapeStage::TrimmedAwsArn);
        }

        // Placeholder suppression. NOTE: the credential-anchor variant
        // (`_with_anchor`) was tried here in v31 to lift the hash-digest
        // and UUID-v4 shape gates for direct `TOKEN=<hex>` assignments.
        // The SecretBench mirror plants `TOKEN=<32-hex>` in BOTH the
        // label=true positive class AND the label=false sha256-hex /
        // git-commit-sha / k8s-resource-uid negative classes - the
        // syntax is identical, only the manifest's labelling differs.
        // Lifting the shape gate added 5681 FPs (P 0.97 → 0.33) for
        // a +14 TP recall gain. Net: catastrophic. Hold the strict
        // variant: hash-digest / UUID values in credential slots are
        // dominated by image digests and resource IDs in real source.
        if let Some(stage) = crate::adjudicate::generic_bridge_canonical_hex_placeholder_stage(
            allow_canonical_hex_key,
            value,
        ) {
            return Some(stage);
        }
        let example_ctx = crate::suppression::api::KnownExampleSuppressionCtx::with_entropy(
            chunk.metadata.path.as_deref(),
            crate::context::CodeContext::Unknown,
            Some(chunk.metadata.source_type.as_ref()),
            entropy,
            allow_canonical_hex_key,
            allow_ambiguous_base64_candidate,
            allow_encoded_text_secret,
        );
        if let Some(stage_id) =
            crate::suppression::api::suppress_known_example_credential_stage(value, example_ctx)
        {
            return Some(GenericValueShapeStage::SharedSuppression(stage_id.as_str()));
        }
        // Decoded-form placeholder check: a docs sample that arrives
        // base64-wrapped (e.g. QUtJQUVYQU1QTEVFWEFNUExFMTI= which
        // decodes to AKIAEXAMPLEEXAMPLE12) is still a sample. The
        // surface-form gate above doesn't see through the base64;
        // this decode-through gate does. Mirror v27 had 9
        // docs-example-marker FPs all surviving here via this exact
        // shape; the ml_pending path's penalty has the same check
        // but generic-secret emits directly via push_match and
        // bypasses it.
        let decode_evidence = crate::decode_structure::evidence(value);
        if decode_evidence.decoded_contains_placeholder() && !allow_decoded_hex_key_material {
            return Some(GenericValueShapeStage::DecodedPlaceholder);
        }
        if let Some(reason) = crate::suppression::decision::decoded_benign_text_reason(value) {
            // A printable value encoded beneath a strong credential anchor is
            // still secret material. Kubernetes Secret data is the canonical
            // case: base64 is transport encoding, not encryption, and readable
            // decoded bytes must not erase the explicit `*_SECRET` evidence.
            // Placeholder-marked decoded values were rejected immediately above,
            // so this exemption cannot revive examples. It also preserves the
            // narrower canonical-hex-key exemption for strong key anchors.
            if allow_encoded_text_secret
                || (allow_decoded_hex_key_material
                    && matches!(reason, "decoded_placeholder" | "decoded_bare_hash_digest"))
            {
                return None;
            }
            return Some(GenericValueShapeStage::DecodedBenignText(reason));
        }
        // Decode-through binary suppression: a generic high-entropy
        // candidate that base64/hex-decodes to identifiable binary
        // bytes (PNG / gzip / ELF / protobuf-wire) is embedded data,
        // not a credential.
        if !high_entropy_punctuation_payload
            && !allow_canonical_hex_key
            && !allow_encoded_text_secret
            && decode_evidence.is_binary_payload()
        {
            return Some(GenericValueShapeStage::EncodedBinary);
        }
        // Random-byte base64 decoy suppression (generic path only).
        // `is_encoded_binary` above only fires on bytes that carry a
        // recognizable magic header OR parse cleanly as a multi-field
        // protobuf-wire stream. The dominant residual FP class is the
        // SecretBench `negatives.py` base64-of-30-80-random-protobuf-
        // bytes decoy: random wire bytes parse as a full protobuf
        // message < 0.5% of the time, so they slip the protobuf-wire
        // gate, and they carry no magic header, so they slip the magic
        // gate too. They are ALSO pure base62 (no `+`/`/`, no padding)
        // when the random bytes happen to encode without them, so the
        // generic base64 punct/pad
        // gate misses them. This decode-through gate closes the family:
        // a value that is pure standard-base64 alphabet, lands in the
        // 40-80-char decoy band, has NO service-prefix anchor, and
        // base64-decodes to bytes that are neither valid UTF-8 text nor
        // a recognizable binary magic is an unanchored proto/config
        // blob, never a service credential. Named-detector matches
        // anchor on a service prefix and take engine/scan.rs's path
        // before this fallback, so a real 40-char anchored secret (AWS
        // etc.) is unaffected - the negative twin still fires.
        if !high_entropy_punctuation_payload
            && !allow_canonical_hex_key
            && !allow_ambiguous_base64_candidate
            && !allow_encoded_text_secret
            && crate::suppression::shape::looks_like_random_byte_base64_blob(value)
        {
            return Some(GenericValueShapeStage::RandomByteBlob);
        }
        None
    }
}
