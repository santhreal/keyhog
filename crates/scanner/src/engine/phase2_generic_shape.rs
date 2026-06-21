//! Generic-secret VALUE-SHAPE rejection gauntlet + its base64/ARN shape
//! helpers, extracted from `phase2_generic.rs` (Law 5).
//! `generic_value_shape_rejected` is the pure per-candidate predicate the
//! `scan_generic_assignments` loop calls after computing `(value, entropy)`: it
//! returns `Some(gate)` iff a precision shape gate would have `continue`d
//! (identifier / type-name / uri / base64-blob / encoded-binary / placeholder
//! families), naming the firing gate, else `None`. Behaviour-identical to the
//! former inline gauntlet — every gate is verbatim, each `continue` became
//! `return Some("<gate>")` (KH-L-0412: the name feeds the `--dogfood`
//! suppression trace; the caller records it, the predicate stays pure). Recall is
//! guarded by the generic-secret bench gates. The three `generic_path_looks_like_*`
//! helpers (the gauntlet's only callers) move with it.
use super::phase2_generic::shape_helpers::{
    generic_path_allows_ambiguous_base64_candidate, generic_path_looks_like_random_base64_blob,
    generic_path_looks_like_random_byte_blob, generic_path_looks_like_trimmed_aws_arn,
};
use super::*;

/// KH-L-0413: the identifier/type-name cluster (`pure_identifier_no_digit` /
/// `pure_identifier` / `type_name_shape` / `word_separated_identifier`) drops
/// code references (`password = getUserName`) — but also ~1114 keyword-anchored
/// REAL random passwords (`GRAPHITE_PASS=gjbubxsu`) that are shape-identical
/// (lowercase, no digit). `keep_identifier_gate` returns false (LIFT the gate,
/// recover the value) ONLY when the value reads as a RANDOM token under the
/// English bigram model — a dictionary identifier still returns true (stay
/// suppressed). The gate is the SHARED `token_randomness::keep_identifier_gate`
/// so this scan-time path and the post-process weak-anchor path agree exactly.
use crate::suppression::token_randomness::{keep_identifier_gate, keep_word_separated_gate};

impl CompiledScanner {
    /// `Some(gate)` iff a generic-secret candidate `value` (with precomputed
    /// `entropy`) is rejected by a precision shape gate — the returned
    /// `&'static str` names the FIRING gate (for the `--dogfood` suppression
    /// trace); `None` means the value passes every gate. Pure: reads `value`,
    /// `entropy`, `chunk` metadata and `self.config` only — no side effects, no
    /// emission (the caller, `scan_generic_assignments`, records the telemetry).
    ///
    /// KH-L-0412: this gauntlet was the last SILENT suppression path — the caller
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
        // KH-L-0110: the keyword bridge proved this is a complete pure-hex value
        // of canonical key length (32/48) under a STRONG credential keyword.
        // Threaded into the placeholder/hash suppression below to exempt it from
        // the bare-hex-digest gate ONLY (every other shape gate here still runs).
        allow_canonical_hex_key: bool,
        allow_encoded_text_secret: bool,
    ) -> Option<&'static str> {
        if chunk.metadata.source_type.contains("/caesar") {
            return Some("caesar_generic_fallback");
        }

        // Keyword-anchored values use the relaxed `generic-keyword-secret`
        // floor when `generic_keyword_low_entropy` is on (the default):
        // the credential keyword in the key is the evidence, and precision
        // is carried downstream by the MoE + shape filters. This is what
        // admits real low-entropy CredData passwords (`gjbubxsu`) that the
        // 2.8/3.2/3.5 `generic-secret` floor discarded. The
        // `--no-keyword-low-entropy` opt-out restores the high floor.
        let floor_id = if self.config.generic_keyword_low_entropy {
            "generic-keyword-secret"
        } else {
            "generic-secret"
        };
        let min_entropy = super::scan_filters::generic_entropy_floor(
            self.config.entropy_threshold,
            floor_id,
            value.len(),
        );
        if entropy < min_entropy {
            return Some("generic_entropy_below_floor");
        }

        // Length gate
        if value.len() < 8 {
            return Some("value_too_short");
        }
        let allow_ambiguous_base64_candidate =
            generic_path_allows_ambiguous_base64_candidate(value, entropy);
        let high_entropy_punctuation_payload =
            crate::suppression::shape::looks_like_high_entropy_punctuation_payload(value, entropy);
        if let Some(reason) = crate::suppression::shape::public_noncredential_shape(
            value,
            crate::suppression::shape::PublicShapeScope::Full,
        ) {
            return Some(reason);
        }

        // Variable-name filter: real secrets have mixed character classes.
        // Reject code expressions and whitespace-bearing labels before they
        // can be scored as keyword-anchored generic credentials.
        if value.contains(' ') {
            return Some("code_expression_chars");
        }
        if !high_entropy_punctuation_payload
            && crate::pipeline::looks_like_source_code_expression(value)
        {
            return Some("source_code_expression");
        }
        if crate::decode::caesar::is_source_code_path(chunk.metadata.path.as_deref())
            && crate::suppression::shape::looks_like_source_symbol_identifier(value)
        {
            return Some("source_symbol_identifier");
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
            return Some("scope_resolution");
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
        if keep_identifier_gate(value)
            && value.len() >= 8
            && value.len() <= 40
            && value.as_bytes()[0].is_ascii_uppercase()
            && value.bytes().all(|b| b.is_ascii_alphanumeric())
            && value.bytes().filter(u8::is_ascii_uppercase).count() >= 2
            && value.bytes().any(|b| b.is_ascii_lowercase())
        {
            return Some("type_name_shape");
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
        if value.contains('.')
            && !crate::engine::phase2_generic::shape_helpers::is_structured_dotted_token(value)
        {
            return Some("non_jwt_dotted");
        }
        // Reject pure identifiers: only alphanumeric + underscore
        if value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            // Must have at least one digit AND one letter to not be a variable name
            let has_digit = value.chars().any(|c| c.is_ascii_digit());
            let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
            if keep_identifier_gate(value) && !(has_digit && (has_upper || has_lower)) {
                return Some("pure_identifier_no_digit");
            }
        }
        // Kebab-case / snake-case identifier shape: same filter the
        // named-detector path applies, just routed here too. Catches
        // `Get-Location` (PowerShell verb-noun), `user-password` (Go
        // config field), `curlx_strdup` (C single-underscore fn).
        // The `chars().all alphanumeric+_` branch above only covers
        // underscore separators; this extends coverage to hyphens.
        if keep_identifier_gate(value) && crate::pipeline::looks_like_pure_identifier(value) {
            return Some("pure_identifier");
        }
        // Word-separated identifier with embedded digits: catches
        // FPs missed by `looks_like_pure_identifier`'s `!has_digit`
        // guard. `s3_secret_access_key` (alist), `d2i_PKCS7_bio`
        // (openssl ts.c), `sqlite3_int` (sqlite fts5), `curlx_memdup0`
        // (curl ntlm_sspi.c), `X-Shopify-Access-Token` (shopify-api
        // headers). Real credentials concentrate randomness in one
        // long segment; programmer identifiers are sequences of
        // short dictionary fragments.
        //
        // KH-L-0414: this gate uses the STRICTER `keep_word_separated_gate`, NOT
        // the contiguous `keep_identifier_gate`. The randomness discriminator is
        // an ENGLISH-WORD model, and multi-segment programmer identifiers carry
        // acronym fragments (`PKCS`, `curlx`, `d2i`) that are improbable under
        // English and would be mis-scored as random (`d2i_PKCS7_bio` −7.88,
        // `curlx_memdup0` −7.09, both below −6.85). `keep_word_separated_gate`
        // only trusts the random verdict for all-lowercase-letter values, so it
        // recovers the 141 real CredData word-separated passwords
        // (`abxnj_gjvpuqzo`, `aapqhgn-qhuuc-trnmf`) while keeping every
        // digit/uppercase-bearing acronym & product-key identifier suppressed.
        if keep_word_separated_gate(value)
            && crate::pipeline::looks_like_word_separated_identifier(value)
        {
            return Some("word_separated_identifier");
        }
        // Scheme-prefixed URI / URN: `urn:shopify:params:oauth:...`,
        // `secret-token:<base64>` (bat-go merchant README). Documented
        // OAuth grant types and protocol URIs that the regex captures
        // via the trailing `token-type:...token` keyword.
        if crate::pipeline::looks_like_scheme_prefixed_uri(value) {
            return Some("scheme_prefixed_uri");
        }
        // Punctuation-decorated identifier: `--api-secret` (CLI flag),
        // `&gss_recv_token` (C pointer), `@v_password` (SQL bind),
        // `!!apiKeyOrOAuthToken` (JS coercion), `Password:` (UI label),
        // `privateAccessToken!` (TS non-null assertion).
        if !high_entropy_punctuation_payload
            && crate::pipeline::looks_like_punctuation_decorated_identifier(value)
        {
            return Some("punctuation_decorated_identifier");
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
            && crate::pipeline::looks_like_url_or_path_segment(value)
        {
            return Some("url_or_path_segment");
        }
        // Vendored 3rd-party minified bundle: drop generic-secret
        // hits in vendored codemirror/pdfjs/wp-includes/etc. paths.
        if crate::pipeline::looks_like_vendored_minified_path(chunk.metadata.path.as_deref()) {
            return Some("vendored_minified_path");
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
        if crate::pipeline::looks_like_regex_literal_tail(value) {
            return Some("regex_literal_tail");
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
            && generic_path_looks_like_random_base64_blob(value, entropy)
        {
            return Some("base64_blob");
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
        if generic_path_looks_like_trimmed_aws_arn(value) {
            return Some("trimmed_aws_arn");
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
        let example_ctx = crate::suppression::api::KnownExampleSuppressionCtx::with_entropy(
            chunk.metadata.path.as_deref(),
            crate::context::CodeContext::Unknown,
            Some(chunk.metadata.source_type.as_str()),
            entropy,
            allow_canonical_hex_key,
            allow_ambiguous_base64_candidate,
            allow_encoded_text_secret,
        );
        if crate::suppression::api::suppress_known_example_credential(value, example_ctx) {
            return Some("known_example_or_placeholder");
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
        if crate::decode_structure::decoded_contains_placeholder(value) {
            return Some("decoded_placeholder");
        }
        if let Some(reason) = crate::suppression::decision::decoded_benign_text_reason(value) {
            return Some(reason);
        }
        // Decode-through binary suppression: a generic high-entropy
        // candidate that base64/hex-decodes to identifiable binary
        // bytes (PNG / gzip / ELF / protobuf-wire) is embedded data,
        // not a credential.
        if !high_entropy_punctuation_payload
            && !allow_canonical_hex_key
            && !allow_encoded_text_secret
            && crate::decode_structure::is_encoded_binary(value)
        {
            return Some("encoded_binary");
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
        // local `generic_path_looks_like_random_base64_blob` punct/pad
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
            && generic_path_looks_like_random_byte_blob(value)
        {
            return Some("random_byte_blob");
        }
        None
    }
}
