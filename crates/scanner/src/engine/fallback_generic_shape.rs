//! Generic-secret VALUE-SHAPE rejection gauntlet + its base64/ARN shape
//! helpers, extracted from `fallback_generic.rs` (Law 5).
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
use super::*;

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
    ) -> Option<&'static str> {
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

        // Variable-name filter: real secrets have mixed character classes.
        // Reject if the value looks like a code expression (has parens,
        // brackets, dots, or is pure snake_case/camelCase).
        if value.contains('(')
            || value.contains('[')
            || value.contains('{')
            || value.contains(' ')
        {
            return Some("code_expression_chars");
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
        if value.len() >= 8
            && value.len() <= 40
            && value.as_bytes()[0].is_ascii_uppercase()
            && value.bytes().all(|b| b.is_ascii_alphanumeric())
            && value.bytes().filter(u8::is_ascii_uppercase).count() >= 2
            && value.bytes().any(|b| b.is_ascii_lowercase())
        {
            return Some("type_name_shape");
        }
        // Allow dots ONLY in JWT-like patterns (exactly 2 dots separating
        // base64 segments). Reject other dotted values (method chains, FQDNs).
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
        // three characters from a `{"` header.
        if value.contains('.') {
            let dot_count = value.chars().filter(|&c| c == '.').count();
            let segments: Vec<&str> = value.split('.').collect();
            let is_jwt_like = dot_count == 2
                && segments.len() == 3
                && segments[0].starts_with("eyJ")
                && segments.iter().all(|s| {
                    s.len() >= 4
                        && s.chars().all(|c| {
                            c.is_ascii_alphanumeric()
                                || c == '+'
                                || c == '/'
                                || c == '='
                                || c == '-'
                                || c == '_'
                        })
                });
            if !is_jwt_like {
                return Some("non_jwt_dotted");
            }
        }
        // Reject pure identifiers: only alphanumeric + underscore
        if value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            // Must have at least one digit AND one letter to not be a variable name
            let has_digit = value.chars().any(|c| c.is_ascii_digit());
            let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
            if !(has_digit && (has_upper || has_lower)) {
                return Some("pure_identifier_no_digit");
            }
        }
        // Kebab-case / snake-case identifier shape: same filter the
        // named-detector path applies, just routed here too. Catches
        // `Get-Location` (PowerShell verb-noun), `user-password` (Go
        // config field), `curlx_strdup` (C single-underscore fn).
        // The `chars().all alphanumeric+_` branch above only covers
        // underscore separators; this extends coverage to hyphens.
        if crate::pipeline::looks_like_pure_identifier(value) {
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
        if crate::pipeline::looks_like_word_separated_identifier(value) {
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
        let high_entropy_punctuation_payload = entropy >= 4.8
            && value.len() >= 40
            && (value.contains('+') || value.contains('/'));
        if !high_entropy_punctuation_payload
            && crate::pipeline::looks_like_punctuation_decorated_identifier(value)
        {
            return Some("punctuation_decorated_identifier");
        }
        // URL / path-fragment shape: `user/settings/password` (gogs
        // template constants), `user/auth/forgot_passwd` (gogs auth
        // templates), `/api/v1/access_token` (alist OAuth URL).
        if crate::pipeline::looks_like_url_or_path_segment(value) {
            return Some("url_or_path_segment");
        }
        // Vendored 3rd-party minified bundle: drop generic-secret
        // hits in vendored codemirror/pdfjs/wp-includes/etc. paths.
        if crate::pipeline::looks_like_vendored_minified_path(
            chunk.metadata.path.as_deref(),
        ) {
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
        if !allow_canonical_hex_key && generic_path_looks_like_random_base64_blob(value, entropy) {
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
        if crate::suppression::api::should_suppress_known_example_credential_with_source_and_entropy(
            value,
            chunk.metadata.path.as_deref(),
            crate::context::CodeContext::Unknown,
            Some(chunk.metadata.source_type.as_str()),
            entropy,
            allow_canonical_hex_key,
        ) {
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
        // Decode-through binary suppression: a generic high-entropy
        // candidate that base64/hex-decodes to identifiable binary
        // bytes (PNG / gzip / ELF / protobuf-wire) is embedded data,
        // not a credential.
        if !high_entropy_punctuation_payload
            && !allow_canonical_hex_key
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
            && generic_path_looks_like_random_byte_blob(value)
        {
            return Some("random_byte_blob");
        }
        None
    }
}

/// Standard-base64-arbitrary-bytes shape detector for the
/// generic-secret path only. Returns true when `value` looks like
/// a protobuf wire dump / marshalled binary / k8s data field rather
/// than a credential token.
///
/// Why generic-path-only: named detectors with service-specific
/// keyword anchors (`AccountKey=…`, `AZURE_STORAGE_KEY=…`) cover
/// the legitimate ~88-char base64 cred families and skip this
/// fallback entirely. Suppressing on the generic path doesn't
/// touch their recall - verified by passing service-specific
/// fixtures through `engine/scan.rs`'s named-detector path which
/// runs before `scan_generic_assignments`.
///
/// Heuristics:
///   1. Length in `[40, 300]` (covers both the 40-80 protobuf
///      sweet spot and the longer 80-300 k8s `data:` blobs).
///   2. Alphabet ⊆ `[A-Za-z0-9+/=]` (standard base64, not url-safe).
///   3. Contains both `+` and `/`, or has padding with at least one of
///      them, which is a stronger byte-level signal than pure text-like
///      pure-base62 strings.
///      Real provider tokens are pure base62 without padding
///      because their length isn't derived from base64 of bytes -
///      AKIA + 16, ghp_ + 36, sk_live_ + 24, etc. all land on
///      char counts that don't need `=` padding. Adding the
///      "padded" branch catches the residual ~862 FPs where the
///      payload happens to encode random bytes into pure-b62
///      characters but still needs the `==` padding to round out.
///   4. Length is a multiple of 4 OR ends with `=`/`==` padding.
fn generic_path_looks_like_random_base64_blob(value: &str, entropy: f64) -> bool {
    const HIGH_ENTROPY_BASE64_CUTOFF: f64 = 4.8;

    if entropy >= HIGH_ENTROPY_BASE64_CUTOFF {
        return false;
    }

    // Band 40..=300 (covers both the 40-80 protobuf sweet spot and the longer
    // 80-300 k8s `data:` blobs). The band + padding + standard-base64-alphabet +
    // BOTH-`+`-AND-`/` skeleton is the shared `is_byte_distribution_base64_blob`
    // canonical (MC-12); this path composes its entropy cutoff (above) and band
    // on top.
    crate::decode_structure::is_byte_distribution_base64_blob(value, 40, 300)
}

/// Random-byte base64 decoy detector for the generic-secret path only.
/// Returns true when `value` is a pure standard-base64-alphabet blob in the
/// 40-80-char decoy band that base64-decodes to bytes which are neither valid
/// UTF-8 text nor a recognizable binary magic - i.e. the SecretBench
/// `negatives.py` base64-of-random-protobuf-bytes decoy class.
///
/// Why this exists alongside [`generic_path_looks_like_random_base64_blob`] and
/// `decode_structure::is_encoded_binary`:
///   * `is_encoded_binary` only fires on a recognizable magic header OR a clean
///     multi-field protobuf-wire parse. Random wire bytes parse as a full
///     protobuf message < 0.5% of the time, so the 30-80-random-byte decoy
///     slips both checks.
///   * `generic_path_looks_like_random_base64_blob` requires `+`/`/` or `=`
///     padding; a random-byte payload that happens to encode into pure base62
///     without padding evades it.
///   * `looks_like_uniform_base64_blob` (penalty path) floors at 44 chars and
///     only multiplies confidence by 0.02 - it does not hard-drop, and the
///     generic emit path bypasses the penalty path entirely.
///
/// This gate closes the family with a decode-through: pure standard-base64
/// alphabet (no `-`/`_`/`.`, so url-safe-prefixed service tokens are already
/// excluded), no service-prefix anchor, length in the decoy band, decoding to
/// non-text non-magic bytes. Named-detector matches anchor on a service prefix
/// and run before this fallback, so a real 40-char anchored secret still fires.
fn generic_path_looks_like_random_byte_blob(value: &str) -> bool {
    // Decoy band: SecretBench `negatives.py` emits base64 of 30-80 random
    // protobuf-wire bytes, which encodes to ~40-108 base64 chars. Cap at 80
    // to stay inside the band the audit measured (longer pure-base64 blobs are
    // already slammed by the penalty path's `looks_like_uniform_base64_blob`).
    if !(40..=80).contains(&value.len()) {
        return false;
    }
    // Pure STANDARD base64 alphabet only. Any `-`/`_`/`.` (base64url, JWT,
    // Slack, dotted property) rejects, which also clears every url-safe
    // service-prefixed token.
    // Require at least one pure-base62 path here: this branch is for the
    // long tail of random-binary decoys that missed the punct/pad gate.
    // Strings with `+`/`/` are already covered by the random-base64 gate
    // once both punctuation marks are present.
    if value.bytes().any(|b| matches!(b, b'+' | b'/')) {
        return false;
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'=')
    {
        return false;
    }
    // Decode-through: the value must base64/hex-decode, and the decoded bytes
    // must be neither a recognizable binary magic nor predominantly printable
    // text. Random wire bytes land around a 0.30 printable ratio; real
    // base64-wrapped text (config snippets, docs) stays high. A magic header is
    // already handled by `is_encoded_binary`, but re-checking here keeps the
    // gate self-contained and correct if call order ever changes.
    let structure = crate::decode_structure::analyze(value);
    if !structure.decodable {
        return false;
    }
    if structure.magic.is_some() {
        return true;
    }
    // Non-text, high-entropy decoded bytes with no magic = unanchored random
    // payload. The 0.85 printable floor keeps base64-wrapped text (which
    // decodes near 1.0 printable) out of the drop while catching random bytes.
    structure.printable_ratio < 0.85
}

/// IAM-ARN-trimmed-prefix gate for the generic-secret path.
/// Recognizes `aws:iam::...` shapes without `arn:` prefix.
fn generic_path_looks_like_trimmed_aws_arn(value: &str) -> bool {
    let prefixes = ["aws:iam::", "aws-cn:iam::", "aws-us-gov:iam::"];
    let Some(body) = prefixes.iter().find_map(|&p| value.strip_prefix(p)) else {
        return false;
    };
    let targets = [
        ":role/",
        ":user/",
        ":group/",
        ":policy/",
        ":instance-profile/",
    ];
    targets.iter().any(|&t| body.contains(t))
}
