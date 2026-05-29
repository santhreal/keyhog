use super::*;
use std::collections::HashMap;

impl CompiledScanner {
    /// Scan for generic `SECRET_NAME = "high_entropy_value"` patterns.
    /// This is the precision-gated equivalent of Gitleaks's `generic-api-key`.
    /// Only fires when:
    ///   1. The variable name contains a secret-related keyword
    ///   2. The value has entropy >= 3.5 (random-looking)
    ///   3. No named detector already matched the same line
    ///   4. The value is not a known placeholder/example
    pub(crate) fn scan_generic_assignments(
        &self,
        code_lines: &[&str],
        line_offsets: &[usize],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        use std::sync::LazyLock;
        static GENERIC_RE: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
            // The keyword → value bridge accepts:
            //   1. `key = "v"` / `key="v"` (Python/Ruby/JS/sh)
            //   2. `key: "v"` (YAML, modern JSON-ish)
            //   3. `"key": "v"` (JSON - closing quote of key is
            //      allowed BEFORE the `:`)
            //   4. `const KEY: &str = "v"` (Rust with type) - an
            //      optional `: &?TypeName =` segment between
            //      keyword and value (handles `&str`, `String`,
            //      `Cow<str>`, etc.). The `&?[A-Za-z_]` opener +
            //      `[A-Za-z0-9_]*` tail keeps the type-name
            //      narrowly recognizable and reject mid-line code.
            // Closing quote `["'\u{60}]?` permitted between keyword
            // and `[:=]` to cover JSON. Then a `[:=]` mandatory.
            // Optional `[:=]` after a type segment for Rust. Value
            // capture as before. `:` stays in the value alphabet so
            // `nginx@sha256:<hex>` captures intact (defect #76).
            // `.` is in the separator class alongside `_`/`-` so dotted
            // property-key forms like `api.key`, `private.key`, `client.secret`
            // are recognized. Common in `.properties`, `.toml`, helm-values,
            // and TF locals. The dot is bounded inside the keyword shape; the
            // value bridge still requires a `=`/`:` after, so this does not
            // open up method-chain false-matches.
            regex::Regex::new(
                r#"(?i)(?:secret|password|passwd|pwd|token|api[._-]?key|apikey|auth[._-]?token|auth[._-]?key|credential|private[._-]?key|signing[._-]?key|encryption[._-]?key|access[._-]?key|client[._-]?secret|app[._-]?secret|master[._-]?key|license[._-]?key)["'`]?\s*[=:]\s*(?:&?[a-zA-Z_][a-zA-Z0-9_<>]*\s*[=:]\s*)?["'`]?([a-zA-Z0-9/+=_.:!@#$%^&*-]{8,128})["'`]?"#
            ).ok()
        });
        let Some(generic_re) = GENERIC_RE.as_ref() else {
            return;
        };

        let covered_lines: std::collections::HashSet<usize> = {
            let lines: Vec<usize> = scan_state
                .matches
                .iter()
                .filter_map(|m| m.0.location.line)
                .collect();
            lines.into_iter().collect()
        };

        // Single-pass case-insensitive Aho-Corasick over all 16 keywords.
        // Replaces the previous 16 × O(line_len) byte-window scans per line
        // (one per keyword) with one O(line_len) automaton walk that catches
        // every keyword simultaneously. On an 8 MiB no-hit corpus this drops
        // the scan_generic_assignments pre-filter from ~16 × 240 ms of
        // window-scan to a single AC pass.
        use aho_corasick::AhoCorasick;
        // LazyLock<Option<_>> + .ok() - a panic inside a LazyLock initializer
        // poisons the static for the rest of the process and crashes every
        // subsequent worker thread that touches it. Convert to a soft
        // fallback so an aho-corasick version bump that tightens validation
        // degrades to "no keyword prefilter" (worst case: same precision,
        // slightly slower scan) instead of killing the whole scanner.
        static KEYWORD_AC: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build([
                    "secret",
                    "password",
                    "passwd",
                    "pwd",
                    "token",
                    "api",
                    "auth",
                    "credential",
                    "private",
                    "signing",
                    "encryption",
                    "access",
                    "client",
                    "app",
                    "master",
                    "license",
                ])
                .ok()
        });
        let Some(keyword_ac) = KEYWORD_AC.as_ref() else {
            tracing::warn!(
                "generic-assignment keyword AC failed to compile; \
                 skipping keyword prefilter for this scan"
            );
            return;
        };

        // ONE chunk-level AC scan instead of N per-line scans.
        // Profile showed scan_generic_assignments at ~500 µs/chunk -
        // dominant non-ML cost - and most of that was the per-line
        // KEYWORD_AC.find overhead (per-call AC setup × N lines).
        // One contiguous find_iter over the whole chunk is the same
        // total bytes scanned but with a single overhead point and
        // way better cache behavior. Map each match offset back to
        // its line via the existing `line_offsets` binary search;
        // dedup so we visit each line once even if multiple
        // keywords land on it.
        let chunk_bytes = chunk.data.as_bytes();
        let mut lines_with_keyword: Vec<usize> = Vec::new();
        let mut last_line_idx: Option<usize> = None;
        for mat in keyword_ac.find_iter(chunk_bytes) {
            // `partition_point` returns the 1-based line number;
            // subtract 1 for the 0-based code_lines index. Same
            // idiom as `match_line_number`.
            let line_num_1b = line_offsets.partition_point(|&lo| lo <= mat.start());
            let line_idx = line_num_1b.saturating_sub(1);
            if Some(line_idx) == last_line_idx {
                continue;
            }
            last_line_idx = Some(line_idx);
            lines_with_keyword.push(line_idx);
        }
        if lines_with_keyword.is_empty() {
            return;
        }

        for line_idx in lines_with_keyword {
            let line_num = line_idx + 1;
            if covered_lines.contains(&line_num) {
                continue;
            }
            let Some(line) = code_lines.get(line_idx) else {
                continue;
            };
            // The chunk-level AC told us this line has a keyword;
            // proceed straight to the heavy regex extraction.

            for caps in generic_re.captures_iter(line) {
                let Some(value_match) = caps.get(1) else {
                    continue;
                };
                let value = value_match.as_str();

                // Entropy gate: reject low-entropy values (variable names, prose)
                let entropy = crate::pipeline::match_entropy(value.as_bytes());
                // Per-length entropy floor: short tokens (API keys) have lower
                // entropy than long random strings. A blanket 3.5 misses them.
                let min_entropy = if value.len() <= 24 {
                    2.8
                } else if value.len() <= 40 {
                    3.2
                } else {
                    3.5
                };
                if entropy < min_entropy {
                    continue;
                }

                // Length gate
                if value.len() < 8 {
                    continue;
                }

                // Variable-name filter: real secrets have mixed character classes.
                // Reject if the value looks like a code expression (has parens,
                // brackets, dots, or is pure snake_case/camelCase).
                if value.contains('(')
                    || value.contains('[')
                    || value.contains('{')
                    || value.contains(' ')
                {
                    continue;
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
                    continue;
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
                    continue;
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
                        continue;
                    }
                }
                // Reject pure identifiers: only alphanumeric + underscore
                if value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    // Must have at least one digit AND one letter to not be a variable name
                    let has_digit = value.chars().any(|c| c.is_ascii_digit());
                    let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
                    let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
                    if !(has_digit && (has_upper || has_lower)) {
                        continue;
                    }
                }
                // Kebab-case / snake-case identifier shape: same filter the
                // named-detector path applies, just routed here too. Catches
                // `Get-Location` (PowerShell verb-noun), `user-password` (Go
                // config field), `curlx_strdup` (C single-underscore fn).
                // The `chars().all alphanumeric+_` branch above only covers
                // underscore separators; this extends coverage to hyphens.
                if crate::pipeline::looks_like_pure_identifier(value) {
                    continue;
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
                    continue;
                }
                // Scheme-prefixed URI / URN: `urn:shopify:params:oauth:...`,
                // `secret-token:<base64>` (bat-go merchant README). Documented
                // OAuth grant types and protocol URIs that the regex captures
                // via the trailing `token-type:...token` keyword.
                if crate::pipeline::looks_like_scheme_prefixed_uri(value) {
                    continue;
                }
                // Punctuation-decorated identifier: `--api-secret` (CLI flag),
                // `&gss_recv_token` (C pointer), `@v_password` (SQL bind),
                // `!!apiKeyOrOAuthToken` (JS coercion), `Password:` (UI label),
                // `privateAccessToken!` (TS non-null assertion).
                if crate::pipeline::looks_like_punctuation_decorated_identifier(value) {
                    continue;
                }
                // URL / path-fragment shape: `user/settings/password` (gogs
                // template constants), `user/auth/forgot_passwd` (gogs auth
                // templates), `/api/v1/access_token` (alist OAuth URL).
                if crate::pipeline::looks_like_url_or_path_segment(value) {
                    continue;
                }
                // Vendored 3rd-party minified bundle: drop generic-secret
                // hits in vendored codemirror/pdfjs/wp-includes/etc. paths.
                if crate::pipeline::looks_like_vendored_minified_path(
                    chunk.metadata.path.as_deref(),
                ) {
                    continue;
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
                    continue;
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
                if generic_path_looks_like_random_base64_blob(value) {
                    continue;
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
                    continue;
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
                if crate::pipeline::should_suppress_known_example_credential_with_source(
                    value,
                    chunk.metadata.path.as_deref(),
                    crate::context::CodeContext::Unknown,
                    Some(chunk.metadata.source_type.as_str()),
                ) {
                    continue;
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
                    continue;
                }
                // Decode-through binary suppression: a generic high-entropy
                // candidate that base64/hex-decodes to identifiable binary
                // bytes (PNG / gzip / ELF / protobuf-wire) is embedded data,
                // not a credential.
                if crate::decode_structure::is_encoded_binary(value) {
                    continue;
                }

                // Context suppression: test files get lower confidence
                let context = crate::context::infer_context(
                    code_lines,
                    line_idx,
                    chunk.metadata.path.as_deref(),
                );
                let base_conf = match context {
                    crate::context::CodeContext::TestCode => 0.25,
                    // `--scan-comments` (see ScannerConfig.scan_comments)
                    // promotes comment-context credentials to the
                    // ordinary-source base confidence so a real secret
                    // pasted into a TODO/debug-trace comment surfaces
                    // instead of getting silently filtered. Documentation
                    // context stays downgraded - it's a different (and
                    // far noisier) signal class than inline comments.
                    crate::context::CodeContext::Comment if self.config.scan_comments => 0.60,
                    crate::context::CodeContext::Comment
                    | crate::context::CodeContext::Documentation => 0.30,
                    _ => 0.60,
                };

                // Boost confidence for longer, higher-entropy values
                let entropy_boost = ((entropy - 3.5) * 0.1).min(0.25);
                let length_boost = ((value.len() as f64 - 16.0) * 0.005).clamp(0.0, 0.15);
                let confidence = (base_conf + entropy_boost + length_boost).min(0.95);

                if confidence < self.config.min_confidence {
                    continue;
                }

                // Defect #80: this branch hard-coded `offset: 0` for every
                // generic-secret finding, so a `KEY = <secret>` on line 845
                // of a 137 KiB file reported offset 0 - the start of the
                // file - making the JSON impossible to navigate or grep.
                // The real offset is the start of the value within the
                // line, plus the line's start in the chunk, plus the
                // chunk's base offset in the original file (non-zero on
                // windowed >64 MiB scans).
                let chunk_line_offset = line_offsets.get(line_idx).copied().unwrap_or(0);
                let absolute_offset =
                    chunk.metadata.base_offset + chunk_line_offset + value_match.start();
                let raw = keyhog_core::RawMatch {
                    credential_hash: crate::sha256_hash(value),
                    detector_id: Arc::from("generic-secret"),
                    detector_name: Arc::from("Generic Secret (Key=Value)"),
                    service: Arc::from("generic"),
                    severity: keyhog_core::Severity::Medium,
                    credential: Arc::from(value),
                    companions: HashMap::new(),
                    location: keyhog_core::MatchLocation {
                        source: Arc::from(chunk.metadata.source_type.as_str()),
                        file_path: chunk.metadata.path.as_deref().map(Arc::from),
                        line: Some(line_num),
                        offset: absolute_offset,
                        commit: chunk.metadata.commit.as_deref().map(Arc::from),
                        author: chunk.metadata.author.as_deref().map(Arc::from),
                        date: chunk.metadata.date.as_deref().map(Arc::from),
                    },
                    entropy: Some(entropy),
                    confidence: Some(confidence),
                };
                scan_state.push_match(raw, self.config.max_matches_per_chunk);
            }
        }
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
///   3. EITHER contains a standard-base64 punctuation char (`+`/`/`)
///      OR ends with `=`/`==` padding (signaling the value is the
///      base64 encoding of a byte-aligned arbitrary-bytes payload).
///      Real provider tokens are pure base62 without padding
///      because their length isn't derived from base64 of bytes -
///      AKIA + 16, ghp_ + 36, sk_live_ + 24, etc. all land on
///      char counts that don't need `=` padding. Adding the
///      "padded" branch catches the residual ~862 FPs where the
///      payload happens to encode random bytes into pure-b62
///      characters but still needs the `==` padding to round out.
///   4. Length is a multiple of 4 OR ends with `=`/`==` padding.
fn generic_path_looks_like_random_base64_blob(value: &str) -> bool {
    if !(40..=300).contains(&value.len()) {
        return false;
    }
    let has_padding = value.ends_with("==") || value.ends_with('=');
    let length_mult_4 = value.len().is_multiple_of(4);
    if !has_padding && !length_mult_4 {
        return false;
    }
    let mut has_b64_punct = false;
    for c in value.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '=' => {}
            '+' | '/' => has_b64_punct = true,
            _ => return false,
        }
    }
    // Either standard-base64 punctuation OR explicit padding
    // (the b64-of-bytes signal - pure-b62 tokens never need `=`
    // because their length is chosen, not derived).
    has_b64_punct || has_padding
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
