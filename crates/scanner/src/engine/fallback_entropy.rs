#[cfg(feature = "entropy")]
use super::fallback_entropy_helpers::*;
#[cfg(feature = "entropy")]
use super::*;
#[cfg(feature = "entropy")]
use keyhog_core::MatchLocation;
#[cfg(feature = "entropy")]
use std::collections::HashMap;

#[cfg(feature = "entropy")]
impl CompiledScanner {
    pub(crate) fn scan_entropy_fallback(
        &self,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        if !self.config.entropy_enabled {
            return;
        }
        if !crate::entropy::is_entropy_appropriate(
            chunk.metadata.path.as_deref(),
            self.config.entropy_in_source_files,
        ) {
            return;
        }

        // Skip entropy scanning on lines that already have named detector matches.
        let mut skip_lines = std::collections::HashSet::new();
        for m in &scan_state.matches {
            let id = &*m.0.detector_id;
            if !id.starts_with("generic-") && !id.starts_with("entropy-") {
                if let Some(line) = m.0.location.line {
                    skip_lines.insert(line);
                }
            }
        }

        let keyword_free_threshold =
            if crate::entropy::is_sensitive_file(chunk.metadata.path.as_deref()) {
                crate::entropy::SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD
            } else {
                crate::entropy::VERY_HIGH_ENTROPY_THRESHOLD
            };

        let entropy_matches = crate::entropy::find_entropy_secrets_with_threshold(
            &preprocessed.text,
            16,
            1,
            self.config.entropy_threshold,
            keyword_free_threshold,
            &self.config.secret_keywords,
            &self.config.test_keywords,
            &self.config.placeholder_keywords,
            Some(&skip_lines),
        );

        for entropy_match in entropy_matches {
            let (detector_id_value, detector_name_value, service_value) =
                classify_entropy_detector(&entropy_match.keyword);
            let base_confidence =
                if entropy_match.entropy >= crate::entropy::VERY_HIGH_ENTROPY_THRESHOLD {
                    0.75
                } else if entropy_match.entropy >= crate::entropy::HIGH_ENTROPY_THRESHOLD {
                    0.65
                } else {
                    0.55_f64.min(entropy_match.entropy / 8.0)
                };
            let confidence = if entropy_match.keyword != "none (high-entropy)" {
                (base_confidence + 0.1).min(0.90_f64)
            } else {
                base_confidence
            };
            // `entropy_match.offset` is ALREADY the byte offset of the
            // start of the containing line (set by `collect_line_candidates`
            // from the same `line_offsets` table). The earlier
            // `line_offsets[entropy_match.line - 1] + entropy_match.offset`
            // double-counted that base, producing offsets ~2× the file
            // size for findings late in the file - defect #80, 130+
            // corrupted finding offsets across the dogfood corpora. Use
            // the value directly. `_line_offsets` retained as a
            // parameter for the windowed/multiline paths that still need
            // it. `chunk.metadata.base_offset` is added for windowed
            // chunks (>64 MiB files) so the reported offset is the
            // absolute file offset, not the per-window one.
            let _ = line_offsets;
            let offset = entropy_match.offset + chunk.metadata.base_offset;

            // Hash-shape / UUID / license-key / RFC-JWT suppression.
            // The named-detector + generic-secret paths call
            // `should_suppress_known_example_credential_with_source`
            // before emitting; the entropy fallback was skipping it,
            // letting UUIDs, sha256 hex, license-key serials,
            // `nginx@sha256:...` docker digests, npm-lock integrity
            // values and the RFC 7519 specimen JWT through as
            // false positives. SecretBench-medium 15k seed-0:
            // 387 leaked FPs across uuid (127) + sha256-hex (118) +
            // sha1-hex (61) + npm-lock-integrity (102) + others.
            // Calling the gate here closes the leak without
            // touching the other emit paths.
            if crate::pipeline::should_suppress_known_example_credential_with_source(
                &entropy_match.value,
                chunk.metadata.path.as_deref(),
                crate::context::CodeContext::Unknown,
                Some(chunk.metadata.source_type.as_str()),
            ) {
                continue;
            }

            // kebab-case-identifier suppression: short values made
            // mostly of lowercase letters with 1+ dashes (e.g.
            // `api-key-secret`, `token-secret`, `db-password`) are
            // k8s/yaml `name:` metadata fields, NOT credentials.
            // The entropy fallback was firing on these as
            // `entropy-api-key` because `key` matched a keyword
            // anchor near the value - but the value itself is an
            // identifier, not a high-entropy random string.
            if entropy_path_looks_like_kebab_identifier(&entropy_match.value) {
                continue;
            }

            // Filename-shape suppression: values ending in a common
            // file extension (`.jks`, `.yml`, `.yaml`, `.toml`,
            // `.json`, `.properties`, `.pem`, `.key`, `.crt`, `.cer`,
            // `.pfx`, `.p12`, `.keystore`, `.truststore`) are
            // file/keystore references next to a `KEYSTORE_FILENAME:`
            // / `TRUSTSTORE_FILENAME:` keyword anchor - NOT
            // credentials. Bat-go's docker-compose.yml had 4+
            // entropy-api-key FPs on `kafka.broker1.keystore.jks`
            // /`kafka.broker1.truststore.jks`.
            if entropy_path_looks_like_filename(&entropy_match.value) {
                continue;
            }

            // Pure-identifier shape: CamelCase, snake_case_no_digit,
            // or pure-alphabetic dictionary word. The named-detector
            // path applies this through `should_suppress_named_detector_finding`,
            // but the entropy fallback emits matches directly so it
            // needs its own gate. Without this, WebGoat's German i18n
            // .properties file fires `entropy-password` on
            // `Benutzername` (12 letters, no digit - clearly a
            // dictionary word, not a credential).
            if crate::pipeline::looks_like_pure_identifier(&entropy_match.value) {
                continue;
            }
            // Whitespace-bearing values are natural-language labels or
            // free-text identifiers, not credentials. Real credentials
            // are tokenized strings without internal whitespace. Catches
            // macaroon `id: "brave-talk-free sku token v1"` (bat-go),
            // YAML descriptions, log-line excerpts.
            if entropy_match.value.bytes().any(|b| b == b' ' || b == b'\t') {
                continue;
            }
            // Comma-bearing values are config/DSN-style metadata, not
            // credentials. Catches Redis DSN
            // `tcp,addr=:6379,password=macaron,db=0,pool_size=100,...`
            // (gogs conf/app.ini commented redis config), CSV rows,
            // multi-key=value config blobs.
            if entropy_match.value.contains(',') {
                continue;
            }
            // Word-separated identifier with embedded digits (digits
            // short-circuit `looks_like_pure_identifier`). Catches
            // `broker1_keystore_creds` (bat-go docker-compose),
            // `s3_secret_access_key` (alist), train-case HTTP header
            // names, snake_case Go consts, etc.
            if crate::pipeline::looks_like_word_separated_identifier(&entropy_match.value) {
                continue;
            }
            // Scheme-prefixed URI / URN (`urn:shopify:...`,
            // `secret-token:<base64>`).
            if crate::pipeline::looks_like_scheme_prefixed_uri(&entropy_match.value) {
                continue;
            }
            // Punctuation-decorated identifier (`--api-secret`,
            // `&gss_token`, `@v_password`, `!!apiKey`, `Password:`,
            // `privateAccessToken!`, `/etc/passwd:/etc/passwd:ro`).
            if crate::pipeline::looks_like_punctuation_decorated_identifier(&entropy_match.value) {
                continue;
            }
            // URL / path-fragment shape (`user/settings/password`,
            // `/api/v1/access_token`).
            if crate::pipeline::looks_like_url_or_path_segment(&entropy_match.value) {
                continue;
            }
            // UUID v4 substring (`TOKEN_LIST=636765a9-1f92-4b40-ab0b-85ebd1e2c23d`
            // in bat-go docker-compose.reputation.yml). The entropy fallback
            // grabs the whole env-var assignment; the high-entropy payload
            // is just the UUID, which is a public identifier, not a credential.
            if crate::pipeline::contains_uuid_v4_substring(&entropy_match.value) {
                continue;
            }
            // Email address (gogs TestInit.golden.ini:89 `USER=noreply@gogs.localhost`
            // captured as entropy-password due to nearby `PASSWORD=` line).
            if crate::pipeline::looks_like_email_address(&entropy_match.value) {
                continue;
            }
            // Blockchain / network address keyword context: the line
            // containing the entropy hit is a `<KEY>=<value>` assignment
            // where KEY names a blockchain or network public identifier
            // (`SOLANA_BAT_MINT_ADDRS=EPeU…1Tpz`, `OWNER_PUBKEY=…`,
            // `CONTRACT_ADDRESS=0x…`, `WALLET=…`). These are PUBLIC
            // identifiers, not credentials. Cheap line lookup via the
            // preprocessed text + line_offsets table.
            let line_idx = entropy_match.line.saturating_sub(1);
            if let Some(&line_start) = line_offsets.get(line_idx) {
                let line_end = line_offsets
                    .get(line_idx + 1)
                    .copied()
                    .unwrap_or(preprocessed.text.len());
                if let Some(line_text) = preprocessed.text.get(line_start..line_end) {
                    let line_upper = line_text.to_ascii_uppercase();
                    const BLOCKCHAIN_ADDR_KEYWORDS: &[&str] = &[
                        "_ADDR=",
                        "_ADDR ",
                        "_ADDR\"",
                        "_ADDR:",
                        "_ADDRS=",
                        "_ADDRS ",
                        "_ADDRS\"",
                        "_ADDRESS=",
                        "_ADDRESS ",
                        "_ADDRESS\"",
                        "_WALLET=",
                        "_WALLET ",
                        "_WALLET\"",
                        "_MINT_ADDR",
                        "_PUBKEY=",
                        "_PUBKEY ",
                        "_PUBLIC_KEY=",
                        "_PUBLIC_KEY ",
                        "_PUBLIC_KEY\"",
                        "_CONTRACT=",
                        "_CONTRACT ",
                        "_OWNER=",
                        "_ACCOUNT_ID=",
                        "_PEER_ID=",
                        "_NODE_ID=",
                    ];
                    if BLOCKCHAIN_ADDR_KEYWORDS
                        .iter()
                        .any(|kw| line_upper.contains(kw))
                    {
                        continue;
                    }
                }
            }
            // Vendored 3rd-party minified bundle: any "secret-like"
            // sequence is a minification coincidence, not a leak.
            if crate::pipeline::looks_like_vendored_minified_path(chunk.metadata.path.as_deref()) {
                continue;
            }
            // Raw base64 files (`.b64`, `.base64`, `base64_string.txt`):
            // alphabet-coincidence matches inside the base64 stream are
            // not credentials.
            if chunk.metadata.path.as_deref().is_some_and(|p| {
                // Raw-byte case-insensitive checks, no per-match alloc.
                let bytes = p.as_bytes();
                if crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b".b64")
                    || crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b".base64")
                {
                    return true;
                }
                // Split on both `/` and `\` so Windows-form paths
                // (`C:\foo\bar\base64_blob.txt`) produce the same
                // basename as their Unix counterparts. Without the
                // backslash, every Windows scan misses this filename
                // gate and emits FP entropy-* findings on legitimate
                // base64-tagged files.
                let basename = bytes
                    .iter()
                    .rposition(|&b| b == b'/' || b == b'\\')
                    .map(|i| &bytes[i + 1..])
                    .unwrap_or(bytes);
                crate::ascii_ci::starts_with_ignore_ascii_case(basename, b"base64_")
                    || crate::ascii_ci::ci_find(basename, b"base64_string")
            }) {
                continue;
            }

            // CI workflow file context: entropy-* in `.github/workflows/`,
            // `.gitlab-ci.yml`, `.circleci/config.yml`, `azure-pipelines.yml`
            // is almost exclusively FPs. Real secrets in CI configs live
            // behind `${{ secrets.NAME }}` references (or equivalent),
            // never as raw values. What entropy-* catches in workflow
            // files is action version refs (`aws-actions/configure-aws-
            // credentials@v1.0`), step names (`Setup Node`,
            // `Upload to Codecov`), bash subshells (`$(echo ${SHA} | ...)`),
            // and GitHub context interpolations. Named detectors
            // (github-pat, aws-akia, slack-token, …) still fire here
            // because their keyword anchors give independent positive
            // evidence - entropy-fallback's "lots of varied bytes" is
            // not enough signal in this context. 25+ FPs across bat-go,
            // bat-ledger, brave-talk, malachite, orb-firmware dogfood.
            if entropy_path_is_ci_workflow_file(chunk.metadata.path.as_deref()) {
                continue;
            }

            // i18n / translation file context: gogs ships ~150 .ini
            // locale files (locale_en-US.ini, locale_hu-HU.ini, etc.)
            // with translation strings around "password", "token",
            // "key" keywords. The entropy fallback fires on the
            // translated text (Hungarian "Jelszó", Portuguese "Senha",
            // Latvian "Parole") because non-ASCII bytes have high
            // entropy. 103 entropy-password FPs in gogs alone.
            // The same family covers .po (gettext), .properties
            // (Java i18n), and any path with /locale/ or /i18n/.
            if entropy_path_is_i18n_file(chunk.metadata.path.as_deref()) {
                continue;
            }

            // Shell-expansion / template-literal shapes: values starting
            // with `$(`, `${`, `$ECR`, `$RUN`, `$VAR`, `\"${`, or `[{ \"`
            // are shell command substitutions, env-var refs, or JSON
            // matrix bodies - not credentials. Workflow files generate
            // these in volume.
            if entropy_match.value.starts_with("$(")
                || entropy_match.value.starts_with("${")
                || entropy_match.value.starts_with("\\\"${")
                || entropy_match.value.starts_with("[{ \"")
                || entropy_match.value.starts_with("{ \"a")
                || entropy_match.value.starts_with("$ECR")
                || entropy_match.value.starts_with("$RUN")
                || (entropy_match.value.starts_with('$')
                    && entropy_match
                        .value
                        .chars()
                        .nth(1)
                        .is_some_and(|c| c.is_ascii_uppercase()))
            {
                continue;
            }

            // Same standard-base64-arbitrary-bytes suppression the
            // generic-secret path applies. Reuses the [40, 300]
            // window + `+/` requirement; covers protobuf wire
            // dumps and k8s `data:` field values that the named-
            // detector path missed because they have no service-
            // specific keyword anchor.
            if entropy_path_looks_like_random_base64_blob(&entropy_match.value) {
                continue;
            }

            // Decode-through coherence (entropy-fallback path). The
            // ML-pending pipeline calls `apply_post_ml_penalties`
            // which gates on `decode_structure::is_encoded_binary`,
            // but the entropy-fallback emits directly via
            // `push_match` and skips that gate - so a generic
            // high-entropy candidate that decodes to a PNG / gzip /
            // PE / protobuf-wire message would surface here even
            // though every named-detector and generic-secret emit
            // would suppress it. This block closes the wiring gap
            // so keyhog's decode-through advantage flows through
            // every emit path, not just the ML-pending one. The
            // verdict is definitional (magic bytes OR full
            // protobuf-wire parse) so it never false-suppresses a
            // real secret. Memoized in `decode_structure`, so the
            // cost is a single bytes-hash + cache lookup.
            if crate::decode_structure::is_encoded_binary(&entropy_match.value) {
                continue;
            }

            let detector_id = scan_state.intern_metadata(detector_id_value);
            let detector_name = scan_state.intern_metadata(detector_name_value);
            let service = scan_state.intern_metadata(service_value);
            let credential = scan_state.intern_credential(&entropy_match.value);
            let source = scan_state.intern_metadata(&chunk.metadata.source_type);
            let file_path = chunk
                .metadata
                .path
                .as_ref()
                .map(|path| scan_state.intern_metadata(path));
            let commit = chunk
                .metadata
                .commit
                .as_ref()
                .map(|commit| scan_state.intern_metadata(commit));
            let author = chunk
                .metadata
                .author
                .as_ref()
                .map(|author| scan_state.intern_metadata(author));
            let date = chunk
                .metadata
                .date
                .as_ref()
                .map(|date| scan_state.intern_metadata(date));

            scan_state.push_match(
                RawMatch {
                    credential_hash: crate::sha256_hash(&entropy_match.value),
                    detector_id,
                    detector_name,
                    service,
                    severity: keyhog_core::Severity::High,
                    credential,
                    companions: HashMap::new(),
                    location: MatchLocation {
                        source,
                        file_path,
                        line: Some(entropy_match.line),
                        offset,
                        commit,
                        author,
                        date,
                    },
                    entropy: Some(entropy_match.entropy),
                    confidence: Some(confidence),
                },
                self.config.max_matches_per_chunk,
            );
        }
    }
}
