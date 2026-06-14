//! Entropy-fallback per-candidate SUPPRESSION GAUNTLET, extracted from
//! `fallback_entropy.rs` (Law 5). `entropy_match_suppressed` is the pure
//! predicate the `scan_entropy_fallback` loop calls after computing a
//! candidate's confidence/offset: true iff any precision gate would have
//! `continue`d (hash / uuid / identifier / uri / prose / blockchain-addr /
//! base64-file / ci-workflow / i18n / encoded-binary / placeholder families).
//! Behaviour-identical to the former inline gauntlet — every gate verbatim,
//! each `continue` became `return true`. Takes no `self`: it reads only the
//! candidate, the chunk/preprocessed context, and the `fallback_entropy_helpers`
//! path predicates. Recall guarded by the entropy bench gates.
#![cfg(feature = "entropy")]
use super::fallback_entropy_helpers::*;
use super::*;

/// True iff an entropy-fallback candidate should be suppressed by any precision
/// gate. Pure — no side effects, no emission. Extracted verbatim from
/// `scan_entropy_fallback` (Law 5).
pub(crate) fn entropy_match_suppressed(
    entropy_match: &crate::entropy::EntropyMatch,
    preprocessed: &ScannerPreprocessedText<'_>,
    line_offsets: &[usize],
    chunk: &Chunk,
) -> bool {
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
    // Strict suppression here: entropy-fallback's "credential context"
    // is keyword-PROXIMITY (any line within ±N lines of a credential
    // keyword), which is too loose to bypass the hash-digest / UUID
    // shape gates. A `# api_key` comment one line above a `sha256:`
    // line would otherwise let the 64-hex digest through. The
    // generic-secret path runs first on the same chunk and DOES use
    // the credential-anchor variant (its regex requires the
    // credential keyword directly adjacent to the value), so direct
    // `TOKEN=<hex>` assignments still surface.
    if crate::pipeline::should_suppress_known_example_credential_with_source(
        &entropy_match.value,
        chunk.metadata.path.as_deref(),
        crate::context::CodeContext::Unknown,
        Some(chunk.metadata.source_type.as_str()),
    ) {
        return true;
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
        return true;
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
        return true;
    }

    // Pure-identifier shape: CamelCase, snake_case_no_digit,
    // or pure-alphabetic dictionary word. The named-detector
    // path applies this through `should_suppress_named_detector_finding`,
    // but the entropy fallback emits matches directly so it
    // needs its own gate. Without this, WebGoat's German i18n
    // .properties file fires `entropy-password` on
    // `Benutzername` (12 letters, no digit - clearly a
    // dictionary word, not a credential).
    // KH-L-0415 (EVALUATED, intentionally NOT discriminator-gated): unlike the
    // generic-bridge + api.rs paths, gating this on `token_randomness` is a
    // measured NO-OP on both bench corpora (mirror + CredData byte-identical
    // A/B). The generic keyword bridge is the PRIMARY surfacing path and already
    // recovers keyword-anchored random passwords (KH-L-0413) before the entropy
    // fallback runs, and this path's own keyword-aware prose backstop (line ~113)
    // already keeps strong-keyword-anchored lowercase values — so the
    // discriminator changes no outcome here while adding model dependence to a
    // precision-sensitive model-authoritative path. Left as the plain gate; the
    // coherence decision is documented, not blindly wired.
    if crate::pipeline::looks_like_pure_identifier(&entropy_match.value) {
        return true;
    }
    // Whitespace-bearing values are natural-language labels or
    // free-text identifiers, not credentials. Real credentials
    // are tokenized strings without internal whitespace. Catches
    // macaroon `id: "brave-talk-free sku token v1"` (bat-go),
    // YAML descriptions, log-line excerpts.
    if entropy_match.value.bytes().any(|b| b == b' ' || b == b'\t') {
        return true;
    }
    // English-prose suppression: a 16+ char value that is pure
    // lowercase ASCII letters (no digit, no symbol), OR a
    // multi-token whitespace-bearing alphabetic value with at
    // least one lowercase word, is virtually never a real
    // credential - real tokens are mixed-case + digits. When
    // the line is NOT directly anchored by a strong credential
    // keyword (e.g. `description = "..."` happens to land near
    // `password` in the file), the joined-word shape is
    // overwhelmingly free-text.
    //
    // We only apply this when the keyword anchor is weak: if
    // the candidate's keyword is itself a strong credential
    // anchor (`api_key`, `token`, `password`, ...), the
    // keyword itself is positive evidence and we keep the
    // candidate - users do plant lowercase-only passwords.
    if !keyword_is_credential_anchor(&entropy_match.keyword)
        && crate::entropy::keywords::entropy_value_looks_like_prose(&entropy_match.value)
    {
        return true;
    }
    // Comma-bearing values are config/DSN-style metadata, not
    // credentials. Catches Redis DSN
    // `tcp,addr=:6379,password=macaron,db=0,pool_size=100,...`
    // (gogs conf/app.ini commented redis config), CSV rows,
    // multi-key=value config blobs.
    if entropy_match.value.contains(',') {
        return true;
    }
    // Word-separated identifier with embedded digits (digits
    // short-circuit `looks_like_pure_identifier`). Catches
    // `broker1_keystore_creds` (bat-go docker-compose),
    // `s3_secret_access_key` (alist), train-case HTTP header
    // names, snake_case Go consts, etc.
    // KH-L-0415: see the `looks_like_pure_identifier` note above — same measured
    // no-op on both corpora, left as the plain gate by documented decision.
    if crate::pipeline::looks_like_word_separated_identifier(&entropy_match.value) {
        return true;
    }
    // Scheme-prefixed URI / URN (`urn:shopify:...`,
    // `secret-token:<base64>`).
    if crate::pipeline::looks_like_scheme_prefixed_uri(&entropy_match.value) {
        return true;
    }
    let high_entropy_punctuation_payload = entropy_match.entropy >= 4.8
        && entropy_match.value.len() >= 40
        && (entropy_match.value.contains('+') || entropy_match.value.contains('/'));
    // Punctuation-decorated identifier (`--api-secret`,
    // `&gss_token`, `@v_password`, `!!apiKey`, `Password:`,
    // `privateAccessToken!`, `/etc/passwd:/etc/passwd:ro`).
    if !high_entropy_punctuation_payload
        && crate::pipeline::looks_like_punctuation_decorated_identifier(
            &entropy_match.value,
        )
    {
        return true;
    }
    // URL / path-fragment shape (`user/settings/password`,
    // `/api/v1/access_token`).
    if crate::pipeline::looks_like_url_or_path_segment(&entropy_match.value) {
        return true;
    }
    // UUID v4 substring (`TOKEN_LIST=636765a9-1f92-4b40-ab0b-85ebd1e2c23d`
    // in bat-go docker-compose.reputation.yml). The entropy fallback
    // grabs the whole env-var assignment; the high-entropy payload
    // is just the UUID, which is a public identifier, not a credential.
    if crate::pipeline::contains_uuid_v4_substring(&entropy_match.value) {
        return true;
    }
    // Email address (gogs TestInit.golden.ini:89 `USER=noreply@gogs.localhost`
    // captured as entropy-password due to nearby `PASSWORD=` line).
    if crate::pipeline::looks_like_email_address(&entropy_match.value) {
        return true;
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
                return true;
            }
        }
    }
    // Vendored 3rd-party minified bundle: any "secret-like"
    // sequence is a minification coincidence, not a leak.
    if crate::pipeline::looks_like_vendored_minified_path(chunk.metadata.path.as_deref()) {
        return true;
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
        return true;
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
        return true;
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
        return true;
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
        return true;
    }

    // Same standard-base64-arbitrary-bytes suppression the
    // generic-secret path applies. Reuses the [40, 300]
    // window + `+/` requirement; covers protobuf wire
    // dumps and k8s `data:` field values that the named-
    // detector path missed because they have no service-
    // specific keyword anchor.
    if !high_entropy_punctuation_payload
        && entropy_path_looks_like_random_base64_blob(&entropy_match.value)
    {
        return true;
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
    if !high_entropy_punctuation_payload
        && crate::decode_structure::is_encoded_binary(&entropy_match.value)
    {
        return true;
    }
    // Same gate for the decoded-form placeholder check: a
    // base64-wrapped docs sample (e.g.
    // QUtJQUVYQU1QTEVFWEFNUExFMTI= = AKIAEXAMPLEEXAMPLE12) gets
    // through the surface-form `should_suppress_known_example_…`
    // call above because the base64 hides the EXAMPLE marker.
    // Keep parity with the generic-secret emit path.
    if crate::decode_structure::decoded_contains_placeholder(&entropy_match.value) {
        return true;
    }
    false
}
