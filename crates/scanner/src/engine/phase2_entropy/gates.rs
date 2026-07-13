//! Entropy-fallback candidate suppression predicate.
use super::helpers::*;
use super::line_context::{
    entropy_value_line, value_line_has_random_byte_blob_owner,
    value_line_has_same_line_credential_keyword,
};
use crate::adjudicate::EntropyShapeStage;
use crate::engine::*;
use crate::suppression::path_filter::{
    looks_like_entropy_raw_base64_file_path, path_is_ci_workflow_file, path_is_i18n_file,
};

pub(crate) fn entropy_match_suppression_stage(
    entropy_match: &crate::entropy::EntropyMatch,
    preprocessed: &ScannerPreprocessedText<'_>,
    line_offsets: &[usize],
    chunk: &Chunk,
    // ML-authoritative credential anchors may release canonical hash/UUID shape
    // gates; all other precision gates stay live.
    allow_canonical_lift: bool,
    source_entropy_requires_same_line_credential: bool,
    // Resolved BPE "rare-not-random" bound. `None` means the owning detector
    // explicitly disabled token efficiency; `Some` carries detector policy
    // with any Tier-A scan ceiling override already applied.
    bpe_max_bytes_per_token: Option<f64>,
) -> Option<EntropyShapeStage> {
    let randomness =
        crate::suppression::token_randomness::TokenRandomness::for_candidate(&entropy_match.value);
    // Proximity context is too loose to release canonical shapes; require the
    // credential keyword on the same line as the candidate.
    let same_line_credential_assignment =
        value_line_has_same_line_credential_keyword(entropy_match, preprocessed, line_offsets);
    if source_entropy_requires_same_line_credential
        && crate::suppression::shape::looks_like_source_type_identifier_with_randomness(
            &entropy_match.value,
            &randomness,
        )
    {
        return Some(EntropyShapeStage::SourceIdentifierInSourceContext);
    }
    if source_entropy_requires_same_line_credential && !same_line_credential_assignment {
        return Some(EntropyShapeStage::MissingSameLineCredential);
    }
    if chunk.metadata.source_type.contains("/caesar") {
        return Some(EntropyShapeStage::CaesarSource);
    }
    let same_line_high_signal_assignment_owner =
        value_line_has_random_byte_blob_owner(entropy_match, preprocessed, line_offsets);
    let canonical_lift = allow_canonical_lift
        && same_line_credential_assignment
        && crate::entropy::scanner::canonical_shape_lift_allowed(
            &entropy_match.value,
            &entropy_match.keyword,
        );
    let isolated_bare_token = entropy_match.keyword == crate::entropy::ISOLATED_BARE_ENTROPY_LABEL;
    let lower_dash_app_password = crate::entropy::scanner::lower_dash_app_password_floor_met(
        &entropy_match.value,
        entropy_match.entropy,
    );
    // Keep shared content gates live even when canonical shape gates are lifted.
    if let Some(stage) = crate::adjudicate::entropy_fallback_example_suppression_stage(
        entropy_match.value.as_str(),
        &entropy_match.keyword,
        entropy_match.entropy,
        chunk.metadata.path.as_deref(),
        Some(chunk.metadata.source_type.as_ref()),
        canonical_lift,
    ) {
        return Some(stage);
    }

    // Kebab identifiers near `key` words are usually config names, not secrets.
    if !isolated_bare_token
        && !lower_dash_app_password
        && crate::suppression::shape::looks_like_kebab_config_identifier(&entropy_match.value)
    {
        return Some(EntropyShapeStage::KebabIdentifier);
    }

    // Filename-shaped values beside keystore/file keywords are references.
    if crate::suppression::shape::looks_like_filename_reference(&entropy_match.value) {
        return Some(EntropyShapeStage::Filename);
    }

    // Pure identifiers are not entropy credentials; keep this local because the
    // entropy fallback emits directly instead of going through named suppression.
    if crate::suppression::shape::looks_like_pure_identifier(&entropy_match.value) {
        return Some(EntropyShapeStage::PureIdentifier);
    }
    // Whitespace-bearing values are natural-language labels or
    // free-text identifiers, not credentials. Real credentials
    // are tokenized strings without internal whitespace. Catches
    // macaroon `id: "brave-talk-free sku token v1"` (bat-go),
    // YAML descriptions, log-line excerpts.
    if entropy_match.value.bytes().any(|b| b == b' ' || b == b'\t') {
        return Some(EntropyShapeStage::Whitespace);
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
        && crate::suppression::shape::looks_like_english_prose(&entropy_match.value)
    {
        return Some(EntropyShapeStage::EnglishProse);
    }
    // Comma-bearing values are config/DSN-style metadata, not
    // credentials. Catches Redis DSN
    // `tcp,addr=:6379,password=macaron,db=0,pool_size=100,...`
    // (gogs conf/app.ini commented redis config), CSV rows,
    // multi-key=value config blobs.
    if entropy_match.value.contains(',') {
        return Some(EntropyShapeStage::CommaDelimited);
    }
    // Word-separated identifier with embedded digits (digits
    // short-circuit `looks_like_pure_identifier`). Catches
    // `broker1_keystore_creds` (bat-go docker-compose),
    // `s3_secret_access_key` (alist), train-case HTTP header
    // names, snake_case Go consts, etc.
    // KH-L-0415: see the `looks_like_pure_identifier` note above, same measured
    // no-op on both corpora, left as the plain gate by documented decision.
    if entropy_match.keyword != crate::entropy::ISOLATED_BARE_ENTROPY_LABEL
        && !(same_line_high_signal_assignment_owner
            && crate::entropy::scanner::mixed_separator_token_floor_met(
                &entropy_match.value,
                entropy_match.entropy,
            ))
        && !(same_line_high_signal_assignment_owner && lower_dash_app_password)
        && crate::suppression::shape::looks_like_word_separated_identifier(&entropy_match.value)
    {
        return Some(EntropyShapeStage::WordSeparatedIdentifier);
    }
    // Long train-case config/policy prose next to a credential keyword is still
    // prose, not an entropy-bearing secret. The same public-shape owner is used
    // by generic and weak-anchor postprocess paths so keyword context cannot
    // silently override a value-only public/non-secret shape.
    if crate::suppression::shape::public_noncredential_shape_with_randomness(
        &entropy_match.value,
        crate::suppression::shape::PublicShapeScope::Full,
        &randomness,
    )
    .is_some()
    {
        return Some(EntropyShapeStage::PublicNoncredentialShape);
    }
    // Scheme-prefixed URI / URN (`urn:shopify:...`,
    // `secret-token:<base64>`).
    if crate::suppression::shape::looks_like_scheme_prefixed_uri(&entropy_match.value) {
        return Some(EntropyShapeStage::SchemePrefixedUri);
    }
    let high_entropy_punctuation_payload =
        crate::suppression::shape::looks_like_high_entropy_punctuation_payload(
            &entropy_match.value,
            entropy_match.entropy,
        );
    if !high_entropy_punctuation_payload
        && crate::suppression::shape::looks_like_source_code_expression_with_randomness(
            &entropy_match.value,
            &randomness,
        )
    {
        return Some(EntropyShapeStage::SourceCodeExpression);
    }
    if crate::decode::caesar::is_program_source_code_path(chunk.metadata.path.as_deref())
        && crate::suppression::shape::looks_like_source_symbol_identifier_with_randomness(
            &entropy_match.value,
            &randomness,
        )
    {
        return Some(EntropyShapeStage::SourceSymbolIdentifier);
    }
    // Punctuation-decorated identifier (`--api-secret`,
    // `&gss_token`, `@v_password`, `!!apiKey`, `Password:`,
    // `privateAccessToken!`, `/etc/passwd:/etc/passwd:ro`).
    if !high_entropy_punctuation_payload
        && crate::suppression::shape::looks_like_punctuation_decorated_identifier(
            &entropy_match.value,
        )
    {
        return Some(EntropyShapeStage::PunctuationDecoratedIdentifier);
    }
    // URL / path-fragment shape (`user/settings/password`,
    // `/api/v1/access_token`). Keep long high-entropy base64 punctuation
    // payloads alive; a slash inside an opaque token is not path structure.
    if !high_entropy_punctuation_payload
        && crate::suppression::shape::looks_like_url_or_path_segment(&entropy_match.value)
    {
        return Some(EntropyShapeStage::UrlOrPathSegment);
    }
    // UUID v4 substring (`TOKEN_LIST=636765a9-1f92-4b40-ab0b-85ebd1e2c23d`
    // in bat-go docker-compose.reputation.yml). The entropy fallback
    // grabs the whole env-var assignment; the high-entropy payload
    // is just the UUID, which is a public identifier, not a credential.
    //
    // CredData recall lane: release this gate ONLY when (a) the lift is
    // engaged for a credential-anchored candidate AND (b) the value is itself
    // EXACTLY a UUID shape: `KEY = "<uuid>"` where the whole assigned value is
    // the UUID, the CredData `UUID` miss class (LaunchDarkly SDK keys, Heroku
    // UUID keys, PowerBI client secrets are all UUID-bodied). A value that
    // merely CONTAINS a UUID as a substring of a longer payload
    // (`TOKEN_LIST=<...uuid...>`) is still suppressed, that residual is a
    // public identifier inside an env list, not a credential, and the MoE has
    // no anchor to arbitrate it. The whole-value UUID under a strong keyword is
    // the one the model can earn.
    let value_is_exact_uuid = crate::suppression::shape::is_uuid_v4_shape(&entropy_match.value);
    if !(canonical_lift && value_is_exact_uuid)
        && crate::suppression::shape::contains_uuid_v4_substring(&entropy_match.value)
    {
        return Some(EntropyShapeStage::UuidV4OrSubstring);
    }
    // Email address (gogs TestInit.golden.ini:89 `USER=noreply@gogs.localhost`
    // captured as entropy-password due to nearby `PASSWORD=` line).
    if crate::suppression::shape::looks_like_email_address(&entropy_match.value) {
        return Some(EntropyShapeStage::EmailAddress);
    }
    // Blockchain / network address keyword context: the line
    // containing the entropy hit is a `<KEY>=<value>` assignment
    // where KEY names a blockchain or network public identifier
    // (`SOLANA_BAT_MINT_ADDRS=EPeU…1Tpz`, `OWNER_PUBKEY=…`,
    // `CONTRACT_ADDRESS=0x…`, `WALLET=…`). These are PUBLIC
    // identifiers, not credentials. Cheap line lookup via the
    // preprocessed text + line_offsets table.
    if let Some(line_text) = entropy_value_line(entropy_match, preprocessed, line_offsets) {
        let line_upper = line_text.to_ascii_uppercase();
        #[derive(serde::Deserialize)]
        struct BlockchainAddrKeywordsFile {
            keywords: Vec<String>,
        }
        // One owner: rules/blockchain-address-keywords.toml (Tier-B data).
        static BLOCKCHAIN_ADDR_KEYWORDS: std::sync::LazyLock<Vec<String>> =
            std::sync::LazyLock::new(|| {
                match toml::from_str::<BlockchainAddrKeywordsFile>(include_str!(
                    "../../../../../rules/blockchain-address-keywords.toml"
                )) {
                    Ok(parsed) => parsed.keywords,
                    Err(error) => panic!(
                        "rules/blockchain-address-keywords.toml is invalid: {error}. \
                         Fix the Tier-B blockchain keyword list."
                    ),
                }
            });
        if BLOCKCHAIN_ADDR_KEYWORDS
            .iter()
            .any(|kw| line_upper.contains(kw.as_str()))
        {
            return Some(EntropyShapeStage::BlockchainOrNetworkAddress);
        }
    }
    // Vendored 3rd-party minified bundle: any "secret-like"
    // sequence is a minification coincidence, not a leak.
    if crate::suppression::path_filter::looks_like_vendored_minified_path(
        chunk.metadata.path.as_deref(),
    ) {
        return Some(EntropyShapeStage::VendoredMinifiedPath);
    }
    // Raw base64 files (`.b64`, `.base64`, `base64_string.txt`):
    // alphabet-coincidence matches inside the base64 stream are
    // not credentials.
    if looks_like_entropy_raw_base64_file_path(chunk.metadata.path.as_deref()) {
        return Some(EntropyShapeStage::RawBase64File);
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
    // evidence - entropy phase-2's "lots of varied bytes" is
    // not enough signal in this context. 25+ FPs across bat-go,
    // bat-ledger, brave-talk, malachite, orb-firmware dogfood.
    if path_is_ci_workflow_file(chunk.metadata.path.as_deref()) {
        return Some(EntropyShapeStage::CiWorkflowFile);
    }

    // i18n / translation file context: gogs ships ~150 .ini
    // locale files (locale_en-US.ini, locale_hu-HU.ini, etc.)
    // with translation strings around "password", "token",
    // "key" keywords. The entropy phase-2 path fires on the
    // translated text (Hungarian "Jelszó", Portuguese "Senha",
    // Latvian "Parole") because non-ASCII bytes have high
    // entropy. 103 entropy-password FPs in gogs alone.
    // The same family covers .po (gettext), .properties
    // (Java i18n), and any path with /locale/ or /i18n/.
    if path_is_i18n_file(chunk.metadata.path.as_deref()) {
        return Some(EntropyShapeStage::I18nFile);
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
        return Some(EntropyShapeStage::ShellExpansionOrTemplate);
    }

    // Same standard-base64-arbitrary-bytes suppression the
    // generic-secret path applies. Reuses the [40, 300]
    // window + `+/` requirement; covers protobuf wire
    // dumps and k8s `data:` field values that the named-
    // detector path missed because they have no service-
    // specific keyword anchor.
    if !high_entropy_punctuation_payload
        && crate::suppression::shape::looks_like_entropy_random_base64_blob_decoy(
            &entropy_match.value,
        )
    {
        return Some(EntropyShapeStage::RandomBase64Blob);
    }
    let decode_evidence = crate::decode_structure::evidence(&entropy_match.value);
    // Decode-through coherence (entropy phase-2 path). The
    // ML-pending pipeline calls `apply_post_ml_penalties`
    // which gates on the shared decode evidence,
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
    if !high_entropy_punctuation_payload && decode_evidence.is_binary_payload() {
        return Some(EntropyShapeStage::EncodedBinary);
    }
    // Random-byte base64 decoy coherence for the entropy path. The generic
    // bridge already dogfood-suppresses pure standard-base64 random-byte blobs,
    // but entropy emits independently. Do not reuse that broad gate verbatim:
    // TOKEN/API_KEY/DEPLOY_TOKEN positives can be opaque base64-looking random
    // bytes. Require decoded NUL evidence before entropy hard-drops the value.
    if !isolated_bare_token
        && !same_line_high_signal_assignment_owner
        && !high_entropy_punctuation_payload
        && decode_evidence.decoded_contains_nul_byte()
        && crate::suppression::shape::looks_like_random_byte_base64_blob(&entropy_match.value)
    {
        return Some(EntropyShapeStage::RandomByteBlob);
    }
    // Same gate for the decoded-form placeholder check: a
    // base64-wrapped docs sample (e.g.
    // QUtJQUVYQU1QTEVFWEFNUExFMTI= = AKIAEXAMPLEEXAMPLE12) gets
    // through the surface-form `should_suppress_known_example_…`
    // call above because the base64 hides the EXAMPLE marker.
    // Keep parity with the generic-secret emit path.
    if decode_evidence.decoded_contains_placeholder() {
        return Some(EntropyShapeStage::DecodedPlaceholder);
    }
    // BPE "rare-not-random" precision gate. LAST, so it only tokenizes the few
    // candidates that survived every cheaper shape gate above. Word-like values
    // (dotted API paths like `PInvoke.User32.WM_*`, prose, XML) compress into a
    // handful of common cl100k_base subword tokens; real secrets tokenize into
    // many short pieces. Opaque-token detectors enable this as a final gate;
    // human-password detectors explicitly disable it because word-like values
    // are legitimate there. Validated as a large CredData precision win (F1
    // 0.368→0.424) for a small recall cost. See `crate::entropy::bpe`.
    if bpe_max_bytes_per_token
        .is_some_and(|bound| crate::entropy::bpe::is_word_like_low_bpe(&entropy_match.value, bound))
    {
        return Some(EntropyShapeStage::WordLikeLowBpe);
    }
    None
}
