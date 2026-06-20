//! Entropy-fallback per-candidate SUPPRESSION GAUNTLET, extracted from
//! `phase2_entropy.rs` (Law 5). `entropy_match_suppressed` is the pure
//! predicate the `scan_entropy_fallback` loop calls after computing a
//! candidate's confidence/offset: true iff any precision gate would have
//! `continue`d (hash / uuid / identifier / uri / prose / blockchain-addr /
//! base64-file / ci-workflow / i18n / encoded-binary / placeholder families).
//! Behaviour-identical to the former inline gauntlet — every gate verbatim,
//! each `continue` became `return true`. Takes no `self`: it reads only the
//! candidate, the chunk/preprocessed context, and the `helpers`
//! path predicates. Recall guarded by the entropy bench gates.
#![cfg(feature = "entropy")]
use super::helpers::*;
use crate::engine::*;

/// True iff an entropy-fallback candidate should be suppressed by any precision
/// gate. Pure — no side effects, no emission. Extracted verbatim from
/// `scan_entropy_fallback` (Law 5).
pub(crate) fn entropy_match_suppressed(
    entropy_match: &crate::entropy::EntropyMatch,
    preprocessed: &ScannerPreprocessedText<'_>,
    line_offsets: &[usize],
    chunk: &Chunk,
    // CredData recall lane (candidate GENERATION). When `true` the MoE is the
    // runtime precision authority; a canonical hash/UUID-shaped candidate that
    // the generation lift produced under a strong credential anchor must reach
    // the model, so the two SHAPE gates that would re-drop it here — the
    // UUID-substring gate and the hash-digest arm of the known-example check —
    // are skipped, but ONLY for a credential-anchored candidate (keyword is a
    // real credential anchor, not the keyword-free `none (high-entropy)`
    // label). Every OTHER gate runs verbatim. False ⇒ byte-identical strict
    // gauntlet.
    allow_canonical_lift: bool,
) -> bool {
    // The lift only releases the shape gates for a candidate that carries a
    // STRONG credential keyword anchor (the only candidates the generation lift
    // produces with a canonical shape). A keyword-free or weak-anchor candidate
    // keeps the full strict gauntlet, so the release surface is exactly the one
    // the model earns.
    //
    // The entropy phase-2 path's "credential context" is keyword PROXIMITY (any line
    // within ±1 line of a credential-keyword assignment), which is too loose to
    // release a shape gate on its own — a `sha256:` digest one line below a
    // `# api_key` comment would qualify. So the lift additionally requires the
    // credential keyword to sit on the SAME line as the value (a true
    // `KEYWORD = <uuid/hex>` assignment), which is the only context where a
    // canonical shape is genuinely the assigned secret. This pins the release to
    // the direct-assignment surface the MoE can actually arbitrate.
    let canonical_lift = allow_canonical_lift
        && keyword_is_credential_anchor(&entropy_match.keyword)
        && value_line_has_same_line_credential_keyword(entropy_match, preprocessed, line_offsets)
        && crate::entropy::scanner::canonical_shape_lift_allowed(
            &entropy_match.value,
            &entropy_match.keyword,
        );
    // Hash/UUID/license/JWT suppression mirrors the named/generic paths. The
    // canonical-lift lane releases only complete credential-anchored hex/UUID
    // shapes; content gates for examples, placeholders, npm integrity, and
    // decoded specimens remain live.
    if entropy_fallback_example_suppressed(entropy_match, chunk, canonical_lift) {
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

    // Pure identifiers are not entropy credentials; keep this local because the
    // entropy fallback emits directly instead of going through named suppression.
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
        && crate::pipeline::looks_like_punctuation_decorated_identifier(&entropy_match.value)
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
    //
    // CredData recall lane: release this gate ONLY when (a) the lift is
    // engaged for a credential-anchored candidate AND (b) the value is itself
    // EXACTLY a UUID shape — `KEY = "<uuid>"` where the whole assigned value is
    // the UUID, the CredData `UUID` miss class (LaunchDarkly SDK keys, Heroku
    // UUID keys, PowerBI client secrets are all UUID-bodied). A value that
    // merely CONTAINS a UUID as a substring of a longer payload
    // (`TOKEN_LIST=<...uuid...>`) is still suppressed — that residual is a
    // public identifier inside an env list, not a credential, and the MoE has
    // no anchor to arbitrate it. The whole-value UUID under a strong keyword is
    // the one the model can earn.
    let value_is_exact_uuid =
        crate::suppression::shape_gates::is_uuid_v4_shape(&entropy_match.value);
    if !(canonical_lift && value_is_exact_uuid)
        && crate::pipeline::contains_uuid_v4_substring(&entropy_match.value)
    {
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
            .unwrap_or(preprocessed.text.len()); // LAW10: bounds-checked next-line offset; last line => end-of-text span, recall-safe boundary default
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
        let basename = crate::platform_compat::path_basename_bytes(bytes);
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
    // evidence - entropy phase-2's "lots of varied bytes" is
    // not enough signal in this context. 25+ FPs across bat-go,
    // bat-ledger, brave-talk, malachite, orb-firmware dogfood.
    if entropy_path_is_ci_workflow_file(chunk.metadata.path.as_deref()) {
        return true;
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
    // Decode-through coherence (entropy phase-2 path). The
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
    // Random-byte base64 decoy coherence for the entropy path. The generic
    // bridge already dogfood-suppresses pure standard-base64 random-byte blobs,
    // but entropy emits independently. Do not reuse that broad gate verbatim:
    // TOKEN/API_KEY/DEPLOY_TOKEN positives can be opaque base64-looking random
    // bytes. Require decoded NUL evidence before entropy hard-drops the value.
    if !high_entropy_punctuation_payload
        && crate::decode_structure::decoded_contains_nul_byte(&entropy_match.value)
        && crate::engine::phase2_generic::shape_helpers::generic_path_looks_like_random_byte_blob(
            &entropy_match.value,
        )
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

/// True iff the value's own line carries a STRONG credential keyword anchor
/// (`api_key`/`secret`/`token`/`password`/… immediately before a `=`/`:`),
/// i.e. the value is the right-hand side of a direct `KEYWORD = <value>`
/// assignment — not merely on a line within ±1 of a credential keyword. The
/// canonical-shape generation lift is restricted to this surface so the model
/// only ever arbitrates a UUID/hex that is genuinely the assigned secret.
fn value_line_has_same_line_credential_keyword(
    entropy_match: &crate::entropy::EntropyMatch,
    preprocessed: &ScannerPreprocessedText<'_>,
    line_offsets: &[usize],
) -> bool {
    let line_idx = entropy_match.line.saturating_sub(1);
    let Some(&line_start) = line_offsets.get(line_idx) else {
        return false;
    };
    let line_end = line_offsets
        .get(line_idx + 1)
        .copied()
        .unwrap_or(preprocessed.text.len()); // LAW10: bounds-checked next-line offset; last line => end-of-text span, recall-safe boundary default
    let Some(line_text) = preprocessed.text.get(line_start..line_end) else {
        return false;
    };
    // The value must appear on this line (defensive: the entropy offset already
    // points at the line, but a multiline preprocessing artifact could shift it).
    if !line_text.contains(entropy_match.value.as_str()) {
        return false;
    }
    crate::entropy::keywords::line_has_credential_assignment_surface(line_text)
}

/// The entropy-fallback known-example / placeholder gate, lift-aware.
///
/// Off the lift (`canonical_lift == false`) this is BYTE-IDENTICAL to the
/// original call: the plain surface-form
/// [`should_suppress_known_example_credential_with_source`]. The lift path only
/// diverges for a candidate the generation lift just produced under a strong
/// credential anchor — a canonical hash/UUID/serial shape — and only releases
/// the two SHAPE arms that would HARD-DROP it before the MoE scores it:
///   * the bare-hash-digest arm (hex32/40/64/128 — the `hex64` AES-256-key miss
///     class), released via the existing `allow_canonical_hex_key` exemption
///     threaded into [`should_suppress_inner`]; and
///   * the UUID-v4 shape arm (the `UUID` miss class), which
///     [`should_suppress_inner`] gates only on `!bypass_shape_gates` and never
///     exempts — so for an EXACT-UUID lifted value we bypass that decision-tree
///     entry entirely and apply the CONTENT gates ourselves (doc/placeholder
///     markers + repetitive-run + decoded-placeholder), keeping a
///     `00000000-0000-0000-0000-000000000000` / `EXAMPLE`-bearing UUID dropped.
///
/// Every CONTENT gate stays live on both paths; only the recall-load-bearing
/// SHAPE arms are released, and only for the model-arbitrated lift surface.
fn entropy_fallback_example_suppressed(
    entropy_match: &crate::entropy::EntropyMatch,
    chunk: &Chunk,
    canonical_lift: bool,
) -> bool {
    let value = entropy_match.value.as_str();
    let path = chunk.metadata.path.as_deref();
    let source = Some(chunk.metadata.source_type.as_str());

    if !canonical_lift {
        // Original behaviour, unchanged.
        return crate::pipeline::should_suppress_known_example_credential_with_source(
            value,
            path,
            crate::context::CodeContext::Unknown,
            source,
        );
    }

    // Lift path. ALL lifted canonical shapes (UUID, hex digest, serial) first
    // pass the crate-visible CONTENT gate — `is_known_example_credential`
    // (EXAMPLE suffix, x/X masking filler, monotonic/repetitive hex bodies,
    // empty-input MD5/SHA hashes) + `contains_placeholder_word`
    // (`changeme`/`yourkey`/…) + the run-of-identical check (all-zero /
    // `deadbeef`-style). These are the SAME content markers the strict path
    // applies; only the shape arm is what the lift releases, so a documentation
    // placeholder of ANY canonical shape stays dropped.
    if crate::context::is_known_example_credential(value)
        || crate::confidence::contains_placeholder_word(value)
        || crate::suppression::shape_gates::has_three_or_more_consecutive_identical(value)
    {
        return true;
    }

    // An EXACT-UUID value cannot be exempted inside `should_suppress_inner` (its
    // UUID arm always fires regardless of `allow_canonical_hex_key`), so for a
    // clean UUID the content gate above is the whole verdict — let it through to
    // the model.
    if crate::suppression::shape_gates::is_uuid_v4_shape(value) {
        return false;
    }

    // Non-UUID lifted value (canonical hex / serial). The entropy-aware variant
    // with `allow_canonical_hex_key = true` releases ONLY the bare-hash-digest
    // arm; every other CONTENT gate inside the decision tree (markers,
    // placeholders, license serials, npm-integrity, prefixed digests) still
    // fires, so `AKIAEXAMPLE…`-class and labelled-digest values stay dropped.
    crate::suppression::api::should_suppress_known_example_credential_with_source_and_entropy(
        value,
        path,
        crate::context::CodeContext::Unknown,
        source,
        entropy_match.entropy,
        true,
        false,
    )
}
