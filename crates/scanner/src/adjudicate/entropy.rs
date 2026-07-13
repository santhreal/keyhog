use super::StageId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntropyShapeStage {
    SourceIdentifierInSourceContext,
    MissingSameLineCredential,
    CaesarSource,
    SuppressionStage(&'static str),
    KebabIdentifier,
    Filename,
    PureIdentifier,
    Whitespace,
    EnglishProse,
    CommaDelimited,
    WordSeparatedIdentifier,
    PublicNoncredentialShape,
    SchemePrefixedUri,
    SourceCodeExpression,
    SourceSymbolIdentifier,
    PunctuationDecoratedIdentifier,
    UrlOrPathSegment,
    UuidV4OrSubstring,
    EmailAddress,
    BlockchainOrNetworkAddress,
    VendoredMinifiedPath,
    RawBase64File,
    CiWorkflowFile,
    I18nFile,
    ShellExpansionOrTemplate,
    RandomBase64Blob,
    EncodedBinary,
    RandomByteBlob,
    DecodedPlaceholder,
    ConcatenationFragmentLine,
    StructuredDottedTooShort,
    /// Word-like non-secret by tiktoken cl100k_base bytes-per-token (dotted API
    /// paths, prose, XML) (the BPE "rare-not-random" gate).
    WordLikeLowBpe,
    CanonicalNonSecretShape,
    CredentialContextTooShort,
    KeywordFreeTooShort,
    CandidatePlausibilityRejected,
    SecretPlausibilityRejected,
}

impl EntropyShapeStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::SourceIdentifierInSourceContext => "entropy_source_identifier_in_source_context",
            Self::MissingSameLineCredential => "entropy_missing_same_line_credential",
            Self::CaesarSource => "entropy_caesar_source",
            Self::SuppressionStage(reason) => reason,
            Self::KebabIdentifier => "entropy_kebab_identifier",
            Self::Filename => "entropy_filename",
            Self::PureIdentifier => "entropy_pure_identifier",
            Self::Whitespace => "entropy_whitespace",
            Self::EnglishProse => "entropy_english_prose",
            Self::CommaDelimited => "entropy_comma_delimited",
            Self::WordSeparatedIdentifier => "entropy_word_separated_identifier",
            Self::PublicNoncredentialShape => "entropy_public_noncredential_shape",
            Self::SchemePrefixedUri => "entropy_scheme_prefixed_uri",
            Self::SourceCodeExpression => "entropy_source_code_expression",
            Self::SourceSymbolIdentifier => "entropy_source_symbol_identifier",
            Self::PunctuationDecoratedIdentifier => "entropy_punctuation_decorated_identifier",
            Self::UrlOrPathSegment => "entropy_url_or_path_segment",
            Self::UuidV4OrSubstring => "entropy_uuid_v4_or_substring",
            Self::EmailAddress => "entropy_email_address",
            Self::BlockchainOrNetworkAddress => "entropy_blockchain_or_network_address",
            Self::VendoredMinifiedPath => "entropy_vendored_minified_path",
            Self::RawBase64File => "entropy_raw_base64_file",
            Self::CiWorkflowFile => "entropy_ci_workflow_file",
            Self::I18nFile => "entropy_i18n_file",
            Self::ShellExpansionOrTemplate => "entropy_shell_expansion_or_template",
            Self::RandomBase64Blob => "entropy_random_base64_blob",
            Self::EncodedBinary => "entropy_encoded_binary",
            Self::RandomByteBlob => "entropy_random_byte_blob",
            Self::DecodedPlaceholder => "entropy_decoded_placeholder",
            Self::ConcatenationFragmentLine => "entropy_concatenation_fragment_line",
            Self::StructuredDottedTooShort => "entropy_structured_dotted_too_short",
            Self::WordLikeLowBpe => "entropy_word_like_low_bpe",
            Self::CanonicalNonSecretShape => "entropy_canonical_non_secret_shape",
            Self::CredentialContextTooShort => "entropy_credential_context_too_short",
            Self::KeywordFreeTooShort => "entropy_keyword_free_too_short",
            Self::CandidatePlausibilityRejected => "entropy_candidate_plausibility_rejected",
            Self::SecretPlausibilityRejected => "entropy_secret_plausibility_rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntropyFallbackSignal {
    NamedDetectorOwnedAssignment,
    ValueShape(EntropyShapeStage),
}

impl EntropyFallbackSignal {
    pub(super) const fn stage_id(self) -> StageId {
        match self {
            Self::NamedDetectorOwnedAssignment => StageId::EntropyNamedDetectorOwnedAssignment,
            Self::ValueShape(stage) => StageId::EntropyValueShape(stage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntropyGenerationSignal {
    SuppressionStage(StageId),
}

impl EntropyGenerationSignal {
    pub(super) const fn stage_id(self) -> StageId {
        match self {
            Self::SuppressionStage(stage_id) => stage_id,
        }
    }
}

/// Lift-aware known-example / placeholder gate for entropy fallback candidates.
///
/// The canonical lift releases only canonical SHAPE drops for model arbitration;
/// content markers still suppress on both paths.
#[cfg(feature = "entropy")]
pub(crate) fn entropy_fallback_example_suppression_stage(
    value: &str,
    keyword: &str,
    entropy: f64,
    path: Option<&str>,
    source: Option<&str>,
    canonical_lift: bool,
) -> Option<EntropyShapeStage> {
    if !canonical_lift {
        let isolated_bare_token = keyword == crate::entropy::ISOLATED_BARE_ENTROPY_LABEL;
        let example_ctx = crate::suppression::api::KnownExampleSuppressionCtx::with_entropy(
            path,
            crate::context::CodeContext::Unknown,
            source,
            entropy,
            false,
            isolated_bare_token,
            false,
        );
        return crate::suppression::api::suppress_known_example_credential_stage(
            value,
            example_ctx,
        )
        .map(|stage_id| EntropyShapeStage::SuppressionStage(stage_id.as_str()));
    }

    if crate::context::is_known_example_credential(value) {
        return Some(EntropyShapeStage::SuppressionStage(
            "algorithmic_placeholder",
        ));
    }
    // Entropy-scoped: a monotonic keyboard/sequence run (`12345678`, alphabet)
    // is a placeholder. NOT in the universal is_known_example_credential above,
    // so strong vendor-anchored detectors keep surfacing sequential filler.
    if crate::context::is_monotonic_sequence_placeholder(value) {
        return Some(EntropyShapeStage::SuppressionStage("sequential_run"));
    }
    if crate::confidence::contains_placeholder_word(value) {
        return Some(EntropyShapeStage::SuppressionStage("placeholder_word"));
    }
    // A three- or four-byte repeat is ordinary in random 128-256-bit material,
    // especially with a 16-symbol hex alphabet. Keep the shared absolute
    // degenerate boundary used by report confidence: long filler runs remain
    // suppressed, while a random key is not discarded for containing `1111`.
    if crate::confidence::penalties::is_degenerate_repeat(value) {
        return Some(EntropyShapeStage::SuppressionStage("repetitive_run"));
    }

    if crate::suppression::shape::is_uuid_v4_shape(value) {
        return None;
    }

    let example_ctx = crate::suppression::api::KnownExampleSuppressionCtx::with_entropy(
        path,
        crate::context::CodeContext::Unknown,
        source,
        entropy,
        true,
        false,
        false,
    );
    crate::suppression::api::suppress_known_example_credential_stage(value, example_ctx)
        .map(|stage_id| EntropyShapeStage::SuppressionStage(stage_id.as_str()))
}
