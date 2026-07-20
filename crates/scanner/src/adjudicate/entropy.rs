use super::StageId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntropyShapeStage {
    #[cfg(feature = "entropy")]
    SourceIdentifierInSourceContext,
    #[cfg(feature = "entropy")]
    MissingSameLineCredential,
    #[cfg(feature = "entropy")]
    CaesarSource,
    #[cfg(feature = "entropy")]
    ValueTooShort,
    ValueTooLong,
    #[cfg(feature = "entropy")]
    SuppressionStage(&'static str),
    #[cfg(feature = "entropy")]
    KebabIdentifier,
    #[cfg(feature = "entropy")]
    Filename,
    #[cfg(feature = "entropy")]
    PureIdentifier,
    #[cfg(feature = "entropy")]
    Whitespace,
    #[cfg(feature = "entropy")]
    EnglishProse,
    #[cfg(feature = "entropy")]
    CommaDelimited,
    #[cfg(feature = "entropy")]
    WordSeparatedIdentifier,
    #[cfg(feature = "entropy")]
    PublicNoncredentialShape,
    #[cfg(feature = "entropy")]
    SchemePrefixedUri,
    #[cfg(feature = "entropy")]
    SourceCodeExpression,
    #[cfg(feature = "entropy")]
    SourceSymbolIdentifier,
    #[cfg(feature = "entropy")]
    PunctuationDecoratedIdentifier,
    #[cfg(feature = "entropy")]
    UrlOrPathSegment,
    #[cfg(feature = "entropy")]
    UuidV4OrSubstring,
    #[cfg(feature = "entropy")]
    EmailAddress,
    #[cfg(feature = "entropy")]
    BlockchainOrNetworkAddress,
    #[cfg(feature = "entropy")]
    VendoredMinifiedPath,
    #[cfg(feature = "entropy")]
    RawBase64File,
    #[cfg(feature = "entropy")]
    CiWorkflowFile,
    #[cfg(feature = "entropy")]
    I18nFile,
    #[cfg(feature = "entropy")]
    ShellExpansionOrTemplate,
    #[cfg(feature = "entropy")]
    RandomBase64Blob,
    #[cfg(feature = "entropy")]
    EncodedBinary,
    #[cfg(feature = "entropy")]
    RandomByteBlob,
    #[cfg(feature = "entropy")]
    DecodedPlaceholder,
    ConcatenationFragmentLine,
    StructuredDottedTooShort,
    /// Word-like non-secret by tiktoken cl100k_base bytes-per-token (dotted API
    /// paths, prose, XML) (the BPE "rare-not-random" gate).
    #[cfg(feature = "entropy")]
    WordLikeLowBpe,
    CanonicalNonSecretShape,
    CredentialContextTooShort,
    KeywordFreeTooShort,
    CandidatePlausibilityRejected,
    SecretPlausibilityRejected,
    #[cfg(feature = "entropy")]
    MissingFallbackMetadata,
}

impl EntropyShapeStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            #[cfg(feature = "entropy")]
            Self::SourceIdentifierInSourceContext => "entropy_source_identifier_in_source_context",
            #[cfg(feature = "entropy")]
            Self::MissingSameLineCredential => "entropy_missing_same_line_credential",
            #[cfg(feature = "entropy")]
            Self::CaesarSource => "entropy_caesar_source",
            #[cfg(feature = "entropy")]
            Self::ValueTooShort => "value_too_short",
            Self::ValueTooLong => "value_too_long",
            #[cfg(feature = "entropy")]
            Self::SuppressionStage(reason) => reason,
            #[cfg(feature = "entropy")]
            Self::KebabIdentifier => "entropy_kebab_identifier",
            #[cfg(feature = "entropy")]
            Self::Filename => "entropy_filename",
            #[cfg(feature = "entropy")]
            Self::PureIdentifier => "entropy_pure_identifier",
            #[cfg(feature = "entropy")]
            Self::Whitespace => "entropy_whitespace",
            #[cfg(feature = "entropy")]
            Self::EnglishProse => "entropy_english_prose",
            #[cfg(feature = "entropy")]
            Self::CommaDelimited => "entropy_comma_delimited",
            #[cfg(feature = "entropy")]
            Self::WordSeparatedIdentifier => "entropy_word_separated_identifier",
            #[cfg(feature = "entropy")]
            Self::PublicNoncredentialShape => "entropy_public_noncredential_shape",
            #[cfg(feature = "entropy")]
            Self::SchemePrefixedUri => "entropy_scheme_prefixed_uri",
            #[cfg(feature = "entropy")]
            Self::SourceCodeExpression => "entropy_source_code_expression",
            #[cfg(feature = "entropy")]
            Self::SourceSymbolIdentifier => "entropy_source_symbol_identifier",
            #[cfg(feature = "entropy")]
            Self::PunctuationDecoratedIdentifier => "entropy_punctuation_decorated_identifier",
            #[cfg(feature = "entropy")]
            Self::UrlOrPathSegment => "entropy_url_or_path_segment",
            #[cfg(feature = "entropy")]
            Self::UuidV4OrSubstring => "entropy_uuid_v4_or_substring",
            #[cfg(feature = "entropy")]
            Self::EmailAddress => "entropy_email_address",
            #[cfg(feature = "entropy")]
            Self::BlockchainOrNetworkAddress => "entropy_blockchain_or_network_address",
            #[cfg(feature = "entropy")]
            Self::VendoredMinifiedPath => "entropy_vendored_minified_path",
            #[cfg(feature = "entropy")]
            Self::RawBase64File => "entropy_raw_base64_file",
            #[cfg(feature = "entropy")]
            Self::CiWorkflowFile => "entropy_ci_workflow_file",
            #[cfg(feature = "entropy")]
            Self::I18nFile => "entropy_i18n_file",
            #[cfg(feature = "entropy")]
            Self::ShellExpansionOrTemplate => "entropy_shell_expansion_or_template",
            #[cfg(feature = "entropy")]
            Self::RandomBase64Blob => "entropy_random_base64_blob",
            #[cfg(feature = "entropy")]
            Self::EncodedBinary => "entropy_encoded_binary",
            #[cfg(feature = "entropy")]
            Self::RandomByteBlob => "entropy_random_byte_blob",
            #[cfg(feature = "entropy")]
            Self::DecodedPlaceholder => "entropy_decoded_placeholder",
            Self::ConcatenationFragmentLine => "entropy_concatenation_fragment_line",
            Self::StructuredDottedTooShort => "entropy_structured_dotted_too_short",
            #[cfg(feature = "entropy")]
            Self::WordLikeLowBpe => "entropy_word_like_low_bpe",
            Self::CanonicalNonSecretShape => "entropy_canonical_non_secret_shape",
            Self::CredentialContextTooShort => "entropy_credential_context_too_short",
            Self::KeywordFreeTooShort => "entropy_keyword_free_too_short",
            Self::CandidatePlausibilityRejected => "entropy_candidate_plausibility_rejected",
            Self::SecretPlausibilityRejected => "entropy_secret_plausibility_rejected",
            #[cfg(feature = "entropy")]
            Self::MissingFallbackMetadata => "entropy_missing_fallback_metadata",
        }
    }
}

#[cfg(feature = "entropy")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntropyFallbackSignal {
    NamedDetectorOwnedAssignment,
    ValueShape(EntropyShapeStage),
}

#[cfg(feature = "entropy")]
impl EntropyFallbackSignal {
    pub(super) const fn stage_id(self) -> StageId {
        match self {
            Self::NamedDetectorOwnedAssignment => StageId::EntropyNamedDetectorOwnedAssignment,
            Self::ValueShape(stage) => StageId::EntropyValueShape(stage),
        }
    }
}

#[cfg(not(feature = "entropy"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntropyFallbackSignal {}

#[cfg(not(feature = "entropy"))]
impl EntropyFallbackSignal {
    pub(super) const fn stage_id(self) -> StageId {
        match self {}
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
    degenerate_run_min_length: usize,
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
    // especially with a 16-symbol hex alphabet. Use the active detector's
    // absolute boundary so custom plans preserve their declared semantics.
    if crate::confidence::penalties::is_degenerate_repeat_at(value, degenerate_run_min_length) {
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
