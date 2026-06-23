use super::StageId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenericBridgeSignal {
    KeywordBoundary,
    NamedDetectorOwnedKeyword,
    BareAuthUnstructured,
    ValueShape(GenericValueShapeStage),
}

impl GenericBridgeSignal {
    pub(super) const fn stage_id(self) -> StageId {
        match self {
            Self::KeywordBoundary => StageId::GenericKeywordBoundary,
            Self::NamedDetectorOwnedKeyword => StageId::GenericNamedDetectorOwnedKeyword,
            Self::BareAuthUnstructured => StageId::BareAuthUnstructured,
            Self::ValueShape(stage) => StageId::GenericValueShape(stage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenericValueShapeStage {
    CaesarGenericFallback,
    EntropyBelowFloor,
    ValueTooShort,
    SharedShape(&'static str),
    CodeExpressionChars,
    SourceCodeExpression,
    SourceSymbolIdentifier,
    ScopeResolution,
    TypeNameShape,
    NonJwtDotted,
    PureIdentifierNoDigit,
    PureIdentifier,
    WordSeparatedIdentifier,
    SchemePrefixedUri,
    PunctuationDecoratedIdentifier,
    UrlOrPathSegment,
    VendoredMinifiedPath,
    RegexLiteralTail,
    Base64Blob,
    TrimmedAwsArn,
    SharedSuppression(&'static str),
    DecodedPlaceholder,
    DecodedBenignText(&'static str),
    EncodedBinary,
    RandomByteBlob,
}

impl GenericValueShapeStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CaesarGenericFallback => "caesar_generic_fallback",
            Self::EntropyBelowFloor => "generic_entropy_below_floor",
            Self::ValueTooShort => "value_too_short",
            Self::SharedShape(reason) => reason,
            Self::CodeExpressionChars => "code_expression_chars",
            Self::SourceCodeExpression => "source_code_expression",
            Self::SourceSymbolIdentifier => "source_symbol_identifier",
            Self::ScopeResolution => "scope_resolution",
            Self::TypeNameShape => "type_name_shape",
            Self::NonJwtDotted => "non_jwt_dotted",
            Self::PureIdentifierNoDigit => "pure_identifier_no_digit",
            Self::PureIdentifier => "pure_identifier",
            Self::WordSeparatedIdentifier => "word_separated_identifier",
            Self::SchemePrefixedUri => "scheme_prefixed_uri",
            Self::PunctuationDecoratedIdentifier => "punctuation_decorated_identifier",
            Self::UrlOrPathSegment => "url_or_path_segment",
            Self::VendoredMinifiedPath => "vendored_minified_path",
            Self::RegexLiteralTail => "regex_literal_tail",
            Self::Base64Blob => "base64_blob",
            Self::TrimmedAwsArn => "trimmed_aws_arn",
            Self::SharedSuppression(reason) => reason,
            Self::DecodedPlaceholder => "decoded_placeholder",
            Self::DecodedBenignText(reason) => reason,
            Self::EncodedBinary => "encoded_binary",
            Self::RandomByteBlob => "random_byte_blob",
        }
    }
}
