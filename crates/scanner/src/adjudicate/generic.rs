use super::StageId;
use crate::entropy::plausibility::{passes_secret_strength_checks, PlausibilityContext};

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

pub(crate) fn generic_bridge_keyword_boundary_rejected(
    keyword: &str,
    line: &str,
    keyword_start: usize,
) -> bool {
    generic_bridge_keyword_requires_word_boundary(keyword)
        && !keyword_has_word_boundary(line, keyword_start)
}

pub(crate) fn generic_bridge_bare_auth_rejected(keyword: &str, value: &str) -> bool {
    keyword.eq_ignore_ascii_case("auth") && !bare_auth_value_allowed(value)
}

pub(crate) fn generic_bridge_canonical_hex_placeholder_stage(
    allow_canonical_hex_key: bool,
    value: &str,
) -> Option<GenericValueShapeStage> {
    if allow_canonical_hex_key && crate::context::is_known_example_credential(value) {
        Some(GenericValueShapeStage::SharedSuppression(
            "algorithmic_placeholder",
        ))
    } else {
        None
    }
}

fn generic_bridge_keyword_requires_word_boundary(keyword: &str) -> bool {
    keyword.eq_ignore_ascii_case("pass") || keyword.eq_ignore_ascii_case("auth")
}

/// Whole-word left boundary for substring-ambiguous generic bridge keywords,
/// including camelCase hinges while rejecting substring tails such as `bypass`.
fn keyword_has_word_boundary(line: &str, keyword_start: usize) -> bool {
    if keyword_start == 0 {
        return true;
    }
    let bytes = line.as_bytes();
    let prev = bytes[keyword_start - 1];
    if !prev.is_ascii_alphabetic() {
        return true;
    }
    let keyword_first = bytes[keyword_start];
    prev.is_ascii_lowercase() && keyword_first.is_ascii_uppercase()
}

fn bare_auth_value_allowed(value: &str) -> bool {
    let context = PlausibilityContext::new(true, false);
    crate::suppression::shape::is_structured_dotted_token(value)
        || (!value.contains('.')
            && value.bytes().any(|byte| !byte.is_ascii_alphanumeric())
            && passes_secret_strength_checks(value, context))
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
