use serde::{Deserialize, Serialize};

/// Syntactic role of the bytes captured as a detector credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureSemanticRole {
    /// No syntax proof is declared. Adjudication must abstain.
    #[default]
    Unknown,
    /// Credential bytes captured from an assignment value.
    AssignmentValue,
    /// Standalone opaque token bytes.
    Token,
    /// Credential bytes captured from a structured envelope.
    CredentialEnvelope,
    /// A complete private-key block.
    PrivateKeyBlock,
    /// A complete credential-bearing connection string.
    ConnectionString,
    /// Credential bytes from URL user information.
    UrlUserinfo,
    /// Credential bytes from a protocol header value.
    HeaderValue,
    /// Credential bytes from a command argument.
    CommandArgumentValue,
}

impl CaptureSemanticRole {
    /// Return the stable detector TOML spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::AssignmentValue => "assignment-value",
            Self::Token => "token",
            Self::CredentialEnvelope => "credential-envelope",
            Self::PrivateKeyBlock => "private-key-block",
            Self::ConnectionString => "connection-string",
            Self::UrlUserinfo => "url-userinfo",
            Self::HeaderValue => "header-value",
            Self::CommandArgumentValue => "command-argument-value",
        }
    }

    /// Whether this role carries no semantic proof.
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Strength and kind of the detector anchor surrounding a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnchorSemanticRole {
    /// No anchor semantics are declared.
    #[default]
    Unknown,
    /// An exact credential key anchors the capture.
    ExactKey,
    /// A vendor-distinctive literal prefix anchors the capture.
    DistinctivePrefix,
    /// A structured credential envelope anchors the capture.
    StructuredEnvelope,
    /// Required companion evidence anchors the capture.
    CompanionBound,
    /// Only weak contextual text anchors the capture.
    WeakContext,
    /// No surrounding anchor is required.
    Unanchored,
}

impl AnchorSemanticRole {
    /// Return the stable detector TOML spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::ExactKey => "exact-key",
            Self::DistinctivePrefix => "distinctive-prefix",
            Self::StructuredEnvelope => "structured-envelope",
            Self::CompanionBound => "companion-bound",
            Self::WeakContext => "weak-context",
            Self::Unanchored => "unanchored",
        }
    }

    /// Whether this role carries no anchor proof.
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Candidate-bounded semantic classification of the source containing a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticSourceRole {
    /// Value of a parsed structured assignment.
    StructuredAssignmentValue,
    /// Value of an environment assignment.
    EnvironmentAssignmentValue,
    /// Literal string value in source code.
    StringLiteral,
    /// Value passed to a command argument.
    CommandArgumentValue,
    /// Declaration of a command option rather than its runtime value.
    CommandOptionDeclaration,
    /// Value of a protocol header.
    HeaderValue,
    /// Authority or user-information field of a URL.
    UrlAuthorityUserinfo,
    /// Credential field within a connection string.
    ConnectionString,
    /// Standalone opaque token.
    StandaloneToken,
    /// Value contained in a PEM block.
    PemBlock,
    /// Regex, scanner rule, or grammar definition.
    RegexRuleDefinition,
    /// Identifier, type, or member name.
    IdentifierTypeMemberName,
    /// Prose or documentation content.
    ProseDocumentation,
    /// Test or example fixture content.
    TestFixture,
    /// Generated or vendored material.
    GeneratedVendorMaterial,
    /// Unsupported, ambiguous, or unparsed context. Policy must abstain.
    Unknown,
}

impl SemanticSourceRole {
    /// Return the stable detector TOML spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StructuredAssignmentValue => "structured-assignment-value",
            Self::EnvironmentAssignmentValue => "environment-assignment-value",
            Self::StringLiteral => "string-literal",
            Self::CommandArgumentValue => "command-argument-value",
            Self::CommandOptionDeclaration => "command-option-declaration",
            Self::HeaderValue => "header-value",
            Self::UrlAuthorityUserinfo => "url-authority-userinfo",
            Self::ConnectionString => "connection-string",
            Self::StandaloneToken => "standalone-token",
            Self::PemBlock => "pem-block",
            Self::RegexRuleDefinition => "regex-rule-definition",
            Self::IdentifierTypeMemberName => "identifier-type-member-name",
            Self::ProseDocumentation => "prose-documentation",
            Self::TestFixture => "test-fixture",
            Self::GeneratedVendorMaterial => "generated-vendor-material",
            Self::Unknown => "unknown",
        }
    }
}

/// Typed semantic proof a detector requires before later policy may enforce it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequiredSemanticEvidence {
    /// Intrinsic checksum validation.
    Checksum,
    /// Required detector companion evidence.
    RequiredCompanion,
    /// Paired private-key companion evidence.
    PrivateKeyCompanion,
    /// Structural grammar validation.
    StructuralGrammar,
    /// Successful live credential verification.
    LiveVerification,
}

impl RequiredSemanticEvidence {
    /// Return the stable detector TOML spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Checksum => "checksum",
            Self::RequiredCompanion => "required-companion",
            Self::PrivateKeyCompanion => "private-key-companion",
            Self::StructuralGrammar => "structural-grammar",
            Self::LiveVerification => "live-verification",
        }
    }
}

/// Canonical detector semantic policy copied into compiled and packed plans.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorSemanticPolicySpec {
    /// Syntactic role of the captured credential bytes.
    #[serde(default)]
    pub capture_role: CaptureSemanticRole,
    /// Strength and kind of the detector anchor.
    #[serde(default)]
    pub anchor_role: AnchorSemanticRole,
    /// Source roles in which later semantic enforcement may apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_source_roles: Vec<SemanticSourceRole>,
    /// Evidence required before later semantic enforcement may apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_evidence: Vec<RequiredSemanticEvidence>,
}
