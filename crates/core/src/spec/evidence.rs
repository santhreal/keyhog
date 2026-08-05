use serde::{Deserialize, Serialize};

/// Confidentiality policy for detector-owned provider evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEvidenceSensitivity {
    /// Emit the selected scalar value in reports.
    Public,
    /// Emit only a stable SHA-256 digest of the selected scalar value. This is
    /// the fail-closed default for detector metadata that predates the field.
    #[default]
    Hashed,
    /// Never admit the selected value to finding metadata or reports.
    Secret,
}

/// Stable semantic role of provider evidence exposed in findings.
///
/// This vocabulary is provider-neutral. Detector TOML owns which response
/// selector supplies a role, while reporters receive only these reviewed keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderEvidenceRole {
    /// Account label.
    Account,
    /// Stable account identifier.
    AccountId,
    /// Whether the credential is currently active.
    Active,
    /// Bot display name.
    BotName,
    /// Channel identifier.
    ChannelId,
    /// Company name.
    Company,
    /// Opaque provider payload.
    Data,
    /// Email address.
    Email,
    /// Human-friendly display name.
    FriendlyName,
    /// Provider-assigned identifier.
    Id,
    /// Login handle.
    Login,
    /// Name.
    Name,
    /// Organization name.
    Organization,
    /// Granted permissions.
    Permissions,
    /// Subscription plan.
    Plan,
    /// Project name.
    Project,
    /// Region.
    Region,
    /// Resource identifier or name.
    Resource,
    /// Result collection returned by the probe.
    Results,
    /// Granted scopes.
    Scope,
    /// Licensed seat count.
    SeatCount,
    /// Status string.
    Status,
    /// Store name.
    StoreName,
    /// Team name.
    Team,
    /// Team identifier.
    TeamId,
    /// Total count reported by the probe.
    Total,
    /// User label.
    User,
    /// User identifier.
    UserId,
    /// User principal name.
    UserPrincipalName,
    /// Username.
    Username,
    /// UUID.
    Uuid,
    /// Workplace name.
    WorkplaceName,
}

impl ProviderEvidenceRole {
    /// Resolve the detector TOML name to a reviewed provider-neutral role.
    pub fn from_metadata_name(name: &str) -> Option<Self> {
        Some(match name {
            "account" => Self::Account,
            "account_id" | "accountID" => Self::AccountId,
            "active" => Self::Active,
            "bot_name" => Self::BotName,
            "channel_id" => Self::ChannelId,
            "company" => Self::Company,
            "data" => Self::Data,
            "email" => Self::Email,
            "friendly_name" => Self::FriendlyName,
            "id" => Self::Id,
            "login" => Self::Login,
            "name" => Self::Name,
            "organization" => Self::Organization,
            "permissions" => Self::Permissions,
            "plan" => Self::Plan,
            "project" => Self::Project,
            "region" => Self::Region,
            "resource" => Self::Resource,
            "results" => Self::Results,
            "scope" => Self::Scope,
            "seat_count" | "seats" => Self::SeatCount,
            "status" => Self::Status,
            "store_name" => Self::StoreName,
            "team" => Self::Team,
            "team_id" | "teamId" => Self::TeamId,
            "total" => Self::Total,
            "user" => Self::User,
            "user_id" => Self::UserId,
            "user_principal_name" | "userPrincipalName" => Self::UserPrincipalName,
            "username" => Self::Username,
            "uuid" => Self::Uuid,
            "workplace_name" => Self::WorkplaceName,
            _ => return None,
        })
    }

    /// Canonical report key for this semantic role.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::AccountId => "account_id",
            Self::Active => "active",
            Self::BotName => "bot_name",
            Self::ChannelId => "channel_id",
            Self::Company => "company",
            Self::Data => "data",
            Self::Email => "email",
            Self::FriendlyName => "friendly_name",
            Self::Id => "id",
            Self::Login => "login",
            Self::Name => "name",
            Self::Organization => "organization",
            Self::Permissions => "permissions",
            Self::Plan => "plan",
            Self::Project => "project",
            Self::Region => "region",
            Self::Resource => "resource",
            Self::Results => "results",
            Self::Scope => "scope",
            Self::SeatCount => "seat_count",
            Self::Status => "status",
            Self::StoreName => "store_name",
            Self::Team => "team",
            Self::TeamId => "team_id",
            Self::Total => "total",
            Self::User => "user",
            Self::UserId => "user_id",
            Self::UserPrincipalName => "user_principal_name",
            Self::Username => "username",
            Self::Uuid => "uuid",
            Self::WorkplaceName => "workplace_name",
        }
    }
}
