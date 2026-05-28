use clap::{Parser, ValueEnum};
use keyhog_core::DedupScope;

#[derive(Clone, ValueEnum)]
pub enum SeverityFilter {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityFilter {
    pub fn to_severity(&self) -> keyhog_core::Severity {
        match self {
            Self::Info => keyhog_core::Severity::Info,
            Self::Low => keyhog_core::Severity::Low,
            Self::Medium => keyhog_core::Severity::Medium,
            Self::High => keyhog_core::Severity::High,
            Self::Critical => keyhog_core::Severity::Critical,
        }
    }
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Sarif,
}

#[derive(Clone, ValueEnum, PartialEq)]
pub enum CliDedupScope {
    Credential,
    File,
    None,
}

impl CliDedupScope {
    pub fn to_core(&self) -> DedupScope {
        match self {
            Self::Credential => DedupScope::Credential,
            Self::File => DedupScope::File,
            Self::None => DedupScope::None,
        }
    }
}
