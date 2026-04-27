use base64::{engine::general_purpose, Engine};
use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use keyhog_core::{load_detectors, Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{decode, entropy, ml_scorer, CompiledScanner};
use std::path::Path;

// TEST DATA GENERATORS

/// Generate 1MB of realistic source code (Python/JS/Go mix) with embedded secrets
fn generate_mixed_source_code_1mb() -> String {
    let mut content = String::with_capacity(1_024_000);

    // Python module with various patterns
    let python_chunk = r#"
# Configuration module for API clients
import os
from typing import Optional

class Config:
    """Application configuration."""

    # AWS configuration
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    AWS_REGION = "us-east-1"

    # Database settings
    DATABASE_URL = "postgresql://user:pass@localhost/db"
    REDIS_URL = "redis://localhost:6379"

    # Third-party APIs
    STRIPE_SECRET_KEY = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx"

    def get_api_key(self, service: str) -> Optional[str]:
        """Retrieve API key for a service."""
        return os.getenv(f"{service.upper()}_API_KEY")

# GitHub integration
def setup_github():
    token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    headers = {"Authorization": f"Bearer {token}"}
    return headers
"#;

    // JavaScript chunk with secrets
    let js_chunk = r#"
// API Client Configuration
const config = {
    slack: {
        botToken: "xoxb-1234567890-1234567890-abcdefghijABCDEFGHIJklmn",
        signingSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    },
    openai: {
        apiKey: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        organization: "org-xxxxxxxx"
    },
    stripe: {
        publishableKey: "pk_live_xxxxxxxxxxxxxxxxxxxxxxxx",
        secretKey: "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx"
    }
};

async function initClient() {
    const client = new ApiClient(config.openai.apiKey);
    await client.connect();
    return client;
}
"#;

    // Go chunk with secrets
    let go_chunk = r#"
package config

type DatabaseConfig struct {
    Host     string
    Port     int
    User     string
    Password string
    Database string
}

var ProductionDB = DatabaseConfig{
    Host:     "prod.db.example.com",
    Port:     5432,
    User:     "app_user",
    Password: "p@ssw0rd123!Secure#2024",
    Database: "production",
}

const apiKey = "SG.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
"#;

    // Repeat chunks until we reach ~1MB
    let chunk_template = format!("{}{}{}", python_chunk, js_chunk, go_chunk);
    let target_size = 1_024_000;

    while content.len() < target_size {
        content.push_str(&chunk_template);
        // Add some variation
        content.push_str(&format!("// Line {} padding\n", content.len()));
    }

    content.truncate(target_size);
    content
}

/// Generate 10MB of .env files with known secrets embedded
fn generate_env_files_10mb() -> String {
    let mut content = String::with_capacity(10_240_000);

    // Base template with various secrets
    let env_template = r#"
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=myapp
DB_USER=postgres
DB_PASSWORD=Sup3rS3cur3P@ssw0rd!2024

# AWS Credentials
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1
AWS_S3_BUCKET=my-bucket-name

# API Keys
OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxxxxxx
STRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxxx
STRIPE_PUBLISHABLE_KEY=pk_live_xxxxxxxxxxxxxxxxxxxxxxxx
SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Slack Integration
SLACK_BOT_TOKEN=xoxb-1234567890-1234567890-abcdefghijABCDEFGHIJklmn
SLACK_SIGNING_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Other Services
DATADOG_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
DATADOG_APP_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ROLLBAR_ACCESS_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
HONEYBADGER_API_KEY=hbp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# JWT Secrets
JWT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
JWT_REFRESH_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
"#;

    // Repeat until 10MB
    while content.len() < 10_240_000 {
        content.push_str(env_template);
    }

    content.truncate(10_240_000);
    content
}

/// Generate 100KB of base64-encoded data containing secrets
fn generate_base64_encoded_data_100kb() -> String {
    let mut content = String::with_capacity(102_400);

    // Create base64-encoded secrets
    let secrets_to_encode = [
        "sk-proj-SuperSecretOpenAIKey1234567890abcdef",
        "ghp_VerySecretGitHubPAT1234567890abcdefghij",
        "xoxb-SecretSlackToken1234567890abcdefghijklmn",
        "AKIAIOSFODNN7EXAMPLEWXYZ123456",
        "sk_live_SecretStripeKey1234567890abcdefghijklmnop",
    ];

    // Generate base64 encoded versions with various formats
    for (i, secret) in secrets_to_encode.iter().cycle().enumerate() {
        if content.len() > 100_000 {
            break;
        }

        let encoded = general_purpose::STANDARD.encode(secret);

        // Various embedding formats
        content.push_str(&format!("secret_{}_b64={}\n", i, encoded));
        content.push_str(&format!("{{\"token\": \"{}\"}}\n", encoded));
        content.push_str(&format!("Authorization: Bearer {}\n", encoded));
        content.push_str(&format!("export API_KEY='{}'\n", encoded));

        // Add some padding
        content.push_str("# Some configuration comment here\n");
    }

    content
}

/// Generate a single line with a secret for latency testing
fn generate_single_line_secret() -> String {
    "api_key = \"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"\n".to_string()
}

// FIXTURE HELPERS

fn make_chunk(data: &str, path: Option<&str>) -> Chunk {
    Chunk {
        data: data.to_string(),
        metadata: ChunkMetadata {
            source_type: "benchmark".into(),
            path: path.map(|p| p.into()),
            commit: None,
            author: None,
            date: None,
        },
    }
}

fn load_all_detectors() -> Vec<DetectorSpec> {
    // Try to load from detectors directory
    let detector_path = Path::new("detectors");
    if detector_path.exists() {
        load_detectors(detector_path).expect("Failed to load detectors")
    } else {
        // Fallback: create a minimal set of detectors for benchmarking
        create_minimal_detectors()
    }
}

fn create_minimal_detectors() -> Vec<DetectorSpec> {
    vec![
        DetectorSpec {
            id: "aws-access-key".into(),
            name: "AWS Access Key".into(),
            service: "aws".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "(AKIA|ASIA)[0-9A-Z]{16}".into(),
                description: Some("AWS access key ID".into()),
                group: None,
            }],
            companions: Vec::new(),
            verify: None,
            keywords: vec!["AKIA".into(), "ASIA".into(), "aws".into()],
        },
        DetectorSpec {
            id: "github-pat".into(),
            name: "GitHub PAT".into(),
            service: "github".into(),
            severity: Severity::Critical,
            patterns: vec![
                PatternSpec {
                    regex: "ghp_[a-zA-Z0-9]{36}".into(),
                    description: Some("GitHub classic PAT".into()),
                    group: None,
                },
                PatternSpec {
                    regex: "github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}".into(),
                    description: Some("GitHub fine-grained PAT".into()),
                    group: None,
                },
            ],
            companions: Vec::new(),
            verify: None,
            keywords: vec!["ghp_".into(), "github".into()],
        },
        DetectorSpec {
            id: "slack-bot-token".into(),
            name: "Slack Bot Token".into(),
            service: "slack".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}".into(),
                description: Some("Slack bot token".into()),
                group: None,
            }],
            companions: Vec::new(),
            verify: None,
            keywords: vec!["xoxb".into(), "slack".into()],
        },
        DetectorSpec {
            id: "openai-api-key".into(),
            name: "OpenAI API Key".into(),
            service: "openai".into(),
            severity: Severity::Critical,
            patterns: vec![
                PatternSpec {
                    regex: "sk-proj-[a-zA-Z0-9_-]{40,}".into(),
                    description: Some("OpenAI project key".into()),
                    group: None,
                },
                PatternSpec {
                    regex: "sk-[a-zA-Z0-9]{48}".into(),
                    description: Some("OpenAI legacy key".into()),
                    group: None,
                },
            ],
            companions: Vec::new(),
            verify: None,
            keywords: vec!["sk-proj-".into(), "sk-".into(), "openai".into()],
        },
        DetectorSpec {
            id: "stripe-secret-key".into(),
            name: "Stripe Secret Key".into(),
            service: "stripe".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "sk_live_[a-zA-Z0-9]{24}".into(),
                description: Some("Stripe live secret key".into()),
                group: None,
            }],
            companions: Vec::new(),
            verify: None,
            keywords: vec!["sk_live_".into(), "stripe".into()],
        },
        DetectorSpec {
            id: "sendgrid-api-key".into(),
            name: "SendGrid API Key".into(),
            service: "sendgrid".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}".into(),
                description: Some("SendGrid API key".into()),
                group: None,
            }],
            companions: Vec::new(),
            verify: None,
            keywords: vec!["SG.".into(), "sendgrid".into()],
        },
    ]
}
