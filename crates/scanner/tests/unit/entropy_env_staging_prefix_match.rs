//! `.env-staging` variants match .env prefix policy.

use keyhog_scanner::entropy::is_entropy_appropriate;

#[test]
fn entropy_env_staging_prefix_match() {
    assert!(
        is_entropy_appropriate(Some(".env-staging"), false),
        ".env-staging must be entropy-appropriate via .env prefix rule"
    );
}
