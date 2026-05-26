//! Migrated from `src/auto_fix.rs` inline tests.
use keyhog_core::auto_fix::{env_var_name_for_service, fix_replacement_text};
#[test]
    fn curated_services_map_correctly() {
        assert_eq!(env_var_name_for_service("aws"), "AWS_ACCESS_KEY_ID");
        assert_eq!(env_var_name_for_service("aws-iam"), "AWS_ACCESS_KEY_ID");
        assert_eq!(env_var_name_for_service("github"), "GITHUB_TOKEN");
        assert_eq!(env_var_name_for_service("openai"), "OPENAI_API_KEY");
        assert_eq!(env_var_name_for_service("anthropic"), "ANTHROPIC_API_KEY");
        assert_eq!(env_var_name_for_service("stripe"), "STRIPE_SECRET_KEY");
        assert_eq!(env_var_name_for_service("snowflake"), "SNOWFLAKE_PASSWORD");
    }
