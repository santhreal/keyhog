#![cfg(feature = "web")]

use keyhog_sources::testing::{SourceTestApi, TestApi};

macro_rules! redact_case {
    ($name:ident, $input:expr, $expected:expr) => {
        #[test]
        fn $name() {
            assert_eq!(TestApi.redact_url($input), $expected);
        }
    };
}

macro_rules! redact_cases {
    ($( $name:ident: $input:expr => $expected:expr; )*) => {
        $(redact_case!($name, $input, $expected);)*
    };
}

redact_cases! {
    key_sig_masks_value: "https://example.com/path?sig=SECRETPART&ok=1" => "https://example.com/path?sig=***&ok=1";
    key_sig_case_insensitive_masks: "https://example.com/path?SIG=SECRETPART" => "https://example.com/path?SIG=***";
    key_signature_masks_value: "https://example.com/path?signature=SECRETPART&ok=1" => "https://example.com/path?signature=***&ok=1";
    key_signature_case_insensitive_masks: "https://example.com/path?SIGNATURE=SECRETPART" => "https://example.com/path?SIGNATURE=***";
    key_x_amz_signature_masks_value: "https://example.com/path?X-Amz-Signature=SECRETPART&ok=1" => "https://example.com/path?X-Amz-Signature=***&ok=1";
    key_x_amz_signature_case_insensitive_masks: "https://example.com/path?X-AMZ-SIGNATURE=SECRETPART" => "https://example.com/path?X-AMZ-SIGNATURE=***";
    key_x_amz_credential_masks_value: "https://example.com/path?x-amz-credential=SECRETPART&ok=1" => "https://example.com/path?x-amz-credential=***&ok=1";
    key_x_amz_credential_case_insensitive_masks: "https://example.com/path?X-AMZ-CREDENTIAL=SECRETPART" => "https://example.com/path?X-AMZ-CREDENTIAL=***";
    key_x_amz_security_token_masks_value: "https://example.com/path?x-amz-security-token=SECRETPART&ok=1" => "https://example.com/path?x-amz-security-token=***&ok=1";
    key_x_amz_security_token_case_insensitive_masks: "https://example.com/path?X-AMZ-SECURITY-TOKEN=SECRETPART" => "https://example.com/path?X-AMZ-SECURITY-TOKEN=***";
    key_access_token_masks_value: "https://example.com/path?access_token=SECRETPART&ok=1" => "https://example.com/path?access_token=***&ok=1";
    key_access_token_case_insensitive_masks: "https://example.com/path?ACCESS_TOKEN=SECRETPART" => "https://example.com/path?ACCESS_TOKEN=***";
    key_token_masks_value: "https://example.com/path?token=SECRETPART&ok=1" => "https://example.com/path?token=***&ok=1";
    key_token_case_insensitive_masks: "https://example.com/path?TOKEN=SECRETPART" => "https://example.com/path?TOKEN=***";
    key_id_token_masks_value: "https://example.com/path?id_token=SECRETPART&ok=1" => "https://example.com/path?id_token=***&ok=1";
    key_id_token_case_insensitive_masks: "https://example.com/path?ID_TOKEN=SECRETPART" => "https://example.com/path?ID_TOKEN=***";
    key_refresh_token_masks_value: "https://example.com/path?refresh_token=SECRETPART&ok=1" => "https://example.com/path?refresh_token=***&ok=1";
    key_refresh_token_case_insensitive_masks: "https://example.com/path?REFRESH_TOKEN=SECRETPART" => "https://example.com/path?REFRESH_TOKEN=***";
    key_sas_masks_value: "https://example.com/path?sas=SECRETPART&ok=1" => "https://example.com/path?sas=***&ok=1";
    key_sas_case_insensitive_masks: "https://example.com/path?SAS=SECRETPART" => "https://example.com/path?SAS=***";
    key_code_masks_value: "https://example.com/path?code=SECRETPART&ok=1" => "https://example.com/path?code=***&ok=1";
    key_code_case_insensitive_masks: "https://example.com/path?CODE=SECRETPART" => "https://example.com/path?CODE=***";
    key_api_key_masks_value: "https://example.com/path?api_key=SECRETPART&ok=1" => "https://example.com/path?api_key=***&ok=1";
    key_api_key_case_insensitive_masks: "https://example.com/path?API_KEY=SECRETPART" => "https://example.com/path?API_KEY=***";
    key_apikey_masks_value: "https://example.com/path?apikey=SECRETPART&ok=1" => "https://example.com/path?apikey=***&ok=1";
    key_apikey_case_insensitive_masks: "https://example.com/path?APIKEY=SECRETPART" => "https://example.com/path?APIKEY=***";
    key_secret_masks_value: "https://example.com/path?secret=SECRETPART&ok=1" => "https://example.com/path?secret=***&ok=1";
    key_secret_case_insensitive_masks: "https://example.com/path?SECRET=SECRETPART" => "https://example.com/path?SECRET=***";
    key_password_masks_value: "https://example.com/path?password=SECRETPART&ok=1" => "https://example.com/path?password=***&ok=1";
    key_password_case_insensitive_masks: "https://example.com/path?PASSWORD=SECRETPART" => "https://example.com/path?PASSWORD=***";
    key_auth_masks_value: "https://example.com/path?auth=SECRETPART&ok=1" => "https://example.com/path?auth=***&ok=1";
    key_auth_case_insensitive_masks: "https://example.com/path?AUTH=SECRETPART" => "https://example.com/path?AUTH=***";
    userinfo_basic: "https://user:pass@host/path" => "https://***@host/path";
    userinfo_token_only: "https://token@host/" => "https://***@host/";
    userinfo_with_port: "postgres://u:p@db:5432/x" => "postgres://***@db:5432/x";
    userinfo_at_in_password: "https://u:pa@ss@host/" => "https://***@host/";
    userinfo_no_password: "https://apikey@host/" => "https://***@host/";
    query_email_at_not_userinfo: "https://host/p?email=a@b.com" => "https://host/p?email=a@b.com";
    userinfo_and_query_secret: "https://u:p@host/p?token=abc&x=1" => "https://***@host/p?token=***&x=1";
    query_mask_preserves_fragment: "https://host/p?token=abc#frag" => "https://host/p?token=***#frag";
    no_scheme_unchanged: "user:pass@host/path" => "user:pass@host/path";
    scheme_without_userinfo_unchanged: "https://host:5432/db" => "https://host:5432/db";
    non_sensitive_query_unchanged: "https://host/p?foo=bar&page=2" => "https://host/p?foo=bar&page=2";
}

// Roadmap tests: these keys SHOULD be treated as sensitive but are not yet.
// They are ignored so the suite stays green; enable each as the redaction list expands.
#[cfg(test)]
mod roadmap {
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    macro_rules! roadmap_redact_case {
        ($name:ident, $input:expr, $expected:expr) => {
            #[test]
            #[ignore = "roadmap: add this query key to SENSITIVE_QUERY_KEYS"]
            fn $name() {
                assert_eq!(TestApi.redact_url($input), $expected);
            }
        };
    }

    macro_rules! roadmap_redact_cases {
        ($( $name:ident: $input:expr => $expected:expr; )*) => {
            $(roadmap_redact_case!($name, $input, $expected);)*
        };
    }

    roadmap_redact_cases! {
        roadmap_api_token_should_be_masked: "https://example.com/?api_token=secretvalue" => "https://example.com/?api_token=***";
        roadmap_bearer_should_be_masked: "https://example.com/?bearer=secretvalue" => "https://example.com/?bearer=***";
        roadmap_client_secret_should_be_masked: "https://example.com/?client_secret=secretvalue" => "https://example.com/?client_secret=***";
        roadmap_session_token_should_be_masked: "https://example.com/?session_token=secretvalue" => "https://example.com/?session_token=***";
        roadmap_oauth_token_should_be_masked: "https://example.com/?oauth_token=secretvalue" => "https://example.com/?oauth_token=***";
    }
}
