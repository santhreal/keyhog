use super::support::*;

#[test]
fn secret_surrounded_by_whitespace_noise() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!("   \t  {VALID_CREDENTIAL}   \t  \n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "whitespace padding must not prevent detection"
    );
}

#[test]
fn secret_in_json_value() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!(
        r#"{{"api_key": "{VALID_CREDENTIAL}", "host": "localhost"}}"#
    ));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "secret inside JSON string value must be detected"
    );
}

#[test]
fn secret_in_yaml_value() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!("api_key: {VALID_CREDENTIAL}\nport: 8080\n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "secret in YAML mapping value must be detected"
    );
}

#[test]
fn secret_in_shell_export() {
    assert_detected(&format!("export API_KEY=\"{VALID_CREDENTIAL}\"\n"));
}

macro_rules! positive_context_case {
    ($name:ident, $template:expr) => {
        #[test]
        fn $name() {
            assert_detected(&format!($template, VALID_CREDENTIAL));
        }
    };
}

positive_context_case!(secret_in_ini_assignment, "api_key={}\n");
positive_context_case!(secret_in_toml_assignment, "api_key = \"{}\"\n");
positive_context_case!(secret_in_xml_element, "<token>{}</token>");
positive_context_case!(
    secret_in_html_meta_tag,
    "<meta name=\"api-key\" content=\"{}\">"
);
positive_context_case!(secret_in_dockerfile_env, "FROM scratch\nENV API_TOKEN={}\n");
positive_context_case!(
    secret_in_systemd_environment_line,
    "[Service]\nEnvironment=TOKEN={}\n"
);
positive_context_case!(secret_in_powershell_assignment, "$env:API_TOKEN = \"{}\"\n");
positive_context_case!(
    secret_in_sql_insert_statement,
    "INSERT INTO creds(token) VALUES ('{}');"
);
positive_context_case!(
    secret_in_rust_const_literal,
    "const API_TOKEN: &str = \"{}\";\n"
);
positive_context_case!(
    secret_in_javascript_object,
    "const cfg = {{ token: \"{}\" }};\n"
);
positive_context_case!(
    secret_in_terraform_variable,
    "variable \"api_token\" {{ default = \"{}\" }}\n"
);
positive_context_case!(
    secret_in_kubernetes_manifest,
    "apiVersion: v1\nkind: Secret\nstringData:\n  token: {}\n"
);
positive_context_case!(secret_in_nginx_env_directive, "env API_TOKEN={};\n");
positive_context_case!(secret_in_java_properties_file, "api.token={}\n");
positive_context_case!(secret_in_yaml_flow_mapping, "{{ api_token: {} }}\n");
positive_context_case!(secret_in_markdown_code_fence, "```env\nAPI_TOKEN={}\n```\n");
positive_context_case!(secret_in_quoted_json_array, "[\"{}\", \"harmless\"]\n");
positive_context_case!(
    secret_in_multiline_heredoc_like_content,
    "cat <<EOF\n{}\nEOF\n"
);
positive_context_case!(
    secret_in_url_query_value,
    "https://example.invalid/?token={}\n"
);
positive_context_case!(secret_in_shell_comment_context, "# rotated token {}\n");
