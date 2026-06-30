//! #114 structured-data nested-key credential context: deeply-nested
//! credential keys across YAML / JSON / TOML / .env / HCL must still surface
//! the exact secret bytes.
//!
//! Real config buries credentials under several container levels
//! (`[database.production] password = …`, `{"services":{"db":{"auth":{…}}}}`,
//! `APP__DB__PASSWORD=…`). Two shapes exist:
//!   * key and value on the SAME line (`password = "<v>"`) — the keyword sits
//!     adjacent to the value regardless of nesting depth, so the per-line
//!     generic bridge / named detectors fire; nesting is just indentation above.
//!   * key and value on DIFFERENT lines (HCL `variable "x" { default = "<v>" }`)
//!     — the structured HCL parser splices `(x, <value>)` so the keyword is
//!     adjacent again.
//! This lock pins that BOTH shapes recover the secret at depth, and that
//! deeply-nested NON-secret keys (host/port) and placeholders do not surface.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;

fn shared() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(scanner)
}

/// Deterministic high-entropy alphanumeric secret of length `n`.
fn secret(n: usize, seed: usize) -> String {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..n)
        .map(|i| ALNUM[(i * 7 + seed * 13 + i * i) % ALNUM.len()] as char)
        .collect()
}

fn surfaces_in(path: &str, text: &str, needle: &str) -> bool {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", path);
    s.scan(&chunk).into_iter().any(|m| m.credential.to_string().contains(needle))
}

fn nothing_in(path: &str, text: &str, needle: &str) -> bool {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", path);
    !s.scan(&chunk).into_iter().any(|m| m.credential.to_string().contains(needle))
}

// ── TOML: nested tables, dotted keys, array-of-tables ─────────────────────────

#[test]
fn toml_nested_table_password_surfaces() {
    let v = secret(24, 1);
    let text = format!("[database.production]\nhost = \"db.internal\"\npassword = \"{v}\"\n");
    assert!(surfaces_in("config.toml", &text, &v), "a [database.production] password must surface");
}

#[test]
fn toml_deeply_nested_table_secret_surfaces() {
    let v = secret(24, 2);
    let text = format!("[services.auth.provider.oauth]\nclient_secret = \"{v}\"\n");
    assert!(surfaces_in("config.toml", &text, &v), "a 4-level-nested client_secret must surface");
}

#[test]
fn toml_dotted_key_api_key_surfaces() {
    let v = secret(28, 3);
    let text = format!("database.production.api_key = \"{v}\"\n");
    assert!(surfaces_in("config.toml", &text, &v), "a dotted-key api_key must surface");
}

#[test]
fn toml_array_of_tables_token_surfaces() {
    let v = secret(28, 4);
    let text = format!("[[clients]]\nname = \"a\"\n[[clients]]\nname = \"b\"\napi_token = \"{v}\"\n");
    assert!(surfaces_in("clients.toml", &text, &v), "an array-of-tables api_token must surface");
}

// ── JSON: deeply-nested objects ───────────────────────────────────────────────

#[test]
fn json_deeply_nested_password_surfaces() {
    let v = secret(24, 5);
    let text = format!("{{\"services\":{{\"db\":{{\"auth\":{{\"password\":\"{v}\"}}}}}}}}\n");
    assert!(surfaces_in("config.json", &text, &v), "a 4-level-nested JSON password must surface");
}

#[test]
fn json_nested_secret_key_surfaces() {
    let v = secret(28, 6);
    let text = format!("{{\"app\":{{\"jwt\":{{\"secret_key\":\"{v}\"}}}}}}\n");
    assert!(surfaces_in("settings.json", &text, &v), "a nested JSON secret_key must surface");
}

#[test]
fn json_pretty_printed_nested_password_surfaces() {
    let v = secret(24, 7);
    let text = format!(
        "{{\n  \"database\": {{\n    \"credentials\": {{\n      \"password\": \"{v}\"\n    }}\n  }}\n}}\n"
    );
    assert!(surfaces_in("config.json", &text, &v), "a pretty-printed nested password must surface");
}

// ── YAML: deeply-nested mappings ──────────────────────────────────────────────

#[test]
fn yaml_deeply_nested_api_key_surfaces() {
    let v = secret(28, 8);
    let text = format!("app:\n  integrations:\n    stripe:\n      api_key: {v}\n");
    assert!(surfaces_in("values.yaml", &text, &v), "a 3-level-nested YAML api_key must surface");
}

#[test]
fn yaml_nested_quoted_password_surfaces() {
    let v = secret(24, 9);
    let text = format!("database:\n  primary:\n    password: \"{v}\"\n");
    assert!(surfaces_in("app.yaml", &text, &v), "a nested quoted YAML password must surface");
}

// ── .env: nested-by-convention double-underscore / prefixed keys ──────────────

#[test]
fn env_double_underscore_nested_password_surfaces() {
    let v = secret(24, 10);
    let text = format!("DATABASE__PRODUCTION__PASSWORD={v}\n");
    assert!(surfaces_in(".env", &text, &v), "a __-nested env password must surface");
}

#[test]
fn env_prefixed_api_secret_surfaces() {
    let v = secret(28, 11);
    let text = format!("APP_STRIPE_API_SECRET={v}\n");
    assert!(surfaces_in(".env", &text, &v), "a prefixed env api_secret must surface");
}

// ── HCL: nested blocks where key + value are on DIFFERENT lines ────────────────

#[test]
fn hcl_nested_block_password_surfaces() {
    let v = secret(24, 12);
    let text =
        format!("resource \"db\" \"main\" {{\n  connection {{\n    password = \"{v}\"\n  }}\n}}\n");
    assert!(surfaces_in("main.tf", &text, &v), "a nested HCL block password must surface");
}

#[test]
fn hcl_variable_default_secret_surfaces() {
    let v = secret(28, 13);
    let text = format!("variable \"db_password\" {{\n  default = \"{v}\"\n}}\n");
    assert!(
        surfaces_in("variables.tf", &text, &v),
        "an HCL variable whose name carries the keyword and value is two lines below must surface"
    );
}

#[test]
fn hcl_provider_nested_token_surfaces() {
    let v = secret(28, 14);
    let text = format!("provider \"vault\" {{\n  auth {{\n    token = \"{v}\"\n  }}\n}}\n");
    assert!(surfaces_in("providers.tf", &text, &v), "a nested HCL provider token must surface");
}

// ── cross-format: two nested secrets in one file both surface ─────────────────

#[test]
fn toml_two_nested_secrets_both_surface() {
    let a = secret(24, 15);
    let b = secret(28, 16);
    let text = format!(
        "[database]\npassword = \"{a}\"\n\n[redis]\nauth_token = \"{b}\"\n"
    );
    assert!(surfaces_in("config.toml", &text, &a), "the first nested secret must surface");
    assert!(surfaces_in("config.toml", &text, &b), "the second nested secret must surface");
}

// ── precision: nested NON-secret keys and placeholders do not surface ─────────

#[test]
fn toml_nested_host_field_does_not_surface() {
    let text = "[database.production]\nhost = \"db.prod.internal.example.com\"\nport = \"5432\"\n";
    assert!(
        nothing_in("config.toml", text, "db.prod.internal.example.com"),
        "a nested non-secret host field must not surface as a credential"
    );
}

#[test]
fn json_nested_placeholder_password_is_suppressed() {
    let text = "{\"db\":{\"auth\":{\"password\":\"YOUR_PASSWORD_PLACEHOLDER_HERE\"}}}\n";
    assert!(
        nothing_in("config.json", text, "YOUR_PASSWORD_PLACEHOLDER_HERE"),
        "a nested placeholder password must be suppressed"
    );
}

#[test]
fn yaml_nested_empty_password_does_not_surface() {
    let text = "database:\n  primary:\n    password: \"\"\n    host: db.local\n";
    assert!(
        nothing_in("app.yaml", text, "password: \"\""),
        "a nested empty password must not surface a credential"
    );
}

#[test]
fn toml_nested_sub_floor_secret_does_not_surface() {
    let text = "[app.auth]\npassword = \"short\"\n";
    assert!(
        nothing_in("config.toml", text, "\"short\""),
        "a nested sub-floor password value must not surface"
    );
}

#[test]
fn hcl_nested_placeholder_default_is_suppressed() {
    let text = "variable \"api_key\" {\n  default = \"CHANGEME_PLACEHOLDER_VALUE\"\n}\n";
    assert!(
        nothing_in("variables.tf", text, "CHANGEME_PLACEHOLDER_VALUE"),
        "a placeholder HCL variable default must be suppressed"
    );
}
