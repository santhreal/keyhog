//! #118 IaC-secret recall lock. The value-shaped secrets that dominate real
//! Infrastructure-as-Code leaks are password / secret assignments in Terraform
//! `.tfvars` + provider blocks (HCL `key = "value"`), Helm `values.yaml` and
//! Ansible vars (YAML `key: value`). keyhog catches these through the generic
//! password-assignment detector; this lock pins that every such IaC form keeps
//! surfacing the exact secret bytes through the on-disk scanner — never
//! `!is_empty`.
//!
//! Out of scope by design: the Ansible *Vault* encrypted blob
//! (`$ANSIBLE_VAULT;...;AES256` + hex ciphertext). keyhog detects value-shaped
//! secrets; an encrypted-blob marker is suppressed by the hex-digest gate (the
//! ciphertext) and the credential-shape gate (the `$;.` header), so it does not
//! fit the engine's model without a core carve-out. The common, plaintext IaC
//! secret forms below are what real scans recover.

mod support;

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;
use support::contracts::{make_chunk, scanner};

fn shared() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(scanner)
}

/// Deterministic high-entropy alphanumeric value of length `n` (no dictionary
/// word, no repeated mask), so a miss is a real recall gap and not a value the
/// dictionary / low-diversity precision gates would legitimately drop.
fn body(n: usize, seed: usize) -> String {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..n)
        .map(|i| ALNUM[(i * 7 + seed * 13 + i * i) % ALNUM.len()] as char)
        .collect()
}

fn surfaces_in(path: &str, text: &str, needle: &str) -> bool {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", path);
    s.scan(&chunk)
        .into_iter()
        .any(|m| m.credential.to_string().contains(needle))
}

fn surfaces(text: &str, needle: &str) -> bool {
    surfaces_in("main.tfvars", text, needle)
}

// ── Terraform .tfvars / provider blocks (HCL `key = "value"`) ─────────────────

#[test]
fn tfvars_db_password_surfaces() {
    let pw = body(16, 1);
    assert!(surfaces(&format!("db_password = \"{pw}\"\n"), &pw));
}

#[test]
fn tfvars_rds_password_surfaces() {
    let pw = body(16, 2);
    assert!(surfaces(&format!("rds_password = \"{pw}\"\n"), &pw));
}

#[test]
fn tfvars_master_password_surfaces() {
    let pw = body(18, 3);
    assert!(surfaces(&format!("master_password = \"{pw}\"\n"), &pw));
}

#[test]
fn tfvars_root_password_surfaces() {
    let pw = body(16, 4);
    assert!(surfaces(&format!("root_password = \"{pw}\"\n"), &pw));
}

#[test]
fn tfvars_admin_password_surfaces() {
    let pw = body(16, 5);
    assert!(surfaces(&format!("admin_password = \"{pw}\"\n"), &pw));
}

#[test]
fn tfvars_passwd_variant_surfaces() {
    let pw = body(16, 6);
    assert!(surfaces(&format!("passwd = \"{pw}\"\n"), &pw));
}

#[test]
fn tfvars_pwd_variant_surfaces() {
    let pw = body(16, 7);
    assert!(surfaces(&format!("pwd = \"{pw}\"\n"), &pw));
}

#[test]
fn terraform_provider_block_password_surfaces() {
    let pw = body(16, 8);
    assert!(surfaces(
        &format!("provider \"mysql\" {{\n  password = \"{pw}\"\n}}\n"),
        &pw
    ));
}

#[test]
fn terraform_var_db_password_env_surfaces() {
    let pw = body(16, 9);
    assert!(surfaces(&format!("TF_VAR_db_password={pw}\n"), &pw));
}

// ── Helm values.yaml / Ansible vars (YAML `key: value`) ───────────────────────

#[test]
fn helm_values_top_level_password_surfaces() {
    let pw = body(16, 10);
    assert!(surfaces_in(
        "values.yaml",
        &format!("password: {pw}\n"),
        &pw
    ));
}

#[test]
fn helm_values_nested_db_password_surfaces() {
    let pw = body(16, 11);
    assert!(surfaces_in(
        "values.yaml",
        &format!("database:\n  auth:\n    db_password: {pw}\n"),
        &pw
    ));
}

#[test]
fn helm_values_quoted_postgresql_password_surfaces() {
    let pw = body(16, 12);
    assert!(surfaces_in(
        "values.yaml",
        &format!("postgresql:\n  auth:\n    password: \"{pw}\"\n"),
        &pw
    ));
}

#[test]
fn helm_values_redis_password_surfaces() {
    let pw = body(16, 13);
    assert!(surfaces_in(
        "values.yaml",
        &format!("redis:\n  password: {pw}\n"),
        &pw
    ));
}

#[test]
fn ansible_become_password_surfaces() {
    let pw = body(16, 14);
    assert!(surfaces_in(
        "playbook.yml",
        &format!("ansible_become_password: {pw}\n"),
        &pw
    ));
}

#[test]
fn ansible_vars_mysql_password_surfaces() {
    let pw = body(16, 15);
    assert!(surfaces_in(
        "group_vars/all.yml",
        &format!("mysql_root_password: \"{pw}\"\n"),
        &pw
    ));
}

#[test]
fn ansible_vault_named_var_password_surfaces() {
    // A var merely NAMED with a `vault_` prefix (not an encrypted vault blob) is
    // an ordinary plaintext password assignment and must surface.
    let pw = body(16, 16);
    assert!(surfaces_in(
        "group_vars/all.yml",
        &format!("vault_db_password: \"{pw}\"\n"),
        &pw
    ));
}

// ── precision / negatives ─────────────────────────────────────────────────────

#[test]
fn sub_floor_password_does_not_surface() {
    // A value below the 12-char generic password floor must not surface.
    assert!(
        !surfaces("db_password = \"shortpw\"", "shortpw"),
        "a 7-char password value is below the floor and must not surface"
    );
}

#[test]
fn empty_password_value_does_not_surface() {
    assert!(
        !surfaces("db_password = \"\"\nnext = 1", "db_password"),
        "an empty password assignment must not surface a credential"
    );
}

#[test]
fn placeholder_password_value_is_suppressed() {
    // A placeholder body (>= floor length) must be dropped by the placeholder gate.
    let text = "db_password = \"YOUR_DB_PASSWORD_PLACEHOLDER_HERE\"";
    assert!(
        !surfaces(text, "YOUR_DB_PASSWORD_PLACEHOLDER_HERE"),
        "a PLACEHOLDER password body must be suppressed, not surfaced"
    );
}

#[test]
fn repetitive_mask_password_value_is_suppressed() {
    // A low-diversity mask (all identical chars) must be dropped, not surfaced.
    let text = "db_password = \"xxxxxxxxxxxxxxxx\"";
    assert!(
        !surfaces(text, "xxxxxxxxxxxxxxxx"),
        "a repetitive-mask password body must be suppressed, not surfaced"
    );
}
