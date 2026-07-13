//! Task #52 lock: the structured-parse size cap must surface ONLY the
//! decode-through coverage gap. When a recognised structured file exceeds
//! `MAX_STRUCTURED_PARSE_BYTES`, `preprocess` skips it; that skip is a *counted*
//! coverage gap only for formats whose structured pass decodes values the raw
//! byte scan cannot recover (k8s Secret / docker-compose / Terraform state /
//! Jupyter notebook). `Env`/`HCL` extract plain scalar values the raw scan still
//! sees, so their oversize skip is lossless and must NOT be counted (Law 10: no
//! false-loud telemetry). A decode-derived buffer is never counted, its encoded
//! surface was already decoded and scanned upstream.
//!
//! This pins `structured_oversize_skip_is_counted`, the single predicate
//! `preprocess` applies at the cap, so the count decision cannot drift from the
//! format classification. Pure classification (no multi-megabyte fixtures).

use keyhog_scanner::testing::structured_oversize_skip_is_counted;

fn counted(text: &str, path: &str) -> bool {
    structured_oversize_skip_is_counted(text, Some(path), false)
}
fn counted_derived(text: &str, path: &str) -> bool {
    structured_oversize_skip_is_counted(text, Some(path), true)
}

const K8S: &str = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\ndata:\n  token: YWJjZGVm\n";

// ── decode-through formats: an oversize skip IS a counted coverage gap ────────

#[test]
fn k8s_secret_yaml_oversize_is_counted() {
    assert!(counted(K8S, "manifests/secret.yaml"));
}

#[test]
fn k8s_secret_yml_extension_is_counted() {
    assert!(counted(K8S, "secret.yml"));
}

#[test]
fn k8s_secret_uppercase_extension_is_counted() {
    // Extension match is ASCII case-insensitive.
    assert!(counted(K8S, "SECRET.YAML"));
}

#[test]
fn docker_compose_named_yaml_is_counted() {
    assert!(counted("services:\n  db: {}\n", "docker-compose.yaml"));
}

#[test]
fn compose_short_name_yml_is_counted() {
    assert!(counted("services:\n  db: {}\n", "compose.yml"));
}

#[test]
fn tfstate_is_counted() {
    assert!(counted("{\"version\":4}", "terraform.tfstate"));
}

#[test]
fn tfstate_uppercase_extension_is_counted() {
    assert!(counted("{\"version\":4}", "STATE.TFSTATE"));
}

#[test]
fn jupyter_ipynb_is_counted() {
    assert!(counted("{\"cells\":[]}", "notebook.ipynb"));
}

// ── context-only formats: an oversize skip is lossless, NOT counted ──────────

#[test]
fn env_dotfile_oversize_is_not_counted() {
    assert!(!counted("API_KEY=value\n", ".env"));
}

#[test]
fn env_suffixed_name_is_not_counted() {
    assert!(!counted("API_KEY=value\n", "prod.env"));
}

#[test]
fn hcl_tf_is_not_counted() {
    assert!(!counted("variable \"x\" {}\n", "main.tf"));
}

#[test]
fn hcl_tfvars_is_not_counted() {
    assert!(!counted("x = 1\n", "vars.tfvars"));
}

#[test]
fn hcl_dot_hcl_is_not_counted() {
    assert!(!counted("x = 1\n", "config.hcl"));
}

// ── unrecognised inputs: nothing to skip, never counted ──────────────────────

#[test]
fn plain_yaml_without_kind_secret_is_not_counted() {
    // A `.yaml` with no `kind: Secret` marker and no compose name is not a
    // recognised decode-through format.
    assert!(!counted("foo: bar\nbaz: qux\n", "config.yaml"));
}

#[test]
fn markdown_is_not_counted() {
    assert!(!counted("# readme\n", "README.md"));
}

#[test]
fn extensionless_path_is_not_counted() {
    assert!(!counted("some data", "Makefile"));
}

#[test]
fn absent_path_is_not_counted() {
    // Every recognised format keys off the path; without one there is nothing to
    // classify, so a k8s-shaped body with no path is not counted.
    assert!(!structured_oversize_skip_is_counted(K8S, None, false));
}

// ── decode-derived buffers: already decoded upstream, never counted ──────────

#[test]
fn k8s_decode_derived_buffer_is_not_counted() {
    assert!(!counted_derived(K8S, "secret.yaml"));
}

#[test]
fn compose_decode_derived_buffer_is_not_counted() {
    assert!(!counted_derived(
        "services:\n  db: {}\n",
        "docker-compose.yaml"
    ));
}

#[test]
fn tfstate_decode_derived_buffer_is_not_counted() {
    assert!(!counted_derived("{\"version\":4}", "terraform.tfstate"));
}

#[test]
fn jupyter_decode_derived_buffer_is_not_counted() {
    assert!(!counted_derived("{\"cells\":[]}", "notebook.ipynb"));
}

// ── partition completeness: exactly the decode-through set is counted ─────────

#[test]
fn only_decode_through_formats_are_counted() {
    let cases: &[(&str, &str, bool)] = &[
        (K8S, "s.yaml", true),
        ("services:\n  a: {}\n", "docker-compose.yml", true),
        ("{\"version\":4}", "x.tfstate", true),
        ("{\"cells\":[]}", "x.ipynb", true),
        ("API_KEY=v\n", ".env", false),
        ("variable \"x\" {}\n", "x.tf", false),
        ("x = 1\n", "x.hcl", false),
        ("plain: text\n", "x.yaml", false),
    ];
    for (text, path, want) in cases {
        assert_eq!(
            counted(text, path),
            *want,
            "partition mismatch for path {path:?}"
        );
    }
}
