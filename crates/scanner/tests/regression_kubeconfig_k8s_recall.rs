//! #115 Kubernetes credential recall: kubeconfig client auth + Secret manifests.
//!
//! The credential-bearing fields of real Kubernetes auth material are:
//!   * kubeconfig `users[].user.client-key-data` — a PEM client **private key**,
//!     base64-encoded inside the YAML value, so the `-----BEGIN … PRIVATE KEY-----`
//!     header is invisible to a raw byte scan;
//!   * kubeconfig `users[].user.token` — a plaintext bearer token (often a JWT);
//!   * Secret `data:` — base64 values (TLS keys, tokens, `.dockerconfigjson`);
//!   * Secret `stringData:` — plaintext values.
//!
//! This lock pins that the secret bytes are recovered (exact value / detector,
//! never `!is_empty`) and that public, non-secret material (a CERTIFICATE block,
//! a benign field) does NOT surface as a private key. Whether a field is reached
//! by the general decode-through pipeline or the structured preprocessor is an
//! implementation detail; the contract is operator-visible recall.

mod support;
use support::paths::detector_dir;

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;

/// PEM RSA private key proven to fire `private-key` unwrapped (shared with the
/// decode-through strict suite). `PEM_NEEDLE` is a stable slice of its body.
const PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
    MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
    KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIWPaVgC5bA8AjVWdjxNm\n\
    -----END RSA PRIVATE KEY-----";
const PEM_NEEDLE: &str = "MIIBOgIBAAJBAKj34Gkx";

/// A public X.509 CERTIFICATE block (NOT a private key). Used as the
/// `client-certificate-data` precision negative — it must never surface as a
/// private key.
const CERT: &str = "-----BEGIN CERTIFICATE-----\n\
    MIIBkTCB+wIJANRrU0E0X0gtMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNVBAMMBXRl\n\
    c3QwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAwWjAQMQ4wDAYDVQQDDAV0\n\
    -----END CERTIFICATE-----";
const CERT_BODY_NEEDLE: &str = "MIIBkTCB";

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        CompiledScanner::compile(detectors).expect("compile scanner")
    })
}

fn scan_file(path: &str, text: &str) -> Vec<RawMatch> {
    let s = scanner();
    s.clear_fragment_cache();
    let chunk = Chunk {
        data: text.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };
    s.scan(&chunk)
}

/// True iff SOME surfaced credential contains `needle`.
fn surfaces(path: &str, text: &str, needle: &str) -> bool {
    scan_file(path, text).iter().any(|m| m.credential.as_ref().contains(needle))
}

/// True iff SOME surfaced credential contains `needle` AND is attributed to `detector`.
fn surfaces_under(path: &str, text: &str, detector: &str, needle: &str) -> bool {
    scan_file(path, text)
        .iter()
        .any(|m| m.detector_id.as_ref() == detector && m.credential.as_ref().contains(needle))
}

/// True iff NO surfaced credential under `detector` contains `needle`.
fn never_under(path: &str, text: &str, detector: &str, needle: &str) -> bool {
    !scan_file(path, text)
        .iter()
        .any(|m| m.detector_id.as_ref() == detector && m.credential.as_ref().contains(needle))
}

/// A kubeconfig carrying one user with the given inline `user:` body lines
/// (already indented under `    `).
fn kubeconfig(user_body: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Config\nclusters:\n- name: prod\n  cluster:\n    server: https://k8s.example.com\ncontexts:\n- name: prod\n  context:\n    cluster: prod\n    user: deploy\ncurrent-context: prod\nusers:\n- name: deploy\n  user:\n{user_body}"
    )
}

// ── BASELINES: prove the harness (else a recall assertion proves nothing) ─────

#[test]
fn baseline_raw_pem_in_kubeconfig_path_fires() {
    // The kubeconfig path/content must not SUPPRESS detection: a raw (unencoded)
    // PEM in such a file still fires private-key.
    assert!(
        surfaces_under("kubeconfig", PEM, "private-key", PEM_NEEDLE),
        "a raw PEM in a kubeconfig file must still fire private-key"
    );
}

#[test]
fn baseline_b64_pem_in_generic_value_surfaces() {
    // The general decode-through recovers a base64-wrapped PEM from an ordinary
    // `key = "value"` line — the capability this whole suite leans on.
    let text = format!("decoded_payload = \"{}\"\n", b64(PEM));
    assert!(surfaces("config.txt", &text, PEM_NEEDLE), "base64-wrapped PEM must decode-through");
}

// ── kubeconfig client-key-data: base64 PEM client private key ─────────────────

#[test]
fn kubeconfig_client_key_data_base64_pem_surfaces() {
    let body = format!("    client-key-data: {}\n", b64(PEM));
    assert!(
        surfaces("kubeconfig", &kubeconfig(&body), PEM_NEEDLE),
        "the base64 client-key-data PEM private key must surface"
    );
}

#[test]
fn kubeconfig_client_key_data_attributed_to_private_key() {
    let body = format!("    client-key-data: {}\n", b64(PEM));
    assert!(
        surfaces_under("kubeconfig", &kubeconfig(&body), "private-key", PEM_NEEDLE),
        "the decoded client-key-data PEM must be attributed to the private-key detector"
    );
}

#[test]
fn kubeconfig_extensionless_config_path_surfaces() {
    // Real kubeconfigs are routinely the extensionless file `~/.kube/config`.
    let body = format!("    client-key-data: {}\n", b64(PEM));
    assert!(
        surfaces("home/.kube/config", &kubeconfig(&body), PEM_NEEDLE),
        "an extensionless ~/.kube/config must still surface the client key"
    );
}

#[test]
fn kubeconfig_yaml_extension_surfaces() {
    let body = format!("    client-key-data: {}\n", b64(PEM));
    assert!(
        surfaces("admin.kubeconfig.yaml", &kubeconfig(&body), PEM_NEEDLE),
        "a .yaml-suffixed kubeconfig must surface the client key"
    );
}

#[test]
fn kubeconfig_quoted_client_key_data_surfaces() {
    let body = format!("    client-key-data: \"{}\"\n", b64(PEM));
    assert!(
        surfaces("kubeconfig", &kubeconfig(&body), PEM_NEEDLE),
        "a quoted client-key-data value must surface the client key"
    );
}

// ── kubeconfig token: plaintext bearer token ──────────────────────────────────

#[test]
fn kubeconfig_plaintext_jwt_token_surfaces() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
               eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06ZGVwbG95In0.\
               dQw4Z2V0X3NpZ25hdHVyZV92YWx1ZV9oZXJlX2Zvcl90ZXN0aW5nXzEyMzQ1Ng";
    let body = format!("    token: {jwt}\n");
    assert!(
        surfaces("kubeconfig", &kubeconfig(&body), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        "a plaintext JWT bearer token in a kubeconfig must surface"
    );
}

#[test]
fn kubeconfig_client_key_and_token_both_surface() {
    let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
               eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.\
               c2lnbmF0dXJlX2Jsb2JfZm9yX3Rlc3Rpbmdfb25seV9ub3RfcmVhbF8wOTg3NjU";
    let body = format!("    client-key-data: {}\n    token: {jwt}\n", b64(PEM));
    let kc = kubeconfig(&body);
    assert!(surfaces("kubeconfig", &kc, PEM_NEEDLE), "client key must surface alongside token");
    assert!(
        surfaces("kubeconfig", &kc, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"),
        "token must surface alongside client key"
    );
}

// ── kubeconfig precision: public cert + benign fields are not secrets ─────────

#[test]
fn kubeconfig_client_certificate_data_is_not_a_private_key() {
    let body = format!("    client-certificate-data: {}\n", b64(CERT));
    assert!(
        never_under("kubeconfig", &kubeconfig(&body), "private-key", CERT_BODY_NEEDLE),
        "a public client-certificate-data X.509 block must NOT surface as a private key"
    );
}

#[test]
fn kubeconfig_without_secret_fields_surfaces_no_private_key() {
    let body = "    exec:\n      command: aws\n      args: [eks, get-token]\n";
    assert!(
        never_under("kubeconfig", &kubeconfig(body), "private-key", "BEGIN"),
        "a kubeconfig with only an exec auth provider must surface no private key"
    );
}

#[test]
fn kubeconfig_doc_mention_without_value_surfaces_nothing() {
    let text = "apiVersion: v1\nkind: Config\n# set client-key-data to your PEM key\n";
    assert!(
        never_under("kubeconfig", text, "private-key", "BEGIN"),
        "prose mentioning client-key-data without a value must surface nothing"
    );
}

#[test]
fn kubeconfig_empty_client_key_data_no_panic_no_surface() {
    let body = "    client-key-data:\n    token: \n";
    assert!(
        never_under("kubeconfig", &kubeconfig(body), "private-key", "BEGIN"),
        "an empty client-key-data must not panic and must surface no private key"
    );
}

// ── Secret manifests: data: base64 + stringData: plaintext ────────────────────

#[test]
fn k8s_secret_data_tls_key_base64_pem_surfaces() {
    let text = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: tls\ntype: kubernetes.io/tls\ndata:\n  tls.key: {}\n",
        b64(PEM)
    );
    assert!(
        surfaces("tls-secret.yaml", &text, PEM_NEEDLE),
        "a base64 tls.key PEM under a Secret data: block must surface"
    );
}

#[test]
fn k8s_secret_stringdata_plaintext_password_surfaces() {
    let pw = "Xy8Q2mNz7aB4dEfGhIjK";
    let text = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\nstringData:\n  password: {pw}\n"
    );
    assert!(surfaces("db-secret.yaml", &text, pw), "a stringData plaintext password must surface");
}

#[test]
fn k8s_secret_data_token_base64_surfaces() {
    let token = "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx";
    let text = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: sa\ndata:\n  token: {}\n",
        b64(token)
    );
    assert!(
        surfaces("sa-secret.yaml", &text, token),
        "a base64 token must decode-through and surface"
    );
}

#[test]
fn k8s_secret_list_items_both_secrets_surface() {
    let text = format!(
        "apiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  kind: Secret\n  metadata:\n    name: a\n  data:\n    tls.key: {}\n- apiVersion: v1\n  kind: Secret\n  metadata:\n    name: b\n  stringData:\n    api_password: Zq7Wm2Np9Rt4Lk6Xs8C\n",
        b64(PEM)
    );
    assert!(surfaces("bundle.yaml", &text, PEM_NEEDLE), "the first List item's PEM must surface");
    assert!(surfaces("bundle.yaml", &text, "Zq7Wm2Np9Rt4Lk6Xs8C"), "the second List item's password must surface");
}

// ── dockerconfigjson: base64 JSON whose inner `auth` is base64(user:pass) ──────

#[test]
fn dockerconfigjson_secret_inner_basic_auth_surfaces() {
    // .dockerconfigjson decodes to JSON; the registry `auth` field is itself
    // base64(user:password). Recovering the credential needs nested decode.
    let inner = b64("deploy:s3cretRegistryPassw0rd");
    let docker_json = format!("{{\"auths\":{{\"registry.example.com\":{{\"auth\":\"{inner}\"}}}}}}");
    let text = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: regcred\ntype: kubernetes.io/dockerconfigjson\ndata:\n  .dockerconfigjson: {}\n",
        b64(&docker_json)
    );
    assert!(
        surfaces("regcred.yaml", &text, "s3cretRegistryPassw0rd"),
        "the dockerconfigjson registry basic-auth password must surface through nested decode"
    );
}

#[test]
fn dockerconfigjson_benign_no_auth_surfaces_no_credential() {
    let docker_json = "{\"auths\":{\"registry.example.com\":{}}}";
    let text = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: regcred\ntype: kubernetes.io/dockerconfigjson\ndata:\n  .dockerconfigjson: {}\n",
        b64(docker_json)
    );
    assert!(
        never_under("regcred.yaml", &text, "private-key", "BEGIN"),
        "a dockerconfigjson with no auth must surface no private key"
    );
}

// ── robustness: malformed inputs must not panic or false-surface ──────────────

#[test]
fn k8s_secret_invalid_base64_data_no_panic() {
    let text =
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\ndata:\n  blob: !!!not-valid-base64!!!\n";
    // Must not panic; the malformed value simply does not decode to a PEM.
    assert!(
        never_under("x-secret.yaml", text, "private-key", "BEGIN"),
        "an invalid-base64 data value must not panic or surface a private key"
    );
}

#[test]
fn configmap_kind_is_not_decoded_as_secret() {
    // ConfigMap is intentionally not a Secret; a base64 value here is config
    // data, not a credential — it must not surface as a private key.
    let text = format!(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  ca: {}\n",
        b64(CERT)
    );
    assert!(
        never_under("cm.yaml", &text, "private-key", CERT_BODY_NEEDLE),
        "a ConfigMap base64 value must not surface as a private key"
    );
}

#[test]
fn kubeconfig_truncated_client_key_data_surfaces_no_private_key() {
    // A short, non-PEM base64 body (benign) must not trip private-key.
    let body = format!("    client-key-data: {}\n", b64("not a private key, just notes"));
    assert!(
        never_under("kubeconfig", &kubeconfig(&body), "private-key", "BEGIN"),
        "a benign short client-key-data value must surface no private key"
    );
}
