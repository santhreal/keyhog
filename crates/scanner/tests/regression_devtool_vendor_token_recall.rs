//! Dev-tool / CI-platform credential recall + precision lock for the vendors not
//! covered by `regression_package_registry_token_recall.rs` (npm/PyPI/RubyGems):
//! JFrog (`AKCp8` API key), Snyk (UUID token), SonarCloud / SonarQube (40-hex
//! token), Terraform Cloud (`.atlasv1.` token), and Docker Hub (`dckr_pat_`
//! PAT). These leak via CI env, publish scripts, and `settings.xml`/`.tfrc`
//! config. None is checksum-gated. Built on the shared `support::vendorgen`
//! harness (no local generator/scan boilerplate).
//!
//! SonarCloud and SonarQube share a bare `SONAR_TOKEN=<40hex>` shape; the vendor
//! label is only unambiguous with a `_CLOUD_`/`QUBE_` infix, so the bare form is
//! asserted against the two-detector set.

mod support;
use support::vendorgen::{alnum, fires, hex, surfaces_under, surfaces_under_any, uuid};

const SONAR: &[&str] = &["sonarcloud-token", "sonarqube-token"];

// ── JFrog: AKCp8<32+> ────────────────────────────────────────────────────────

#[test]
fn jfrog_api_key_surfaces() {
    let k = format!("AKCp8{}", alnum(40, 1));
    assert!(
        surfaces_under(&k, "jfrog-api-key", &k),
        "AKCp8 key must surface"
    );
}

#[test]
fn jfrog_api_key_env_anchor_surfaces() {
    let k = format!("AKCp8{}", alnum(40, 2));
    assert!(surfaces_under(
        &format!("JFROG_API_KEY={k}"),
        "jfrog-api-key",
        &k
    ));
}

#[test]
fn jfrog_api_key_min_body_surfaces() {
    let k = format!("AKCp8{}", alnum(32, 3)); // 32 = minimum body
    assert!(surfaces_under(&k, "jfrog-api-key", &k));
}

#[test]
fn jfrog_api_key_31_body_does_not_fire() {
    let k = format!("AKCp8{}", alnum(31, 4)); // 31 < the required 32
    assert!(!fires(&k, "jfrog-api-key"));
}

// ── Snyk: context-anchored UUID ──────────────────────────────────────────────

#[test]
fn snyk_token_surfaces() {
    let u = uuid(5);
    assert!(surfaces_under(
        &format!("SNYK_TOKEN={u}"),
        "snyk-api-token",
        &u
    ));
}

#[test]
fn snyk_api_token_variant_surfaces() {
    let u = uuid(6);
    assert!(surfaces_under(
        &format!("SNYK_API_TOKEN={u}"),
        "snyk-api-token",
        &u
    ));
}

#[test]
fn snyk_lowercase_anchor_surfaces() {
    let u = uuid(7);
    assert!(surfaces_under(
        &format!("snyk_token={u}"),
        "snyk-api-token",
        &u
    ));
}

#[test]
fn snyk_non_uuid_does_not_fire() {
    let bad = hex(32, 8); // a bare 32-hex is not the UUID token shape
    assert!(!fires(&format!("SNYK_TOKEN={bad}"), "snyk-api-token"));
}

// ── SonarCloud / SonarQube: 40-hex ───────────────────────────────────────────

#[test]
fn sonarcloud_token_surfaces() {
    let k = hex(40, 9);
    assert!(surfaces_under(
        &format!("SONAR_CLOUD_TOKEN={k}"),
        "sonarcloud-token",
        &k
    ));
}

#[test]
fn sonarqube_token_surfaces() {
    let k = hex(40, 10);
    assert!(surfaces_under(
        &format!("SONARQUBE_TOKEN={k}"),
        "sonarqube-token",
        &k
    ));
}

#[test]
fn bare_sonar_token_surfaces_under_either_label() {
    // `SONAR_TOKEN=<40hex>` matches both detectors; dedup keeps one label.
    let k = hex(40, 11);
    assert!(surfaces_under_any(&format!("SONAR_TOKEN={k}"), SONAR, &k));
}

#[test]
fn sonarcloud_39_hex_does_not_fire() {
    let k = hex(39, 12); // 39 < the required 40
    assert!(!fires(
        &format!("SONAR_CLOUD_TOKEN={k}"),
        "sonarcloud-token"
    ));
}

// ── Terraform Cloud: <14>.atlasv1.<67+> ──────────────────────────────────────

#[test]
fn terraform_cloud_token_surfaces() {
    let t = format!("{}.atlasv1.{}", alnum(14, 13), alnum(70, 14));
    assert!(surfaces_under(&t, "terraform-cloud-api-token", &t));
}

#[test]
fn terraform_cloud_tfe_anchor_surfaces() {
    let t = format!("{}.atlasv1.{}", alnum(14, 15), alnum(70, 16));
    assert!(surfaces_under(
        &format!("TFE_TOKEN={t}"),
        "terraform-cloud-api-token",
        &t
    ));
}

#[test]
fn terraform_cloud_min_tail_surfaces() {
    let t = format!("{}.atlasv1.{}", alnum(14, 17), alnum(67, 18)); // 67 = min tail
    assert!(surfaces_under(&t, "terraform-cloud-api-token", &t));
}

#[test]
fn terraform_cloud_66_tail_does_not_fire() {
    let t = format!("{}.atlasv1.{}", alnum(14, 19), alnum(66, 20)); // 66 < 67
    assert!(!fires(&t, "terraform-cloud-api-token"));
}

// ── Docker Hub: dckr_pat_<27..64> ────────────────────────────────────────────

#[test]
fn dockerhub_pat_surfaces() {
    let k = format!("dckr_pat_{}", alnum(40, 21));
    assert!(
        surfaces_under(&k, "dockerhub-pat", &k),
        "dckr_pat_ token must surface"
    );
}

#[test]
fn dockerhub_pat_env_anchor_surfaces() {
    let k = format!("dckr_pat_{}", alnum(40, 22));
    assert!(surfaces_under(
        &format!("DOCKER_PAT={k}"),
        "dockerhub-pat",
        &k
    ));
}

#[test]
fn dockerhub_pat_max_body_surfaces() {
    let k = format!("dckr_pat_{}", alnum(64, 23)); // 64 = maximum body
    assert!(surfaces_under(&k, "dockerhub-pat", &k));
}

#[test]
fn dockerhub_pat_26_body_does_not_fire() {
    let k = format!("dckr_pat_{}", alnum(26, 24)); // 26 < the required 27
    assert!(!fires(&k, "dockerhub-pat"));
}

// ── cross: several dev-tool tokens co-surface ────────────────────────────────

#[test]
fn multiple_devtool_tokens_cosurface() {
    let jf = format!("AKCp8{}", alnum(40, 25));
    let dk = format!("dckr_pat_{}", alnum(40, 26));
    let tf = format!("{}.atlasv1.{}", alnum(14, 27), alnum(70, 28));
    let text = format!("JFROG_API_KEY={jf}\nDOCKER_PAT={dk}\nTFE_TOKEN={tf}\n");
    assert!(surfaces_under(&text, "jfrog-api-key", &jf));
    assert!(surfaces_under(&text, "dockerhub-pat", &dk));
    assert!(surfaces_under(&text, "terraform-cloud-api-token", &tf));
}

#[test]
fn snyk_and_sonar_tokens_cosurface() {
    let sn = uuid(29);
    let sc = hex(40, 30);
    let jf = format!("AKCp8{}", alnum(40, 31));
    let text = format!("SNYK_TOKEN={sn}\nSONAR_CLOUD_TOKEN={sc}\nJFROG_API_KEY={jf}\n");
    assert!(surfaces_under(&text, "snyk-api-token", &sn));
    assert!(surfaces_under(&text, "sonarcloud-token", &sc));
    assert!(surfaces_under(&text, "jfrog-api-key", &jf));
}
