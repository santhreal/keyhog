//! #117 GitLab token-family completeness lock. GitLab prefixes every routable
//! credential with a `gl<type>-` marker; keyhog already covered glpat- / gldt- /
//! glrt- / glcbt- / glptt-, but six documented prefixes had NO detector:
//!
//!   glagent-  Agent for Kubernetes token   (critical, cluster access)
//!   gloas-    OAuth application secret      (critical, app impersonation)
//!   glsoat-   SCIM OAuth access token       (high, group provisioning)
//!   glimt-    incoming-mail token           (medium)
//!   glffct-   feature-flags client token    (low)
//!   glft-     feed token                    (medium)
//!
//! This lock pins that all eleven prefixes surface the exact token bytes through
//! the on-disk scanner, that each new prefix attributes to its own detector, and
//! that the new patterns don't collide (glft- vs glffct-) or fire below their
//! length floor. Never `!is_empty`: every assertion is on the exact token.

mod support;

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;
use support::contracts::{make_chunk, scanner};

fn shared() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(scanner)
}

/// True iff scanning `text` surfaces a finding whose credential CONTAINS `token`.
fn surfaces(text: &str, token: &str) -> bool {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", "gitlab.env");
    s.scan(&chunk)
        .into_iter()
        .any(|m| m.credential.as_str().to_string().contains(token))
}

/// Detector ids of every finding produced for `text` (unfiltered).
fn fired_ids(text: &str) -> Vec<String> {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", "gitlab.env");
    s.scan(&chunk)
        .into_iter()
        .map(|m| m.detector_id.to_string())
        .collect()
}

// ── new prefixes: the token surfaces ─────────────────────────────────────────

#[test]
fn glagent_kubernetes_agent_token_surfaces() {
    let t = "glagent-Hx7Kp2Qm9Rn4Sb6Tw8Vz1Yc3";
    assert!(surfaces(&format!("KAS_TOKEN={t}\n"), t));
}

#[test]
fn gloas_oauth_application_secret_surfaces() {
    let t = "gloas-Jb3Mn7Pq2Rs8Tv5Wx1Yz4Ac6D";
    assert!(surfaces(&format!("GITLAB_OAUTH_CLIENT_SECRET={t}\n"), t));
}

#[test]
fn glsoat_scim_token_surfaces() {
    let t = "glsoat-Kc4Np8Qr3St9Uw6Xz2Yb5Bd7E";
    assert!(surfaces(&format!("SCIM_TOKEN={t}\n"), t));
}

#[test]
fn glimt_incoming_mail_token_surfaces() {
    let t = "glimt-Ld5Pp9Rs4Tu1Vx7Za3Yc6Ce8F";
    assert!(surfaces(&format!("INCOMING_EMAIL_TOKEN={t}\n"), t));
}

#[test]
fn glffct_feature_flags_token_surfaces() {
    let t = "glffct-Me6Qq1St5Uv2Wy8Ab4Zd7Df9G";
    assert!(surfaces(&format!("UNLEASH_API_TOKEN={t}\n"), t));
}

#[test]
fn glft_feed_token_surfaces() {
    let t = "glft-Nf7Rr2Tu6Vw3Xz9Bc5Ae8Eg1H";
    assert!(surfaces(
        &format!("https://gitlab.com/dashboard/issues.atom?feed_token={t}"),
        t
    ));
}

// ── existing prefixes still surface (regression alongside the new detectors) ──

#[test]
fn glpat_personal_access_token_still_surfaces() {
    let t = "glpat-Ab3Cd6Ef9Gh2Ij5Kl8Mn";
    assert!(surfaces(&format!("GITLAB_TOKEN={t}\n"), t));
}

#[test]
fn gldt_deploy_token_still_surfaces() {
    let t = "gldt-Bc4De7Fg1Hi4Jk7Lm0No";
    assert!(surfaces(&format!("GITLAB_DEPLOY_TOKEN={t}\n"), t));
}

#[test]
fn glrt_runner_token_still_surfaces() {
    // glrt- pattern 1 captures EXACTLY 20 body chars, so use a 20-char body.
    let t = "glrt-Cd5Ef8Gh1Ij4Kl7Mn0Op";
    assert!(surfaces(&format!("RUNNER_TOKEN={t}\n"), t));
}

#[test]
fn glcbt_cicd_build_token_still_surfaces() {
    let t = "glcbt-De6Fg9Hi2Jk5Lm8No1Pq";
    assert!(surfaces(&format!("CI_JOB_TOKEN={t}\n"), t));
}

#[test]
fn glptt_pipeline_trigger_token_still_surfaces() {
    let t = "glptt-Ef7Gh0Ij3Kl6Mn9Op2Qr";
    assert!(surfaces(&format!("TRIGGER_TOKEN={t}\n"), t));
}

// ── attribution: each new prefix routes through its own detector ──────────────

#[test]
fn glagent_attributes_to_agent_detector() {
    let t = "glagent-Hx7Kp2Qm9Rn4Sb6Tw8Vz1Yc3";
    assert!(fired_ids(t).iter().any(|id| id == "gitlab-agent-token"));
}

#[test]
fn gloas_attributes_to_oauth_secret_detector() {
    let t = "gloas-Jb3Mn7Pq2Rs8Tv5Wx1Yz4Ac6D";
    assert!(fired_ids(t)
        .iter()
        .any(|id| id == "gitlab-oauth-application-secret"));
}

#[test]
fn glsoat_attributes_to_scim_detector() {
    let t = "glsoat-Kc4Np8Qr3St9Uw6Xz2Yb5Bd7E";
    assert!(fired_ids(t).iter().any(|id| id == "gitlab-scim-token"));
}

#[test]
fn glimt_attributes_to_incoming_mail_detector() {
    let t = "glimt-Ld5Pp9Rs4Tu1Vx7Za3Yc6Ce8F";
    assert!(fired_ids(t)
        .iter()
        .any(|id| id == "gitlab-incoming-mail-token"));
}

#[test]
fn glffct_attributes_to_feature_flags_detector() {
    let t = "glffct-Me6Qq1St5Uv2Wy8Ab4Zd7Df9G";
    assert!(fired_ids(t)
        .iter()
        .any(|id| id == "gitlab-feature-flags-client-token"));
}

#[test]
fn glft_attributes_to_feed_detector() {
    let t = "glft-Nf7Rr2Tu6Vw3Xz9Bc5Ae8Eg1H";
    assert!(fired_ids(t).iter().any(|id| id == "gitlab-feed-token"));
}

// ── precision / non-collision ─────────────────────────────────────────────────

#[test]
fn glagent_short_body_does_not_surface() {
    let ids = fired_ids("glagent-short");
    assert!(
        !ids.iter().any(|id| id == "gitlab-agent-token"),
        "a sub-20-char body must not fire gitlab-agent-token; got {ids:?}"
    );
}

#[test]
fn gloas_short_body_does_not_surface() {
    let ids = fired_ids("gloas-short");
    assert!(
        !ids.iter().any(|id| id == "gitlab-oauth-application-secret"),
        "a sub-20-char body must not fire gitlab-oauth-application-secret; got {ids:?}"
    );
}

#[test]
fn glffct_token_does_not_misattribute_to_feed_detector() {
    // `glffct-` must not be mistaken for `glft-` (no substring collision).
    let t = "glffct-Me6Qq1St5Uv2Wy8Ab4Zd7Df9G";
    let ids = fired_ids(t);
    assert!(
        ids.iter()
            .any(|id| id == "gitlab-feature-flags-client-token"),
        "glffct- must fire its own detector; got {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id == "gitlab-feed-token"),
        "glffct- must NOT also fire gitlab-feed-token; got {ids:?}"
    );
}

#[test]
fn bare_gitlab_word_fires_no_gitlab_token_detector() {
    let ids = fired_ids("gitlab is a great platform for devops pipelines");
    let gl = [
        "gitlab-agent-token",
        "gitlab-oauth-application-secret",
        "gitlab-scim-token",
        "gitlab-incoming-mail-token",
        "gitlab-feature-flags-client-token",
        "gitlab-feed-token",
    ];
    assert!(
        !ids.iter().any(|id| gl.contains(&id.as_str())),
        "a bare 'gitlab' mention must not fire any new GitLab token detector; got {ids:?}"
    );
}
