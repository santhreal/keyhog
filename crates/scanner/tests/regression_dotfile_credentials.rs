//! Recall + precision lock for the dotfile credential detectors:
//!   * `npmrc-auth-token` — the `.npmrc` `_authToken=` registry-auth slot, which
//!     carries legacy base64 tokens, GitHub-Packages PATs, GitLab tokens and
//!     CI-injected secrets that the `npm_<36>`-only `npm-access-token` misses.
//!   * `netrc-password`  — the `~/.netrc` / `.authinfo`
//!     `machine … login … password <secret>` triple (whitespace-separated, so
//!     generic key=value detectors miss it).
//!
//! Both are STRUCTURAL-SLOT detectors: the anchor (`_authToken=` /
//! `machine…login…password`) is decisive, so each declares `min_confidence=0.2`.
//! This suite drives the REAL `CompiledScanner::scan` path and asserts the exact
//! detector id + the captured token (group 1), never `!is_empty` (Law 6):
//! it pins that real tokens fire, the capture is the SECRET only (not the
//! surrounding registry path / host), and template/placeholder/short slots stay
//! silent.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::CompiledScanner;

fn scan(text: &str) -> Vec<RawMatch> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(".npmrc".into()),
            ..Default::default()
        },
    };
    scanner.scan(&chunk)
}

/// The captured credential for detector `id`, if it fired.
fn capture_for(text: &str, id: &str) -> Option<String> {
    scan(text)
        .into_iter()
        .find(|m| m.detector_id.as_ref() == id)
        .map(|m| m.credential.as_ref().to_string())
}

fn npmrc(text: &str) -> Option<String> {
    capture_for(text, "npmrc-auth-token")
}
fn netrc(text: &str) -> Option<String> {
    capture_for(text, "netrc-password")
}

// ===========================================================================
// npmrc-auth-token — RECALL across token vendors.
// ===========================================================================

#[test]
fn npmrc_legacy_npmtoken_uuid_fires() {
    // The pre-`npm_` legacy `NpmToken.<token>` format is exactly what
    // `npm-access-token` (`npm_<36>`) misses — the detector's core reason to
    // exist. Exercises the `.` in the value class with a high-entropy body.
    let line = "//registry.npmjs.org/:_authToken=NpmToken.AbCd1234EfGh5678IjKl9012MnOp3456";
    assert_eq!(
        npmrc(line).as_deref(),
        Some("NpmToken.AbCd1234EfGh5678IjKl9012MnOp3456"),
        "capture must be the token only, not the //registry path"
    );
}

#[test]
fn npmrc_legacy_base64_token_fires() {
    let line = "//registry.npmjs.org/:_authToken=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=";
    assert_eq!(
        npmrc(line).as_deref(),
        Some("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="),
        "legacy base64 tokens (incl. `=` padding) must fire and capture fully"
    );
}

#[test]
fn npmrc_opaque_ci_token_fires() {
    // An opaque CI-injected token (no vendor prefix, no checksum shape) — the
    // common GitHub-Actions/GitLab-CI `.npmrc` case the prefix detectors miss.
    let line = "//npm.pkg.example.com/:_authToken=Zk9Lm2Qw7Rt4Yp1Xc8Vb3Nh6Jf5Dg0SaWe";
    assert_eq!(
        npmrc(line).as_deref(),
        Some("Zk9Lm2Qw7Rt4Yp1Xc8Vb3Nh6Jf5Dg0SaWe")
    );
}

#[test]
fn npmrc_fabricated_vendor_shape_is_owned_by_the_vendor_detector() {
    // A `npm_<36>` value is the dedicated `npm-access-token`'s shape and is
    // checksum-gated: a fabricated one is dropped at the checksum stage, so it
    // does NOT surface under `npmrc-auth-token`. This pins the ownership
    // boundary — npmrc-auth-token claims the OPAQUE/legacy slot values the
    // checksummed vendor detectors don't (a real vendor token still surfaces via
    // its own detector). See the checksum-fixture gotcha in keyhog memory.
    let line = "//registry.npmjs.org/:_authToken=npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    assert_eq!(
        npmrc(line),
        None,
        "fabricated npm_ vendor shape is owned by npm-access-token, not npmrc-auth-token"
    );
}

#[test]
fn npmrc_gitlab_glpat_token_fires() {
    let line = "//gitlab.example.com/api/v4/packages/npm/:_authToken=glpat-AbCdEfGhIjKlMnOpQrSt";
    assert_eq!(npmrc(line).as_deref(), Some("glpat-AbCdEfGhIjKlMnOpQrSt"));
}

#[test]
fn npmrc_bare_authtoken_without_registry_prefix_fires() {
    // A bare `_authToken=` line (no `//host/:` scope) still fires.
    assert_eq!(
        npmrc("_authToken=s0meL3gacyT0kenValue12345").as_deref(),
        Some("s0meL3gacyT0kenValue12345")
    );
}

#[test]
fn npmrc_authtoken_with_spaces_around_equals_fires() {
    assert_eq!(
        npmrc("_authToken = s0meL3gacyT0kenValue12345").as_deref(),
        Some("s0meL3gacyT0kenValue12345")
    );
}

#[test]
fn npmrc_capture_stops_at_end_of_line() {
    // A following line must not be swallowed into the token.
    let text =
        "//registry.npmjs.org/:_authToken=npmTokenABCDEFGH12345\nregistry=https://registry.npmjs.org/";
    let cap = npmrc(text).expect("fires");
    assert_eq!(
        cap, "npmTokenABCDEFGH12345",
        "value class must stop at newline"
    );
}

// ===========================================================================
// npmrc-auth-token — PRECISION (templates / empty / short slots stay silent).
// ===========================================================================

#[test]
fn npmrc_env_template_does_not_fire() {
    assert_eq!(npmrc("//registry.npmjs.org/:_authToken=${NPM_TOKEN}"), None);
}

#[test]
fn npmrc_empty_slot_does_not_fire() {
    assert_eq!(npmrc("//registry.npmjs.org/:_authToken="), None);
}

#[test]
fn npmrc_short_value_below_floor_does_not_fire() {
    // 7 chars < the {8,} floor.
    assert_eq!(npmrc("_authToken=abc1234"), None);
}

#[test]
fn npmrc_fires_under_exact_id_and_service() {
    let m = scan("//registry.npmjs.org/:_authToken=npmTokenABCDEFGH12345")
        .into_iter()
        .find(|m| m.detector_id.as_ref() == "npmrc-auth-token")
        .expect("fires");
    assert_eq!(m.detector_id.as_ref(), "npmrc-auth-token");
    assert_eq!(m.service.as_ref(), "npm");
}

// ===========================================================================
// netrc-password — RECALL across single-line + multi-line layouts.
// ===========================================================================

#[test]
fn netrc_single_line_fires_capturing_password_only() {
    let line = "machine api.example.com login deploy password Zx9Qw3Rt7Lp2Mk";
    assert_eq!(
        netrc(line).as_deref(),
        Some("Zx9Qw3Rt7Lp2Mk"),
        "capture must be the password only, not the machine/login fields"
    );
}

#[test]
fn netrc_multi_line_entry_fires() {
    let text = "machine api.example.com\nlogin deploy\npassword Zx9Qw3Rt7Lp2Mk\n";
    assert_eq!(netrc(text).as_deref(), Some("Zx9Qw3Rt7Lp2Mk"));
}

#[test]
fn netrc_password_stops_at_whitespace() {
    // Trailing fields (e.g. a macro) must not be glued onto the password.
    let line = "machine api.example.com login deploy password Zx9Qw3Rt7Lp2Mk port 443";
    assert_eq!(netrc(line).as_deref(), Some("Zx9Qw3Rt7Lp2Mk"));
}

#[test]
fn netrc_two_entries_yield_two_findings() {
    let text = "machine a.example.com login u1 password Secret111aaaa\n\
                machine b.example.com login u2 password Secret222bbbb";
    let hits: Vec<_> = scan(text)
        .into_iter()
        .filter(|m| m.detector_id.as_ref() == "netrc-password")
        .collect();
    assert_eq!(hits.len(), 2, "two machine entries → two findings");
    assert!(hits
        .iter()
        .any(|m| m.credential.as_ref() == "Secret111aaaa"));
    assert!(hits
        .iter()
        .any(|m| m.credential.as_ref() == "Secret222bbbb"));
}

#[test]
fn netrc_fires_under_exact_id_and_service() {
    let m = scan("machine api.example.com login deploy password Zx9Qw3Rt7Lp2Mk")
        .into_iter()
        .find(|m| m.detector_id.as_ref() == "netrc-password")
        .expect("fires");
    assert_eq!(m.detector_id.as_ref(), "netrc-password");
    assert_eq!(m.service.as_ref(), "netrc");
}

// ===========================================================================
// netrc-password — PRECISION (missing anchor / template / short / placeholder).
// ===========================================================================

#[test]
fn netrc_without_login_field_does_not_fire() {
    // `machine … password` without the `login` field is not the full triple.
    assert_eq!(
        netrc("machine api.example.com password Zx9Qw3Rt7Lp2Mk"),
        None
    );
}

#[test]
fn netrc_env_template_does_not_fire() {
    assert_eq!(
        netrc("machine api.example.com login deploy password ${NETRC_PW}"),
        None
    );
}

#[test]
fn netrc_angle_placeholder_does_not_fire() {
    assert_eq!(
        netrc("machine api.example.com login deploy password <your-password>"),
        None
    );
}

#[test]
fn netrc_short_password_below_floor_does_not_fire() {
    // 5 chars < the {6,} floor.
    assert_eq!(netrc("machine h.example.com login u password abc12"), None);
}

#[test]
fn netrc_prose_machine_password_does_not_fire() {
    // Prose that mentions the words but lacks the login-anchored triple stays
    // silent (the triple is the anchor, not the bare words).
    assert_eq!(
        netrc("Reset the machine when you forget the admin password please now"),
        None
    );
}

// ===========================================================================
// .pypirc — pypi-api-token (the `pypi-` upload token in the password slot).
// ===========================================================================

/// A `pypi-` upload token body in the detector's required {100,128} range:
/// a 40-char `[a-zA-Z0-9]` unit x3 = 120 chars (subset of the value class).
fn pypi_token() -> String {
    format!(
        "pypi-{}",
        "abcdefGHIJ0123456789klmnopQRSTUV01234567".repeat(3)
    )
}

#[test]
fn pypirc_upload_token_fires_and_captures_full_token() {
    let tok = pypi_token();
    let text = format!("[pypi]\nusername = __token__\npassword = {tok}\n");
    assert_eq!(
        capture_for(&text, "pypi-api-token").as_deref(),
        Some(tok.as_str()),
        "the whole pypi- upload token is the credential"
    );
}

#[test]
fn pypirc_bare_token_attributed_to_pypi_detector() {
    let tok = pypi_token();
    assert_eq!(
        capture_for(&tok, "pypi-api-token").as_deref(),
        Some(tok.as_str())
    );
}

#[test]
fn pypirc_short_pypi_mention_does_not_fire() {
    // pypi-api-token requires a 100+ char body; a `pypi-main` index/repo name
    // stays silent.
    let text = "[distutils]\nindex-servers = pypi\nrepository = pypi-main\n";
    assert_eq!(capture_for(text, "pypi-api-token"), None);
}

// ===========================================================================
// .git-credentials — url-credentials (https://user:pass@host userinfo).
// ===========================================================================

#[test]
fn git_credentials_userinfo_password_fires() {
    let line = "https://gituser:Xk7Qw9RpLm5Vn8Zt@github.com";
    assert_eq!(
        capture_for(line, "url-credentials").as_deref(),
        Some("Xk7Qw9RpLm5Vn8Zt"),
        "capture is the userinfo password only, not the host/path"
    );
}

#[test]
fn git_credentials_template_password_does_not_fire() {
    assert_eq!(
        capture_for("https://gituser:<password>@github.com", "url-credentials"),
        None
    );
}

#[test]
fn git_credentials_empty_userinfo_password_does_not_fire() {
    // No password between `:` and `@`.
    assert_eq!(
        capture_for("https://gituser:@github.com", "url-credentials"),
        None
    );
}

// ===========================================================================
// .my.cnf — generic-password ([client] password= slot).
// ===========================================================================

#[test]
fn mycnf_password_slot_fires() {
    let text = "[client]\nuser=root\nhost=localhost\npassword=Tn4Bv8Cx2Wq6Hs9Jp\n";
    assert_eq!(
        capture_for(text, "generic-password").as_deref(),
        Some("Tn4Bv8Cx2Wq6Hs9Jp")
    );
}

#[test]
fn mycnf_env_template_does_not_fire() {
    assert_eq!(
        capture_for(
            "[client]\nuser=root\npassword=${DB_PASS}\n",
            "generic-password"
        ),
        None
    );
}

// ===========================================================================
// .pgpass — DOCUMENTED GAP (positional colon password, no literal anchor).
// ===========================================================================

const PGPASS: &str = "localhost:5432:mydb:admin:Rk5Mn8Qw2Lp6Vt";

#[test]
fn pgpass_password_is_a_documented_gap_not_yet_surfaced() {
    // The `.pgpass` password is a pure positional colon field with NO content
    // keyword to anchor; the weak `word:NUMBER:word:word:word` shape cannot
    // justify skipping the entropy floor (netrc earns that via its
    // machine/login/password literals). Closing it cleanly needs a
    // path/filename trigger — a follow-up. This pins the current behavior so the
    // gap stays VISIBLE; flip it to a positive lock when the trigger lands.
    let surfaced = scan(PGPASS)
        .iter()
        .any(|m| m.credential.as_ref().contains("Rk5Mn8Qw2Lp6Vt"));
    assert!(
        !surfaced,
        "if .pgpass is now supported, convert this to a recall lock"
    );
}

#[test]
fn pgpass_line_does_not_false_fire_url_or_generic_password() {
    // Precision: the 5-colon `.pgpass` shape is neither a URL userinfo nor a
    // `password=` slot, so it must not be misread as either.
    let hits = scan(PGPASS);
    assert!(!hits
        .iter()
        .any(|m| m.detector_id.as_ref() == "url-credentials"));
    assert!(!hits
        .iter()
        .any(|m| m.detector_id.as_ref() == "generic-password"));
}

// ===========================================================================
// All covered dotfile formats surface together in one mixed dump.
// ===========================================================================

#[test]
fn all_covered_dotfile_credentials_surface_together() {
    let tok = pypi_token();
    let blob = format!(
        "machine api.example.com login deploy password Zx9Qw3Rt7Lp2Mk\n\
         //registry.npmjs.org/:_authToken=s0meL3gacyT0kenValue12345\n\
         password = {tok}\n\
         https://gituser:Xk7Qw9RpLm5Vn8Zt@github.com\n\
         [client]\npassword=Tn4Bv8Cx2Wq6Hs9Jp\n"
    );
    let creds: Vec<String> = scan(&blob)
        .into_iter()
        .map(|m| m.credential.as_ref().to_string())
        .collect();
    for needle in [
        "Zx9Qw3Rt7Lp2Mk",
        "s0meL3gacyT0kenValue12345",
        "Xk7Qw9RpLm5Vn8Zt",
        "Tn4Bv8Cx2Wq6Hs9Jp",
    ] {
        assert!(
            creds.iter().any(|c| c.contains(needle)),
            "missing {needle}: {creds:?}"
        );
    }
    assert!(
        creds.iter().any(|c| c.contains("pypi-")),
        "missing pypi token: {creds:?}"
    );
}
