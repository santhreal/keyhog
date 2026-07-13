//! Recall regression for the CredData "URL Credentials" class (~210 labeled
//! positives), the password embedded in a URL userinfo component,
//! `scheme://[user]:<password>@host`.
//!
//! Before the generic `url-credentials` detector keyhog only had four
//! SCHEME-SPECIFIC connection-string detectors (mongodb/mysql/postgres/redis),
//! so every ftp/http/https/amqp/mqtt/git userinfo password fell through, and
//! the bulk of the real CredData values are SHORT all-lowercase random strings
//! (`pxidztpv`, `zavvfuco`, `hjxzyi`) that the generic random-vs-dictionary
//! floor declines. `url-credentials` is a STRONG-anchor structural detector:
//! the suppression pipeline skips the Tier-B randomness floor (`apply_tier_b
//! == false`), so those random values surface, while precision against
//! placeholders is held by three orthogonal gates that do NOT penalise a short
//! random password
//!   * the `{6,128}` value floor drops the short placeholders (`pass`, `admin`);
//!   * the `dictionary_word_placeholder` gate drops a value the English bigram
//!     model is CONFIDENT is a real word (`password`, `secret`, `welcome`);
//!   * the regex excludes `<` `>` (templates) and the Tier-A marker gate drops
//!     `$VAR` references.
//!
//! Each `text` is a VERBATIM shape from the corpus (file/line cited). Assertions
//! check the exact surfaced credential bytes via the on-disk scanner, never
//! `!is_empty`.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

fn matches(s: &CompiledScanner, chunk: &Chunk) -> Vec<(String, String)> {
    s.clear_fragment_cache();
    s.scan(chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

/// True iff `credential` surfaces under exactly `detector_id`.
fn surfaces_under(text: &str, detector_id: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    matches(&s, &chunk)
        .iter()
        .any(|(id, cred)| id == detector_id && cred == credential)
}

/// True iff NOTHING surfaces `credential` (under any detector).
fn nothing_surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    !matches(&s, &chunk)
        .iter()
        .any(|(_, cred)| cred == credential)
}

/// True iff the `url-credentials` detector produced no match at all.
fn no_url_cred_match(text: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    !matches(&s, &chunk)
        .iter()
        .any(|(id, _)| id == "url-credentials")
}

// ── SURFACE: real CredData random userinfo passwords (≥6 chars) ─────────────

#[test]
fn ftp_userinfo_password_surfaces() {
    // eee97fd2.c:4256 / a1676f19.c:3150 value, in a non-comment context (the
    // corpus shape is a C comment, which keyhog's orthogonal comment policy
    // suppresses (see `comment_embedded_userinfo_suppressed`)).
    let text = "ftp_url = \"ftp://user:pxidztpv@ftp.my.site:8021/README\"";
    assert!(
        surfaces_under(text, "url-credentials", "pxidztpv"),
        "ftp:// userinfo password must surface (no database detector covers ftp)"
    );
}

#[test]
fn http_proxy_credential_surfaces() {
    // 17ed1848.md:318 shape (git credential.httpsProxy with an embedded password).
    let text =
        "git config --global credential.httpsProxy http://john.doe:zavvfuco@proxy.contoso.com";
    assert!(
        surfaces_under(text, "url-credentials", "zavvfuco"),
        "http proxy userinfo password must surface"
    );
}

#[test]
fn https_composer_repo_credential_surfaces() {
    // 2efd6594.md:150 shape (composer repository auth token-as-password).
    let text = "composer config repositories composer.unique-name https://username:vvaitgiz@repo.example.org";
    assert!(
        surfaces_under(text, "url-credentials", "vvaitgiz"),
        "https repository userinfo password must surface"
    );
}

#[test]
fn redis_six_char_password_surfaces() {
    // cee930a7.php:170 shape, exactly 6 chars (`hjxzyi`): the `{6,128}` floor
    // admits it and the strong anchor skips the randomness floor, so this short
    // random value the GENERIC bridge would decline is recovered here.
    let text = "$uri = 'redis://predis:hjxzyi@10.10.10.10:6400/5?timeout=0.5';";
    assert!(
        surfaces_under(text, "url-credentials", "hjxzyi"),
        "a 6-char random userinfo password must surface under the strong anchor"
    );
}

#[test]
fn mqtt_broker_credential_surfaces() {
    // cc66396f.rb:47 shape: CloudMQTT broker URL, mixed-case password.
    let text = "'uri' => 'mqtt://kcqlmkgx:xGZbzxyqsGuM@m10.cloudmqtt.com:13858',";
    assert!(
        surfaces_under(text, "url-credentials", "xGZbzxyqsGuM"),
        "mqtt:// broker userinfo password must surface"
    );
}

#[test]
fn percent_encoded_password_surfaces() {
    // 9a6d8adf.php:106 shape: `h%40co` (the percent-encoded `h@co`), 6 chars;
    // only 3 alphabetic, so the bigram model returns None (NOT a confident
    // dictionary word) and the value surfaces. A real CredData positive.
    let text = "array($server, 'http://repo.org', 'http://user:h%40co@proxy.com:80',";
    assert!(
        surfaces_under(text, "url-credentials", "h%40co"),
        "a 6-char percent-encoded userinfo password must surface"
    );
}

#[test]
fn mysql_url_password_surfaces() {
    // a9d11eea.js:19 shape.
    let text = "'mysql://root:nxruoapftabufvcsa@localhost:23306/?charset=utf8&connectTimeout=500',";
    assert!(
        surfaces_under(text, "url-credentials", "nxruoapftabufvcsa"),
        "mysql userinfo password must surface as the bare value under url-credentials"
    );
}

#[test]
fn postgres_url_long_password_surfaces() {
    // a9d11eea.js:12 shape: 20-char lowercase value.
    let text = "'postgres://postgres:lwymqqpotlnpfaetwtuz@localhost:25432/postgres',";
    assert!(
        surfaces_under(text, "url-credentials", "lwymqqpotlnpfaetwtuz"),
        "postgres userinfo password must surface as the bare value under url-credentials"
    );
}

#[test]
fn redis_empty_username_password_surfaces() {
    // a758153b.example:22 shape: CELERY redis broker, no username, just `:pw@`.
    let text = "CELERY_BROKER_URL=redis://:ypdlovjpwrwpldxvz@localhost:6379/1";
    assert!(
        surfaces_under(text, "url-credentials", "ypdlovjpwrwpldxvz"),
        "empty-username `redis://:pw@host` must still capture the password"
    );
}

// ── BOUNDARY: real positives below the `{6,128}` regex floor ────────────────

#[test]
fn five_char_postgres_password_below_regex_floor() {
    // a758153b.example:94 shape. `zhpal` is a REAL labeled positive but only 5
    // chars, below the `{6,128}` value floor that drops the short placeholders
    // (`pass`, `admin`). Pinned so a future floor change is a conscious
    // recall/precision decision, never an accident.
    let text = "DATABASE_URL=postgres://cabot:zhpal@localhost:5432/index";
    assert!(
        no_url_cred_match(text),
        "a 5-char userinfo value is below the regex floor and must not match"
    );
}

#[test]
fn five_char_amqp_password_below_regex_floor() {
    // `lwokh` (5 chars) is below the `{6,128}` floor, so url-credentials must
    // not match it. (The rabbitmq default-`guest`-credential detector fires on
    // `guest:lwokh` independently, that orthogonal detector is not asserted
    // here; this pins the url-credentials regex floor specifically.)
    let text = "conn, err := amqp.Dial(\"amqp://guest:lwokh@localhost:5672/\")";
    assert!(
        no_url_cred_match(text),
        "a 5-char userinfo value is below the url-credentials regex floor and must not match"
    );
}

// ── PRECISION: dictionary-word placeholders (≥6) stay suppressed ────────────

#[test]
fn dictionary_word_password_suppressed() {
    assert!(
        nothing_surfaces(
            "https://username:password@repo.example.org/team/repo.git",
            "password"
        ),
        "the literal word `password` is a confident dictionary placeholder, drop it"
    );
}

#[test]
fn dictionary_word_secret_suppressed() {
    assert!(
        nothing_surfaces("redis://app:secret@cache.example.com:6379/0", "secret"),
        "the literal word `secret` (6 chars, English) must STAY suppressed"
    );
}

#[test]
fn dictionary_word_welcome_suppressed() {
    assert!(
        nothing_surfaces("https://user:welcome@host.example.com/", "welcome"),
        "the literal word `welcome` is a confident dictionary placeholder, drop it"
    );
}

// ── PRECISION: short placeholders (<6) never match the regex ────────────────

#[test]
fn short_placeholder_pass_not_matched() {
    assert!(
        no_url_cred_match("https://user:pass@host.example.com/"),
        "`pass` is 4 chars, below the `{{6,128}}` floor, so the regex never matches"
    );
}

#[test]
fn short_placeholder_admin_not_matched() {
    assert!(
        no_url_cred_match("https://admin:admin@host.example.com/"),
        "`admin` is 5 chars, below the `{{6,128}}` floor, so the regex never matches"
    );
}

// ── PRECISION: refs / templates / placeholder words ─────────────────────────

#[test]
fn shell_variable_password_suppressed() {
    assert!(
        nothing_surfaces(
            "redis://cache:$REDIS_PASSWORD@cache.example.net:6379/0",
            "$REDIS_PASSWORD"
        ),
        "a `:$VAR@` shell reference must STAY suppressed (Tier-A marker gate)"
    );
}

#[test]
fn angle_bracket_template_structurally_rejected() {
    assert!(
        no_url_cred_match("DATABASE_URL=postgres://user:<password>@db.example.com:5432/app"),
        "a `user:<password>@` angle-bracket template must not match at all"
    );
}

#[test]
fn placeholder_word_changeme_suppressed() {
    assert!(
        nothing_surfaces("see https://user:changeme@host.example.com/", "changeme"),
        "`changeme` is a canonical placeholder word and must STAY suppressed"
    );
}

// ── STRUCTURAL NON-MATCHES, no credential slot ─────────────────────────────

#[test]
fn host_port_without_userinfo_no_match() {
    assert!(
        no_url_cred_match("Connect to https://api.example.com:8443/v1/users for details."),
        "a `host:port` URL with no `@` userinfo must not match"
    );
}

#[test]
fn plain_url_no_userinfo_no_match() {
    assert!(
        no_url_cred_match("git clone https://github.com/example/repo.git"),
        "a plain URL with no userinfo component must not match"
    );
}

#[test]
fn scp_ssh_syntax_no_match() {
    assert!(
        no_url_cred_match("git@github.com:example/repo.git"),
        "scp-style `git@host:path` must not match (no scheme, no userinfo slot)"
    );
}

#[test]
fn empty_password_no_match() {
    assert!(
        no_url_cred_match("postgres://user:@db.example.com:5432/app"),
        "an empty userinfo password must not match"
    );
}

#[test]
fn comment_embedded_userinfo_suppressed_by_comment_policy() {
    // The verbatim CredData ftp shape lives in a C comment. keyhog's orthogonal
    // comment-context policy suppresses credentials there uniformly (the same
    // value surfaces outside a comment, see `ftp_userinfo_password_surfaces`),
    // so this is an existing-policy boundary, NOT a url-credentials decision.
    let text = "* ftp://user:pxidztpv@ftp.my.site:8021/README */";
    assert!(
        no_url_cred_match(text),
        "a userinfo credential inside a C comment is suppressed by the comment policy"
    );
}

// ── CAPTURE PRECISION + DETECTOR ATTRIBUTION ────────────────────────────────

#[test]
fn capture_is_password_only_not_whole_url() {
    // The surfaced url-credentials value must be the BARE password, never the
    // scheme/host/port/path (that is the whole point of the group-1 capture).
    let s = scanner();
    let chunk = make_chunk(
        "deploy = \"ftp://ci:Kc4mLp9Rt8Vy3Bn6@ftp.internal.example.com/\"",
        "source",
        "probe.conf",
    );
    let url_cred: Vec<String> = matches(&s, &chunk)
        .into_iter()
        .filter(|(id, _)| id == "url-credentials")
        .map(|(_, cred)| cred)
        .collect();
    assert_eq!(
        url_cred,
        vec!["Kc4mLp9Rt8Vy3Bn6".to_string()],
        "url-credentials must capture ONLY the password, not the scheme/host/path"
    );
}

#[test]
fn ftp_scheme_covered_by_url_credentials_not_a_connection_string_detector() {
    // For an ftp:// URL NO scheme-specific connection-string detector exists
    // (those cover only mongodb/mysql/postgres/redis), so url-credentials is
    // the detector that closes the gap. The unanchored generic-password bridge
    // may co-fire on a high-entropy value, that is fine; the load-bearing
    // claim is (a) url-credentials surfaces it and (b) no `*-connection-string`
    // detector does.
    let s = scanner();
    let chunk = make_chunk(
        "deploy_url = \"ftp://ci:Kc4mLp9Rt8Vy3Bn6@ftp.internal.example.com/\"",
        "source",
        "probe.conf",
    );
    let ids: Vec<String> = matches(&s, &chunk)
        .into_iter()
        .filter(|(_, cred)| cred == "Kc4mLp9Rt8Vy3Bn6")
        .map(|(id, _)| id)
        .collect();
    assert!(
        ids.iter().any(|id| id == "url-credentials"),
        "the ftp userinfo password must be surfaced by url-credentials; got {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id.ends_with("-connection-string")),
        "no scheme-specific connection-string detector covers ftp; got {ids:?}"
    );
}
