//! Recall regression for the CredData "SQL Password" + "CMD Password" classes.
//!
//! These two classes (~39 + ~25 labeled positives) scored 0.00 recall before
//! the `sql-password` / `cli-password-flag` detectors: the secret sits after a
//! NON-assignment anchor (`IDENTIFIED BY '<x>'`, `--password <x>`) that the
//! generic `keyword=value` bridge never produced a candidate for. Each line
//! below is a VERBATIM shape from the corpus; the detectors close the gap for
//! the clearly-random values while the shared identifier/example gauntlet keeps
//! the very-short / placeholder values suppressed (both detectors are
//! classified weak_anchor, so the random-vs-dictionary discriminator runs).
//!
//! Assertions check the exact surfaced credential bytes via the on-disk scanner
//! — never `!is_empty`.

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
    let chunk = make_chunk(text, "source", "probe.sql");
    matches(&s, &chunk)
        .iter()
        .any(|(id, cred)| id == detector_id && cred == credential)
}

/// True iff NOTHING surfaces `credential`.
fn nothing_surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.sql");
    !matches(&s, &chunk)
        .iter()
        .any(|(_, cred)| cred == credential)
}

/// True iff neither structural-password-slot detector matched at all.
fn no_password_slot_match(text: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.sql");
    !matches(&s, &chunk)
        .iter()
        .any(|(id, _)| id == "sql-password" || id == "cli-password-flag")
}

// ── SQL `IDENTIFIED BY` — verbatim CredData shapes ──────────────────────────

#[test]
fn sql_random_lowercase_value_recovered_by_strong_anchor() {
    // af273ae2.sh:325 shape. `argriyjqr` is a REAL labeled positive that the
    // PRIOR weak-anchor sql-password DROPPED via the Tier-B identifier-shape arm
    // (it is a pure-lowercase token, which that arm treats as a code identifier).
    // Its adjacent bigrams (`yj`,`jq`,`qr`) are improbable English (mean ≈ −7.3,
    // below the −6.85 threshold), so it is NOT a confident dictionary word and the
    // strong anchor — which skips that Tier-B arm — correctly recovers it. This is
    // the recall the generalization buys; `IDENTIFIED BY '<x>'` is an unambiguous
    // credential context, so a random token there is a real secret, not an FP.
    let text = "mysql -e \"CREATE USER 'cactiuser'@'localhost' IDENTIFIED BY 'argriyjqr';\"";
    assert!(
        surfaces_under(text, "sql-password", "argriyjqr"),
        "a random lowercase IDENTIFIED BY value must surface under the strong anchor"
    );
}

#[test]
fn sql_short_value_below_regex_floor_no_match() {
    // A 5-char value is below the `{6,128}` regex floor (which drops short
    // placeholders `pass`/`admin`), so sql-password never matches it.
    assert!(
        no_password_slot_match("CREATE USER 'svc' IDENTIFIED BY 'k7v2x';"),
        "a 5-char IDENTIFIED BY value is below the regex floor and must not match"
    );
}

#[test]
fn sql_identified_by_secret_dictionary_suppressed() {
    assert!(
        nothing_surfaces("ALTER USER app IDENTIFIED BY 'secret';", "secret"),
        "`secret` is a confident dictionary word — the dictionary gate must drop it"
    );
}

#[test]
fn sql_alter_user_with_plugin_by_surfaces() {
    // a5f87782.md:444 shape — the WITH <plugin> BY form, dash-bearing value.
    let text =
        "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'bjy-jbpuyowe';";
    assert!(
        surfaces_under(text, "sql-password", "bjy-jbpuyowe"),
        "CredData ALTER USER ... WITH <plugin> BY '<random>' must surface"
    );
}

#[test]
fn sql_truly_random_lowercase_surfaces() {
    // A truly-random all-lowercase value (improbable bigrams `xq`,`qz`,`zj`) scores
    // BELOW the −6.85 English threshold ⇒ NOT a confident dictionary word ⇒ the
    // strong anchor surfaces it (the floor-skipping recall this generalization buys).
    let text = "CREATE USER 'svc'@'localhost' IDENTIFIED BY 'pxqzjwkv';";
    assert!(
        surfaces_under(text, "sql-password", "pxqzjwkv"),
        "a truly-random lowercase IDENTIFIED BY value must surface under the strong anchor"
    );
}

#[test]
fn sql_double_quoted_value_with_inner_quote_surfaces() {
    // 3245bad3.md:32 shape — double-quoted value containing an inner single quote.
    let text = "CREATE USER root@'hostname' IDENTIFIED BY \"5q'jK3d7ca\";";
    assert!(
        surfaces_under(text, "sql-password", "5q'jK3d7ca"),
        "double-quoted IDENTIFIED BY value (inner ' allowed) must surface"
    );
}

// ── CLI `--password` / `-Password` — verbatim CredData shapes ────────────────

#[test]
fn cli_powershell_password_flag_surfaces() {
    // 7269210a.md:313 shape — PowerShell -Password with a 10-char mixed value.
    let text = "Invoke-MSOLSpray -UserList .\\userlist.txt -Password Rcuhxw1486";
    assert!(
        surfaces_under(text, "cli-password-flag", "Rcuhxw1486"),
        "CredData PowerShell -Password <random> must surface"
    );
}

#[test]
fn cli_low_alpha_short_password_surfaces() {
    // 0c5a8c1e.md:189 shape. `i8cr1w!` is a REAL labeled positive: 7 chars (≥ the
    // `{6,128}` regex floor) but only 4 alphabetic, so the bigram model returns
    // None (cannot judge < 6 alpha) ⇒ NOT a confident dictionary word ⇒ the strong
    // anchor surfaces it. This is the recall the weak-anchor fail-safe used to drop.
    let text = "nats server raft step-down --user admin --password i8cr1w!";
    assert!(
        surfaces_under(text, "cli-password-flag", "i8cr1w!"),
        "a ≥6-char low-alpha --password value must surface under the strong anchor"
    );
}

#[test]
fn cli_passwd_alias_random_surfaces() {
    // The `--passwd` alias with a random mixed value.
    let text = "mysqldump --user=root --passwd=Qx7Kp2Vn9Rm4Lt8w db";
    assert!(
        surfaces_under(text, "cli-password-flag", "Qx7Kp2Vn9Rm4Lt8w"),
        "the --passwd alias with a random value must surface"
    );
}

#[test]
fn cli_short_value_below_regex_floor_no_match() {
    // A 5-char value is below the `{6,128}` regex floor, so cli-password-flag
    // never matches it (drops the short placeholders `admin`/`pass`).
    assert!(
        no_password_slot_match("svc --password k7v2x"),
        "a 5-char --password value is below the regex floor and must not match"
    );
}

// ── PRECISION: the placeholder / dictionary twins stay suppressed ───────────

#[test]
fn sql_identified_by_placeholder_stays_suppressed() {
    assert!(
        nothing_surfaces("CREATE USER 'x' IDENTIFIED BY 'password';", "password"),
        "an `IDENTIFIED BY 'password'` placeholder must STAY suppressed"
    );
}

#[test]
fn sql_identified_by_your_password_here_suppressed() {
    assert!(
        nothing_surfaces(
            "CREATE USER 'svc' IDENTIFIED BY 'your_password_here';",
            "your_password_here"
        ),
        "the instructional `your_password_here` placeholder must STAY suppressed"
    );
}

#[test]
fn cli_password_dictionary_value_stays_suppressed() {
    assert!(
        nothing_surfaces("deploy --password changeme", "changeme"),
        "a `--password changeme` placeholder must STAY suppressed"
    );
}

#[test]
fn cli_password_welcome_dictionary_suppressed() {
    assert!(
        nothing_surfaces("login-tool --password welcome", "welcome"),
        "`welcome` is a confident dictionary word — the dictionary gate must drop it"
    );
}

#[test]
fn cli_password_shell_variable_stays_suppressed() {
    assert!(
        nothing_surfaces("run --host db --password $DB_PASSWORD", "$DB_PASSWORD"),
        "a `--password $VAR` shell reference must STAY suppressed"
    );
}

#[test]
fn cli_password_angle_template_suppressed() {
    assert!(
        nothing_surfaces("deploy --password <YOUR_PASSWORD>", "<YOUR_PASSWORD>"),
        "a `--password <YOUR_PASSWORD>` angle template must STAY suppressed"
    );
}

// ── STRUCTURAL NON-MATCHES — no quoted/flagged credential slot ───────────────

#[test]
fn sql_prose_identified_by_no_quotes_no_match() {
    assert!(
        no_password_slot_match(
            "The bug was identified by the security team during the Q3 audit."
        ),
        "prose `identified by` with no quoted value must not match"
    );
}

#[test]
fn cli_prose_without_flag_no_match() {
    assert!(
        no_password_slot_match("See the docs to set the password value before deploying."),
        "prose mentioning `password` with no `--password` flag must not match"
    );
}

// ── CAPTURE PRECISION — group 1 is the password, never the whole clause ──────

#[test]
fn sql_capture_is_password_only() {
    let s = scanner();
    let chunk = make_chunk(
        "CREATE USER 'svc'@'localhost' IDENTIFIED BY 'Zx9KmPq2LvWnB7tR';",
        "source",
        "probe.sql",
    );
    let caps: Vec<String> = matches(&s, &chunk)
        .into_iter()
        .filter(|(id, _)| id == "sql-password")
        .map(|(_, cred)| cred)
        .collect();
    assert_eq!(
        caps,
        vec!["Zx9KmPq2LvWnB7tR".to_string()],
        "sql-password must capture ONLY the quoted password, not the IDENTIFIED BY clause"
    );
}

#[test]
fn cli_capture_is_password_only() {
    let s = scanner();
    let chunk = make_chunk(
        "deploy --user admin --password Zx9KmPq2LvWnB7tR --verbose",
        "source",
        "probe.sh",
    );
    let caps: Vec<String> = matches(&s, &chunk)
        .into_iter()
        .filter(|(id, _)| id == "cli-password-flag")
        .map(|(_, cred)| cred)
        .collect();
    assert_eq!(
        caps,
        vec!["Zx9KmPq2LvWnB7tR".to_string()],
        "cli-password-flag must capture ONLY the flag value, not the surrounding args"
    );
}
