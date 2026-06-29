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

// ── SQL `IDENTIFIED BY` — verbatim CredData shapes ──────────────────────────

#[test]
fn sql_short_half_dictionary_value_stays_below_precision_floor() {
    // af273ae2.sh:325 shape. `argriyjqr` is a REAL labeled positive, but its
    // bigrams are half-English (`arg`, `gri`) so the shared random-vs-dictionary
    // discriminator (the same one that stops keyhog flagging every lowercase
    // token) scores it below the randomness floor and the weak-anchor gauntlet
    // declines it. This is the deliberate precision boundary, not a detector
    // bug — the `sql-password` regex DOES match here; the value is what is
    // declined. Pinned so a future floor change is a conscious recall/precision
    // decision, verified on both corpora, never an accident.
    let text = "mysql -e \"CREATE USER 'cactiuser'@'localhost' IDENTIFIED BY 'argriyjqr';\"";
    assert!(
        nothing_surfaces(text, "argriyjqr"),
        "a short half-dictionary IDENTIFIED BY value sits below the randomness floor"
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
fn cli_very_short_password_stays_below_precision_floor() {
    // 0c5a8c1e.md:189 shape. `i8cr1w!` is a REAL labeled positive but only 6
    // alphanumeric chars; the randomness discriminator fail-SAFEs to "identifier"
    // below ~6 alpha chars (KH-L-0413), so the weak-anchor gauntlet declines it.
    // The `cli-password-flag` regex DOES match; the short value is declined — the
    // deliberate precision boundary, pinned so it cannot move silently.
    let text = "nats server raft step-down --user admin --password i8cr1w!";
    assert!(
        nothing_surfaces(text, "i8cr1w!"),
        "a sub-6-alpha --password value sits below the randomness floor"
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
fn cli_password_dictionary_value_stays_suppressed() {
    assert!(
        nothing_surfaces("deploy --password changeme", "changeme"),
        "a `--password changeme` placeholder must STAY suppressed"
    );
}

#[test]
fn cli_password_shell_variable_stays_suppressed() {
    assert!(
        nothing_surfaces("run --host db --password $DB_PASSWORD", "$DB_PASSWORD"),
        "a `--password $VAR` shell reference must STAY suppressed"
    );
}
