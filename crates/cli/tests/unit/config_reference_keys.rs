//! Every `.keyhog.toml` key the configuration reference names must exist in the
//! real config schema.
//!
//! `docs/src/reference/configuration.md` is hand-maintained beside the Rust
//! config structs (KH-088). A reader who copies a key that was renamed gets
//! `unknown table or key` and a scan that fails closed before any output, which
//! is the correct behaviour and a terrible experience.
//!
//! The authoritative field list is not hand-copied here. Every section carries
//! `#[serde(deny_unknown_fields)]`, so deserializing a deliberately impossible
//! key makes serde report the complete set of fields it expected. That set is
//! the schema, read from the schema.

use std::collections::BTreeSet;

/// Serde's `deny_unknown_fields` diagnostic lists every accepted field. Parse
/// that list rather than restating it.
fn accepted_fields(table: Option<&str>) -> BTreeSet<String> {
    let probe = match table {
        Some(name) => format!("[{name}]\nkeyhog_probe_unknown_key = 1\n"),
        None => "keyhog_probe_unknown_key = 1\n".to_string(),
    };
    let error = toml::from_str::<super::schema::ConfigFile>(&probe)
        .err()
        .unwrap_or_else(|| {
            panic!(
                "{probe:?} must be rejected by deny_unknown_fields, otherwise this gate is blind"
            )
        })
        .to_string();
    // serde phrases the list three ways depending on how many fields there
    // are: "expected `a`", "expected `a` or `b`", and "expected one of `a`,
    // `b`, ...". Taking everything after the last "expected " covers all three.
    let listed = error
        .rsplit_once("expected ")
        .map(|(_, tail)| tail)
        .unwrap_or_else(|| panic!("serde must enumerate the accepted fields; got: {error}"));
    let fields: BTreeSet<String> = listed
        .split('`')
        .filter(|piece| {
            !piece.is_empty()
                && piece
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        })
        .map(str::to_owned)
        .collect();
    assert!(
        !fields.is_empty(),
        "no accepted fields parsed out of: {error}"
    );
    fields
}

fn configuration_reference() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/src/reference/configuration.md"),
    )
    .expect("read the configuration reference")
}

/// The `.keyhog.toml` key column of the reference table, as `(table, key)`.
/// A cell may hold several keys, an assignment example, or a dash for "no
/// surface"; all three appear in the shipped table.
fn documented_keys() -> BTreeSet<(Option<String>, String)> {
    let reference = configuration_reference();

    let mut keys = BTreeSet::new();
    for line in reference.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        // `| Setting | Default | key | CLI flag | Effect |`
        let Some(cell) = line.split('|').nth(3) else {
            continue;
        };
        // Only the odd segments of a backtick split are INSIDE backticks; the
        // even ones are the prose between them (`no_ml = true` disables).
        for (index, token) in cell.split('`').enumerate() {
            if index.is_multiple_of(2) {
                continue;
            }
            let token = token.trim();
            // Keep only the identifier: cells write `no_ml = true` and
            // `[scan].incremental / [scan].incremental_cache`.
            let token = token.split(['=', ' ']).next().unwrap_or_default().trim();
            if token.is_empty() || token == "-" {
                continue;
            }
            let (table, key) = match token.strip_prefix('[') {
                Some(rest) => match rest.split_once("].") {
                    Some((table, key)) => (Some(table.to_owned()), key.to_owned()),
                    // A bare `[tuning]` names the table itself, not a key.
                    None => continue,
                },
                None => (None, token.to_owned()),
            };
            if key.is_empty()
                || !key
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                continue;
            }
            keys.insert((table, key));
        }
    }
    keys
}

/// Every documented key exists in the schema that would parse it.
#[test]
fn documented_config_keys_exist_in_the_schema() {
    let mut unknown = Vec::new();
    for (table, key) in documented_keys() {
        let accepted = accepted_fields(table.as_deref());
        if !accepted.contains(&key) {
            let owner = table.as_deref().unwrap_or("(root)");
            unknown.push(format!("[{owner}].{key}"));
        }
    }
    assert!(
        unknown.is_empty(),
        "the configuration reference names keys the schema does not accept:\n{}",
        unknown.join("\n")
    );
}

/// WHY: `[tuning]` fields affect runtime work selection and autoroute identity;
/// every schema addition must become operator-visible in the same change.
#[test]
fn every_tuning_schema_key_is_documented() {
    let reference = configuration_reference();
    let tuning_section = reference
        .split_once("### `[tuning]`")
        .map(|(_, section)| section)
        .and_then(|section| section.split_once("\n### ").map(|(body, _)| body))
        .expect("configuration reference has one bounded tuning section");
    let tuning_block = tuning_section
        .split_once("```toml")
        .map(|(_, block)| block)
        .and_then(|block| block.split_once("```").map(|(body, _)| body))
        .expect("tuning section has a TOML example");
    let documented: BTreeSet<String> = tuning_block
        .lines()
        .filter_map(|line| line.split_once('=').map(|(key, _)| key.trim().to_owned()))
        .collect();
    let missing: Vec<String> = accepted_fields(Some("tuning"))
        .difference(&documented)
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "the tuning schema accepts keys missing from its configuration reference: {missing:?}"
    );
}

/// Every table the reference writes as `[name].key` is a real table. A renamed
/// table would otherwise make each of its keys look merely misplaced.
#[test]
fn documented_config_tables_exist_in_the_schema() {
    let root = accepted_fields(None);
    let mut unknown: Vec<String> = documented_keys()
        .into_iter()
        .filter_map(|(table, _)| table)
        .filter(|table| !root.contains(table))
        .collect();
    unknown.sort();
    unknown.dedup();
    assert!(
        unknown.is_empty(),
        "the configuration reference names tables the schema does not accept: {unknown:?}"
    );
}

/// The extractor must be reading real rows. Without this, a table-format change
/// that stops matching would make both gates above pass by checking nothing.
#[test]
fn the_extractor_reads_a_substantial_number_of_documented_keys() {
    let keys = documented_keys();
    assert!(
        keys.len() >= 40,
        "expected at least 40 documented `.keyhog.toml` keys, found {}; the reference \
         table format has probably changed",
        keys.len()
    );
    assert!(
        keys.iter().any(|(table, _)| table.is_some()),
        "the extractor must recognise table-qualified keys such as `[scan].min_confidence`"
    );
    assert!(
        keys.iter().any(|(table, _)| table.is_none()),
        "the extractor must recognise root keys such as `detectors`"
    );
}
