//! CAPABILITY TARGET-SPEC: per-detector context-variant recall.
//!
//! For EVERY credential-sufficient detector in the contract corpus this lane
//! takes the canonical credential and re-plants it in the surrounding contexts
//! real leaks live in — an env assignment, a YAML value, a JSON field, inside a
//! line of source code, wrapped in single/double quotes, padded with leading
//! whitespace — then asserts the SAME credential still surfaces under the real
//! scan path. The contract proved the credential fires in ONE context; the
//! product claim is that it fires in the contexts an operator actually scans.
//!
//! Each (detector, variant) that does NOT surface is a tracked recall gap. A
//! large fraction are expected RED today: many detectors anchor on a single
//! quoting/keyword shape and miss the others. Those reds are the worklist; they
//! MUST NOT be weakened to pass (Law 9). The lane is sound because every variant
//! is a BYTE-PRESERVING re-context of a credential-sufficient token — the
//! credential bytes are untouched, so a disappearance is a context-sensitivity
//! hole, never a fixture artifact (see mod.rs sufficiency partition).

use crate::target_spec::{
    join_capped, load_canonicals, scan, sufficient_canonicals, surfaces, Canonical,
};

/// One named context variant: given a raw credential, produce a body that
/// embeds it, plus the logical path the body would live at.
struct Variant {
    name: &'static str,
    build: fn(&str) -> (String, String),
}

/// The realistic-context variant battery. Each must preserve the credential
/// bytes verbatim (no truncation, no case change) so the lane stays sound.
fn variants() -> Vec<Variant> {
    vec![
        Variant {
            name: "env-export",
            build: |cred| {
                (
                    format!("export SERVICE_API_TOKEN={cred}\n"),
                    "deploy/.env".to_string(),
                )
            },
        },
        Variant {
            name: "env-quoted",
            build: |cred| {
                (
                    format!("SERVICE_API_TOKEN=\"{cred}\"\n"),
                    "deploy/.env".to_string(),
                )
            },
        },
        Variant {
            name: "yaml-value",
            build: |cred| {
                (
                    format!("config:\n  service:\n    api_token: {cred}\n"),
                    "k8s/values.yaml".to_string(),
                )
            },
        },
        Variant {
            name: "yaml-quoted",
            build: |cred| {
                (
                    format!("config:\n  service:\n    api_token: \"{cred}\"\n"),
                    "k8s/values.yaml".to_string(),
                )
            },
        },
        Variant {
            name: "json-field",
            build: |cred| {
                (
                    format!("{{\n  \"service\": {{\n    \"apiToken\": \"{cred}\"\n  }}\n}}\n"),
                    "settings/config.json".to_string(),
                )
            },
        },
        Variant {
            name: "code-assignment",
            build: |cred| {
                (
                    format!("const client = new Client({{ token: \"{cred}\" }});\n"),
                    "src/client.js".to_string(),
                )
            },
        },
        Variant {
            name: "code-call-arg",
            build: |cred| {
                (
                    format!(
                        "    response = requests.get(url, headers={{'Authorization': '{cred}'}})\n"
                    ),
                    "src/fetch.py".to_string(),
                )
            },
        },
        Variant {
            name: "single-quoted",
            build: |cred| (format!("token = '{cred}'\n"), "src/config.rb".to_string()),
        },
        Variant {
            name: "leading-whitespace",
            build: |cred| (format!("\t\t  {cred}\n"), "notes/scratch.txt".to_string()),
        },
        Variant {
            name: "ini-section",
            build: |cred| {
                (
                    format!("[credentials]\napi_token = {cred}\n"),
                    "app.ini".to_string(),
                )
            },
        },
    ]
}

/// Recall floor across the whole sufficient set: the fraction of (detector,
/// variant) pairs that surface the credential. This is the TARGET — keyhog
/// SHOULD recover a credential-sufficient token in every realistic context, so
/// the target ratio is 1.0. It is measured against the real engine and is
/// expected BELOW 1.0 today; the assertion fails until the gap closes.
///
/// The exact ratio is printed so the integrator can watch it climb as detectors
/// widen. We pin the TARGET (>= 0.99), not today's number — that is the whole
/// point of a target-spec test (Law 6): it stays red until the product meets the
/// bar, and is never lowered to match the current value (Law 9).
const TARGET_CONTEXT_RECALL: f64 = 0.99;

#[test]
fn every_sufficient_detector_recovers_credential_in_every_context() {
    let all = load_canonicals();
    let sufficient = sufficient_canonicals(&all);
    assert!(
        sufficient.len() >= 150,
        "expected >= 150 credential-sufficient detectors to context-vary, found {} \
         (the contract corpus or sufficiency partition shrank)",
        sufficient.len()
    );

    let variants = variants();
    let mut total = 0usize;
    let mut surfaced = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for canon in &sufficient {
        for variant in &variants {
            let (body, path) = (variant.build)(&canon.credential);
            // Soundness guard: the credential bytes MUST survive the re-context
            // verbatim, else a miss would be an artifact of the variant, not a
            // detector hole.
            assert!(
                body.contains(&canon.credential),
                "variant {} mangled the credential bytes for {}",
                variant.name,
                canon.detector_id
            );
            let matches = scan(&body, &path);
            total += 1;
            if surfaces(&matches, &canon.credential) {
                surfaced += 1;
            } else {
                failures.push(format!(
                    "{} :: variant `{}` lost the credential (path {path})",
                    canon.detector_id, variant.name
                ));
            }
        }
    }

    let ratio = surfaced as f64 / total.max(1) as f64;
    println!(
        "context-variant recall: {surfaced}/{total} = {ratio:.4} \
         ({} sufficient detectors x {} variants); {} failing pairs",
        sufficient.len(),
        variants.len(),
        failures.len()
    );

    assert!(
        ratio >= TARGET_CONTEXT_RECALL,
        "context-variant recall {surfaced}/{total} = {ratio:.4} is below the target \
         {TARGET_CONTEXT_RECALL:.2}; {} (detector,variant) pairs lose a credential-sufficient \
         token when it is re-contexted into realistic env/yaml/json/code shapes. Each is a \
         narrow-detector recall gap to close (widen the keyword set / quoting tolerance), \
         NOT a test to weaken:\n  - {}",
        failures.len(),
        join_capped(&failures, 60)
    );
}

/// Rotated-key variant: a credential that is structurally the same shape as the
/// canonical one but with a freshly-randomised body (a "rotated" key) must still
/// fire. A detector that only matches the EXACT canonical bytes (an over-fit
/// regex or an accidental literal) is broken — real keys rotate. We rotate only
/// the high-entropy alphanumeric run inside the credential, preserving every
/// structural/prefix character, so the rotated token stays the same detector's
/// shape.
#[test]
fn every_sufficient_detector_fires_on_a_rotated_key() {
    let all = load_canonicals();
    let sufficient = sufficient_canonicals(&all);

    let mut total = 0usize;
    let mut surfaced = 0usize;
    let mut skipped = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for canon in &sufficient {
        let Some(rotated) = rotate_body(&canon.credential) else {
            // No rotatable alphanumeric run of length >= 8 — e.g. a pure
            // structural token. Skip: there is nothing to rotate without
            // changing the shape. (Counted in `skipped`.)
            skipped += 1;
            continue;
        };
        // Plant the rotated token in the SAME minimal context the contract used,
        // so only the body bytes differ from the proven-firing case.
        let body = canon.canonical_text.replace(&canon.credential, &rotated);
        if !body.contains(&rotated) {
            continue; // credential not a literal substring of its own text; skip.
        }
        let matches = scan(&body, "rotated/secret.env");
        total += 1;
        if surfaces(&matches, &rotated) {
            surfaced += 1;
        } else {
            failures.push(format!(
                "{} :: rotated body `{}` lost (canonical fired, rotated did not)",
                canon.detector_id, rotated
            ));
        }
    }

    let ratio = surfaced as f64 / total.max(1) as f64;
    println!(
        "rotated-key recall: {surfaced}/{total} = {ratio:.4}; {} skipped; {} failing detectors",
        skipped,
        failures.len(),
    );
    if !failures.is_empty() {
        println!(
            "remaining rotated-key failures:\n  - {}",
            join_capped(&failures, 20)
        );
    }
    assert!(
        total >= 150,
        "expected >= 150 rotatable credential-sufficient detectors, ran {total}"
    );
    assert!(
        ratio >= TARGET_CONTEXT_RECALL,
        "rotated-key recall {surfaced}/{total} = {ratio:.4} below target {TARGET_CONTEXT_RECALL:.2}; \
         these detectors fail on a rotated key (over-fit to the canonical body — a real key \
         rotation would slip past keyhog):\n  - {}",
        join_capped(&failures, 60)
    );
}

/// Replace the longest alphanumeric run (>= 8 chars) inside `cred` with a body
/// of the SAME length drawn from the same character classes, deterministically
/// (a fixed pseudo-random shift) so the test is reproducible. Returns `None`
/// when there is no rotatable run. Preserves prefixes/suffixes/separators so the
/// detector's structural anchor is untouched.
fn rotate_body(cred: &str) -> Option<String> {
    if is_non_secret_literal_shape(cred) {
        return None;
    }
    if let Some(rotated) = rotate_embedded_checksum_token(cred) {
        return Some(rotated);
    }

    let bytes = cred.as_bytes();
    let mut runs: Vec<(usize, usize)> = Vec::new(); // (start, len)
    let mut run_start = None;
    for (i, b) in bytes.iter().enumerate() {
        let alnum = b.is_ascii_alphanumeric();
        match (alnum, run_start) {
            (true, None) => run_start = Some(i),
            (false, Some(s)) => {
                let len = i - s;
                if len >= 8 {
                    runs.push((s, len));
                }
                run_start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = run_start {
        let len = bytes.len() - s;
        if len >= 8 {
            runs.push((s, len));
        }
    }
    while let Some((mut start, mut len)) = runs.pop() {
        let fixed_prefix_len = no_separator_fixed_prefix_len(cred, start, len);
        if fixed_prefix_len > 0 {
            start += fixed_prefix_len;
            len = len.saturating_sub(fixed_prefix_len);
        }
        if len < 8 {
            continue;
        }
        let mut out = cred.as_bytes().to_vec();
        rotate_alnum_run_preserving_grammar(&mut out[start..start + len]);
        let rotated = String::from_utf8(out).ok()?;
        if rotated != cred {
            return Some(rotated);
        }
    }
    None
}

fn is_non_secret_literal_shape(cred: &str) -> bool {
    cred.contains("NEVER__MATCH__K8S_DISABLED")
        || cred.eq_ignore_ascii_case("INTERNETOFTHINGS.ibmcloud.com")
}

fn no_separator_fixed_prefix_len(cred: &str, start: usize, len: usize) -> usize {
    if start != 0 || len < 12 {
        return 0;
    }
    if cred.starts_with("ABSKQmVkcm9ja0FQSUtleS") {
        return "ABSKQmVkcm9ja0FQSUtleS".len();
    }
    if cred.starts_with("AKCp8") {
        return "AKCp8".len();
    }
    if len >= 12 {
        // No-separator tokens often carry fixed detector prefixes inside the
        // same alphanumeric run (`AKIA...`, `AIza...`). Preserve that structural
        // prefix and rotate the body bytes behind it, matching the test's
        // contract instead of accidentally generating a different token shape.
        return 4;
    }
    0
}

fn rotate_embedded_checksum_token(cred: &str) -> Option<String> {
    if let Some(payload) = cred.strip_prefix("ghp_") {
        if payload.len() == 36 && payload.as_bytes().iter().all(u8::is_ascii_alphanumeric) {
            let mut body = payload[..30].as_bytes().to_vec();
            rotate_alnum_run_preserving_grammar(&mut body);
            let body = String::from_utf8(body).ok()?;
            return Some(format!(
                "ghp_{body}{}",
                crc32_base62_suffix(body.as_bytes(), 6)
            ));
        }
    }

    if let Some(payload) = cred.strip_prefix("npm_") {
        if payload.len() == 36 && payload.as_bytes().iter().all(u8::is_ascii_alphanumeric) {
            let mut body = payload[..30].as_bytes().to_vec();
            rotate_alnum_run_preserving_grammar(&mut body);
            let body = String::from_utf8(body).ok()?;
            return Some(format!(
                "npm_{body}{}",
                crc32_base62_suffix(body.as_bytes(), 6)
            ));
        }
    }

    if let Some(payload) = cred.strip_prefix("github_pat_") {
        let Some((left, right)) = payload.split_once('_') else {
            return None;
        };
        if left.len() == 22
            && right.len() == 59
            && left.as_bytes().iter().all(u8::is_ascii_alphanumeric)
            && right.as_bytes().iter().all(u8::is_ascii_alphanumeric)
        {
            let mut right_body = right[..53].as_bytes().to_vec();
            rotate_alnum_run_preserving_grammar(&mut right_body);
            let right_body = String::from_utf8(right_body).ok()?;
            return Some(format!(
                "github_pat_{left}_{right_body}{}",
                crc32_base62_suffix(right_body.as_bytes(), 6)
            ));
        }
    }

    None
}

fn rotate_alnum_run_preserving_grammar(run: &mut [u8]) {
    let hex_lower = run
        .iter()
        .all(|b| b.is_ascii_digit() || matches!(*b, b'a'..=b'f'));
    let hex_upper = run
        .iter()
        .all(|b| b.is_ascii_digit() || matches!(*b, b'A'..=b'F'));

    for (k, b) in run.iter_mut().enumerate() {
        let shift = ((k * 7 + 3) % 23) as u8;
        if b.is_ascii_digit() {
            *b = b'0' + ((*b - b'0' + shift) % 10);
        } else if hex_lower && matches!(*b, b'a'..=b'f') {
            *b = b'a' + ((*b - b'a' + shift) % 6);
        } else if hex_upper && matches!(*b, b'A'..=b'F') {
            *b = b'A' + ((*b - b'A' + shift) % 6);
        } else if b.is_ascii_uppercase() {
            *b = b'A' + ((*b - b'A' + shift) % 26);
        } else if b.is_ascii_lowercase() {
            *b = b'a' + ((*b - b'a' + shift) % 26);
        }
    }
}

fn crc32_base62_suffix(data: &[u8], width: usize) -> String {
    base62_encode_u32(crc32(data), width)
}

fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut j = 0;
            while j < 8 {
                if crc & 1 != 0 {
                    crc = 0xEDB88320 ^ (crc >> 1);
                } else {
                    crc >>= 1;
                }
                j += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    };

    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc = TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

fn base62_encode_u32(mut value: u32, width: usize) -> String {
    const BASE62_DIGITS: &[u8; 62] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if value == 0 {
        return "0".repeat(width);
    }
    let mut rev = Vec::with_capacity(width.max(6));
    while value > 0 {
        rev.push(BASE62_DIGITS[(value % 62) as usize] as char);
        value /= 62;
    }
    while rev.len() < width {
        rev.push('0');
    }
    rev.reverse();
    rev.into_iter().collect()
}

#[test]
fn rotated_key_generator_preserves_hex_anchors_and_checksums() {
    let activepieces = rotate_body("ap_0123456789abcdef0123456789abcdef").unwrap();
    assert!(activepieces.starts_with("ap_"));
    assert!(
        activepieces["ap_".len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')),
        "{activepieces}"
    );

    let bedrock = rotate_body(
        "ABSKQmVkcm9ja0FQSUtleSYGcEYmTIBr6ysnXHravYjroDShigIQLS0PNHDWjrpil9o3qRwpbzFl0vePrls1cDN8QvUdbqJwNSlzq23meO5ACW3zsuzeDQgwLd92dO3gFCPF",
    )
    .unwrap();
    assert!(bedrock.starts_with("ABSKQmVkcm9ja0FQSUtleS"));

    let ghp = rotate_body("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").unwrap();
    let ghp_payload = ghp.strip_prefix("ghp_").unwrap();
    assert_eq!(
        &ghp_payload[30..],
        crc32_base62_suffix(ghp_payload[..30].as_bytes(), 6)
    );

    let npm = rotate_body("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").unwrap();
    let npm_payload = npm.strip_prefix("npm_").unwrap();
    assert_eq!(
        &npm_payload[30..],
        crc32_base62_suffix(npm_payload[..30].as_bytes(), 6)
    );
}

/// Population floor + visibility: how many detectors are credential-sufficient
/// at all. A detector that is NOT sufficient (needs a companion/keyword anchor)
/// is a separate, weaker class — this prints the partition so the integrator
/// sees how much of the 900-detector set ships a self-firing shape.
#[test]
fn sufficiency_partition_is_reported_and_bounded() {
    let all = load_canonicals();
    let sufficient = sufficient_canonicals(&all);
    let total = all.len();
    let suff = sufficient.len();
    let ratio = suff as f64 / total.max(1) as f64;

    let insufficient: Vec<&Canonical> = all
        .iter()
        .filter(|c| !sufficient.iter().any(|s| s.detector_id == c.detector_id))
        .collect();

    println!(
        "credential-sufficient: {suff}/{total} = {ratio:.4}; \
         {} detectors NEED surrounding context to fire on their own canonical credential",
        insufficient.len()
    );

    // TARGET: a strong secret scanner's detectors should be majority
    // credential-sufficient (distinctive prefix/shape, no anchor needed). The
    // target is 0.75; today it is lower because ~half the corpus is
    // keyword-anchored generic shapes (uuid/hex/base64 bodies) that only fire
    // next to a `key=` token — exactly the CredData generation gap. This pins
    // that as a visible target, not a passing fact.
    assert!(
        ratio >= 0.75,
        "only {suff}/{total} = {ratio:.4} of detectors fire on their canonical credential \
         WITHOUT surrounding context; target is 0.75. The {} context-dependent detectors are \
         the CredData generation gap (keyword-anchored hex/uuid/base64 bodies that never \
         produce a candidate on their own bytes):\n  - {}",
        insufficient.len(),
        join_capped(
            &insufficient
                .iter()
                .map(|c| c.detector_id.clone())
                .collect::<Vec<_>>(),
            80
        )
    );
}
