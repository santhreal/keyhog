//! Package-registry token recall + precision lock: npm, PyPI, RubyGems. These
//! leak constantly via `.npmrc`/`.pypirc`/CI logs and `gem` credentials, and had
//! no dedicated recall test.
//!
//! npm and PyPI are CHECKSUM/STRUCTURE validated (the precision feature that the
//! [[checksum-wiring-invalidates-fabricated-token-fixtures]] memory warns about):
//!   * npm  = `npm_` + 30-char entropy + 6-char base62 CRC32 of the entropy.
//!   * PyPI = `pypi-` + base64 payload that must strictly decode to >= 32 bytes.
//! So a recall test MUST build VALID fixtures (this file replicates npm's CRC32
//! and uses a length-multiple-of-4 PyPI payload so it decodes canonically), and
//! an INVALID-checksum token is a precision NEGATIVE (correctly suppressed).
//! RubyGems (`rubygems_` + 48 hex) has no checksum, so a plain hex fixture works.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x70AC_1259);
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            charset[((s >> 33) % m) as usize] as char
        })
        .collect()
}
fn alnum(n: usize, seed: usize) -> String {
    gen(
        n,
        seed,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    )
}
fn hex(n: usize, seed: usize) -> String {
    gen(n, seed, b"0123456789abcdef")
}

/// Standard CRC32 (poly 0xEDB88320), identical to the scanner's checksum owner.
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                0xEDB8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc = table[((crc ^ (byte as u32)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// base62 (`0-9A-Za-z`) of `value`, left-padded with '0' to 6 chars.
fn base62_6(mut value: u32) -> String {
    const D: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if value == 0 {
        return "000000".to_string();
    }
    let mut rev = Vec::new();
    while value > 0 {
        rev.push(D[(value % 62) as usize]);
        value /= 62;
    }
    while rev.len() < 6 {
        rev.push(b'0');
    }
    rev.reverse();
    String::from_utf8(rev).expect("base62 digits are ascii")
}

/// A valid modern npm token: `npm_` + 30 entropy + 6-char base62 CRC32.
fn npm_token(seed: usize) -> String {
    let entropy = alnum(30, seed);
    format!("npm_{}{}", entropy, base62_6(crc32(entropy.as_bytes())))
}

/// A valid PyPI token: `pypi-` + alphanumeric payload of length `n` (use a
/// multiple of 4 so it decodes canonically to n*3/4 >= 32 bytes).
fn pypi_token(n: usize, seed: usize) -> String {
    format!("pypi-{}", alnum(n, seed))
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "registry.conf");
    s.clear_fragment_cache();
    s.scan(&chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.as_str().to_string()))
        .collect()
}
fn surfaces_under(text: &str, detector: &str, needle: &str) -> bool {
    scan(text)
        .iter()
        .any(|(id, cred)| id == detector && cred.contains(needle))
}
fn surfaces_any(text: &str, needle: &str) -> bool {
    scan(text).iter().any(|(_, cred)| cred.contains(needle))
}
fn fires(text: &str, detector: &str) -> bool {
    scan(text).iter().any(|(id, _)| id == detector)
}

// ── npm (valid CRC32 surfaces; invalid CRC32 suppressed) ──────────────────────

#[test]
fn npm_valid_checksum_token_bare_surfaces() {
    let t = npm_token(1);
    assert!(
        surfaces_under(&t, "npm-access-token", &t),
        "valid-checksum npm token must surface"
    );
}

#[test]
fn npm_valid_token_in_npmrc_authtoken_surfaces() {
    let t = npm_token(2);
    let text = format!("//registry.npmjs.org/:_authToken={t}\n");
    assert!(
        surfaces_under(&text, "npm-access-token", &t),
        "npm token in .npmrc must surface"
    );
}

#[test]
fn npm_valid_token_env_anchor_surfaces() {
    let t = npm_token(3);
    assert!(surfaces_under(
        &format!("NPM_TOKEN={t}"),
        "npm-access-token",
        &t
    ));
}

#[test]
fn npm_invalid_checksum_token_does_not_fire() {
    // A `npm_` + 36-alnum token whose trailing 6 chars are not the base62 CRC32 of
    // the first 30 is fabricated/corrupt (the checksum gate must reject it).
    let bad = format!("npm_{}", alnum(36, 4));
    // Guard: make sure the random fixture really is checksum-invalid (not a fluke).
    let entropy = &bad[4..34];
    assert_ne!(
        base62_6(crc32(entropy.as_bytes())),
        bad[34..],
        "fixture must be checksum-invalid"
    );
    assert!(
        !fires(&bad, "npm-access-token"),
        "invalid-checksum npm token must be suppressed"
    );
}

#[test]
fn npm_token_35_chars_does_not_fire() {
    // 35 chars is below the 36-char body; the regex never matches.
    let t = format!("npm_{}", alnum(35, 5));
    assert!(!fires(&t, "npm-access-token"));
}

// ── PyPI (canonical base64 payload surfaces; non-decodable suppressed) ─────────

#[test]
fn pypi_valid_token_bare_surfaces() {
    let t = pypi_token(112, 6); // 112 % 4 == 0 -> decodes to 84 bytes
    assert!(
        surfaces_under(&t, "pypi-api-token", &t),
        "valid pypi- token must surface"
    );
}

#[test]
fn pypi_valid_token_in_pypirc_password_surfaces() {
    let t = pypi_token(112, 7);
    let text = format!("[pypi]\nusername = __token__\npassword = {t}\n");
    assert!(
        surfaces_under(&text, "pypi-api-token", &t),
        "pypi token in .pypirc must surface"
    );
}

#[test]
fn pypi_token_min_length_100_surfaces() {
    let t = pypi_token(100, 8); // 100 (regex min, % 4 == 0)
    assert!(surfaces_under(&t, "pypi-api-token", &t));
}

#[test]
fn pypi_token_max_length_128_surfaces() {
    let t = pypi_token(128, 9); // 128 (regex max, % 4 == 0)
    assert!(surfaces_under(&t, "pypi-api-token", &t));
}

#[test]
fn pypi_payload_below_min_length_does_not_fire() {
    let t = pypi_token(80, 10); // 80 < 100 regex minimum
    assert!(!fires(&t, "pypi-api-token"));
}

#[test]
fn pypi_non_decodable_length_does_not_fire() {
    // 101 % 4 == 1 is an invalid base64 (no-pad) length, so the structural decode
    // fails and the token is suppressed even though the regex shape matches.
    let t = pypi_token(101, 11);
    assert!(
        !fires(&t, "pypi-api-token"),
        "a non-decodable pypi payload must be suppressed"
    );
}

// ── RubyGems (no checksum; plain 48-hex) ──────────────────────────────────────

#[test]
fn rubygems_token_bare_surfaces() {
    let t = format!("rubygems_{}", hex(48, 12));
    assert!(
        surfaces_under(&t, "rubygems-api-key", &t),
        "bare rubygems_ token must surface"
    );
}

#[test]
fn rubygems_token_anchored_surfaces() {
    let t = format!("rubygems_{}", hex(48, 13));
    assert!(surfaces_under(
        &format!("RUBYGEMS_API_KEY={t}"),
        "rubygems-api-key",
        &t
    ));
}

#[test]
fn rubygems_bare_hex_under_anchor_surfaces() {
    let h = hex(48, 14);
    assert!(surfaces_under(
        &format!("RUBYGEMS_API_KEY={h}"),
        "rubygems-api-key",
        &h
    ));
}

#[test]
fn rubygems_token_in_gem_credentials_yaml_surfaces() {
    let t = format!("rubygems_{}", hex(48, 15));
    assert!(surfaces_any(&format!(":rubygems_api_key: {t}\n"), &t));
}

#[test]
fn rubygems_47_hex_does_not_fire() {
    let t = format!("rubygems_{}", hex(47, 16));
    assert!(!fires(&t, "rubygems-api-key"));
}

#[test]
fn rubygems_non_hex_value_does_not_fire() {
    let bad = format!("rubygems_z{}", hex(47, 17));
    assert!(!fires(&bad, "rubygems-api-key"));
}

#[test]
fn npm_valid_token_in_yaml_surfaces() {
    // A valid-checksum npm token also surfaces from a structured YAML value.
    let t = npm_token(18);
    assert!(
        surfaces_any(&format!("npm:\n  token: {t}\n"), &t),
        "npm token in YAML must surface"
    );
}

// ── cross-registry co-surfacing ───────────────────────────────────────────────

#[test]
fn npm_and_pypi_tokens_cosurface() {
    let n = npm_token(19);
    let p = pypi_token(112, 20);
    let text = format!("NPM_TOKEN={n}\nTWINE_PASSWORD={p}\n");
    assert!(
        surfaces_under(&text, "npm-access-token", &n),
        "npm surfaces alongside pypi"
    );
    assert!(
        surfaces_under(&text, "pypi-api-token", &p),
        "pypi surfaces alongside npm"
    );
}

#[test]
fn all_three_registry_tokens_cosurface() {
    let n = npm_token(21);
    let p = pypi_token(112, 22);
    let r = format!("rubygems_{}", hex(48, 23));
    let text = format!("npm: {n}\npypi: {p}\nrubygems: {r}\n");
    assert!(surfaces_under(&text, "npm-access-token", &n));
    assert!(surfaces_under(&text, "pypi-api-token", &p));
    assert!(surfaces_under(&text, "rubygems-api-key", &r));
}
