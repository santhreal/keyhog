//! Panic-safety / bounded-output property sweep for the template interpolation
//! surface (6318 slice 3). The fixed-value suites
//! (`new_verifier_interpolate`, `adversarial/interpolate_no_second_order_expansion`,
//! `unit/interpolate_oob_control_chars_in_host`) pin specific templates; this
//! sweep throws a DENSE stream of adversarial structural templates, unbalanced
//! `{{`/`}}`, nested `{{companion.` runs, multibyte (`é`, `🔑`) and control bytes
//! astride token boundaries, `scheme://` fragments, at both the URL and the
//! header/body interpolation contexts, with companion maps whose VALUES also
//! carry `{{…}}` tokens (the second-order-expansion vector). The invariants:
//!   1. No input panics (a slice on a non-char boundary, an OOB index into a
//!      multibyte name, or an unterminated `{{` must never crash).
//!   2. Output is BOUNDED, the single left-to-right pass caps at
//!      `MAX_TEMPLATE_TOKENS` replacements, so a substituted value can never be
//!      re-scanned into unbounded growth.
//! Uses the same hand-rolled LCG as the SSRF sweep (no `proptest` dev-dep here)
//! so any failing template is reproducible from its seed.

use crate::common::lcg;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

/// Structural fragments chosen to stress the parser's boundary handling: partial
/// and complete tokens, multibyte chars straddling `{{`/`}}`, control bytes, and
/// `scheme://` punctuation. Concatenating any subset stays valid UTF-8.
const FRAGMENTS: &[&str] = &[
    "{{",
    "}}",
    "{{match}}",
    "{{companion.",
    "{{companion.a}}",
    "{{interactsh}}",
    "{{interactsh.url}}",
    "{{interactsh.host}}",
    "companion.",
    "match",
    "interactsh",
    ".",
    "a",
    "b",
    "x",
    "é",
    "🔑",
    "\n",
    "\r",
    "\0",
    "\t",
    "://",
    "http",
    "-",
    "/",
    ":",
    "0",
    " ",
    "{",
    "}",
];

/// Build a bounded pseudo-random template from up to 18 fragments (kept small so
/// any blowup on tiny input is unmistakable, and 100k iterations stay fast).
fn build_string(state: &mut u32, max_fragments: usize) -> String {
    let n = (lcg(state) as usize) % (max_fragments + 1);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(FRAGMENTS[(lcg(state) as usize) % FRAGMENTS.len()]);
    }
    s
}

/// 0–3 companion entries with short names; VALUES may themselves contain `{{…}}`
/// tokens, so this exercises the no-second-order-expansion guard under fuzz.
fn build_companions(state: &mut u32) -> HashMap<String, String> {
    let names = ["a", "b", "s", "secret"];
    let count = (lcg(state) as usize) % 4;
    let mut map = HashMap::new();
    for _ in 0..count {
        let name = names[(lcg(state) as usize) % names.len()].to_string();
        let value = build_string(state, 4);
        map.insert(name, value);
    }
    map
}

/// A hostile input: structural fragments PLUS several arbitrary Unicode scalars
/// drawn across the entire valid range (`char::from_u32` skips surrogates), so
/// the sanitizers are exercised on astral-plane characters, exotic punctuation,
/// and every control class (not just the small fragment alphabet).
fn build_hostile_input(state: &mut u32) -> String {
    let mut s = build_string(state, 16);
    let extra = (lcg(state) as usize) % 6;
    for _ in 0..extra {
        let cp = lcg(state) % 0x11_0000;
        if let Some(c) = char::from_u32(cp) {
            s.push(c);
        }
    }
    s
}

const SAMPLES: usize = 100_000;

/// 6350: the two sanitizers must CLOSE their output charset on ANY input. A byte
/// escaping `sanitize_oob_value`'s `[a-z0-9.-]` set is a structural-punctuation
/// smuggle into a URL/header/body (DNS-exfil vector); a control byte escaping
/// `sanitize_raw_value` is a CR/LF/NUL header-injection vector.
#[test]
fn oob_and_raw_sanitizers_enforce_their_charsets_on_any_input() {
    let mut state = 0xF00D_5EED;
    for _ in 0..SAMPLES {
        let input = build_hostile_input(&mut state);

        // OOB → strictly the DNS-hostname charset (uppercase already folded down).
        let oob = TestApi.sanitize_oob_value(&input);
        assert!(
            oob.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'),
            "sanitize_oob_value leaked an out-of-charset char: {oob:?} from {input:?}",
        );

        // Raw → no ASCII/C1 control survives except tab (0x09).
        let raw = TestApi.sanitize_raw_value(&input);
        assert!(
            raw.chars().all(|c| {
                let cp = c as u32;
                c == '\t' || (cp >= 0x20 && cp != 0x7F && !(0x80..=0x9F).contains(&cp))
            }),
            "sanitize_raw_value leaked a control char: {raw:?} from {input:?}",
        );
    }
}

#[test]
fn interpolation_never_panics_and_output_is_bounded() {
    let mut state = 0xBADD_CAFE;
    for _ in 0..SAMPLES {
        let template = build_string(&mut state, 18);
        let credential = build_string(&mut state, 6);
        let companions = build_companions(&mut state);

        // Both contexts, plus the OOB-injected companion map, must survive.
        let oob =
            TestApi.companions_with_oob(&companions, "h.oob.test", "http://h.oob.test", "id0");
        for comps in [&companions, &oob] {
            let http = TestApi.interpolate_http_value(&template, &credential, comps);
            let url = TestApi.interpolate_url(&template, &credential, comps);

            // Bounded: on inputs this small (template ≤ ~90 bytes, values ≤ ~40),
            // a correct single pass yields a few KB at most. A megabyte-scale
            // output would mean a substituted value was re-expanded, the exact
            // failure the single-pass design forbids.
            assert!(
                http.len() < 1_000_000,
                "interpolate_http_value blew up ({} bytes) on template {template:?}",
                http.len(),
            );
            assert!(
                url.len() < 1_000_000,
                "interpolate_url blew up ({} bytes) on template {template:?}",
                url.len(),
            );
        }
    }
}

/// URL-context CORRECTNESS, not merely no-panic/bounded: an embedded `{{match}}`
/// reduces the credential to the percent-encoded `[A-Za-z0-9%]` charset, so a
/// hostile scanned value can NEVER contribute a structural URL byte (`/ : @ ? #
/// &`, space, CR, LF) that would restructure the outbound request, a second
/// host, an extra path segment, a smuggled query, or a CRLF header split. The
/// sweep above proves the pass terminates; this proves the substitution is inert
/// in URL position. (`interpolate_url` percent-encodes NON_ALPHANUMERIC, so even
/// `.`/`-`/`_` are encoded, the surviving alphabet is exactly letters, digits,
/// and the `%` of an escape.)
#[test]
fn url_context_reduces_the_credential_to_the_percent_encoded_charset() {
    // A literal prefix free of `{{`, so everything the scan emits after it is the
    // credential's own (already percent-encoded) contribution.
    const PREFIX: &str = "https://host.example/p/";
    const TEMPLATE: &str = "https://host.example/p/{{match}}";
    let mut state = 0x5EA1_C0DE;
    for _ in 0..SAMPLES {
        let credential = build_hostile_input(&mut state);
        let out = TestApi.interpolate_url(TEMPLATE, &credential, &HashMap::new());
        assert!(
            out.starts_with(PREFIX),
            "URL template prefix was mutated: {out:?} (credential {credential:?})",
        );
        let encoded = &out[PREFIX.len()..];
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '%'),
            "URL-interpolated credential {credential:?} contributed a structural char: {encoded:?}",
        );
    }
}

/// HTTP header/body-context CORRECTNESS: an embedded `{{match}}` is
/// control-stripped, so a hostile credential can never inject a CR/LF (header
/// split / request smuggling) or any other control byte into the outbound
/// request. The adversarial suite pins the single `a\r\nb` vector; this sweeps
/// every hostile shape through the FULL interpolation path (not just the bare
/// `sanitize_raw_value` the charset test calls directly).
#[test]
fn http_value_context_strips_control_bytes_from_the_credential() {
    const TEMPLATE: &str = "X-Auth: {{match}} trailer";
    let mut state = 0xC0FF_EE11;
    for _ in 0..SAMPLES {
        let credential = build_hostile_input(&mut state);
        let out = TestApi.interpolate_http_value(TEMPLATE, &credential, &HashMap::new());
        assert!(
            out.chars().all(|c| {
                let cp = c as u32;
                c == '\t' || (cp >= 0x20 && cp != 0x7F && !(0x80..=0x9F).contains(&cp))
            }),
            "http-value interpolation leaked a control byte from credential {credential:?}: {out:?}",
        );
    }
}
