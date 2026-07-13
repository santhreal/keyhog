//! Regression coverage for the scanner's file/path/source SUPPRESSION ALLOWLIST
//! (`crates/scanner/src/suppression/{api,path_filter}.rs`). These gates form the
//! scanner-owned allowlist: a finding is dropped when its *source file* is a
//! secret-scanner's own source, a vendored/minified third-party bundle, an
//! extracted native-binary string dump, or an explicitly-base64 file, and it
//! survives when the file is ordinary first-party source. This is the layer
//! below the CLI's declarative `.keyhogignore` (that lives in `keyhog_cli` and
//! cannot be imported here); this file pins the EXACT boolean the scanner
//! suppression cascade returns for each allowlisted vs non-listed shape.
//!
//! Every case uses a service-anchored detector (`stripe-api-key`) so the
//! Tier-B *shape* gates are bypassed (`bypass_shape_gates = true`): the ONLY
//! remaining suppression reason for the clean high-entropy `CLEAN` value is the
//! path / source / universal gate under test, which makes each positive precise
//! and each negative twin a true isolation of that gate.
//!
//! Facades used (all public, non-`cfg`-gated, integration-test reachable):
//!   * `named_detector_suppressed(cred, path, ctx, source, detector_id) -> bool`
//!   * `is_canonical_service_hex_key(cred) -> bool`
//!   * `shape::looks_like_syntactic_punctuation_marker(cred) -> bool`

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::shape::looks_like_syntactic_punctuation_marker;
use keyhog_scanner::testing::{is_canonical_service_hex_key, named_detector_suppressed};

/// A clean, high-entropy, mixed-case alphanumeric token: not uniform hex, not a
/// UUID, not a base64 blob (no `+/=`), not an email, not a regex/CLI sigil. Under
/// a service-anchored detector it survives the whole cascade, so any suppression
/// observed with it is attributable solely to the path/source gate under test.
const CLEAN: &str = "xR7pQ2mfKz9wTnB4vL6h";

/// Service-anchored detector id (not `generic-*` / `entropy-*` / `private-key`),
/// so `bypass_shape_gates` is set and only the universal / path / source gates
/// can fire on `CLEAN`. Uses the REAL embedded id (`stripe-secret-key`), not the
/// former phantom `stripe-api-key`, so this fixture can't drift from the corpus.
const STRIPE: &str = "stripe-secret-key";

/// The canonical filesystem source type used by the on-disk walker.
const FS: Option<&str> = Some("filesystem");

// ── secret-scanner source file: universal allowlist (fires for ALL detectors) ──

/// A `gitleaks` source tree matches the scanner-source needle: every detector
/// routinely re-matches its own regex definitions there, so the finding is
/// suppressed even though the value is a real-shaped random token.
#[test]
fn gitleaks_scanner_source_path_is_suppressed() {
    assert!(
        named_detector_suppressed(
            CLEAN,
            Some("/repo/scanners/gitleaks/config.toml"),
            CodeContext::Assignment,
            FS,
            STRIPE,
        ),
        "a value inside a gitleaks scanner source tree must be allowlisted (suppressed)"
    );
}

/// Twin needle: a `trufflehog` path is likewise a scanner-source allowlist hit.
#[test]
fn trufflehog_scanner_source_path_is_suppressed() {
    assert!(
        named_detector_suppressed(
            CLEAN,
            Some("/repo/tools/trufflehog/detectors.go"),
            CodeContext::Assignment,
            FS,
            STRIPE,
        ),
        "a value inside a trufflehog scanner source tree must be allowlisted (suppressed)"
    );
}

/// NEGATIVE TWIN: ordinary first-party source (`/repo/src/auth.rs`) is NOT on any
/// allowlist, and `CLEAN` survives every shape gate under a service anchor, so
/// the finding passes. This is the baseline the positives are measured against.
#[test]
fn ordinary_first_party_source_path_is_not_suppressed() {
    assert!(
        !named_detector_suppressed(
            CLEAN,
            Some("/repo/src/auth.rs"),
            CodeContext::Assignment,
            FS,
            STRIPE,
        ),
        "a clean random token in ordinary first-party source must survive (not allowlisted)"
    );
}

// ── vendored / minified third-party bundle: universal allowlist ──

/// A `node_modules/` path is a vendored third-party tree: any secret-like match
/// there is a coincidence in someone else's code, so it is allowlisted.
#[test]
fn node_modules_vendored_path_is_suppressed() {
    assert!(
        named_detector_suppressed(
            CLEAN,
            Some("/repo/node_modules/lodash/index.js"),
            CodeContext::Assignment,
            FS,
            STRIPE,
        ),
        "a value inside node_modules must be allowlisted (suppressed)"
    );
}

/// A `.min.js` suffix marks a minified bundle regardless of directory, the
/// suffix arm of the vendored-path allowlist fires.
#[test]
fn minified_js_suffix_path_is_suppressed() {
    assert!(
        named_detector_suppressed(
            CLEAN,
            Some("/repo/dist/bundle.min.js"),
            CodeContext::Assignment,
            FS,
            STRIPE,
        ),
        "a value inside a *.min.js bundle must be allowlisted (suppressed)"
    );
}

/// NEGATIVE TWIN: a hand-written `.js` file in first-party `src/` is NOT vendored
/// (no `node_modules`, no `.min.js`/`.bundle.js` suffix) (the finding passes).
#[test]
fn first_party_js_source_path_is_not_suppressed() {
    assert!(
        !named_detector_suppressed(
            CLEAN,
            Some("/repo/src/app.js"),
            CodeContext::Assignment,
            FS,
            STRIPE,
        ),
        "a clean token in first-party /src/app.js must survive (not vendored)"
    );
}

// ── extracted native-binary strings: universal allowlist ──

/// The `binary-strings` source type means the bytes were `strings`-extracted from
/// a compiled ELF/Mach-O/PE, prefix detectors generate noise on random rodata,
/// so every named-detector finding on that source is allowlisted.
#[test]
fn binary_strings_source_is_suppressed() {
    assert!(
        named_detector_suppressed(
            CLEAN,
            Some("/repo/build/app"),
            CodeContext::Unknown,
            Some("filesystem:binary-strings"),
            STRIPE,
        ),
        "a value extracted from binary strings must be allowlisted (suppressed)"
    );
}

/// Twin source: `archive-binary` (strings pulled from an archived binary) is on
/// the same allowlist arm.
#[test]
fn archive_binary_source_is_suppressed() {
    assert!(
        named_detector_suppressed(
            CLEAN,
            Some("/repo/build/lib.a"),
            CodeContext::Unknown,
            Some("filesystem/archive-binary"),
            STRIPE,
        ),
        "a value extracted from an archived binary must be allowlisted (suppressed)"
    );
}

// ── explicitly-base64 file: allowlist REQUIRES the exact `filesystem` source ──

/// A `.b64` file scanned in text mode (`source_type == "filesystem"`) holds an
/// encoded blob; raw text-mode alphabet coincidences there are allowlisted.
#[test]
fn raw_base64_file_with_filesystem_source_is_suppressed() {
    assert!(
        named_detector_suppressed(
            CLEAN,
            Some("/repo/data/blob.b64"),
            CodeContext::Assignment,
            Some("filesystem"),
            STRIPE,
        ),
        "a text-mode hit inside a .b64 file must be allowlisted (suppressed)"
    );
}

/// BOUNDARY/ADVERSARIAL: the raw-base64 allowlist is gated on the source being
/// EXACTLY `filesystem`. The same `.b64` path with a derived source
/// (`filesystem/base64`, the decoder's own chunk) is NOT the raw text-mode read,
/// so the raw-base64 arm does NOT fire and `CLEAN` survives. Pins that the gate
/// keys on an exact string, not a substring.
#[test]
fn raw_base64_file_with_derived_source_is_not_suppressed() {
    assert!(
        !named_detector_suppressed(
            CLEAN,
            Some("/repo/data/blob.b64"),
            CodeContext::Assignment,
            Some("filesystem/base64"),
            STRIPE,
        ),
        "the raw-base64 allowlist must require source == \"filesystem\" exactly, \
         so a derived 'filesystem/base64' source must NOT suppress"
    );
}

// ── universal value-shape allowlist arms (Tier-A, fire for ALL detectors) ──

/// An email-shaped value is a public identifier, never a credential, suppressed
/// universally even under a strong service anchor that bypasses Tier-B shape
/// gates. Concrete value from the shopify golden-fixture family.
#[test]
fn email_shaped_value_is_suppressed_under_service_anchor() {
    assert!(
        named_detector_suppressed(
            "bob.norman@mail.example.com",
            Some("/repo/src/config.rs"),
            CodeContext::Assignment,
            FS,
            STRIPE,
        ),
        "an email-shaped value must be allowlisted for every detector (Tier-A universal)"
    );
}

/// Cross-detector proof the email arm is truly universal: the SAME value under a
/// `generic-password` detector (Tier-B gates active) is also suppressed.
#[test]
fn email_shaped_value_is_suppressed_under_generic_password() {
    assert!(
        named_detector_suppressed(
            "bob.norman@mail.example.com",
            Some("/repo/src/config.rs"),
            CodeContext::Assignment,
            FS,
            "generic-password",
        ),
        "the email allowlist arm must fire for generic-password too (universal)"
    );
}

/// A value ending in a regex sigil (`]+`) is a regex-pattern definition captured
/// from another scanner's own source, never a credential (universal allowlist).
#[test]
fn regex_literal_tail_value_is_suppressed() {
    assert!(
        named_detector_suppressed(
            "Xk9mQ2pAbcDef]+",
            Some("/repo/src/patterns.rs"),
            CodeContext::Assignment,
            FS,
            STRIPE,
        ),
        "a value ending in the regex sigil `]+` must be allowlisted (suppressed)"
    );
}

/// A pure CLI-flag / grammar marker (`--api-secret`) is never a credential body
/// and is suppressed universally (Tier-A) even under the service anchor.
#[test]
fn cli_flag_syntactic_marker_is_suppressed() {
    assert!(
        named_detector_suppressed(
            "--api-secret",
            Some("/repo/src/cli.rs"),
            CodeContext::Assignment,
            FS,
            STRIPE,
        ),
        "a `--flag` syntactic marker must be allowlisted (Tier-A universal)"
    );
}

// ── direct helper-predicate truth: the classifiers the allowlist is built on ──

/// `looks_like_syntactic_punctuation_marker` truth table: leading `--flag` and a
/// trailing-colon label suppress; a real prefixed secret and a single-dash token
/// (`xoxb-…` shape) do NOT.
#[test]
fn syntactic_punctuation_marker_truth_table() {
    assert!(
        looks_like_syntactic_punctuation_marker("--api-secret"),
        "leading double-dash CLI flag is a syntactic marker"
    );
    assert!(
        looks_like_syntactic_punctuation_marker("Password:"),
        "an alpha label with a trailing colon is a syntactic marker"
    );
    assert!(
        !looks_like_syntactic_punctuation_marker("sk_live_51HbY2klWn9RtsZ4u"),
        "a real prefixed secret is NOT a syntactic marker"
    );
    assert!(
        !looks_like_syntactic_punctuation_marker("xoxb-1234-abcd"),
        "a single leading dash (xoxb- token shape) is NOT a double-dash marker"
    );
}

/// `is_canonical_service_hex_key` truth table: exactly {32,40,48,64}-char uniform
/// hex qualifies; a 31-char length (boundary just below 32) and a 32-char string
/// carrying a non-hex letter both fail.
#[test]
fn canonical_service_hex_key_truth_table() {
    // 32-char uniform hex (MD5 length).
    assert!(is_canonical_service_hex_key(
        "0123456789abcdef0123456789abcdef"
    ));
    // 40-char uniform hex (SHA1 length).
    assert!(is_canonical_service_hex_key(
        "0123456789abcdef0123456789abcdef01234567"
    ));
    // 31 chars: below the 32 boundary → not canonical.
    assert!(!is_canonical_service_hex_key(
        "0123456789abcdef0123456789abcde"
    ));
    // 32 chars but contains a non-hex letter ('g') → not uniform hex.
    assert!(!is_canonical_service_hex_key(
        "0123456789abcdef0123456789abcdeg"
    ));
}
