#!/usr/bin/env python3
"""Generate table-driven contract test modules for keyhog-sources.

These are not hand-typed one-at-a-time; each module is a dense contract grid
expanded by macro_rules into individual #[test] functions so `cargo test` counts
and failure names are precise.

Run from repo root:
    python3 scripts/generate_source_contract_tests.py
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "crates/sources/tests/unit"

_IDENT_RE = re.compile(r"[^A-Za-z0-9_]+")

def safe_name(name: str) -> str:
    return _IDENT_RE.sub("_", name).strip("_").lower()

def rust_str(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")


def write(path: pathlib.Path, content: str) -> None:
    path.write_text(content)


def url_redaction_cases() -> str:
    """Sensitive query keys, userinfo boundary, and fragment preservation."""
    sensitive_keys = [
        "sig",
        "signature",
        "X-Amz-Signature",
        "x-amz-credential",
        "x-amz-security-token",
        "access_token",
        "token",
        "id_token",
        "refresh_token",
        "sas",
        "code",
        "api_key",
        "apikey",
        "secret",
        "password",
        "auth",
    ]
    cases = []

    # sensitive key values are masked, original key case preserved
    for key in sensitive_keys:
        lower = key.lower()
        cases.append((safe_name(f"key_{lower}_masks_value"), f"https://example.com/path?{key}=SECRETPART&ok=1", f"https://example.com/path?{key}=***&ok=1"))
        cases.append((safe_name(f"key_{lower}_case_insensitive_masks"), f"https://example.com/path?{key.upper()}=SECRETPART", f"https://example.com/path?{key.upper()}=***"))

    # userinfo redaction
    cases.extend([
        ("userinfo_basic", "https://user:pass@host/path", "https://***@host/path"),
        ("userinfo_token_only", "https://token@host/", "https://***@host/"),
        ("userinfo_with_port", "postgres://u:p@db:5432/x", "postgres://***@db:5432/x"),
        ("userinfo_at_in_password", "https://u:pa@ss@host/", "https://***@host/"),
        ("userinfo_no_password", "https://apikey@host/", "https://***@host/"),
        ("query_email_at_not_userinfo", "https://host/p?email=a@b.com", "https://host/p?email=a@b.com"),
    ])

    # combined userinfo + query
    cases.append(("userinfo_and_query_secret", "https://u:p@host/p?token=abc&x=1", "https://***@host/p?token=***&x=1"))

    # fragment preservation
    cases.append(("query_mask_preserves_fragment", "https://host/p?token=abc#frag", "https://host/p?token=***#frag"))

    # no scheme returns unchanged
    cases.append(("no_scheme_unchanged", "user:pass@host/path", "user:pass@host/path"))
    cases.append(("scheme_without_userinfo_unchanged", "https://host:5432/db", "https://host:5432/db"))

    # non-sensitive query keys unchanged
    cases.append(("non_sensitive_query_unchanged", "https://host/p?foo=bar&page=2", "https://host/p?foo=bar&page=2"))

    # roadmap: keys that should be masked but currently are not
    roadmap_keys = ["api_token", "bearer", "client_secret", "session_token", "oauth_token"]
    roadmap = []
    for key in roadmap_keys:
        name = f"roadmap_{key}_should_be_masked"
        url = f"https://example.com/?{key}=secretvalue"
        expected = f"https://example.com/?{key}=***"
        roadmap.append((name, url, expected))

    return cases, roadmap


def filter_cases() -> str:
    cases = []
    # extension: valid
    for ext in ["exe", "png", "tar", "gz", "zip"]:
        cases.append((safe_name(f"extension_accepts_{ext}"), "extension", ext, True))
    # extension: invalid
    for bad in [".png", "a/b", "a\\b", "PNG", "pi\ng", "", "  "]:
        safe = bad.replace("\\", "backslash").replace("/", "slash").replace("\n", "nl").replace(" ", "space")
        cases.append((safe_name(f"extension_rejects_{safe or 'empty'}"), "extension", bad, False))
    # suffix/infix
    cases.append(("suffix_accepts_dotmin", "suffix", ".min", True))
    cases.append(("suffix_rejects_bare", "suffix", "min", False))
    cases.append(("infix_accepts_dotted", "infix", ".chunk.", True))
    cases.append(("infix_rejects_unbalanced", "infix", "chunk", False))
    # path/filename
    for kind in ["path_segment", "filename"]:
        cases.append((safe_name(f"{kind}_accepts_plain"), kind, "target", True))
        cases.append((safe_name(f"{kind}_rejects_slash"), kind, "a/b", False))
    return cases


def magic_cases() -> str:
    cases = []
    # PDF
    cases.append(("pdf_header", "has_unambiguous_binary_prefix_for_test", [0x25, 0x50, 0x44, 0x46], True))
    cases.append(("pdf_negative", "has_unambiguous_binary_prefix_for_test", [0x00, 0x00, 0x00], False))
    # BMP
    cases.append(("bmp_header", "has_bmp_header_for_test", [0x42, 0x4D, 0x00, 0x00], True))
    cases.append(("bmp_negative", "has_bmp_header_for_test", [0x00, 0x00, 0x00, 0x00], False))
    # PE
    cases.append(("pe_header", "has_pe_header_for_test", [0x4D, 0x5A], True))
    cases.append(("pe_negative", "has_pe_header_for_test", [0x00, 0x00], False))
    # ZIP
    cases.append(("zip_header", "starts_with_zip_container_prefix_for_test", [0x50, 0x4B, 0x03, 0x04], True))
    cases.append(("zip_negative", "starts_with_zip_container_prefix_for_test", [0x00, 0x00, 0x00, 0x00], False))
    # GZIP
    cases.append(("gzip_header", "starts_with_gzip_for_test", [0x1F, 0x8B], True))
    cases.append(("gzip_negative", "starts_with_gzip_for_test", [0x00, 0x00], False))
    # ZSTD
    cases.append(("zstd_header", "starts_with_zstd_frame_for_test", [0x28, 0xB5, 0x2F, 0xFD], True))
    cases.append(("zstd_negative", "starts_with_zstd_frame_for_test", [0x00, 0x00, 0x00, 0x00], False))
    # WASM
    cases.append(("wasm_header", "starts_with_wasm_module_for_test", [0x00, 0x61, 0x73, 0x6D], True))
    cases.append(("wasm_negative", "starts_with_wasm_module_for_test", [0x00, 0x00, 0x00, 0x00], False))
    return cases


def ssrf_cases() -> str:
    public = [
        "http://example.com/",
        "https://github.com/santhsecurity/keyhog",
        "http://1.1.1.1/",
        "https://1.1.1.1:443/",
    ]
    private = [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://169.254.1.1/",
        "http://100.64.0.1/",
        "http://0.0.0.0/",
        "http://255.255.255.255/",
        "http://[::1]/",
        "http://[fd00::1]/",
        "http://[fe80::1]/",
        "http://localhost/",
        "http://foo.local/",
        "http://foo.internal/",
        "http://foo.localdomain/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://017700000001/",
        "http://127.1/",
        "http://0x7f.1/",
        "http://file:///etc/passwd",
        "ftp://example.com/",
        "not-a-url",
    ]
    ip_cases = [
        ("127.0.0.1", True),
        ("10.0.0.1", True),
        ("172.16.0.1", True),
        ("192.168.0.1", True),
        ("1.1.1.1", False),
        ("8.8.8.8", False),
        ("::1", True),
        ("fd00::1", True),
        ("2001:4860:4860::8888", False),
    ]
    return public, private, ip_cases


def emit_url_redaction():
    cases, roadmap = url_redaction_cases()
    lines = [
        "#![cfg(feature = \"web\")]",
        "",
        "use keyhog_sources::testing::{SourceTestApi, TestApi};",
        "",
        "macro_rules! redact_case {",
        "    ($name:ident, $input:expr, $expected:expr) => {",
        "        #[test]",
        "        fn $name() {",
        "            assert_eq!(TestApi.redact_url($input), $expected);",
        "        }",
        "    };",
        "}",
        "",
        "macro_rules! redact_cases {",
        "    ($( $name:ident: $input:expr => $expected:expr; )*) => {",
        "        $(redact_case!($name, $input, $expected);)*",
        "    };",
        "}",
        "",
        "redact_cases! {",
    ]
    for name, inp, exp in cases:
        lines.append(f'    {name}: "{rust_str(inp)}" => "{rust_str(exp)}";')
    lines.append("}")

    if roadmap:
        lines.extend([
            "",
            "// Roadmap tests: these keys SHOULD be treated as sensitive but are not yet.",
            "// They are ignored so the suite stays green; enable each as the redaction list expands.",
            "#[cfg(test)]",
            "mod roadmap {",
            "    use keyhog_sources::testing::{SourceTestApi, TestApi};",
            "",
            "    macro_rules! roadmap_redact_case {",
            "        ($name:ident, $input:expr, $expected:expr) => {",
            "            #[test]",
            "            #[ignore = \"roadmap: add this query key to SENSITIVE_QUERY_KEYS\"]",
            "            fn $name() {",
            "                assert_eq!(TestApi.redact_url($input), $expected);",
            "            }",
            "        };",
            "    }",
            "",
            "    macro_rules! roadmap_redact_cases {",
            "        ($( $name:ident: $input:expr => $expected:expr; )*) => {",
            "            $(roadmap_redact_case!($name, $input, $expected);)*",
            "        };",
            "    }",
            "",
            "    roadmap_redact_cases! {",
        ])
        for name, inp, exp in roadmap:
            lines.append(f'        {name}: "{rust_str(inp)}" => "{rust_str(exp)}";')
        lines.extend(["    }", "}"])

    write(OUT / "url_redaction_generated.rs", "\n".join(lines) + "\n")


def emit_filter():
    cases = filter_cases()
    validate_lines = [
        "#![cfg(test)]",
        "",
        "use keyhog_sources::testing::{normalize_rule_list_for_test, validate_rule_value_for_test};",
        "",
        "macro_rules! validate_case {",
        "    ($name:ident, $kind:expr, $value:expr, $ok:expr) => {",
        "        #[test]",
        "        fn $name() {",
        "            let result = validate_rule_value_for_test(\"test\", $value, $kind);",
        "            assert_eq!(result.is_ok(), $ok, \"validate_rule_value_for_test({:?}, {:?}, {:?}) -> {:?}\", $kind, $value, $ok, result);",
        "        }",
        "    };",
        "}",
        "",
        "macro_rules! validate_cases {",
        "    ($( $name:ident: $kind:expr, $value:expr, $ok:expr; )*) => {",
        "        $(validate_case!($name, $kind, $value, $ok);)*",
        "    };",
        "}",
        "",
        "validate_cases! {",
    ]
    for name, kind, value, ok in cases:
        if not isinstance(value, list):
            validate_lines.append(f'    {name}: "{rust_str(kind)}", "{rust_str(value)}", {str(ok).lower()};')
    validate_lines.append("}")

    normalize_lines = [
        "",
        "macro_rules! normalize_case {",
        "    ($name:ident, $values:expr, $expected:expr) => {",
        "        #[test]",
        "        fn $name() {",
        "            let got = normalize_rule_list_for_test(\"extensions\", $values.iter().map(|s| s.to_string()).collect(), \"extension\").expect(\"normalize\");",
        "            assert_eq!(got, $expected.iter().map(|s| s.to_string()).collect::<Vec<_>>());",
        "        }",
        "    };",
        "}",
        "",
        "normalize_case!(normalize_trims_and_dedupes, [\" exe \", \"png\", \"jpg\"], [\"exe\", \"png\", \"jpg\"]);",
    ]
    write(OUT / "filesystem_filter_generated.rs", "\n".join(validate_lines + normalize_lines) + "\n")


def emit_magic():
    cases = magic_cases()
    lines = [
        "#![cfg(test)]",
        "",
        "use keyhog_sources::testing::{",
        "    has_bmp_header_for_test, has_bzip2_header_for_test, has_pe_header_for_test,",
        "    has_unambiguous_binary_prefix_for_test,",
        "    starts_with_gzip_for_test, starts_with_pdf_for_test,",
        "    starts_with_python_pickle_protocol2_for_test,",
        "    starts_with_wasm_module_for_test, starts_with_zip_container_prefix_for_test,",
        "    starts_with_zstd_frame_for_test,",
        "};",
        "",
        "macro_rules! magic_case {",
        "    ($name:ident, $fn:ident, $bytes:expr, $expected:expr) => {",
        "        #[test]",
        "        fn $name() {",
        "            assert_eq!($fn($bytes), $expected);",
        "        }",
        "    };",
        "}",
        "",
        "magic_case!(pdf_positive, starts_with_pdf_for_test, b\"%PDF-1.4\", true);",
        "magic_case!(pdf_unambiguous, has_unambiguous_binary_prefix_for_test, b\"%PDF-1.4\", true);",
        "magic_case!(pdf_negative, starts_with_pdf_for_test, b\"hello world\", false);",
        "magic_case!(bmp_positive, has_bmp_header_for_test, &[0x42, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00], true);",
        "magic_case!(bmp_negative_too_short, has_bmp_header_for_test, &[0x42, 0x4D], false);",
        "magic_case!(bmp_negative_bad_zeros, has_bmp_header_for_test, &[0x42, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00], false);",
        "magic_case!(pe_positive, has_pe_header_for_test, &[0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00], true);",
        "magic_case!(pe_negative_too_short, has_pe_header_for_test, &[0x4D, 0x5A], false);",
        "magic_case!(zip_local_positive, starts_with_zip_container_prefix_for_test, b\"PK\\x03\\x04file\", true);",
        "magic_case!(zip_eocd_positive, starts_with_zip_container_prefix_for_test, b\"PK\\x05\\x06empty\", true);",
        "magic_case!(zip_negative, starts_with_zip_container_prefix_for_test, b\"PK_is_plain_text\", false);",
        "magic_case!(gzip_positive, starts_with_gzip_for_test, &[0x1F, 0x8B, 0x08], true);",
        "magic_case!(gzip_negative, starts_with_gzip_for_test, &[0x00, 0x00], false);",
        "magic_case!(zstd_positive, starts_with_zstd_frame_for_test, &[0x28, 0xB5, 0x2F, 0xFD], true);",
        "magic_case!(zstd_negative, starts_with_zstd_frame_for_test, &[0x00, 0x00, 0x00, 0x00], false);",
        "magic_case!(wasm_positive, starts_with_wasm_module_for_test, &[0x00, 0x61, 0x73, 0x6D], true);",
        "magic_case!(wasm_negative, starts_with_wasm_module_for_test, &[0x00, 0x00, 0x00, 0x00], false);",
        "magic_case!(bzip2_positive, has_bzip2_header_for_test, b\"BZh9\", true);",
        "magic_case!(bzip2_negative_bad_digit, has_bzip2_header_for_test, b\"BZh0\", false);",
        "magic_case!(pickle_positive, starts_with_python_pickle_protocol2_for_test, &[0x80, 0x02], true);",
        "magic_case!(pickle_negative, starts_with_python_pickle_protocol2_for_test, &[0x00, 0x00], false);",
        "magic_case!(unambiguous_png, has_unambiguous_binary_prefix_for_test, b\"\\x89PNG\\r\\n\\x1a\\n\", true);",
        "magic_case!(unambiguous_elf, has_unambiguous_binary_prefix_for_test, b\"\\x7fELF\", true);",
        "magic_case!(unambiguous_plain_text, has_unambiguous_binary_prefix_for_test, b\"hello world\", false);",
    ]
    write(OUT / "magic_generated.rs", "\n".join(lines) + "\n")


def emit_ssrf():
    public, private, ip_cases = ssrf_cases()
    lines = [
        "#![cfg(feature = \"web\")]",
        "",
        "use keyhog_sources::testing::{SourceTestApi, TestApi};",
        "use std::net::IpAddr;",
        "",
        "macro_rules! ssrf_url_case {",
        "    ($name:ident, $url:expr, $expected_private:expr) => {",
        "        #[test]",
        "        fn $name() {",
        "            assert_eq!(TestApi.is_disallowed_web_host($url), $expected_private, \"URL: {:?}\", $url);",
        "        }",
        "    };",
        "}",
        "",
        "macro_rules! ssrf_url_cases {",
        "    ($( $name:ident: $url:expr => $expected:expr; )*) => {",
        "        $(ssrf_url_case!($name, $url, $expected);)*",
        "    };",
        "}",
        "",
        "ssrf_url_cases! {",
    ]
    idx = 0
    for url in public:
        lines.append(f'    public_{idx}: "{rust_str(url)}" => false;')
        idx += 1
    idx = 0
    for url in private:
        lines.append(f'    private_{idx}: "{rust_str(url)}" => true;')
        idx += 1
    lines.append("}")

    lines.extend([
        "",
        "macro_rules! ssrf_ip_case {",
        "    ($name:ident, $ip:expr, $expected:expr) => {",
        "        #[test]",
        "        fn $name() {",
        "            let ip: IpAddr = $ip.parse().expect(\"valid IP\");",
        "            assert_eq!(TestApi.is_disallowed_ip(ip), $expected);",
        "        }",
        "    };",
        "}",
        "",
        "macro_rules! ssrf_ip_cases {",
        "    ($( $name:ident: $ip:expr => $expected:expr; )*) => {",
        "        $(ssrf_ip_case!($name, $ip, $expected);)*",
        "    };",
        "}",
        "",
        "ssrf_ip_cases! {",
    ])
    idx = 0
    for ip, expected in ip_cases:
        lines.append(f'    ip_{idx}: "{ip}" => {str(expected).lower()};')
        idx += 1
    lines.append("}")

    write(OUT / "ssrf_generated.rs", "\n".join(lines) + "\n")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    emit_url_redaction()
    emit_filter()
    emit_magic()
    emit_ssrf()
    print("generated:", OUT / "url_redaction_generated.rs", OUT / "filesystem_filter_generated.rs", OUT / "magic_generated.rs", OUT / "ssrf_generated.rs")


if __name__ == "__main__":
    main()
