use super::*;

fn eval(src: &[u8], defined: &[&[u8]]) -> Result<bool, CPreprocessorError> {
    PreprocessorExprParser {
        bytes: src,
        index: 0,
        base_offset: 0,
        defined_macros: defined,
    }
    .parse()
}

#[test]
fn has_attribute_returns_zero_and_consumes_argument() {
    // Real glibc / kernel pattern: gate attribute application on a
    // __has_attribute probe. We don't promise any attribute, so the
    // probe must evaluate to 0 (false) AND fully consume its argument
    // so the directive parses cleanly.
    assert_eq!(eval(b"__has_attribute(visibility)", &[]), Ok(false));
    assert_eq!(eval(b"__has_feature(c_static_assert)", &[]), Ok(false));
    assert_eq!(eval(b"__has_extension(c_alignof)", &[]), Ok(false));
    assert_eq!(eval(b"__has_warning(\"-Wfoo\")", &[]), Ok(false));
}

#[test]
fn has_builtin_uses_frontend_builtin_catalog() {
    assert_eq!(eval(b"__has_builtin(__builtin_expect)", &[]), Ok(true));
    assert_eq!(eval(b"__has_builtin(__builtin_popcount)", &[]), Ok(true));
    assert_eq!(
        eval(b"__has_constexpr_builtin(__builtin_bitreverse32)", &[]),
        Ok(true)
    );
    assert_eq!(
        eval(b"__has_builtin(__builtin_vyre_unknown)", &[]),
        Ok(false)
    );
    assert_eq!(eval(b"__has_builtin(ordinary_identifier)", &[]), Ok(false));
}

#[test]
fn has_attribute_inside_or_chain() {
    // `#if !__has_attribute(x) || defined(FALLBACK)`  -  the OR short-circuit
    // requires the right-hand side to evaluate too.
    assert_eq!(
        eval(
            b"!__has_attribute(visibility) || defined(FALLBACK)",
            &[b"FALLBACK"]
        ),
        Ok(true)
    );
    assert_eq!(
        eval(b"!__has_attribute(visibility) || defined(FALLBACK)", &[]),
        Ok(true)
    );
}

#[test]
fn has_c_attribute_with_scoped_name() {
    // C23 / C++ scoped attribute name: `__has_c_attribute(gnu::packed)`.
    // We must consume `vendor::name` syntactically and still return 0.
    assert_eq!(eval(b"__has_c_attribute(gnu::packed)", &[]), Ok(false));
    assert_eq!(
        eval(b"__has_cpp_attribute(clang::trivial_abi)", &[]),
        Ok(false)
    );
}

#[test]
fn is_identifier_matches_keyword_guard_semantics() {
    assert_eq!(eval(b"__is_identifier(regular_name)", &[]), Ok(true));
    assert_eq!(eval(b"__is_identifier(__int128)", &[]), Ok(false));
    assert_eq!(eval(b"__is_identifier(typeof)", &[]), Ok(false));
    assert_eq!(eval(b"__is_identifier(_Static_assert)", &[]), Ok(false));
}

#[test]
fn has_include_angle_and_quoted() {
    // Real defensive header pattern:
    //   #if __has_include(<threads.h>)
    //     #include <threads.h>
    //   #else
    //     ...
    //   #endif
    assert_eq!(eval(b"__has_include(<threads.h>)", &[]), Ok(false));
    assert_eq!(eval(b"__has_include(\"local.h\")", &[]), Ok(false));
    assert_eq!(eval(b"__has_include_next(<stdio.h>)", &[]), Ok(false));
}

#[test]
fn has_embed_consumes_resource_and_parameters() {
    assert_eq!(eval(b"__has_embed(<asset.bin>)", &[]), Ok(false));
    assert_eq!(eval(b"__has_embed(\"asset.bin\" limit(4))", &[]), Ok(false));
    assert_eq!(
        eval(b"__has_embed(__FILE__ limit (4) vendor::attr(42))", &[]),
        Ok(false)
    );
}

#[test]
fn has_include_rejects_unterminated_header() {
    // An unterminated angle-form header must produce a Fix: diagnostic,
    // not silently swallow the rest of the directive.
    let err = eval(b"__has_include(<threads.h", &[]).expect_err("unterminated header");
    assert!(
        err.to_string().contains("close __has_include header"),
        "unterminated header error: {err}"
    );
}

#[test]
fn has_embed_rejects_unterminated_operands() {
    let err_angle = eval(b"__has_embed(<asset.bin", &[]).expect_err("unterminated angle resource");
    assert!(
        err_angle.to_string().contains("close __has_embed resource"),
        "unterminated embed angle error: {err_angle}"
    );
    let err_paren = eval(b"__has_embed(\"asset.bin\" limit(4)", &[])
        .expect_err("unterminated embed tail");
    assert!(
        err_paren.to_string().contains("close __has_embed operator"),
        "unterminated embed paren error: {err_paren}"
    );
}

#[test]
fn has_attribute_rejects_missing_paren() {
    // `__has_attribute visibility` (no parens) is a malformed directive  -
    // we must reject it rather than silently treating it as 0.
    let err = eval(b"__has_attribute visibility", &[]).expect_err("missing paren");
    assert!(
        err.to_string().contains("parenthesized argument"),
        "missing-paren __has_attribute error: {err}"
    );
}

#[test]
fn has_attribute_does_not_collide_with_macro_lookup() {
    // If the user `#define __has_attribute 1` (some headers do this as a
    // polyfill on non-clang compilers), the operator-form must still
    // parse  -  we don't currently honor the user's override, but we MUST
    // continue to consume the `(name)` payload so the directive is valid.
    assert_eq!(
        eval(b"__has_attribute(visibility)", &[b"__has_attribute"]),
        Ok(false)
    );
}

#[test]
fn modern_integer_literals_consume_digit_separators_and_suffixes() {
    assert_eq!(eval(b"1'024ULL == 1024", &[]), Ok(true));
    assert_eq!(eval(b"0xFF'00z == 65280", &[]), Ok(true));
    assert_eq!(eval(b"0b1010'0101WB == 165", &[]), Ok(true));
    assert_eq!(eval(b"0755'1uL > 0", &[]), Ok(true));
}
