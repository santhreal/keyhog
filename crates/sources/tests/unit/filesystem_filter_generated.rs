#![cfg(test)]

use keyhog_sources::testing::{normalize_rule_list_for_test, validate_rule_value_for_test};

macro_rules! validate_case {
    ($name:ident, $kind:expr, $value:expr, $ok:expr) => {
        #[test]
        fn $name() {
            let result = validate_rule_value_for_test("test", $value, $kind);
            assert_eq!(
                result.is_ok(),
                $ok,
                "validate_rule_value_for_test({:?}, {:?}, {:?}) -> {:?}",
                $kind,
                $value,
                $ok,
                result
            );
        }
    };
}

macro_rules! validate_cases {
    ($( $name:ident: $kind:expr, $value:expr, $ok:expr; )*) => {
        $(validate_case!($name, $kind, $value, $ok);)*
    };
}

validate_cases! {
    extension_accepts_exe: "extension", "exe", true;
    extension_accepts_png: "extension", "png", true;
    extension_accepts_tar: "extension", "tar", true;
    extension_accepts_gz: "extension", "gz", true;
    extension_accepts_zip: "extension", "zip", true;
    extension_rejects__png: "extension", ".png", false;
    extension_rejects_aslashb: "extension", "a/b", false;
    extension_rejects_abackslashb: "extension", "a\\b", false;
    extension_rejects_png: "extension", "PNG", false;
    extension_rejects_pinlg: "extension", "pi\ng", false;
    extension_rejects_empty: "extension", "", false;
    extension_rejects_spacespace: "extension", "  ", false;
    suffix_accepts_dotmin: "suffix", ".min", true;
    suffix_rejects_bare: "suffix", "min", false;
    infix_accepts_dotted: "infix", ".chunk.", true;
    infix_rejects_unbalanced: "infix", "chunk", false;
    path_segment_accepts_plain: "path_segment", "target", true;
    path_segment_rejects_slash: "path_segment", "a/b", false;
    filename_accepts_plain: "filename", "target", true;
    filename_rejects_slash: "filename", "a/b", false;
}

macro_rules! normalize_case {
    ($name:ident, $values:expr, $expected:expr) => {
        #[test]
        fn $name() {
            let got = normalize_rule_list_for_test(
                "extensions",
                $values.iter().map(|s| s.to_string()).collect(),
                "extension",
            )
            .expect("normalize");
            assert_eq!(
                got,
                $expected.iter().map(|s| s.to_string()).collect::<Vec<_>>()
            );
        }
    };
}

normalize_case!(
    normalize_trims_and_preserves_order,
    [" exe ", "png", "jpg"],
    ["exe", "png", "jpg"]
);

#[test]
fn normalize_rejects_duplicate_extension_after_trimming() {
    let error = normalize_rule_list_for_test(
        "extensions",
        [" exe ", "png", "exe"]
            .iter()
            .map(|value| value.to_string())
            .collect(),
        "extension",
    )
    .expect_err("duplicate normalized extension must fail closed");
    assert!(
        error.contains("duplicate") && error.contains("\"exe\""),
        "duplicate rejection must name the normalized value: {error}"
    );
}
