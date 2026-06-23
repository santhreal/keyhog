//! Gate startup banner gradient rendering through one ANSI branch owner.

#[test]
fn report_banner_has_one_gradient_writer_owner() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/report/banner.rs");
    let src = std::fs::read_to_string(path).expect("banner source readable");
    let prod = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        prod.contains("fn write_gradient_char"),
        "banner gradient ANSI/true-color branch needs one helper owner"
    );
    assert_eq!(
        prod.matches("super::style::write_rgb_fg").count(),
        1,
        "true-color branch should exist only inside write_gradient_char"
    );
    assert_eq!(
        prod.matches("super::style::write_ansi256_fg").count(),
        1,
        "ANSI-256 branch should exist only inside write_gradient_char"
    );
}
