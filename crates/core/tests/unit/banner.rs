use keyhog_core::report::banner::print_banner;

#[test]
fn banner_renders_brand_credit_and_detector_count() {
    let mut buf = Vec::new();
    print_banner(&mut buf, false, false, 886).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(output.contains("K E Y H O G"));
    assert!(output.contains("santh"));
    assert!(output.contains("886 detectors"));
}

#[test]
fn banner_color_renders_ansi_escapes() {
    let mut buf = Vec::new();
    print_banner(&mut buf, true, false, 886).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(output.contains("\x1b["));
}
