use keyhog::testing::{CliTestApi as _, API};

#[test]
fn bytes_under_kib_format_in_bytes() {
    assert_eq!(API.format_bytes(0), "0 B");
    assert_eq!(API.format_bytes(1023), "1023 B");
}

#[test]
fn kib_threshold_starts_at_1024() {
    assert_eq!(API.format_bytes(1024), "1.00 KiB");
    assert_eq!(API.format_bytes(1024 + 512), "1.50 KiB");
}

#[test]
fn larger_units_match_prior_decimals() {
    assert_eq!(API.format_bytes(1024 * 1024), "1.00 MiB");
    assert_eq!(API.format_bytes(1024 * 1024 * 1024), "1.00 GiB");
    assert_eq!(API.format_bytes(1024_u64.pow(4)), "1.00 TiB");
}

#[test]
fn fractional_gib_renders_two_places() {
    assert_eq!(API.format_bytes(1024 * 1024 * 1024 * 3 / 2), "1.50 GiB");
}
