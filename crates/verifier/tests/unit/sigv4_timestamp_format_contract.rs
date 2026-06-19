use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sigv4_timestamp_format_always_8_digits_date() {
    // Test that date_stamp is always exactly 8 characters (YYYYMMDD).
    // This is critical for AWS SigV4 signature calculation which depends
    // on exact format.

    let test_cases = vec![
        (0u64, "19700101"),             // epoch zero
        (1_704_067_200u64, "20240101"), // 2024-01-01
        (1_709_210_096u64, "20240229"), // 2024-02-29
    ];

    for (unix_secs, expected_date) in test_cases {
        let (d, _) = TestApi.format_sigv4_timestamps(unix_secs);
        assert_eq!(
            d.len(),
            8,
            "date_stamp must be exactly 8 characters (YYYYMMDD)"
        );
        assert_eq!(d, expected_date, "date_stamp format {}", expected_date);
        // Verify all characters are ASCII digits
        assert!(
            d.chars().all(|c| c.is_ascii_digit()),
            "date_stamp must contain only digits"
        );
    }
}

#[test]
fn sigv4_timestamp_format_always_16_chars_amz_date() {
    // Test that amz_date is always exactly 16 characters (YYYYMMDDTHHMMSSZ).
    // This is critical for AWS SigV4 canonical headers.

    let test_cases = vec![
        (0u64, "19700101T000000Z"),
        (1_704_067_200u64, "20240101T000000Z"),
        (1_709_210_096u64, "20240229T123456Z"),
    ];

    for (unix_secs, expected_amz) in test_cases {
        let (_, a) = TestApi.format_sigv4_timestamps(unix_secs);
        assert_eq!(
            a.len(),
            16,
            "amz_date must be exactly 16 characters (YYYYMMDDTHHMMSSZ)"
        );
        assert_eq!(a, expected_amz, "amz_date format {}", expected_amz);
        // Verify format: YYYYMMDDTHHMMSSZ
        assert_eq!(&a[8..9], "T", "position 8 must be 'T'");
        assert_eq!(&a[15..16], "Z", "position 15 must be 'Z'");
    }
}

#[test]
fn sigv4_timestamp_format_consistency_for_range() {
    // Test consistency across a range of timestamps to ensure the
    // formatting functions are stable and always produce valid output.

    for unix_secs in (0u64..1_000_000u64).step_by(100_000) {
        let (d, a) = TestApi.format_sigv4_timestamps(unix_secs);

        assert_eq!(
            d.len(),
            8,
            "date_stamp must always be 8 chars at unix_secs={}",
            unix_secs
        );
        assert_eq!(
            a.len(),
            16,
            "amz_date must always be 16 chars at unix_secs={}",
            unix_secs
        );

        // date_stamp: all digits, no separators
        assert!(
            d.chars().all(|c| c.is_ascii_digit()),
            "date_stamp all digits at unix_secs={}",
            unix_secs
        );

        // amz_date: correct structure
        assert_eq!(
            &a[8..9],
            "T",
            "amz_date position 8 at unix_secs={}",
            unix_secs
        );
        assert_eq!(
            &a[15..16],
            "Z",
            "amz_date position 15 at unix_secs={}",
            unix_secs
        );
        assert!(
            a[0..8].chars().all(|c| c.is_ascii_digit()),
            "amz_date date part digits at unix_secs={}",
            unix_secs
        );
        assert!(
            a[9..15].chars().all(|c| c.is_ascii_digit()),
            "amz_date time part digits at unix_secs={}",
            unix_secs
        );
    }
}
