use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sigv4_aws_reference_vector_example_from_docs() {
    // AWS SigV4 documentation example from:
    // https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
    //
    // This test ensures format_sigv4_timestamps produces the correct
    // date and time components for the AWS reference example:
    // Request timestamp: 20150830T123600Z
    // Date value: 20150830

    // August 30, 2015 at 12:36:00 UTC
    // Unix epoch: 1440930960
    let unix_secs = 1_440_938_160u64;
    let (date_stamp, amz_date) = TestApi.format_sigv4_timestamps(unix_secs);

    // AWS docs specify this exact date and timestamp in canonical request
    assert_eq!(
        date_stamp, "20150830",
        "date_stamp must match AWS reference vector"
    );
    assert_eq!(
        amz_date, "20150830T123600Z",
        "amz_date must match AWS reference vector"
    );
}

#[test]
fn sigv4_aws_reference_vector_second_example() {
    // Additional reference vector from AWS documentation examples.
    // January 19, 2024 at 14:55:42 UTC
    // This tests that the implementation handles various dates correctly.

    let unix_secs = 1_705_676_142u64;
    let (date_stamp, amz_date) = TestApi.format_sigv4_timestamps(unix_secs);

    // Verify the date and time components are correctly extracted
    assert_eq!(date_stamp, "20240119", "date_stamp month/day correct");
    assert_eq!(
        amz_date, "20240119T145542Z",
        "amz_date time components correct"
    );

    // Verify component positions in amz_date for signature building
    assert_eq!(&amz_date[0..8], "20240119", "date part of amz_date");
    assert_eq!(&amz_date[9..11], "14", "hour part of amz_date");
    assert_eq!(&amz_date[11..13], "55", "minute part of amz_date");
    assert_eq!(&amz_date[13..15], "42", "second part of amz_date");
}
