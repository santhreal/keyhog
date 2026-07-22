//! Horizontal whitespace separates a CLI flag from its encoded credential.

use keyhog_scanner::decode::find_base64_strings;

#[test]
fn cli_flag_base64_value_found() {
    let blob = "WHk5S21QcTJMdlduQjd0Ug==";
    let text = format!("mysql -u root --password {blob} -e 'SELECT 1'");

    let matches = find_base64_strings(&text, 12);

    assert_eq!(
        matches
            .iter()
            .filter(|candidate| candidate.value == blob)
            .count(),
        1,
        "neighboring CLI words must not be concatenated into the candidate"
    );
}
