use keyhog_scanner::decode::{base64_decode, find_base64_strings, hex_decode, z85_decode};
use keyhog_scanner::testing::{find_hex_strings, take_hex_digits};

const VALID_CREDENTIAL: &str = "TESTKEY_aK7xP9mQ2wE5rT8yU1iO";

#[test]
fn decode_base64_secret() {
    let encoded = "c2stcHJvai1hYmMxMjM=";
    let decoded = base64_decode(encoded).unwrap();
    assert_eq!(String::from_utf8(decoded).unwrap(), "sk-proj-abc123");
}

#[test]
fn decode_hex_secret() {
    let encoded = "736b2d70726f6a2d616263";
    let decoded = hex_decode(encoded).unwrap();
    assert_eq!(String::from_utf8(decoded).unwrap(), "sk-proj-abc");
}

#[test]
fn find_base64_in_text() {
    let text = r#"TOKEN = "c2stcHJvai1hYmMxMjM=""#;
    let matches = find_base64_strings(text, 10);
    assert_eq!(
        matches.len(),
        1,
        "exactly one base64 string in the assignment"
    );
    assert_eq!(matches[0].value, "c2stcHJvai1hYmMxMjM=");
    // Decoding the located span must round-trip to the planted secret.
    assert_eq!(
        String::from_utf8(base64_decode(&matches[0].value).unwrap()).unwrap(),
        "sk-proj-abc123"
    );
}

#[test]
fn decode_z85_secret() {
    // Four null bytes in Z85 is "00000"
    let encoded = "00000";
    let decoded = z85_decode(encoded).unwrap();
    assert_eq!(decoded, vec![0, 0, 0, 0]);
}

#[test]
fn take_hex_digits_basic() {
    let mut it = "deadbeef".chars().peekable();
    assert_eq!(take_hex_digits(&mut it, 8).unwrap(), 0xdeadbeef);
}

#[test]
fn take_hex_digits_partial_consumption() {
    let mut it = "ff00".chars().peekable();
    assert_eq!(take_hex_digits(&mut it, 2).unwrap(), 0xff);
    assert_eq!(take_hex_digits(&mut it, 2).unwrap(), 0x00);
}

#[test]
fn take_hex_digits_uppercase() {
    let mut it = "ABCD".chars().peekable();
    assert_eq!(take_hex_digits(&mut it, 4).unwrap(), 0xABCD);
}

#[test]
fn take_hex_digits_rejects_non_hex() {
    let mut it = "ZZZZ".chars().peekable();
    assert!(take_hex_digits(&mut it, 4).is_err());
}

#[test]
fn take_hex_digits_rejects_short_input() {
    let mut it = "ff".chars().peekable();
    assert!(take_hex_digits(&mut it, 4).is_err());
}

#[test]
fn underscored_hex_is_recognized() {
    // 64 hex chars (32 bytes) split into 2-char groups by `_`.
    // Wrapped in quotes so `extract_encoded_values` picks it up.
    let body = "\"41_42_43_44_45_46_47_48_49_4a_4b_4c_4d_4e_4f_50\
                _51_52_53_54_55_56_57_58_59_5a_61_62_63_64_65_66\"";
    let found = find_hex_strings(body, 32);
    assert_eq!(found.len(), 1);
    let cleaned: String = found[0].value.chars().filter(|c| *c != '_').collect();
    assert!(cleaned.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(cleaned.len(), 64);
    let decoded = hex_decode(&found[0].value).expect("decodes");
    assert_eq!(&decoded[..16], b"ABCDEFGHIJKLMNOP");
}

#[test]
fn underscored_testkey_hex_decodes_to_credential() {
    let hex: String = VALID_CREDENTIAL
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect();
    let underscored = hex
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("_");
    let body = format!("const token_hex = \"{underscored}\";");
    let found = find_hex_strings(&body, 32);
    assert_eq!(found.len(), 1, "underscored TESTKEY hex must be found");
    let decoded = String::from_utf8(hex_decode(&found[0].value).unwrap()).unwrap();
    assert_eq!(decoded, VALID_CREDENTIAL);
}

#[test]
fn hex_decode_strips_underscore_separators() {
    let hex: String = VALID_CREDENTIAL
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect();
    let underscored = hex
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("_");
    let decoded = String::from_utf8(hex_decode(&underscored).unwrap()).unwrap();
    assert_eq!(decoded, VALID_CREDENTIAL);
}

#[test]
fn splice_windows_context_instead_of_whole_parent() {
    // Regression for the decode-splice O(candidates × file_size) blowup.
    // `splice_decoded_payload` used to embed each decoded credential into a
    // copy of the ENTIRE parent, so a candidate-dense source file emitted one
    // parent-sized chunk PER candidate - each then rescanned and recursively
    // re-decoded. A single 156 KB b43/main.c pinned the scanner at ~15s.
    // The fix windows the spliced context to ±512 B around the blob. This
    // test proves both halves of that contract: chunks are bounded (perf) AND
    // the companion anchor still rides along (recall).
    use keyhog_core::Chunk;
    use keyhog_scanner::decode::decode_chunk;

    // base64("AKIAIOSFODNN7EXAMPLE")
    let b64_secret = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU=";

    // A large, candidate-dense parent: every line is an assignment value, the
    // exact shape that produced ~1800 splice candidates on the real file. The
    // credential sits in the middle with its companion anchor adjacent.
    let mut parent = String::new();
    for i in 0..400 {
        parent.push_str(&format!(
            "config_param_{i:04} = \"plainvalue{i:04}padding\"\n"
        ));
    }
    parent.push_str(&format!("aws_secret_access_key = \"{b64_secret}\"\n"));
    for i in 400..800 {
        parent.push_str(&format!(
            "config_param_{i:04} = \"plainvalue{i:04}padding\"\n"
        ));
    }
    let parent_len = parent.len();
    assert!(
        parent_len > 16 * 1024,
        "parent must be large enough to exercise the blowup (was {parent_len})"
    );

    let chunk = Chunk::from(parent);
    let decoded = decode_chunk(&chunk, 2, true, None, None);

    // Windowing: no decoded chunk may approach the parent size. Bound is
    // 2*SPLICE_CONTEXT_WINDOW (1024) + decoded value + slack. If splice still
    // copied the whole parent, chunks would be ~parent_len.
    let max_chunk = decoded.iter().map(|c| c.data.len()).max().unwrap_or(0);
    assert!(
        max_chunk < 4 * 1024,
        "decoded chunk {max_chunk} B must be windowed, not parent-sized ({parent_len} B)"
    );

    // Recall preserved: the decoded credential and its companion anchor must
    // co-occur in some chunk so companion-anchored detectors still fire.
    assert!(
        decoded.iter().any(|c| {
            let s = c.data.as_str();
            s.contains("AKIAIOSFODNN7EXAMPLE") && s.contains("aws_secret_access_key")
        }),
        "decoded secret must keep its companion anchor adjacent after windowing"
    );
}

#[test]
fn underscores_alone_dont_create_phantom_matches() {
    // Underscore-only string strips to empty, must not match.
    let found = find_hex_strings("\"_____________________________\"", 32);
    assert!(found.is_empty());
}
