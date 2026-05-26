//! SARIF artifact URI helpers.

/// Render a filesystem path as a SARIF v2.1.0 `artifactLocation.uri`.
pub fn file_path_to_sarif_uri(path: &str) -> String {
    if path.starts_with('/') {
        format!("file://{}", percent_encode_path(path))
    } else if is_windows_absolute(path) {
        let normalised = path.replace('\\', "/");
        format!("file:///{}", percent_encode_path(&normalised))
    } else {
        path.to_string()
    }
}

fn is_windows_absolute(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')
}

fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        let safe =
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/' | b':');
        if safe {
            out.push(byte as char);
        } else {
            out.push('%');
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0F) as usize] as char);
        }
    }
    out
}
