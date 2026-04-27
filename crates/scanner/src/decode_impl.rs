fn extract_encoded_values(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = text.as_bytes();
    
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        
        if ch == b'"' || ch == b'\'' || ch == b'`' {
            let quote = ch;
            i += 1;
            let start = i;
            let mut escaping = false;
            while i < bytes.len() {
                if escaping {
                    escaping = false;
                } else if bytes[i] == b'\\' {
                    escaping = true;
                } else if bytes[i] == quote {
                    if i > start {
                        values.push(text[start..i].to_string());
                    }
                    break;
                }
                i += 1;
            }
        } else if ch == b':' || ch == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b';' && bytes[i] != b',' && bytes[i] != b'"' && bytes[i] != b'\'' && bytes[i] != b'`' {
                i += 1;
            }
            if i > start {
                values.push(text[start..i].to_string());
            }
            continue;
        }
        i += 1;
    }
    
    values
}
