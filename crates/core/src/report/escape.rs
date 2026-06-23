//! Shared report escaping and control-character sanitization.

use std::borrow::Cow;

/// True for bytes that can drive a terminal rather than display as text: the C0
/// controls (0x00-0x1F, incl. ESC/CR/LF/TAB), DEL (0x7F), and the C1 range
/// (0x80-0x9F).
pub(crate) fn is_terminal_control(c: char) -> bool {
    let u = c as u32;
    u < 0x20 || c == '\u{7F}' || (0x80..=0x9F).contains(&u)
}

fn replace_controls<F>(value: &str, is_control: F) -> Cow<'_, str>
where
    F: Fn(char) -> bool,
{
    if value.chars().any(&is_control) {
        Cow::Owned(
            value
                .chars()
                .map(|c| if is_control(c) { '\u{FFFD}' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(value)
    }
}

/// Replace terminal control characters in an untrusted display value with the
/// visible replacement char `U+FFFD`, so scan-derived strings cannot inject
/// escape sequences into the terminal. Borrows on the common clean path.
pub(crate) fn sanitize_terminal(value: &str) -> Cow<'_, str> {
    replace_controls(value, is_terminal_control)
}

fn is_xml_illegal_control(c: char) -> bool {
    let u = c as u32;
    u < 0x20 && !matches!(u, 0x09 | 0x0A | 0x0D)
}

/// Replace XML-1.0-illegal control characters with the visible replacement char
/// U+FFFD. XML 1.0 keeps tab/LF/CR legal but rejects other C0 controls even if
/// entity-escaped, so the report must make those bytes visible before writing XML.
pub(crate) fn sanitize_xml(value: &str) -> Cow<'_, str> {
    replace_controls(value, is_xml_illegal_control)
}

/// Escape a value for a CSV field, including spreadsheet formula neutralization.
/// Clean, non-formula values are borrowed.
pub(crate) fn escape_csv(value: &str) -> Cow<'_, str> {
    let formula_prefix = matches!(
        value.as_bytes().first(),
        Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r')
    );
    let needs_quotes =
        value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r');

    if !formula_prefix && !needs_quotes {
        return Cow::Borrowed(value);
    }

    let mut escaped = String::with_capacity(value.len() + usize::from(formula_prefix) + 2);
    if needs_quotes {
        escaped.push('"');
    }
    if formula_prefix {
        escaped.push('\'');
    }
    for ch in value.chars() {
        if ch == '"' {
            escaped.push('"');
        }
        escaped.push(ch);
    }
    if needs_quotes {
        escaped.push('"');
    }
    Cow::Owned(escaped)
}

fn is_xml_attr_escape(c: char) -> bool {
    matches!(c, '&' | '<' | '>' | '"' | '\'') || is_xml_illegal_control(c)
}

/// Escape a value for an XML attribute after replacing XML-illegal control bytes.
/// Clean values are borrowed.
pub(crate) fn escape_xml_attr(value: &str) -> Cow<'_, str> {
    if !value.chars().any(is_xml_attr_escape) {
        return Cow::Borrowed(value);
    }

    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            c if is_xml_illegal_control(c) => escaped.push('\u{FFFD}'),
            c => escaped.push(c),
        }
    }
    Cow::Owned(escaped)
}

/// Neutralize the CDATA terminator inside a value written into a `<![CDATA[…]]>`
/// body, and replace XML-illegal control bytes first.
pub(crate) fn escape_cdata(value: &str) -> Cow<'_, str> {
    let sanitized = sanitize_xml(value);
    if sanitized.contains("]]>") {
        Cow::Owned(sanitized.replace("]]>", "]]]]><![CDATA[>"))
    } else {
        sanitized
    }
}
