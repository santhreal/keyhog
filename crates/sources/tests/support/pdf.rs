//! Shared PDF fixture builders for structured source tests.

pub fn minimal_pdf(stream_dict: &str, stream: &[u8]) -> Vec<u8> {
    let mut pdf = format!(
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n2 0 obj\n<< /Length {}{} >>\nstream\n",
        stream.len(),
        stream_dict
    )
    .into_bytes();
    pdf.extend_from_slice(stream);
    pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
    pdf
}

/// Build a stream-less PDF whose body carries an arbitrary raw object segment 
/// e.g. an Info dictionary holding metadata literal/hex strings
/// (`/Author`, `/Title`, `/Keywords`, `/Producer`). Exercises the "strings
/// outside streams" extraction path (`append_pdf_strings_outside_streams`),
/// which is where a credential pasted into a document's metadata lives and
/// which no content-stream fixture reaches. The `%PDF-` magic + catalog + a
/// trailer with an `/Info` reference make it a well-formed, extractable PDF.
pub fn pdf_with_body(body: &str) -> Vec<u8> {
    let mut pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n".to_vec();
    pdf.extend_from_slice(body.as_bytes());
    pdf.extend_from_slice(b"\ntrailer\n<< /Root 1 0 R /Info 3 0 R >>\n%%EOF\n");
    pdf
}

/// Build a stream-less PDF whose sole body object is an Info dictionary with the
/// given `entries` (each already rendered as a `/Key (value)` or `/Key <hex>`
/// fragment). The dominant metadata-leak shape.
pub fn pdf_with_info_dict(entries: &str) -> Vec<u8> {
    pdf_with_body(&format!("3 0 obj\n<< {entries} >>\nendobj\n"))
}
