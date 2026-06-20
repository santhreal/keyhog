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
