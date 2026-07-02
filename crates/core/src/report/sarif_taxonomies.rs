//! Static SARIF taxonomy metadata (CWE + OWASP).

/// CWE / OWASP taxonomy block for SARIF `runs[0].taxonomies`.
pub(crate) fn sarif_taxonomies_json() -> serde_json::Value {
    serde_json::json!([
        {
            "name": "CWE",
            "version": "4.13",
            "informationUri": "https://cwe.mitre.org/data/definitions/798.html",
            "shortDescription": { "text": "Common Weakness Enumeration" },
            "taxa": [{
                "id": (super::CWE_HARDCODED_CREDENTIALS_ID),
                "name": "Use of Hard-coded Credentials",
                "shortDescription": {
                    "text": "The product contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data."
                },
                "helpUri": "https://cwe.mitre.org/data/definitions/798.html"
            }]
        },
        {
            "name": "OWASP",
            "version": "2021",
            "informationUri": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "shortDescription": { "text": "OWASP Top 10:2021" },
            "taxa": [{
                "id": (super::OWASP_AUTH_FAILURES_ID),
                "name": "Identification and Authentication Failures",
                "shortDescription": {
                    "text": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks."
                },
                "helpUri": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
            }]
        }
    ])
}

#[cfg(test)]
mod tests {
    use super::super::{CWE_HARDCODED_CREDENTIALS_ID, OWASP_AUTH_FAILURES_ID};
    use super::sarif_taxonomies_json;

    #[test]
    fn taxonomy_ids_come_from_the_single_owner() {
        // The taxonomy taxa ids must be exactly the shared constants that
        // `result.properties.cwe` / `.owasp` are built from, or the SARIF
        // cross-reference silently fails to resolve in consuming dashboards.
        assert_eq!(CWE_HARDCODED_CREDENTIALS_ID, "CWE-798");
        assert_eq!(OWASP_AUTH_FAILURES_ID, "A07:2021");

        let taxonomies = sarif_taxonomies_json();
        let entries = taxonomies.as_array().expect("taxonomies is a JSON array");
        assert_eq!(entries.len(), 2, "expected CWE + OWASP taxonomy entries");

        let cwe_id = entries[0]["taxa"][0]["id"]
            .as_str()
            .expect("CWE taxa id is a string");
        let owasp_id = entries[1]["taxa"][0]["id"]
            .as_str()
            .expect("OWASP taxa id is a string");
        assert_eq!(cwe_id, CWE_HARDCODED_CREDENTIALS_ID);
        assert_eq!(owasp_id, OWASP_AUTH_FAILURES_ID);
    }
}
