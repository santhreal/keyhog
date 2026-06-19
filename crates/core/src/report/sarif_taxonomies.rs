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
                "id": "CWE-798",
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
                "id": "A07:2021",
                "name": "Identification and Authentication Failures",
                "shortDescription": {
                    "text": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks."
                },
                "helpUri": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
            }]
        }
    ])
}
