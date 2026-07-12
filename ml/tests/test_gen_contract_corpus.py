import gen_contract_corpus as g


def test_contract_records_labels_positive_evasion_negative():
    spec = {
        "positive": [
            {"text": "password=S4oxj2N-bVEi6ivQsrW3", "credential": "S4oxj2N-bVEi6ivQsrW3"},
        ],
        "evasion": [
            {"text": '{"secret":"S4oxj2N-bVEi6ivQsrW3"}', "credential": "S4oxj2N-bVEi6ivQsrW3"},
        ],
        "negative": [
            {"text": "password=YOUR_API_KEY_HERE_PLACEHOLDER"},
        ],
    }
    recs = g.contract_records(spec, "generic-password")
    assert [(r["kind"], r["label"], r["text"]) for r in recs] == [
        ("contract-pos", 1, "S4oxj2N-bVEi6ivQsrW3"),
        ("contract-evasion", 1, "S4oxj2N-bVEi6ivQsrW3"),
        ("contract-neg", 0, "YOUR_API_KEY_HERE_PLACEHOLDER"),
    ]
    # provenance fields drive the split (source_file) + gate (class/detector_id)
    for r in recs:
        assert r["source_file"] == "contract:generic-password"
        assert r["class"] == "Contract:generic-password"
        assert r["detector_id"] == "generic-password"
        assert r["context"].startswith("file:contract:generic-password\n")


def test_contract_records_skips_empty_credential():
    # a positive with no credential value must NOT emit a blank training record
    spec = {"positive": [{"text": "password=", "credential": ""}]}
    assert g.contract_records(spec, "x") == []


def test_extract_negative_value_prefers_quoted_then_assignment():
    assert g.extract_negative_value('{"api_key":"GOCSPX-ABC"}') == "GOCSPX-ABC"
    assert g.extract_negative_value("password=YOUR_KEY_HERE") == "YOUR_KEY_HERE"
    assert g.extract_negative_value("token: sk_live_x") == "sk_live_x"
    assert g.extract_negative_value("bareword") == "bareword"
