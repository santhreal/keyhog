pub fn parse_json_array(stdout: &str, context: &str) -> Vec<serde_json::Value> {
    let value = serde_json::from_str::<serde_json::Value>(stdout)
        .unwrap_or_else(|error| panic!("{context}: stdout is not valid JSON: {error}\n{stdout}"));
    value
        .as_array()
        .unwrap_or_else(|| panic!("{context}: JSON report must be an array, got {value}"))
        .clone()
}

pub fn json_array_string_field_values(stdout: &str, field: &str, context: &str) -> Vec<String> {
    parse_json_array(stdout, context)
        .iter()
        .filter_map(|finding| {
            finding
                .get(field)
                .and_then(|value| value.as_str())
                .map(String::from)
        })
        .collect()
}
