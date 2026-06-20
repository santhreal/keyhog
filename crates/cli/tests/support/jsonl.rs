pub fn parse_jsonl_objects(stdout: &str, context: &str) -> Vec<serde_json::Value> {
    let mut objects = Vec::new();
    for (index, line) in stdout.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let value = serde_json::from_str::<serde_json::Value>(trimmed).unwrap_or_else(|error| {
            panic!(
                "{context}: JSONL line {} is not valid JSON: {error}\n{line}",
                index + 1
            )
        });
        assert!(
            value.is_object(),
            "{context}: JSONL line {} must be a JSON object, got {value}",
            index + 1
        );
        objects.push(value);
    }
    objects
}
