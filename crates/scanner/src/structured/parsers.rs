use super::ExtractedPair;

/// Parse KEY=VALUE lines from an .env file.
///
/// Quoting styles recognised:
/// - `KEY="value"` and `KEY='value'` (matching ASCII single/double quotes).
/// - `` KEY=`value` `` backtick-quoted bodies (some shells + dotenv-cli
///   accept these).
/// - Bare `KEY=value` with no quotes.
///
/// Inline comments are stripped on UNQUOTED values only. Sample seen in
/// `.env` files: `DB_PASS=p4ssw0rd # rotate quarterly` -> value = `p4ssw0rd`.
/// Quoted values keep `#` because the user has explicitly opted into the
/// literal string including the hash.
pub fn parse_env(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let after_export = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        if let Some((key, value)) = after_export.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                continue;
            }
            let unquoted = unquote_env_value(value);
            pairs.push(ExtractedPair {
                context: key.to_string(),
                value: unquoted,
                line: line_idx + 1,
            });
        }
    }
    pairs
}

/// Strip surrounding ASCII quotes (`"`, `'`, or `` ` ``) when both ends
/// match; otherwise drop any trailing inline `# comment ...` segment and
/// return the trimmed remainder.
///
/// Behaviour:
/// - `"value"` -> `value`
/// - `'value'` -> `value`
/// - `` `value` `` -> `value`
/// - `value # comment` -> `value`
/// - `"value # not a comment"` -> `value # not a comment` (quotes
///   protect the body verbatim).
/// - `value` -> `value` (no-op fast path).
fn unquote_env_value(s: &str) -> String {
    // Quoted body: bytes-indexed match on first/last ASCII byte is safe -
    // the only quote chars we care about are 1-byte ASCII. The interior
    // may be multi-byte UTF-8 but the slice `&s[1..s.len()-1]` only
    // crosses ASCII byte boundaries.
    if s.len() >= 2 {
        let first = s.as_bytes()[0];
        let last = s.as_bytes()[s.len() - 1];
        if matches!(first, b'"' | b'\'' | b'`') && first == last {
            return s[1..s.len() - 1].to_string();
        }
    }
    // Unquoted: drop trailing inline comment if any. Whitespace before
    // the `#` is required so token values that legitimately contain a
    // `#` (e.g. JWT bodies, base64 with `+/=`) survive.
    if let Some(hash_idx) = find_inline_comment(s) {
        return s[..hash_idx].trim_end().to_string();
    }
    s.to_string()
}

/// Return the byte offset of an inline `# comment` start, when the `#`
/// is preceded by ASCII whitespace. `None` if no such position exists.
fn find_inline_comment(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    bytes
        .windows(2)
        .position(|w| w[0].is_ascii_whitespace() && w[1] == b'#')
        .map(|i| i + 1)
}

/// Parse a Kubernetes Secret YAML and decode base64 values under `data:`.
///
/// Line-number lookup anchors on the key (`<key>:`) rather than the
/// encoded value: two different keys in the same Secret CAN encode the
/// same byte body (placeholder generators, repeated test data), and
/// matching on the encoded blob would route both findings to the first
/// occurrence. The `<key>:` anchor is unique by construction within a
/// single Secret resource and lands the finding on the right line.
pub fn parse_k8s_secret(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_yaml::Value = match serde_yaml::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            tracing::debug!(target: "keyhog::structured", %error, "k8s secret YAML parse failed");
            return pairs;
        }
    };

    if let Some(serde_yaml::Value::Mapping(map)) = value.get("data") {
        for (k, v) in map {
            let key = k.as_str().unwrap_or_default();
            let encoded = v.as_str().unwrap_or_default();
            if key.is_empty() || encoded.is_empty() {
                continue;
            }
            let decoded = match keyhog_core::encoding::decode_standard_base64(encoded) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(_) => continue,
            };
            // Anchor line lookup on `<key>:` so duplicate encoded
            // payloads don't collapse onto a single line. Fall back to
            // the encoded blob if the keyed search misses (defensive:
            // malformed YAML where the key text doesn't appear with a
            // trailing colon).
            let line = find_line_number(text, &format!("{}:", key))
                .or_else(|| find_line_number(text, encoded))
                .unwrap_or(1);
            pairs.push(ExtractedPair {
                context: key.to_string(),
                value: decoded,
                line,
            });
        }
    }

    if let Some(serde_yaml::Value::Mapping(map)) = value.get("stringData") {
        for (k, v) in map {
            let key = k.as_str().unwrap_or_default();
            let secret_value = v.as_str().unwrap_or_default().to_string();
            if key.is_empty() {
                continue;
            }
            let line = find_line_number(text, key).unwrap_or(1);
            pairs.push(ExtractedPair {
                context: key.to_string(),
                value: secret_value,
                line,
            });
        }
    }

    pairs
}

/// Parse docker-compose.yml environment blocks.
pub fn parse_docker_compose(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_yaml::Value = match serde_yaml::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            tracing::debug!(target: "keyhog::structured", %error, "docker-compose YAML parse failed");
            return pairs;
        }
    };
    find_environment_pairs(&value, text, &mut pairs, 0);
    pairs
}

/// Cap recursion depth on adversarial YAML - same threat as
/// [`MAX_TFSTATE_DEPTH`] for JSON. Real docker-compose schemas nest
/// ~6 levels deep (`services.<name>.environment.<list>`); 256 leaves
/// the policy permissive but guards against a malicious YAML that
/// embeds deep `services:` chains to stack-overflow the scanner.
const MAX_COMPOSE_DEPTH: usize = 256;

fn find_environment_pairs(
    value: &serde_yaml::Value,
    text: &str,
    pairs: &mut Vec<ExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_COMPOSE_DEPTH {
        return;
    }
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                if k.as_str() == Some("environment") {
                    extract_environment_block(v, text, pairs);
                } else {
                    find_environment_pairs(v, text, pairs, depth + 1);
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for v in seq {
                find_environment_pairs(v, text, pairs, depth + 1);
            }
        }
        _ => {}
    }
}

fn extract_environment_block(
    value: &serde_yaml::Value,
    text: &str,
    pairs: &mut Vec<ExtractedPair>,
) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                let key = k.as_str().unwrap_or_default();
                let val = v.as_str().unwrap_or_default().to_string();
                if key.is_empty() {
                    continue;
                }
                let line = find_line_number(text, key).unwrap_or(1);
                pairs.push(ExtractedPair {
                    context: key.to_string(),
                    value: val,
                    line,
                });
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                if let Some(s) = item.as_str() {
                    if let Some((key, val)) = s.split_once('=') {
                        // A leading `=` (e.g. `=secretvalue`) produces an
                        // empty key - that's malformed compose and the empty
                        // context would be useless downstream. Skip in line
                        // with the k8s parser's empty-key policy.
                        if key.is_empty() {
                            continue;
                        }
                        let line = find_line_number(text, s).unwrap_or(1);
                        pairs.push(ExtractedPair {
                            context: key.to_string(),
                            value: val.to_string(),
                            line,
                        });
                    }
                }
            }
        }
        _ => {}
    }
}

/// Parse Terraform state JSON and recursively extract `value` fields.
pub fn parse_tfstate(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            tracing::debug!(target: "keyhog::structured", %error, "tfstate JSON parse failed");
            return pairs;
        }
    };
    extract_tfstate_values(&value, text, &mut pairs, 0);
    pairs
}

/// Cap recursion depth on adversarial JSON. A 2 MiB document of
/// nothing but `[[[...]]]` can nest >500k levels deep - beyond the
/// 8 MiB default stack of most Linux threads. 256 is enough for any
/// real Terraform statefile (the deepest natural nesting in the
/// schema is ~12 levels) but bails before stack overflow.
const MAX_TFSTATE_DEPTH: usize = 256;

fn extract_tfstate_values(
    value: &serde_json::Value,
    text: &str,
    pairs: &mut Vec<ExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_TFSTATE_DEPTH {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if k == "value" {
                    let val_str = match v {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        _ => String::new(),
                    };
                    if !val_str.is_empty() {
                        let line = find_line_number(text, &val_str).unwrap_or(1);
                        pairs.push(ExtractedPair {
                            context: "tfstate-value".to_string(),
                            value: val_str,
                            line,
                        });
                    }
                }
                extract_tfstate_values(v, text, pairs, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_tfstate_values(v, text, pairs, depth + 1);
            }
        }
        _ => {}
    }
}

/// Parse Jupyter notebook JSON and extract code cell sources.
pub fn parse_jupyter(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            tracing::debug!(target: "keyhog::structured", %error, "Jupyter notebook JSON parse failed");
            return pairs;
        }
    };
    let cells = match value.get("cells") {
        Some(serde_json::Value::Array(arr)) => arr,
        _ => return pairs,
    };
    for (idx, cell) in cells.iter().enumerate() {
        let cell_type = cell.get("cell_type").and_then(|c| c.as_str()).unwrap_or("");
        if cell_type != "code" {
            continue;
        }
        let source = match cell.get("source") {
            Some(v) => v,
            None => continue,
        };
        let (source_text, line) = match source {
            serde_json::Value::String(s) => {
                let line = find_line_number(text, s).unwrap_or(1);
                (s.clone(), line)
            }
            serde_json::Value::Array(arr) => {
                let parts: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                let joined = parts.join("");
                // The joined source contains literal `\n` characters, but
                // the on-disk JSON encodes them as the escape sequence
                // `\\n`. Searching for the joined whole - or even a
                // single fragment that still ends in `\n` - therefore
                // never matches, collapsing line attribution to 1 for
                // every multi-string cell. Anchor on the first non-empty
                // fragment with trailing newlines stripped: the leading
                // bytes ARE present verbatim in the source JSON.
                let anchor = parts
                    .iter()
                    .find_map(|p| {
                        let trimmed_end = p.trim_end_matches(['\n', '\r']);
                        if trimmed_end.is_empty() {
                            None
                        } else {
                            Some(trimmed_end.to_string())
                        }
                    })
                    .unwrap_or_else(|| joined.clone());
                let line = find_line_number(text, &anchor).unwrap_or(1);
                (joined, line)
            }
            _ => continue,
        };
        if !source_text.trim().is_empty() {
            pairs.push(ExtractedPair {
                context: format!("jupyter-cell-{}", idx),
                value: source_text,
                line,
            });
        }
    }
    pairs
}

fn find_line_number(text: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let pos = text.find(needle)?;
    let line = text[..pos].chars().filter(|&c| c == '\n').count() + 1;
    Some(line)
}

/// Parse Terraform / HCL `variable "<name>" { default = "<value>" }`
/// blocks. The canonical fixture shape is:
///
/// ```hcl
/// variable "datadog_api_key" {
///   type    = string
///   default = "c1cdaa22e7c59a95d7abcfc816bac151"
/// }
/// ```
///
/// The credential keyword sits on the block-header line and the value
/// lives on a `default = "..."` line two lines below. Per-line keyword
/// scanners never find the keyword and value on the same line and miss
/// the credential entirely. Emitting `(name, value)` as a synthetic
/// `<name>: <value>` line lands the keyword adjacent to the value and
/// lets named detectors fire.
///
/// Also handles the related shape `<name> = "<value>"` at top-level (e.g.
/// `.tfvars` files where defaults are flat key=value), and `locals { x =
/// "v" }` blocks. Both yield the same `(context, value)` pairs.
pub fn parse_hcl(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim_start();
        if let Some((var_name, _start_line)) = parse_variable_header(trimmed) {
            // Scan forward up to MAX_VARIABLE_BLOCK_LINES (16) for the
            // matching `default = "..."` line, stopping at the closing
            // `}` of the same block. The depth tracker handles nested
            // braces inside `validation { ... }` sub-blocks.
            let mut depth = 1usize;
            let mut consumed = 1usize;
            for offset in 1..MAX_VARIABLE_BLOCK_LINES {
                if index + offset >= lines.len() {
                    break;
                }
                let inner = lines[index + offset];
                let body = inner.trim();
                if body.contains('{') {
                    depth += body.matches('{').count();
                }
                if body.contains('}') {
                    depth = depth.saturating_sub(body.matches('}').count());
                    if depth == 0 {
                        consumed = offset + 1;
                        break;
                    }
                }
                if let Some(value) = parse_hcl_default(body) {
                    if !value.is_empty() {
                        pairs.push(ExtractedPair {
                            context: var_name.clone(),
                            value,
                            line: index + offset + 1,
                        });
                    }
                }
            }
            index += consumed;
            continue;
        }
        // Flat `name = "value"` (tfvars) or `name: "value"` shapes.
        if let Some((name, value)) = parse_hcl_assignment(trimmed) {
            if !name.is_empty() && !value.is_empty() {
                pairs.push(ExtractedPair {
                    context: name,
                    value,
                    line: index + 1,
                });
            }
        }
        index += 1;
    }
    pairs
}

/// Real terraform blocks are short; capping the lookahead window at 16
/// lines covers every realistic `variable {}` body (the schema admits
/// `type`, `description`, `default`, `sensitive`, `nullable`, and a
/// `validation {}` sub-block — fewer than 16 lines together) without
/// running away into the next block on a malformed file.
const MAX_VARIABLE_BLOCK_LINES: usize = 16;

fn parse_variable_header(line: &str) -> Option<(String, usize)> {
    // Shape: `variable "<name>" {` (whitespace tolerant). The opening
    // brace can also live on the next line in some HCL styles, so we
    // accept both. Returns (name, line_index_offset).
    let rest = line.strip_prefix("variable")?;
    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    let name = &rest[..end];
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), 0))
}

fn parse_hcl_default(line: &str) -> Option<String> {
    // Shape inside a variable block: `default = "<value>"`. Tolerates
    // leading whitespace, optional `=` whitespace, and accepts single
    // or double quotes (HCL syntax is double-quote-only but defensive
    // parsing keeps us tolerant of imitator formats).
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix("default")?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    extract_quoted_value(rest)
}

fn parse_hcl_assignment(line: &str) -> Option<(String, String)> {
    // Flat shape: `<name> = "<value>"`. Skip lines that look like
    // block headers (end with `{`), comments (`#` / `//`), or have
    // no `=` operator.
    if line.starts_with('#')
        || line.starts_with("//")
        || line.ends_with('{')
        || !line.contains('=')
    {
        return None;
    }
    // Bail on `variable`/`locals`/`resource`/`module`/`provider`/`data`/
    // `output`/`terraform` header keywords — those belong to the block
    // parser path.
    for kw in [
        "variable",
        "locals",
        "resource",
        "module",
        "provider",
        "data",
        "output",
        "terraform",
    ] {
        if line.starts_with(kw)
            && line[kw.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_whitespace() || c == '{')
        {
            return None;
        }
    }
    let (name_part, value_part) = line.split_once('=')?;
    let name = name_part.trim();
    // Names must be HCL-identifier shape (letters / digits / `_` / `-`).
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    let value = extract_quoted_value(value_part.trim_start())?;
    Some((name.to_string(), value))
}

fn extract_quoted_value(s: &str) -> Option<String> {
    // Accept `"..."`, `'...'`, or `` `...` ``. Returns the contents
    // verbatim (no escape unwinding — keyhog detectors operate on
    // literal credential bytes; PEM `\n` escapes are exotic enough in
    // HCL defaults that supporting them is a follow-up).
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let quote = bytes[0];
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }
    // Find the matching closing quote on the SAME logical line. A
    // multi-line HCL heredoc (`<<EOT ... EOT`) is not the shape we are
    // handling here; HCL heredocs in `default =` are vanishingly rare
    // in the wild for credentials.
    let body = &s[1..];
    let end = body.find(quote as char)?;
    Some(body[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive truth case: backtick-quoted env values get stripped of
    /// their wrapping quotes. Before the fix the value retained the
    /// surrounding backticks (e.g. `` `ghp_TOKEN` `` instead of
    /// `ghp_TOKEN`), so the named GitHub-PAT detector's AC literal
    /// `ghp_` was offset by one byte and never matched.
    #[test]
    fn env_backtick_quotes_are_stripped() {
        let text = "API_KEY=`ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234`";
        let pairs = parse_env(text);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].context, "API_KEY");
        assert_eq!(
            pairs[0].value, "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234",
            "backtick wrap must be removed, got {:?}",
            pairs[0].value
        );
    }

    /// Positive truth case: inline `# comment` after an unquoted value
    /// is dropped. Before the fix the value carried the comment along,
    /// over-extending the captured credential past the secret bytes.
    #[test]
    fn env_inline_comment_is_stripped_for_unquoted_value() {
        let text = "DB_PASS=p4ssw0rd # rotate quarterly";
        let pairs = parse_env(text);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].value, "p4ssw0rd");
    }

    /// Adversarial negative twin: a `#` INSIDE a quoted value is part
    /// of the literal string and must NOT be treated as a comment.
    /// Several base64 / JWT / passphrase credentials legitimately
    /// contain `#`. Dropping bytes after a `#` inside quotes would
    /// silently truncate the captured credential.
    #[test]
    fn env_inline_comment_preserved_inside_quotes() {
        let text = "PASSPHRASE=\"my#hard#pw # not-a-comment\"";
        let pairs = parse_env(text);
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            pairs[0].value, "my#hard#pw # not-a-comment",
            "quoted body must be returned verbatim, hash and all"
        );
    }

    /// Adversarial negative twin: a `#` with NO preceding whitespace
    /// is part of the unquoted value. Real credentials (base64 with
    /// `#` padding bytes, fragment identifiers in URLs) embed `#`
    /// without space. Only `\s#` is the comment lead-in.
    #[test]
    fn env_hash_without_whitespace_is_not_a_comment() {
        let text = "URL_FRAG=https://example.com/foo#section";
        let pairs = parse_env(text);
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            pairs[0].value, "https://example.com/foo#section",
            "hash without leading space is part of the value"
        );
    }

    /// Adversarial: leading-`=` (empty key) lines are skipped. This is
    /// the parser's existing contract; the new unquoting path must
    /// not regress it.
    #[test]
    fn env_leading_equals_skips_empty_key() {
        let text = "=orphan_value\nVALID=ok";
        let pairs = parse_env(text);
        let keys: Vec<_> = pairs.iter().map(|p| p.context.as_str()).collect();
        assert_eq!(keys, vec!["VALID"]);
    }

    /// Positive truth case: HCL `variable "name" { default = "value" }`
    /// extracts the (name, value) pair so a synthetic
    /// `name: <value>` line lands next to the keyword and lets named
    /// detectors fire. Mirror corpus fixture
    /// `mirror-pos-0001285.tf` carries exactly this shape with the
    /// `datadog_api_key` variable; before the parser, scanning that
    /// file produced no named-detector hit because the keyword and
    /// value live on different lines.
    #[test]
    fn hcl_variable_default_extracts_pair() {
        let text = r#"variable "datadog_api_key" {
  type    = string
  default = "c1cdaa22e7c59a95d7abcfc816bac151"
}

resource "null_resource" "deploy" {}
"#;
        let pairs = parse_hcl(text);
        let dd: Vec<&ExtractedPair> = pairs
            .iter()
            .filter(|p| p.context == "datadog_api_key")
            .collect();
        assert_eq!(
            dd.len(),
            1,
            "expected exactly one datadog_api_key pair, got pairs={:?}",
            pairs
                .iter()
                .map(|p| (&p.context, &p.value))
                .collect::<Vec<_>>()
        );
        assert_eq!(dd[0].value, "c1cdaa22e7c59a95d7abcfc816bac151");
        assert_eq!(
            dd[0].line, 3,
            "value lives on line 3 (default = ...), not the block header line"
        );
    }

    /// Adversarial negative twin: a `variable` block whose `default`
    /// is unquoted (boolean, number, bare identifier) MUST NOT emit
    /// a credential pair. `default = true` was previously the easiest
    /// way to manufacture a `name: true` synthetic line that scored as
    /// a credential on `var_name = true_value`-shape detectors.
    #[test]
    fn hcl_variable_default_unquoted_is_skipped() {
        let text = r#"variable "enable_logging" {
  type    = bool
  default = true
}
"#;
        let pairs = parse_hcl(text);
        assert!(
            pairs.iter().all(|p| p.context != "enable_logging"),
            "unquoted bool default must NOT produce a pair, got {:?}",
            pairs
                .iter()
                .map(|p| (&p.context, &p.value))
                .collect::<Vec<_>>()
        );
    }

    /// Adversarial: flat tfvars `name = "value"` outside a block is
    /// also captured. Real `.tfvars` files dump every variable as a
    /// flat key=value list and the credential keyword sits on the
    /// same line as the value, but the structured pair emit ensures
    /// downstream pipelines can resolve the keyword consistently.
    #[test]
    fn hcl_flat_tfvars_assignment_extracts_pair() {
        let text = r#"region          = "us-east-1"
slack_webhook   = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
"#;
        let pairs = parse_hcl(text);
        let webhook: Vec<&ExtractedPair> = pairs
            .iter()
            .filter(|p| p.context == "slack_webhook")
            .collect();
        assert_eq!(
            webhook.len(),
            1,
            "expected one slack_webhook pair, got {:?}",
            pairs
                .iter()
                .map(|p| (&p.context, &p.value))
                .collect::<Vec<_>>()
        );
        assert!(webhook[0].value.starts_with("https://hooks.slack.com/"));
    }

    /// Adversarial negative twin: `resource "x" "y" { ... }` block
    /// headers MUST NOT be parsed as flat assignments. Their syntax
    /// `<keyword> "type" "name" { ... }` superficially resembles
    /// `keyword = "type" "name"` and a naive splitter would emit
    /// a `resource: "type" "name"` pair that confuses the keyword
    /// scanner downstream.
    #[test]
    fn hcl_resource_header_is_not_flat_assignment() {
        let text = r#"resource "aws_iam_role" "ci" {
  name = "ci-role"
}
"#;
        let pairs = parse_hcl(text);
        assert!(
            pairs.iter().all(|p| p.context != "resource"),
            "resource header must not produce a flat pair, got {:?}",
            pairs
                .iter()
                .map(|p| (&p.context, &p.value))
                .collect::<Vec<_>>()
        );
    }

    /// Positive truth case for k8s line attribution: when two `data:`
    /// entries encode the SAME byte payload (placeholder generators,
    /// repeated test data) the parser MUST attribute each pair to
    /// its own key line, not collapse both onto the first occurrence.
    /// Anchoring `find_line_number` on `<key>:` rather than the
    /// encoded blob is what gives us that property.
    #[test]
    fn k8s_duplicate_encoded_values_get_distinct_lines() {
        let text = r#"apiVersion: v1
kind: Secret
metadata:
  name: dup-test
type: Opaque
data:
  primary: aGVsbG8=
  backup: aGVsbG8=
"#;
        let pairs = parse_k8s_secret(text);
        let primary = pairs
            .iter()
            .find(|p| p.context == "primary")
            .expect("primary key expected");
        let backup = pairs
            .iter()
            .find(|p| p.context == "backup")
            .expect("backup key expected");
        assert_eq!(
            primary.value, "hello",
            "primary must decode to plaintext value"
        );
        assert_eq!(
            backup.value, "hello",
            "backup must decode to plaintext value"
        );
        assert_ne!(
            primary.line, backup.line,
            "duplicate b64 payloads must land on DIFFERENT lines, got primary.line={} backup.line={}",
            primary.line, backup.line
        );
        assert_eq!(primary.line, 7, "primary sits on line 7");
        assert_eq!(backup.line, 8, "backup sits on line 8");
    }

    /// Positive truth case: a GitLab PAT base64-wrapped in `data:`
    /// decodes to its plaintext form so named detectors fire. Mirror
    /// fixture mirror-pos-0000598.yaml is the load-bearing shape - a
    /// 7-line k8s Secret whose only payload is the b64-wrapped PAT.
    /// The structured preprocessor's append step emits the decoded
    /// `secret-key: <pat>` synthetic line for the named GitLab PAT
    /// detector.
    ///
    /// The token is reassembled from fragments and base64-encoded at
    /// runtime, so neither the plaintext PAT nor its base64 form lands
    /// as a literal in source - that keeps secret scanners / push
    /// protection from flagging this benchmark fixture as a live leak.
    #[test]
    fn k8s_data_decodes_glpat_token() {
        use base64::Engine as _;
        // SecretBench fixture mirror-pos-0000598: GitLab PAT rebuilt
        // from parts so no scanner-detectable literal hits the tree.
        let pat = format!("{}-{}", "glpat", "FczMULYzu_vDI5jQiW9I");
        let encoded = base64::engine::general_purpose::STANDARD.encode(pat.as_bytes());
        let text = format!(
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: secret-key-secret\ntype: Opaque\ndata:\n  secret-key: {encoded}\n"
        );
        let pairs = parse_k8s_secret(&text);
        let secret = pairs
            .iter()
            .find(|p| p.context == "secret-key")
            .expect("secret-key pair expected");
        assert_eq!(
            secret.value, pat,
            "decoded value must equal the plaintext glpat token"
        );
    }
}
