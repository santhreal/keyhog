//! Bounded rooted selectors for detector-owned verification responses.

use std::fmt;

/// Maximum encoded selector length accepted from a detector specification.
pub const MAX_SELECTOR_BYTES: usize = 1024;
/// Maximum object-key and array-index segments in one selector.
pub const MAX_SELECTOR_SEGMENTS: usize = 64;
const MAX_ARRAY_INDEX: u64 = 1_000_000;
const MAX_ERROR_SELECTOR_PREVIEW_BYTES: usize = 160;

/// A syntax error in a detector verification response selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorError {
    selector_preview: String,
    selector_bytes: usize,
    offset: usize,
    reason: &'static str,
}

impl SelectorError {
    fn new(selector: &str, offset: usize, reason: &'static str) -> Self {
        let preview_end = if selector.len() <= MAX_ERROR_SELECTOR_PREVIEW_BYTES {
            selector.len()
        } else {
            selector
                .char_indices()
                .map(|(index, _)| index)
                .take_while(|index| *index <= MAX_ERROR_SELECTOR_PREVIEW_BYTES)
                .last()
                .unwrap_or(0)
        };
        Self {
            selector_preview: selector[..preview_end].to_string(),
            selector_bytes: selector.len(),
            offset,
            reason,
        }
    }
}

impl fmt::Display for SelectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid response selector {:?}",
            self.selector_preview
        )?;
        if self.selector_preview.len() < self.selector_bytes {
            write!(formatter, " ({} bytes)", self.selector_bytes)?;
        }
        write!(
            formatter,
            " at byte {}: {}. Fix: use a `$`-rooted selector such as `$.data.account.email` or `$.orgs[0].name`",
            self.offset, self.reason
        )
    }
}

impl std::error::Error for SelectorError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Segment<'a> {
    Key(&'a str),
    Index(usize),
}

fn visit_segments<'a>(
    selector: &'a str,
    mut visit: impl FnMut(Segment<'a>),
) -> Result<(), SelectorError> {
    let bytes = selector.as_bytes();
    if bytes.len() > MAX_SELECTOR_BYTES {
        return Err(SelectorError::new(
            selector,
            MAX_SELECTOR_BYTES,
            "the selector exceeds the 1024-byte limit",
        ));
    }
    if bytes.first() != Some(&b'$') {
        return Err(SelectorError::new(
            selector,
            0,
            "the selector must start with `$`",
        ));
    }
    let mut cursor = 1;
    let mut segment_count = 0usize;

    let mut visit_bounded = |segment| {
        segment_count += 1;
        if segment_count > MAX_SELECTOR_SEGMENTS {
            return false;
        }
        visit(segment);
        true
    };

    while cursor < bytes.len() {
        if bytes[cursor] == b'.' {
            cursor += 1;
            let key_start = cursor;
            while cursor < bytes.len() && !matches!(bytes[cursor], b'.' | b'[' | b']') {
                if !bytes[cursor].is_ascii_alphanumeric() && !matches!(bytes[cursor], b'_' | b'-') {
                    return Err(SelectorError::new(
                        selector,
                        cursor,
                        "bare object keys may contain only ASCII letters, digits, `_`, and `-`",
                    ));
                }
                cursor += 1;
            }
            if cursor == key_start {
                return Err(SelectorError::new(
                    selector,
                    cursor,
                    "an object key is missing after `.`",
                ));
            }
            if !visit_bounded(Segment::Key(&selector[key_start..cursor])) {
                return Err(SelectorError::new(
                    selector,
                    cursor,
                    "the selector exceeds the 64-segment limit",
                ));
            }
            continue;
        }
        if bytes[cursor] != b'[' {
            return Err(SelectorError::new(
                selector,
                cursor,
                "expected `.` or `[` after the current segment",
            ));
        }
        let bracket_start = cursor;
        cursor += 1;
        if cursor < bytes.len() && bytes[cursor] == b'"' {
            cursor += 1;
            let key_start = cursor;
            while cursor < bytes.len() && bytes[cursor] != b'"' {
                if bytes[cursor] == b'\\' || bytes[cursor].is_ascii_control() {
                    return Err(SelectorError::new(
                        selector,
                        cursor,
                        "quoted object keys cannot contain escapes or control characters",
                    ));
                }
                cursor += 1;
            }
            if cursor == key_start {
                return Err(SelectorError::new(
                    selector,
                    cursor,
                    "a quoted object key cannot be empty",
                ));
            }
            if cursor == bytes.len() || bytes[cursor] != b'"' {
                return Err(SelectorError::new(
                    selector,
                    bracket_start,
                    "a quoted object key is missing its closing quote",
                ));
            }
            if !visit_bounded(Segment::Key(&selector[key_start..cursor])) {
                return Err(SelectorError::new(
                    selector,
                    cursor,
                    "the selector exceeds the 64-segment limit",
                ));
            }
            cursor += 1;
            if cursor == bytes.len() || bytes[cursor] != b']' {
                return Err(SelectorError::new(
                    selector,
                    bracket_start,
                    "a quoted object key is missing its closing `]`",
                ));
            }
            cursor += 1;
            continue;
        }
        let index_start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if cursor == index_start {
            return Err(SelectorError::new(
                selector,
                cursor,
                "an array index must contain decimal digits",
            ));
        }
        if cursor == bytes.len() || bytes[cursor] != b']' {
            return Err(SelectorError::new(
                selector,
                bracket_start,
                "an array index is missing its closing `]`",
            ));
        }
        if cursor - index_start > 1 && bytes[index_start] == b'0' {
            return Err(SelectorError::new(
                selector,
                index_start,
                "array indexes cannot contain leading zeroes",
            ));
        }
        let index = selector[index_start..cursor].parse::<u64>().map_err(|_| {
            SelectorError::new(selector, index_start, "the array index is too large")
        })?;
        if index > MAX_ARRAY_INDEX {
            return Err(SelectorError::new(
                selector,
                index_start,
                "the array index exceeds the 1000000 limit",
            ));
        }
        if !visit_bounded(Segment::Index(index as usize)) {
            return Err(SelectorError::new(
                selector,
                cursor,
                "the selector exceeds the 64-segment limit",
            ));
        }
        cursor += 1;
    }
    Ok(())
}

/// Validate the rooted response selector grammar used by detector TOMLs.
pub fn validate(selector: &str) -> Result<(), SelectorError> {
    visit_segments(selector, |_| {})
}

fn validate_at(errors: &mut Vec<String>, scope: String, selector: Option<&str>) {
    if let Some(selector) = selector {
        if let Err(error) = validate(selector) {
            errors.push(format!("{scope}: {error}"));
        }
    }
}

/// Validate every response selector and selector-dependent field in a detector.
pub fn validate_detector_response_selectors(detector: &crate::DetectorSpec) -> Vec<String> {
    let Some(verify) = &detector.verify else {
        return Vec::new();
    };
    let mut errors = Vec::new();
    if let Some(success) = &verify.success {
        validate_at(
            &mut errors,
            "verify.success.json_path".to_string(),
            success.json_path.as_deref(),
        );
        if success.equals.is_some() && success.json_path.is_none() {
            errors.push(
                "verify.success.equals requires verify.success.json_path so the expected value has an explicit response selector"
                    .to_string(),
            );
        }
    }
    for (metadata_index, metadata) in verify.metadata.iter().enumerate() {
        validate_at(
            &mut errors,
            format!("verify.metadata[{metadata_index}].json_path"),
            Some(&metadata.json_path),
        );
    }
    for (step_index, step) in verify.steps.iter().enumerate() {
        validate_at(
            &mut errors,
            format!("verify.steps[{step_index}].success.json_path"),
            step.success.json_path.as_deref(),
        );
        if step.success.equals.is_some() && step.success.json_path.is_none() {
            errors.push(format!(
                "verify.steps[{step_index}].success.equals requires verify.steps[{step_index}].success.json_path so the expected value has an explicit response selector"
            ));
        }
        for (extract_index, metadata) in step.extract.iter().enumerate() {
            validate_at(
                &mut errors,
                format!("verify.steps[{step_index}].extract[{extract_index}].json_path"),
                Some(&metadata.json_path),
            );
        }
    }
    errors
}

/// Resolve a dotted selector against a JSON value.
///
/// A valid selector that does not exist returns `Ok(None)`. Invalid syntax
/// returns an error so verifier configuration faults cannot look like dead
/// credentials or missing metadata.
pub fn select<'a>(
    value: &'a serde_json::Value,
    selector: &str,
) -> Result<Option<&'a serde_json::Value>, SelectorError> {
    let mut selected = Some(value);
    visit_segments(selector, |segment| {
        selected = match (selected, segment) {
            (Some(serde_json::Value::Object(object)), Segment::Key(key)) => object.get(key),
            (Some(serde_json::Value::Array(array)), Segment::Index(index)) => array.get(index),
            _ => None,
        };
    })?;
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::{select, validate};

    #[test]
    fn resolves_shipped_object_and_array_forms() {
        let json = serde_json::json!({
            "data": {"account": {"email": "ops@example.com"}},
            "orgs": [{"name": "acme"}]
        });
        assert_eq!(
            select(&json, "$.data.account.email")
                .expect("valid selector")
                .and_then(serde_json::Value::as_str),
            Some("ops@example.com")
        );
        assert_eq!(
            select(&json, "$.orgs[0].name")
                .expect("valid selector")
                .and_then(serde_json::Value::as_str),
            Some("acme")
        );
        assert_eq!(select(&json, "$"), Ok(Some(&json)));
        let dotted_key = serde_json::json!({"a.b": true});
        assert_eq!(
            select(&dotted_key, "$[\"a.b\"]"),
            Ok(Some(&serde_json::Value::Bool(true)))
        );
        let root_array = serde_json::json!([{"naïve.key": 7}]);
        assert_eq!(
            select(&root_array, "$[0][\"naïve.key\"]")
                .expect("valid selector")
                .and_then(serde_json::Value::as_u64),
            Some(7)
        );
    }

    #[test]
    fn distinguishes_missing_values_from_invalid_syntax() {
        let json = serde_json::json!({"items": []});
        assert_eq!(select(&json, "$.items[0].name"), Ok(None));
        for invalid in [
            "",
            ".name",
            "name",
            "$.name.",
            "$.name..value",
            "$[]",
            "/name",
        ] {
            assert!(
                validate(invalid).is_err(),
                "selector should fail: {invalid:?}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_operators_and_platform_dependent_indexes() {
        for invalid in [
            "$.items[*]",
            "$.items[?(@.live)]",
            "$..name",
            "$.white space",
            "$[00]",
            "$[1000001]",
        ] {
            assert!(
                validate(invalid).is_err(),
                "selector should fail: {invalid:?}"
            );
        }
    }

    #[test]
    fn bounds_selector_size_depth_and_error_output() {
        let oversized = format!("$.{}", "a".repeat(super::MAX_SELECTOR_BYTES));
        let error = validate(&oversized).expect_err("oversized selector");
        let rendered = error.to_string();
        assert!(rendered.contains(&format!("{} bytes", oversized.len())));
        assert!(rendered.len() < 500, "error preview must stay bounded");

        let too_deep = format!("${}", ".a".repeat(super::MAX_SELECTOR_SEGMENTS + 1));
        assert!(validate(&too_deep).is_err());
    }
}
