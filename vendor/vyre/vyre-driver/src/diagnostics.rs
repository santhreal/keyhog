//! Structured, machine-readable diagnostics.
//!
//! Every fallible operation in vyre eventually surfaces a failure. The
//! legacy `Error` enum carried prose (and `Fix:` hints inside the
//! formatted message). That shape is great for humans reading stderr but
//! useless for IDEs, language servers, CI annotators, or editor
//! integrations that want to jump to the offending op and show a
//! lightbulb suggesting the fix.
//!
//! `Diagnostic` is the structured form: severity, stable code, message,
//! optional op location, optional suggested fix, optional doc URL.
//! Every `Error` variant converts into a `Diagnostic` via `From`. The
//! prose that lived inside `#[error(...)]` strings is split into the
//! `message` and `suggested_fix` fields — no data is lost, all of it
//! becomes addressable.
//!
//! Two consumption modes are guaranteed:
//!
//! * [`Diagnostic::render_human`] — rustc-style formatted output for
//!   terminals and logs.
//! * [`Diagnostic::to_json`] — stable JSON surface for LSP / editors /
//!   CI annotators.
//!
//! The diagnostic code (`E-*` for errors, `W-*` for warnings) is
//! stable across vyre versions — tooling can hang rules off the code
//! without worrying about prose drift.

use std::borrow::Cow;
use std::fmt::Write as _;

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::Error;

/// Deserialize helper that forces an owned `Cow<'static, str>`.
///
/// The default `Cow<'static, str>` serde path tries to borrow from the
/// input, which fails whenever the input buffer does not outlive the
/// deserialized value (the common case — a `String` on the stack).
/// Routing every field through this helper forces an owned `String`
/// under a `Cow::Owned`, which is always valid.
fn de_cow_static<'de, D: Deserializer<'de>>(d: D) -> Result<Cow<'static, str>, D::Error> {
    String::deserialize(d).map(Cow::Owned)
}

/// Deserialize helper for `Option<Cow<'static, str>>` — see
/// [`de_cow_static`] for the rationale.
fn de_opt_cow_static<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Cow<'static, str>>, D::Error> {
    Option::<String>::deserialize(d).map(|opt| opt.map(Cow::Owned))
}

/// Severity of a [`Diagnostic`].
///
/// `Error` halts compilation. `Warning` surfaces a deprecation or a
/// soft-failed invariant but leaves the program usable. `Note` is an
/// informational follow-up attached to another diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Severity {
    /// A hard failure — the caller must not use the program.
    Error,
    /// A soft failure — the program is usable but something is off
    /// (deprecated op, unused buffer, etc.).
    Warning,
    /// An informational follow-up attached to another diagnostic.
    Note,
}

impl Severity {
    /// Short label suitable for `render_human` ("error", "warning",
    /// "note").
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Note => "note",
        }
    }
}

/// Stable, machine-readable diagnostic code.
///
/// The code is a string of the form `E-<CATEGORY>-<NAME>` or
/// `W-<CATEGORY>-<NAME>`. Tooling hangs rules off the code, so the
/// spelling is a compatibility surface — do not rename codes, only
/// add new ones. Internally stored as `Cow<'static, str>` so that
/// built-in codes are zero-alloc `&'static str` while decoded codes
/// from JSON carry `String` ownership.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DiagnosticCode(#[serde(deserialize_with = "de_cow_static")] pub Cow<'static, str>);

impl DiagnosticCode {
    /// Construct a code from a static string (the common case).
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self(Cow::Borrowed(code))
    }

    /// The raw code string (e.g. `"E-INLINE-CYCLE"`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Location of a diagnostic inside a `Program`.
///
/// Diagnostics that pin-point an op (the common case) fill in
/// `op_id`. Operand-level diagnostics add `operand_idx`; attribute-
/// level diagnostics add `attr_name`. A diagnostic with no location
/// refers to the program as a whole (wire-format header issues, for
/// example).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpLocation {
    /// The op identifier (e.g., `"math.add"`).
    #[serde(deserialize_with = "de_cow_static")]
    pub op_id: Cow<'static, str>,
    /// Zero-based operand index, if the diagnostic is about a
    /// specific operand.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operand_idx: Option<u32>,
    /// Attribute name, if the diagnostic is about a specific
    /// attribute.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "de_opt_cow_static"
    )]
    pub attr_name: Option<Cow<'static, str>>,
}

impl OpLocation {
    /// Build a location that only identifies the op.
    #[must_use]
    pub fn op(op_id: impl Into<Cow<'static, str>>) -> Self {
        Self {
            op_id: op_id.into(),
            operand_idx: None,
            attr_name: None,
        }
    }

    /// Attach a specific operand index.
    #[must_use]
    pub fn with_operand(mut self, idx: u32) -> Self {
        self.operand_idx = Some(idx);
        self
    }

    /// Attach a specific attribute name.
    #[must_use]
    pub fn with_attr(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.attr_name = Some(name.into());
        self
    }
}

/// A structured diagnostic.
///
/// Every failure in vyre becomes a `Diagnostic`. See the module docs
/// for the rationale and the rendering contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Severity of the diagnostic.
    pub severity: Severity,
    /// Stable machine-readable code (e.g. `"E-INLINE-CYCLE"`).
    pub code: DiagnosticCode,
    /// The primary human-readable message.
    #[serde(deserialize_with = "de_cow_static")]
    pub message: Cow<'static, str>,
    /// Optional op / operand / attribute location.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub location: Option<OpLocation>,
    /// Optional actionable fix the caller can apply.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "de_opt_cow_static"
    )]
    pub suggested_fix: Option<Cow<'static, str>>,
    /// Optional documentation URL.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "de_opt_cow_static"
    )]
    pub doc_url: Option<Cow<'static, str>>,
}

impl Diagnostic {
    /// Construct a new error-severity diagnostic.
    #[must_use]
    pub fn error(code: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            severity: Severity::Error,
            code: DiagnosticCode::new(code),
            message: message.into(),
            location: None,
            suggested_fix: None,
            doc_url: None,
        }
    }

    /// Construct a new warning-severity diagnostic.
    #[must_use]
    pub fn warning(code: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            severity: Severity::Warning,
            code: DiagnosticCode::new(code),
            message: message.into(),
            location: None,
            suggested_fix: None,
            doc_url: None,
        }
    }

    /// Construct a new note-severity diagnostic.
    #[must_use]
    pub fn note(code: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            severity: Severity::Note,
            code: DiagnosticCode::new(code),
            message: message.into(),
            location: None,
            suggested_fix: None,
            doc_url: None,
        }
    }

    /// Attach an op location.
    #[must_use]
    pub fn with_location(mut self, loc: OpLocation) -> Self {
        self.location = Some(loc);
        self
    }

    /// Attach a suggested fix.
    #[must_use]
    pub fn with_fix(mut self, fix: impl Into<Cow<'static, str>>) -> Self {
        self.suggested_fix = Some(fix.into());
        self
    }

    /// Attach a documentation URL.
    #[must_use]
    pub fn with_doc_url(mut self, url: impl Into<Cow<'static, str>>) -> Self {
        self.doc_url = Some(url.into());
        self
    }

    /// Render the diagnostic as rustc-style human text.
    ///
    /// Format:
    /// ```text
    /// error[E-INLINE-CYCLE]: IR inlining cycle at operation `foo`
    ///   --> op `foo`
    ///   = help: remove the recursive Expr::Call chain ...
    ///   = note: https://docs.vyre.dev/errors/E-INLINE-CYCLE
    /// ```
    #[must_use]
    pub fn render_human(&self) -> String {
        let mut out = String::with_capacity(256);
        let _ = write!(
            out,
            "{}[{}]: {}",
            self.severity.label(),
            self.code,
            self.message
        );
        if let Some(loc) = &self.location {
            out.push_str("\n  --> op `");
            out.push_str(&loc.op_id);
            out.push('`');
            if let Some(idx) = loc.operand_idx {
                let _ = write!(out, " operand[{idx}]");
            }
            if let Some(attr) = &loc.attr_name {
                out.push_str(" attr `");
                out.push_str(attr);
                out.push('`');
            }
        }
        if let Some(fix) = &self.suggested_fix {
            out.push_str("\n  = help: ");
            out.push_str(fix);
        }
        if let Some(url) = &self.doc_url {
            out.push_str("\n  = note: ");
            out.push_str(url);
        }
        out
    }

    /// Serialize the diagnostic to a JSON string.
    ///
    /// The JSON shape is part of the stable tooling contract: LSP
    /// clients, editor integrations, and CI annotators consume it.
    /// Fields match the `Diagnostic` struct one-to-one; absent
    /// `location`, `suggested_fix`, and `doc_url` are omitted.
    #[must_use]
    pub fn to_json(&self) -> String {
        // CRITIQUE_DRIVER_2026-04-23 Finding 1.1: the backend wrapper
        // must never propagate a silent panic. The `Diagnostic` type
        // has no non-serializable fields *today*, but a future regression
        // (e.g. an added `HashMap<NonSerializable, _>` field) would panic
        // at runtime through every LSP and CI annotator. Serialize here
        // with an actionable fallback: if serde_json fails we return a
        // minimal hand-rolled JSON that names the regression, so the
        // caller still receives structured output and the error message
        // points at the fix site.
        match serde_json::to_string(self) {
            Ok(json) => json,
            Err(e) => {
                // Hand-roll a stable error envelope. The message names the
                // struct so `jq .error` catches the failure mode in CI.
                format!(
                    r#"{{"error":"Diagnostic::to_json serialization failed","code":"{code}","message":"{message}","serde_error":"{serde_error}","fix":"Fix: inspect Diagnostic fields for non-serializable types; every field must implement Serialize."}}"#,
                    code = self.code.as_str().replace('"', "\\\""),
                    message = self.message.replace('"', "\\\""),
                    serde_error = e.to_string().replace('"', "\\\""),
                )
            }
        }
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render_human())
    }
}

/// Split a legacy error message on the first `". Fix: "` delimiter.
///
/// Legacy `Error` variants encode the actionable hint inside the
/// `#[error(...)]` prose as `<message>. Fix: <fix>.`. This helper
/// lifts the fix out so `Diagnostic` can present it as structured
/// data. Messages without the delimiter pass through as-is with
/// `suggested_fix == None`.
fn split_fix(full: String) -> (String, Option<String>) {
    if let Some((head, tail)) = full.split_once(". Fix: ") {
        let head = head.to_owned();
        let tail = tail.trim_end_matches('.').to_owned();
        (head, Some(tail))
    } else {
        (full, None)
    }
}

/// Map a legacy `Error` variant to a diagnostic code + op location.
///
/// Codes are stable; changing them is a breaking API change.
fn classify(err: &Error) -> (&'static str, Option<OpLocation>) {
    match err {
        Error::InlineCycle { op_id } => ("E-INLINE-CYCLE", Some(OpLocation::op(op_id.clone()))),
        Error::InlineUnknownOp { op_id } => {
            ("E-INLINE-UNKNOWN-OP", Some(OpLocation::op(op_id.clone())))
        }
        Error::InlineNonInlinable { op_id } => (
            "E-INLINE-NON-INLINABLE",
            Some(OpLocation::op(op_id.clone())),
        ),
        Error::InlineArgCountMismatch { op_id, .. } => {
            ("E-INLINE-ARG-COUNT", Some(OpLocation::op(op_id.clone())))
        }
        Error::InlineNoOutput { op_id } => {
            ("E-INLINE-NO-OUTPUT", Some(OpLocation::op(op_id.clone())))
        }
        Error::InlineOutputCountMismatch { op_id, .. } => {
            ("E-INLINE-OUTPUT-COUNT", Some(OpLocation::op(op_id.clone())))
        }
        Error::WireFormatValidation { .. } => ("E-WIRE-VALIDATION", None),
        Error::Lowering { .. } => ("E-LOWERING", None),
        Error::Interp { .. } => ("E-INTERP", None),
        Error::Gpu { .. } => ("E-GPU", None),
        Error::DecodeConfig { .. } => ("E-DECODE-CONFIG", None),
        Error::Decode { .. } => ("E-DECODE", None),
        Error::Decompress { .. } => ("E-DECOMPRESS", None),
        Error::Dfa { .. } => ("E-DFA", None),
        Error::Dataflow { .. } => ("E-DATAFLOW", None),
        Error::Prefix { .. } => ("E-PREFIX", None),
        Error::Csr { .. } => ("E-CSR", None),
        Error::Serialization { .. } => ("E-SERIALIZATION", None),
        Error::RuleEval { .. } => ("E-RULE-EVAL", None),
        Error::VersionMismatch { .. } => ("E-WIRE-VERSION", None),
        Error::UnknownDialect { .. } => ("E-WIRE-UNKNOWN-DIALECT", None),
        Error::UnknownOp { dialect, op } => (
            "E-WIRE-UNKNOWN-OP",
            Some(OpLocation::op(format!("{dialect}.{op}"))),
        ),
        _ => ("E-UNKNOWN", None),
    }
}

impl From<&Error> for Diagnostic {
    fn from(err: &Error) -> Self {
        let (code, location) = classify(err);
        let (message, fix) = split_fix(err.to_string());
        let mut diag = Diagnostic::error(code, message);
        if let Some(fix) = fix {
            diag = diag.with_fix(fix);
        }
        if let Some(loc) = location {
            diag = diag.with_location(loc);
        }
        diag
    }
}

impl From<Error> for Diagnostic {
    fn from(err: Error) -> Self {
        Diagnostic::from(&err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_labels() {
        assert_eq!(Severity::Error.label(), "error");
        assert_eq!(Severity::Warning.label(), "warning");
        assert_eq!(Severity::Note.label(), "note");
    }

    #[test]
    fn split_fix_basic() {
        let (msg, fix) =
            split_fix("IR inlining cycle at operation `foo`. Fix: do the thing.".to_owned());
        assert_eq!(msg, "IR inlining cycle at operation `foo`");
        assert_eq!(fix.as_deref(), Some("do the thing"));
    }

    #[test]
    fn split_fix_absent() {
        let (msg, fix) = split_fix("no fix hint".to_owned());
        assert_eq!(msg, "no fix hint");
        assert!(fix.is_none());
    }

    #[test]
    fn render_inline_cycle() {
        let err = Error::InlineCycle {
            op_id: "foo".to_owned(),
        };
        let diag = Diagnostic::from(&err);
        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(diag.code.as_str(), "E-INLINE-CYCLE");
        assert!(diag.location.is_some());
        assert_eq!(diag.location.as_ref().unwrap().op_id.as_ref(), "foo");
        assert!(diag.suggested_fix.is_some());
        let rendered = diag.render_human();
        assert!(rendered.starts_with("error[E-INLINE-CYCLE]:"));
        assert!(rendered.contains("op `foo`"));
        assert!(rendered.contains("help:"));
    }

    #[test]
    fn json_round_trip() {
        let diag = Diagnostic::error("E-TEST", "boom")
            .with_location(OpLocation::op("math.add").with_operand(1))
            .with_fix("do the thing")
            .with_doc_url("https://docs.vyre.dev/E-TEST");
        let j = diag.to_json();
        let back: Diagnostic = serde_json::from_str(&j).unwrap();
        assert_eq!(back, diag);
    }

    #[test]
    fn every_error_variant_classifies() {
        // Every constructible variant must round-trip through the
        // classifier without panicking and produce a non-empty code.
        let samples = [
            Error::InlineCycle { op_id: "a".into() },
            Error::InlineUnknownOp { op_id: "a".into() },
            Error::InlineNonInlinable { op_id: "a".into() },
            Error::InlineArgCountMismatch {
                op_id: "a".into(),
                expected: 1,
                got: 2,
            },
            Error::InlineNoOutput { op_id: "a".into() },
            Error::InlineOutputCountMismatch {
                op_id: "a".into(),
                got: 2,
            },
            Error::WireFormatValidation {
                message: "bad bytes".into(),
            },
            Error::Lowering {
                message: "bad lower".into(),
            },
            Error::Interp {
                message: "bad interp".into(),
            },
            Error::Gpu {
                message: "bad gpu".into(),
            },
            Error::DecodeConfig {
                message: "bad cfg".into(),
            },
            Error::Decode {
                message: "bad decode".into(),
            },
            Error::Decompress {
                message: "bad decomp".into(),
            },
            Error::Dfa {
                message: "bad dfa".into(),
            },
            Error::Dataflow {
                message: "bad dataflow".into(),
            },
            Error::Prefix {
                message: "bad prefix".into(),
            },
            Error::Csr {
                message: "bad csr".into(),
            },
            Error::Serialization {
                message: "bad ser".into(),
            },
            Error::RuleEval {
                message: "bad rule".into(),
            },
            Error::VersionMismatch {
                expected: 3,
                found: 1,
            },
            Error::UnknownDialect {
                name: "math".into(),
                requested: "1.0".into(),
            },
            Error::UnknownOp {
                dialect: "math".into(),
                op: "add".into(),
            },
        ];
        for err in samples {
            let diag = Diagnostic::from(&err);
            assert!(diag.code.as_str().starts_with("E-"));
            assert!(!diag.message.is_empty());
            assert_eq!(diag.severity, Severity::Error);
            // render + JSON must not panic
            let _ = diag.render_human();
            let _ = diag.to_json();
        }
    }

    #[test]
    fn warning_and_note_constructors() {
        let w = Diagnostic::warning("W-DEPRECATED", "x is deprecated");
        assert_eq!(w.severity, Severity::Warning);
        assert!(w.render_human().starts_with("warning[W-DEPRECATED]:"));

        let n = Diagnostic::note("N-INFO", "fyi");
        assert_eq!(n.severity, Severity::Note);
        assert!(n.render_human().starts_with("note[N-INFO]:"));
    }

    #[test]
    fn operand_and_attr_location_render() {
        let diag = Diagnostic::error("E-X", "boom")
            .with_location(OpLocation::op("math.add").with_operand(2).with_attr("mode"));
        let r = diag.render_human();
        assert!(r.contains("op `math.add` operand[2] attr `mode`"));
    }
}
