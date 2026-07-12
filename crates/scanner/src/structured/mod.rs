//! Structured format preprocessor.
//!
//! Detects known configuration formats (.env, Kubernetes Secrets, Docker Compose,
//! Terraform state, Jupyter notebooks), extracts (context, value) pairs, and
//! appends them as scannable lines to the original text.  This lets the regex
//! pipeline see values with their keys as context while keeping original line
//! mappings intact.

use crate::types::ScannerPreprocessedText;

pub(crate) mod parsers;

const MAX_STRUCTURED_PARSE_BYTES: usize = 2 * 1024 * 1024;

/// Separator inserted between a key and its value in each synthetic scannable
/// line (`"{context}: {value}"`). Single owner for both the literal pushed into
/// the output text and the `.len()` used in the pre-size / offset arithmetic
/// below: if the two ever diverged, the synthetic-line offsets would be wrong.
const SYNTHETIC_PAIR_SEPARATOR: &str = ": ";

pub(crate) struct ExtractedPair {
    pub context: String,
    pub value: String,
    pub line: usize,
}

/// A recognised structured format, decoupled from parsing so the size cap can
/// reason about a file it is about to skip (which the coupled detect-and-parse
/// flow could not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StructuredFormat {
    Env,
    K8sSecret,
    DockerCompose,
    Tfstate,
    Hcl,
    Jupyter,
}

impl StructuredFormat {
    /// True for formats whose structured pass *decodes* values (base64 `data:`
    /// blocks etc.) the regular byte scan cannot recover. Skipping the structured
    /// pass on these is a real recall gap. `Env`/`Hcl` only extract plain scalar
    /// values the regular scan still sees, so skipping them loses context, not a
    /// secret — they must NOT be counted as coverage gaps (that would be the
    /// false-loud telemetry the module forbids).
    fn uses_decode_through(self) -> bool {
        matches!(
            self,
            Self::K8sSecret | Self::DockerCompose | Self::Tfstate | Self::Jupyter
        )
    }
}

/// The exact partition the structured size cap applies: an oversize skip is a
/// *counted* decode-through coverage gap only when the file is a recognised
/// decode-through format (k8s Secret / compose / tfstate / notebook) AND is not
/// a decode-derived buffer (whose encoded surface was already decoded and
/// scanned upstream). `Env`/`Hcl` are context-only — skipping them loses context
/// the regular byte scan still recovers, not a secret — so they are never
/// counted (Law 10: no false-loud telemetry). Single source of truth shared by
/// [`preprocess`] and its tests, so the counting decision cannot drift from the
/// classification it is tested against.
pub(crate) fn oversize_skip_is_counted(
    text: &str,
    path: Option<&str>,
    decode_derived: bool,
) -> bool {
    !decode_derived && detect_format(text, path).is_some_and(StructuredFormat::uses_decode_through)
}

/// Detect format by path and/or content, parse it, and build a preprocessed text.
/// Returns `None` when the file is not a recognised structured format, when it
/// exceeds the size limit, or when no pairs could be extracted.
/// Pre-process structured configuration files to extract key-value pairs.
///
/// `decode_derived` must be true when `text` is a buffer the decode-through
/// pipeline synthesised (the chunk carries `ChunkMetadata::decoded_span`), not
/// the original file. It is threaded to the YAML parsers so a parse failure on a
/// derived buffer - which is expected and loses nothing, because the encoded
/// surface was already decoded and scanned - is not counted or announced as a
/// lost decode surface (Law 10: no false-loud signals, honest telemetry).
pub(crate) fn preprocess<'a>(
    text: &str,
    path: Option<&str>,
    decode_derived: bool,
) -> Option<ScannerPreprocessedText<'a>> {
    if text.len() > MAX_STRUCTURED_PARSE_BYTES {
        // A recognised structured DECODE-THROUGH file (k8s Secret / compose /
        // tfstate / notebook) over the cap loses its base64 `data:` decode-through
        // surface, which the regular byte scan does not recover. Previously this
        // was a bare silent `return None` (Law 10 violation). Surface it loudly +
        // counted, like the parse-failure path. `decode_derived` buffers are not
        // counted: the encoded surface was already decoded and scanned upstream,
        // so a skip there loses nothing (no false-loud telemetry). Env/HCL are
        // not decode-through, so their oversize skip is genuinely lossless and
        // stays silent.
        if oversize_skip_is_counted(text, path, decode_derived) {
            crate::telemetry::record_structured_oversize_skip();
            tracing::warn!(
                bytes = text.len(),
                cap = MAX_STRUCTURED_PARSE_BYTES,
                path = path.unwrap_or("<unknown>"),
                "structured decode-through skipped: file exceeds the structured-parse \
                 size cap, so base64-encoded values (e.g. a k8s `data:` block) were NOT \
                 decoded; the raw text was still scanned"
            );
        }
        return None;
    }
    let pairs = detect_and_parse(text, path, decode_derived)?;
    if pairs.is_empty() {
        return None;
    }
    Some(build_preprocessed_text(text, pairs))
}

/// Detect which structured format `text`/`path` is, without parsing it. Pure
/// path/content sniffing — used both by `detect_and_parse` (to dispatch) and by
/// the size cap (to decide whether an oversized skip is a real recall gap).
fn detect_format(text: &str, path: Option<&str>) -> Option<StructuredFormat> {
    // ASCII case-insensitive byte compares - every chunk runs through this
    // detector to decide whether a structured parser applies. The previous
    // flow built a fully-lowercased copy of the path on every call.
    let path_bytes = path.map(str::as_bytes).unwrap_or(&[]); // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
    let ends_ci = |suffix: &[u8]| -> bool {
        path_bytes.len() >= suffix.len()
            && path_bytes[path_bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };
    let last_sep = path_bytes
        .iter()
        .rposition(|&b| b == b'/' || b == b'\\')
        .map(|i| i + 1)
        .unwrap_or(0); // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
    let file_bytes = &path_bytes[last_sep..];
    let file_starts_ci = |prefix: &[u8]| -> bool {
        file_bytes.len() >= prefix.len() && file_bytes[..prefix.len()].eq_ignore_ascii_case(prefix)
    };
    let file_ends_ci = |suffix: &[u8]| -> bool {
        file_bytes.len() >= suffix.len()
            && file_bytes[file_bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };
    let file_contains_ci = |needle: &[u8]| -> bool {
        if needle.is_empty() || needle.len() > file_bytes.len() {
            return false;
        }
        file_bytes
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    };

    if file_starts_ci(b".env") || file_ends_ci(b".env") {
        return Some(StructuredFormat::Env);
    }

    if (ends_ci(b".yaml") || ends_ci(b".yml")) && text.contains("kind: Secret") {
        return Some(StructuredFormat::K8sSecret);
    }

    if (file_contains_ci(b"docker-compose") || file_contains_ci(b"compose"))
        && (ends_ci(b".yaml") || ends_ci(b".yml"))
    {
        return Some(StructuredFormat::DockerCompose);
    }

    if ends_ci(b".tfstate") {
        return Some(StructuredFormat::Tfstate);
    }

    // HCL / Terraform configuration. The block shape
    //   variable "x" { default = "<value>" }
    // hides the credential keyword (`x`) on the header line and the
    // value two lines below. Per-line keyword scanning misses both.
    // Extract `(x, <value>)` pairs so the keyword sits adjacent to the
    // value as a synthetic line and named detectors fire.
    if ends_ci(b".tf") || ends_ci(b".tfvars") || ends_ci(b".hcl") {
        return Some(StructuredFormat::Hcl);
    }

    if ends_ci(b".ipynb") {
        return Some(StructuredFormat::Jupyter);
    }

    None
}

fn detect_and_parse(
    text: &str,
    path: Option<&str>,
    decode_derived: bool,
) -> Option<Vec<ExtractedPair>> {
    Some(match detect_format(text, path)? {
        StructuredFormat::Env => parsers::parse_env(text),
        StructuredFormat::K8sSecret => parsers::parse_k8s_secret(text, decode_derived),
        StructuredFormat::DockerCompose => parsers::parse_docker_compose(text, decode_derived),
        StructuredFormat::Tfstate => parsers::parse_tfstate(text, decode_derived),
        StructuredFormat::Hcl => parsers::parse_hcl(text),
        StructuredFormat::Jupyter => parsers::parse_jupyter(text, decode_derived),
    })
}

/// One synthesized offset→line mapping. Field-identical to both the multiline
/// and non-multiline `LineMapping`; the cfg-gated wrapper copies it into whichever
/// concrete type is active. This is the single owner of the offset arithmetic.
struct SynthMapping {
    line_number: usize,
    start_offset: usize,
    end_offset: usize,
    original_start_offset: usize,
}

/// Always-compiled offset synthesis: build `final_text` (original bytes + one
/// `'\n'` + each synthetic `"{context}: {value}"` line) and its flat mapping
/// table. Both `build_preprocessed_text` wrappers convert the result into the
/// feature-specific `LineMapping`/`PreprocessedText` type, so the offset math
/// lives in exactly one place.
fn synthesize_preprocessed(text: &str, pairs: Vec<ExtractedPair>) -> (String, Vec<SynthMapping>) {
    let original_end = text.len();

    // Pre-size the output: original bytes + one '\n' separator + each synthetic
    // line ("{context}: {value}\n"). Avoids repeated reallocation while pushing
    // and the throwaway String that a `format!` per pair would allocate.
    let appended_len: usize = pairs
        .iter()
        .map(|p| p.context.len() + SYNTHETIC_PAIR_SEPARATOR.len() + p.value.len() + 1)
        .sum();
    let mut final_text = String::with_capacity(original_end + 1 + appended_len);
    final_text.push_str(text);

    // One mapping per source line plus one per synthetic line.
    // `compute_line_offsets` already yields the byte start of every line in a
    // single SIMD (`memchr`) pass; reuse it for the source-line mappings instead
    // of re-walking the text twice more (a `.split('\n').count()` plus a
    // `.split('\n').enumerate()`). Line count == number of line-start offsets.
    let source_line_offsets = crate::compute_line_offsets(text);
    let line_count = source_line_offsets.len();
    let mut mappings: Vec<SynthMapping> = Vec::with_capacity(line_count + pairs.len());

    for line_idx in 0..line_count {
        let start = source_line_offsets[line_idx];
        // End of this line is the start of the next (one past its '\n'); the
        // final newline-less line clamps to the text length instead of one past.
        let end = source_line_offsets
            .get(line_idx + 1)
            .copied()
            .unwrap_or(original_end)
            .min(original_end);
        mappings.push(SynthMapping {
            line_number: line_idx + 1,
            start_offset: start,
            end_offset: end,
            original_start_offset: start,
        });
    }

    final_text.push('\n');
    let mut current_offset = original_end + 1;
    for pair in pairs {
        // line == "{context}: {value}"; push the parts directly instead of
        // allocating an intermediate String via format!.
        let line_len = pair.context.len() + SYNTHETIC_PAIR_SEPARATOR.len() + pair.value.len();
        mappings.push(SynthMapping {
            line_number: pair.line,
            start_offset: current_offset,
            end_offset: current_offset + line_len,
            original_start_offset: source_line_start(&source_line_offsets, pair.line),
        });
        final_text.push_str(&pair.context);
        final_text.push_str(SYNTHETIC_PAIR_SEPARATOR);
        final_text.push_str(&pair.value);
        final_text.push('\n');
        current_offset += line_len + 1;
    }

    (final_text, mappings)
}

#[cfg(feature = "multiline")]
fn build_preprocessed_text<'a>(
    text: &str,
    pairs: Vec<ExtractedPair>,
) -> ScannerPreprocessedText<'a> {
    use crate::multiline::LineMapping;
    let original_end = text.len();
    let (final_text, synth) = synthesize_preprocessed(text, pairs);
    let mappings = synth
        .into_iter()
        .map(|m| LineMapping {
            line_number: m.line_number,
            start_offset: m.start_offset,
            end_offset: m.end_offset,
            original_start_offset: m.original_start_offset,
        })
        .collect();
    crate::multiline::PreprocessedText {
        // Synthesized text (original + appended key/value lines): owned.
        text: std::borrow::Cow::Owned(final_text),
        original_end,
        mappings,
    }
}

#[cfg(not(feature = "multiline"))]
fn build_preprocessed_text<'a>(
    text: &str,
    pairs: Vec<ExtractedPair>,
) -> ScannerPreprocessedText<'a> {
    use crate::types::LineMapping;
    let (final_text, synth) = synthesize_preprocessed(text, pairs);
    let mappings = synth
        .into_iter()
        .map(|m| LineMapping {
            line_number: m.line_number,
            start_offset: m.start_offset,
            end_offset: m.end_offset,
            original_start_offset: m.original_start_offset,
        })
        .collect();
    crate::types::PreprocessedText {
        // Synthesized text (original + appended key/value lines): owned.
        text: std::borrow::Cow::Owned(final_text),
        mappings,
    }
}

fn source_line_start(line_offsets: &[usize], one_based_line: usize) -> usize {
    line_offsets
        .get(one_based_line.saturating_sub(1))
        .copied()
        .unwrap_or(0) // LAW10: reporting-only fallback for malformed structured pair line
}
