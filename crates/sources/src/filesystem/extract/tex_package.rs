//! Bounded dependency and provenance analysis for TeX source archives.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_PACKAGE_MEMBERS: usize = 16_384;
const MAX_SOURCE_MEMBER_BYTES: usize = 2 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REFERENCES_PER_MEMBER: usize = 4_096;
const MAX_COMMENT_SPANS_PER_MEMBER: usize = 65_536;
const MAX_PACKAGE_PROVENANCE_SPANS: usize = 131_072;
const MAX_GROUP_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TexMemberRole {
    Root,
    Referenced,
    Orphaned,
}

impl TexMemberRole {
    pub(super) const fn source_type(self) -> &'static str {
        match self {
            Self::Root => "filesystem/archive/tex-root",
            Self::Referenced => "filesystem/archive/tex-referenced",
            Self::Orphaned => "filesystem/archive/tex-orphaned",
        }
    }

    pub(super) const fn comment_source_type(self) -> &'static str {
        match self {
            Self::Root => "filesystem/archive/tex-comment/root",
            Self::Referenced => "filesystem/archive/tex-comment/referenced",
            Self::Orphaned => "filesystem/archive/tex-comment/orphaned",
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct TexMemberProvenance {
    pub(super) role: TexMemberRole,
    pub(super) comment_spans: Vec<(usize, usize)>,
}

#[derive(Default)]
pub(super) struct TexPackageBuilder {
    members: BTreeMap<String, Option<Vec<u8>>>,
    source_bytes: usize,
    bounded: bool,
}

impl TexPackageBuilder {
    pub(super) const fn source_member_read_cap() -> u64 {
        MAX_SOURCE_MEMBER_BYTES as u64
    }

    pub(super) fn mark_bounded(&mut self) {
        self.bounded = true;
    }

    pub(super) fn add_member(&mut self, name: &str, content: Option<&[u8]>) {
        if self.members.len() >= MAX_PACKAGE_MEMBERS || self.members.contains_key(name) {
            self.bounded = true;
            return;
        }

        let source = content.and_then(|bytes| {
            if bytes.len() > MAX_SOURCE_MEMBER_BYTES
                || self.source_bytes.saturating_add(bytes.len()) > MAX_SOURCE_BYTES
            {
                self.bounded = true;
                None
            } else {
                self.source_bytes += bytes.len();
                Some(bytes.to_vec())
            }
        });
        self.members.insert(name.to_string(), source);
    }

    pub(super) fn finish(self) -> TexPackageAnalysis {
        if self.bounded {
            return TexPackageAnalysis::bounded();
        }

        let member_names: BTreeSet<&str> = self.members.keys().map(String::as_str).collect();
        let mut parsed = BTreeMap::new();
        let mut roots = BTreeSet::new();
        let mut provenance_spans = 0usize;
        for (name, content) in &self.members {
            let Some(content) = content else {
                continue;
            };
            let Ok(text) = std::str::from_utf8(content) else {
                continue;
            };
            let document = parse_document(text);
            provenance_spans = provenance_spans
                .saturating_add(document.references.len())
                .saturating_add(document.comment_spans.len());
            if document.bounded || provenance_spans > MAX_PACKAGE_PROVENANCE_SPANS {
                return TexPackageAnalysis::bounded();
            }
            if document.is_root {
                roots.insert(name.clone());
            }
            parsed.insert(name.clone(), document);
        }

        if roots.is_empty() {
            return TexPackageAnalysis::default();
        }

        let mut reachable = roots.clone();
        let mut queue: VecDeque<String> = roots.iter().cloned().collect();
        while let Some(parent) = queue.pop_front() {
            let Some(document) = parsed.get(&parent) else {
                continue;
            };
            for reference in &document.references {
                if let Some(target) = resolve_reference(&parent, reference, &member_names) {
                    if reachable.insert(target.clone()) {
                        queue.push_back(target);
                    }
                }
            }
        }

        drop(member_names);
        let mut members = BTreeMap::new();
        let mut source_contents = BTreeMap::new();
        for (name, content) in self.members {
            let role = if roots.contains(&name) {
                TexMemberRole::Root
            } else if reachable.contains(&name) {
                TexMemberRole::Referenced
            } else {
                TexMemberRole::Orphaned
            };
            let comment_spans = parsed
                .get(&name)
                .map(|document| document.comment_spans.clone())
                .unwrap_or_default(); // LAW10: absent optional TeX parse metadata means no comment spans; member bytes are still scanned.
            if let Some(content) = content {
                source_contents.insert(name.clone(), content);
            }
            members.insert(
                name,
                TexMemberProvenance {
                    role,
                    comment_spans,
                },
            );
        }

        TexPackageAnalysis {
            members,
            source_contents,
            bounded: false,
        }
    }
}

#[derive(Default)]
pub(super) struct TexPackageAnalysis {
    members: BTreeMap<String, TexMemberProvenance>,
    source_contents: BTreeMap<String, Vec<u8>>,
    bounded: bool,
}

impl TexPackageAnalysis {
    fn bounded() -> Self {
        Self {
            members: BTreeMap::new(),
            source_contents: BTreeMap::new(),
            bounded: true,
        }
    }

    pub(super) fn get(&self, name: &str) -> Option<&TexMemberProvenance> {
        self.members.get(name)
    }

    pub(super) fn is_bounded(&self) -> bool {
        self.bounded
    }

    pub(super) fn take_source_content(&mut self, name: &str) -> Option<Vec<u8>> {
        self.source_contents.remove(name)
    }
}

pub(super) fn member_needs_source_bytes(name: &str) -> bool {
    name.rsplit_once('.')
        .map(|(_, ext)| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "tex" | "ltx" | "sty" | "cls"
            )
        })
        .unwrap_or(false) // LAW10: a member without an extension is not TeX source; recall-preserving ordinary archive scanning still handles the member.
}

pub(super) fn bytes_might_contain_source_extension(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|window| {
        window[0] == b'.'
            && matches!(
                [
                    window[1].to_ascii_lowercase(),
                    window[2].to_ascii_lowercase(),
                    window[3].to_ascii_lowercase(),
                ],
                [b't', b'e', b'x'] | [b'l', b't', b'x'] | [b's', b't', b'y'] | [b'c', b'l', b's']
            )
    })
}

#[derive(Debug)]
struct ParsedDocument {
    is_root: bool,
    references: Vec<Reference>,
    comment_spans: Vec<(usize, usize)>,
    bounded: bool,
}

#[derive(Clone, Copy, Debug)]
enum ReferenceKind {
    Tex,
    Graphics,
    Bibliography,
}

#[derive(Debug)]
struct Reference {
    kind: ReferenceKind,
    value: String,
}

fn parse_document(text: &str) -> ParsedDocument {
    let bytes = text.as_bytes();
    let (comment_spans, mut bounded) = comment_spans(bytes);
    let mut references = Vec::new();
    let mut is_root = false;
    let mut cursor = 0usize;
    let mut comment_index = 0usize;

    while cursor < bytes.len() {
        while comment_index < comment_spans.len() && comment_spans[comment_index].1 <= cursor {
            comment_index += 1;
        }
        if comment_index < comment_spans.len() && comment_spans[comment_index].0 <= cursor {
            cursor = comment_spans[comment_index].1;
            continue;
        }
        if bytes[cursor] != b'\\' {
            cursor += 1;
            continue;
        }

        let command_start = cursor + 1;
        let mut command_end = command_start;
        while command_end < bytes.len()
            && (bytes[command_end].is_ascii_alphabetic() || bytes[command_end] == b'@')
        {
            command_end += 1;
        }
        if command_end == command_start {
            cursor = cursor.saturating_add(2);
            continue;
        }
        let command = &text[command_start..command_end];
        let mut argument_cursor = command_end;
        if bytes.get(argument_cursor) == Some(&b'*') {
            argument_cursor += 1;
        }
        argument_cursor = skip_space(bytes, argument_cursor);
        let mut malformed_optional = false;
        while bytes.get(argument_cursor) == Some(&b'[') {
            let Some((_, end)) = parse_group(bytes, argument_cursor, b'[', b']') else {
                malformed_optional = true;
                break;
            };
            argument_cursor = skip_space(bytes, end);
        }
        if malformed_optional {
            cursor = command_end;
            continue;
        }

        if matches!(command, "documentclass" | "begin") {
            if let Some((value, end)) = parse_required_value(text, argument_cursor) {
                is_root |= command == "documentclass"
                    || (command == "begin" && value.trim() == "document");
                cursor = end;
                continue;
            }
        }

        let kind = match command {
            "input" | "include" | "subfile" => Some(ReferenceKind::Tex),
            "includegraphics" => Some(ReferenceKind::Graphics),
            "bibliography" | "addbibresource" => Some(ReferenceKind::Bibliography),
            _ => None,
        };
        if let Some(kind) = kind {
            if let Some((value, end)) = parse_required_value(text, argument_cursor) {
                for raw in value.split(',') {
                    let value = raw.trim();
                    if !value.is_empty() {
                        if references.len() < MAX_REFERENCES_PER_MEMBER {
                            references.push(Reference {
                                kind,
                                value: value.to_string(),
                            });
                        } else {
                            bounded = true;
                        }
                    }
                }
                cursor = end;
                continue;
            }
        }

        cursor = command_end;
    }

    ParsedDocument {
        is_root,
        references,
        comment_spans,
        bounded,
    }
}

fn comment_spans(bytes: &[u8]) -> (Vec<(usize, usize)>, bool) {
    let mut spans = Vec::new();
    let mut bounded = false;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] != b'%' || is_escaped(bytes, cursor) {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < bytes.len() && bytes[cursor] != b'\n' && bytes[cursor] != b'\r' {
            cursor += 1;
        }
        if spans.len() < MAX_COMMENT_SPANS_PER_MEMBER {
            spans.push((start, cursor));
        } else {
            bounded = true;
        }
    }
    (spans, bounded)
}

fn is_escaped(bytes: &[u8], index: usize) -> bool {
    let mut slashes = 0usize;
    let mut cursor = index;
    while cursor > 0 && bytes[cursor - 1] == b'\\' {
        slashes += 1;
        cursor -= 1;
    }
    slashes % 2 == 1
}

fn skip_space(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    cursor
}

fn parse_required_value(text: &str, cursor: usize) -> Option<(&str, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(cursor) == Some(&b'{') {
        let (span, end) = parse_group(bytes, cursor, b'{', b'}')?;
        return Some((&text[span.0..span.1], end));
    }

    let mut end = cursor;
    while end < bytes.len()
        && !bytes[end].is_ascii_whitespace()
        && !matches!(bytes[end], b'%' | b'\\' | b'{' | b'}')
    {
        end += 1;
    }
    (end > cursor).then_some((&text[cursor..end], end))
}

fn parse_group(bytes: &[u8], start: usize, open: u8, close: u8) -> Option<((usize, usize), usize)> {
    if bytes.get(start) != Some(&open) {
        return None;
    }
    let mut depth = 1usize;
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == open && !is_escaped(bytes, cursor) {
            depth += 1;
            if depth > MAX_GROUP_DEPTH {
                return None;
            }
        } else if bytes[cursor] == close && !is_escaped(bytes, cursor) {
            depth -= 1;
            if depth == 0 {
                return Some(((start + 1, cursor), cursor + 1));
            }
        }
        cursor += 1;
    }
    None
}

fn resolve_reference(
    parent: &str,
    reference: &Reference,
    members: &BTreeSet<&str>,
) -> Option<String> {
    let parent_dir = parent.rsplit_once('/').map(|(dir, _)| dir).unwrap_or(""); // LAW10: a root-level TeX member has the documented default empty parent path; reference resolution remains exact.
    let raw = reference.value.trim().trim_matches('"').replace('\\', "/");
    if raw.is_empty() || raw.starts_with('/') || raw.contains('\0') {
        return None;
    }
    let joined = if parent_dir.is_empty() {
        raw
    } else {
        format!("{parent_dir}/{raw}")
    };
    let normalized = normalize_relative_path(&joined)?;

    let extensions: &[&str] = match reference.kind {
        ReferenceKind::Tex => &["tex"],
        ReferenceKind::Graphics => &["pdf", "png", "jpg", "jpeg", "eps", "svg"],
        ReferenceKind::Bibliography => &["bib"],
    };
    if members.contains(normalized.as_str()) {
        return Some(normalized);
    }
    extensions.iter().find_map(|extension| {
        let candidate = format!("{normalized}.{extension}");
        members.contains(candidate.as_str()).then_some(candidate)
    })
}

fn normalize_relative_path(path: &str) -> Option<String> {
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            _ => components.push(component),
        }
    }
    (!components.is_empty()).then(|| components.join("/"))
}
