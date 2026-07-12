//! Path-glob matching engine for the allowlist.
//!
//! This module owns the gitignore-style path matcher used to suppress findings
//! by path: pattern normalization, segment splitting, the first-segment
//! bucketed [`PathGlobIndex`], and the segment-automaton matcher itself
//! ([`glob_match_segments`] + the ASCII/char `*`-wildcard backtrackers). It is
//! a self-contained subsystem - the [`super::Allowlist`] type holds a
//! precompiled [`PathGlobIndex`] and delegates every path decision here, so the
//! glob automaton can be tested and evolved independently of `.keyhogignore`
//! parsing and hash/detector suppression.

use std::collections::HashMap;
use std::path::Component;
use std::path::Path;

pub(super) const MAX_GLOB_SEGMENTS: usize = 256;
pub(super) const MAX_GLOB_SEGMENT_LEN: usize = 1024;

/// The one oversize fail-safe predicate, shared by the pattern side (`build`)
/// and the path side (`matches`) so the two verdicts can never drift. Too many
/// segments or a single over-long segment is refused rather than matched.
fn segments_oversize<S: AsRef<str>>(segments: &[S]) -> bool {
    segments.len() > MAX_GLOB_SEGMENTS
        || segments
            .iter()
            .any(|s| s.as_ref().len() > MAX_GLOB_SEGMENT_LEN)
}

/// One precompiled ignored-path glob: its normalized segments computed ONCE at
/// parse time, plus the oversize verdict that `glob_match_normalized` used to
/// recompute per finding. `anchor` records how the pattern's first segment can
/// match a path's first segment, so the index can skip patterns that cannot
/// possibly match a given path without running the full automaton.
#[derive(Debug, Clone)]
struct CompiledGlob {
    /// Normalized pattern segments (the `normalize_path` + `split_segments`
    /// result, owned). Empty when the pattern normalized to nothing.
    segments: Vec<String>,
    /// True when the pattern (or, at match time, the path) is too large to
    /// match safely - preserves the original `glob_match_normalized` fail-safe.
    /// A path larger than the cap is rejected at match time; an oversize
    /// pattern is pre-marked here so it never matches anything.
    oversize: bool,
}

/// First-segment bucketed index over the compiled globs. A path can match a
/// glob only if the glob's first segment is `**` (matches any prefix), or it
/// matches the path's FIRST segment. Literal first segments key a hash bucket;
/// wildcard / `**` first segments (which can match many first segments) fall
/// into `wild_first`, always tested. This turns the per-finding O(rules) sweep
/// into O(wild_first + matching_literal_bucket), sub-linear in total rule count
/// for the realistic monorepo `.gitignore` shape (mostly literal-anchored dir
/// rules), while reproducing `glob_match_segments` bit-for-bit.
#[derive(Debug, Clone, Default)]
pub(super) struct PathGlobIndex {
    /// Globs whose first segment is a pure literal, keyed by that literal. A
    /// path is tested only against the bucket for its own first segment.
    literal_first: HashMap<String, Vec<CompiledGlob>>,
    /// Globs whose first segment is `**` or contains a `*` wildcard (it can
    /// match more than one distinct first segment, so it cannot be bucketed by
    /// a literal). Always tested.
    wild_first: Vec<CompiledGlob>,
    /// Globs that normalized to ZERO segments (e.g. a pattern that was only
    /// `.` / `..` noise). `glob_match_segments(&[], path)` is true only for the
    /// empty path, so these are kept apart and only consulted for that case.
    empty_pattern: Vec<CompiledGlob>,
    /// Source patterns this index was compiled from. `ignored_paths` is a
    /// PUBLIC, mutable field: callers may push/extend/clear OR replace entries
    /// directly after construction. The matcher compares this against the live
    /// `ignored_paths` and rebuilds on mismatch, so a directly-mutated allowlist
    /// never silently under- or over-suppresses. Construction paths
    /// (`parse`/`load`/`empty`) keep it in sync, so the hot scanner path pays
    /// only a Vec equality check over the same small rule list the old
    /// length-only guard already inspected.
    source_patterns: Vec<String>,
}

impl PathGlobIndex {
    /// Build the index from raw ignored-path patterns. Runs `normalize_path` +
    /// `split_segments` + the oversize scan ONCE per pattern (the work
    /// `glob_match_normalized` previously repeated on every finding).
    pub(super) fn build(patterns: &[String]) -> Self {
        let mut index = PathGlobIndex {
            source_patterns: patterns.to_vec(),
            ..PathGlobIndex::default()
        };
        for pattern in patterns {
            let directory_pattern = pattern.replace('\\', "/").ends_with('/');
            let mut normalized_pattern = normalize_path(pattern);
            if directory_pattern && !normalized_pattern.is_empty() {
                normalized_pattern.push_str("/**");
            }
            let segments: Vec<String> = split_segments(&normalized_pattern)
                .into_iter()
                .map(str::to_string)
                .collect();
            // Mirror the pattern half of the original oversize fail-safe: an
            // oversize pattern can never match (it returned false before).
            let oversize = segments_oversize(&segments);
            let glob = CompiledGlob { segments, oversize };

            match glob.segments.first() {
                None => index.empty_pattern.push(glob),
                Some(first) if first == "**" || first.contains('*') => {
                    index.wild_first.push(glob);
                }
                Some(first) => {
                    index
                        .literal_first
                        .entry(first.clone())
                        .or_default()
                        .push(glob);
                }
            }
        }
        index
    }

    /// True when this index was compiled from the current public pattern list.
    /// Length-only checks miss in-place replacement (`ignored_paths[0] = ...`)
    /// because the public Vec shape stays the same while suppression semantics
    /// change.
    pub(super) fn matches_sources(&self, patterns: &[String]) -> bool {
        self.source_patterns == patterns
    }

    /// True when any compiled glob matches `normalized_path`. Tests only the
    /// candidate set for `normalized_path`'s first segment plus the always-on
    /// wildcard-anchored globs - never the full rule list.
    pub(super) fn matches(&self, normalized_path: &str) -> bool {
        let path_segments = split_segments(normalized_path);

        // Path-side oversize fail-safe (was recomputed per pattern before).
        if segments_oversize(&path_segments) {
            tracing::warn!(
                "skipping oversized allowlist path match ({} segments). Fix: shorten the path",
                path_segments.len()
            );
            return false;
        }

        let test = |glob: &CompiledGlob| -> bool {
            !glob.oversize && glob_match_segments(&glob.segments, &path_segments)
        };

        // Empty path: only a zero-segment pattern (or a `**`-led one, which is
        // in wild_first) can match. Mirror `glob_match_segments(&[], &[])`.
        if path_segments.is_empty() {
            return self.empty_pattern.iter().any(test) || self.wild_first.iter().any(test);
        }

        let first = path_segments[0];
        if let Some(bucket) = self.literal_first.get(first) {
            if bucket.iter().any(test) {
                return true;
            }
        }
        self.wild_first.iter().any(test)
    }
}

pub(super) fn split_segments(path: &str) -> Vec<&str> {
    if path.is_empty() {
        Vec::new()
    } else {
        path.split(['/', '\\']).collect()
    }
}

/// Segment-automaton glob match. Pattern segments are accepted by reference
/// (`AsRef<str>`) so the precompiled `Vec<String>` index entries match WITHOUT
/// re-borrowing into a `Vec<&str>` per finding; the path segments stay
/// `&[&str]` (borrowed from the normalized path string). The matching logic is
/// byte-for-byte the original automaton - only the pattern element type was
/// generalized, so suppression decisions are identical.
fn glob_match_segments<S: AsRef<str>>(pattern: &[S], path: &[&str]) -> bool {
    // Two reusable state rows swapped per segment - the previous code allocated
    // a fresh `next` Vec for every pattern segment (O(pattern) heap allocs per
    // finding); reusing two buffers makes it two allocations total.
    let mut states = vec![false; path.len() + 1];
    let mut next = vec![false; path.len() + 1];
    states[0] = true;

    for segment in pattern {
        let segment = segment.as_ref();
        next.iter_mut().for_each(|slot| *slot = false);
        if segment == "**" {
            let mut reachable = false;
            for idx in 0..=path.len() {
                reachable |= states[idx];
                next[idx] = reachable;
            }
        } else {
            for idx in 0..path.len() {
                if states[idx] && segment_match(segment, path[idx]) {
                    next[idx + 1] = true;
                }
            }
        }
        std::mem::swap(&mut states, &mut next);
    }

    states[path.len()]
}

fn segment_match(pattern: &str, text: &str) -> bool {
    if pattern.is_ascii() && text.is_ascii() {
        return segment_match_units(pattern.as_bytes(), text.as_bytes(), b'*');
    }

    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    segment_match_units(&pattern_chars, &text_chars, '*')
}

#[allow(clippy::similar_names)] // star_pi / star_ti name the same Kleene-star state in two coordinate systems
fn segment_match_units<T>(pattern: &[T], text: &[T], star_unit: T) -> bool
where
    T: Copy + Eq,
{
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi = None;
    let mut star_ti = 0usize;

    while ti < text.len() {
        if pi < pattern.len() && pattern[pi] == star_unit {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
            continue;
        }

        if pi < pattern.len() && pattern[pi] == text[ti] {
            pi += 1;
            ti += 1;
            continue;
        }

        if let Some(star) = star_pi {
            star_ti += 1;
            ti = star_ti;
            pi = star + 1;
            continue;
        }

        return false;
    }

    while pi < pattern.len() && pattern[pi] == star_unit {
        pi += 1;
    }

    pi == pattern.len()
}

pub(super) fn normalize_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let mut parts = Vec::new();
    for component in Path::new(&path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !parts.is_empty() && parts.last().is_some_and(|part| part != "..") {
                    parts.pop();
                } else {
                    parts.push("..".to_string());
                }
            }
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::RootDir => parts.clear(),
            Component::Prefix(prefix) => parts.push(prefix.as_os_str().to_string_lossy().into()),
        }
    }
    parts.join("/")
}
