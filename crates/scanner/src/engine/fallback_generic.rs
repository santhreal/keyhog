use super::*;
use aho_corasick::AhoCorasick;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::LazyLock;

static GENERIC_RE: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
    // The keyword -> value bridge accepts:
    //   1. `key = "v"` / `key="v"` (Python/Ruby/JS/sh)
    //   2. `key: "v"` (YAML, modern JSON-ish)
    //   3. `"key": "v"` (JSON - closing quote of key is allowed before `:`)
    //   4. `const KEY: &str = "v"` (Rust with type)
    //
    // Group 1 is the KEYWORD, group 2 is the VALUE. The keyword is captured (not
    // the usual non-capturing alternation) so the caller can apply a whole-word
    // left boundary in code — see `keyword_has_word_boundary`. A pure-regex
    // boundary cannot be used here: `[^A-Za-z]` would reject camelCase keys
    // (`clientSecret`, `apiToken`, `accessKey`), which are pervasive in real
    // JS/Java/C# code and cost ~40 real CredData positives when tried. The code
    // boundary accepts a separator/start OR a lowercase->Uppercase camelCase
    // transition, so `GRAPHITE_PASS=`, `clientSecret=` and `SECRET=` all match
    // while `bypass=`/`compass=`/`xtoken=` do not. This is what makes the short
    // `pass` abbreviation safe to include (CredData's dominant `*_PASS=` shape).
    match regex::Regex::new(
        r#"(?i)(secret|passphrase|password|passwd|pwd|pass|token|api[._-]?key|apikey|auth[._-]?token|auth[._-]?key|credential|private[._-]?key|signing[._-]?key|encryption[._-]?key|access[._-]?key|client[._-]?secret|app[._-]?secret|master[._-]?key|license[._-]?key)["'`]?\s*[=:]\s*(?:&?[a-zA-Z_][a-zA-Z0-9_<>]*\s*[=:]\s*)?["'`]?([a-zA-Z0-9/+=_.:!@#$%^&*-]{8,128})["'`]?"#
    ) {
        Ok(re) => Some(re),
        // Law 10: this static, build-from-constant regex compiling is a build
        // invariant. If it ever fails the generic value bridge (the dominant
        // CredData `*_PASS=` / `secret:` surface) goes dark — there is no
        // recall-preserving alternative, so surface it as loudly as possible.
        Err(e) => {
            crate::prefilter_degrade::warn_prefilter_disabled(
                "generic-assignment value bridge (GENERIC_RE)",
                &e,
            );
            None
        }
    }
});

static KEYWORD_AC: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
    match AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(
            super::scan_filters::GENERIC_ASSIGNMENT_KEYWORDS
                .iter()
                .copied(),
        ) {
        Ok(ac) => Some(ac),
        Err(e) => {
            crate::prefilter_degrade::warn_prefilter_disabled(
                "generic-assignment keyword prefilter (KEYWORD_AC)",
                &e,
            );
            None
        }
    }
});

pub(crate) fn warm_generic_assignment_runtime() {
    let _ = GENERIC_RE.as_ref();
    let _ = KEYWORD_AC.as_ref();
}

/// Whole-word left boundary for the [`GENERIC_RE`] keyword bridge, applied in
/// code because the `regex` crate has no lookbehind and a `[^A-Za-z]` regex
/// prefix would reject camelCase credential keys (`apiToken`, `clientSecret`,
/// `accessKey`), which are pervasive in real JS/Java/C# source and cost ~40 real
/// CredData positives when tried as a pure-regex boundary.
///
/// The keyword at byte offset `kw_start` in `line` is a genuine word-start when
/// it begins the line, follows a non-letter byte (`_`, `-`, `.`, space, quote,
/// digit, or any non-ASCII), or sits at a lowercase->Uppercase camelCase hinge.
/// This rejects substring tails such as the `pass` in `bypass`/`compass` and the
/// `token` in `xtoken`, which is what makes the bare `pass` abbreviation safe.
fn keyword_has_word_boundary(line: &str, kw_start: usize) -> bool {
    if kw_start == 0 {
        return true;
    }
    let bytes = line.as_bytes();
    let prev = bytes[kw_start - 1];
    if !prev.is_ascii_alphabetic() {
        return true;
    }
    // `prev` is a letter: the only legitimate in-word start is a camelCase
    // hinge — a lowercase byte immediately followed by the (uppercase) keyword.
    let kw_first = bytes[kw_start];
    prev.is_ascii_lowercase() && kw_first.is_ascii_uppercase()
}

/// KH-L-0110: True iff the bridge `keyword` → `value` capture is a COMPLETE
/// pure-hex value of canonical key length (32 or 48) anchored by a STRONG
/// cryptographic-key keyword — a real key, not a hash digest.
///
/// On the real CredData corpus these are overwhelmingly genuine: hex48+kw is
/// 1033 POS / **0 NEG** (precision 1.0), hex32+kw 1279 / 31 (0.976). Yet the
/// bare-hex-digest shape gate (`suppression::shape_gates::looks_like_bare_hex_
/// digest`, lengths 32|40|48|56|64|72|128) suppresses them as MD5/SHA1 digests,
/// pinning generic recall near zero on this dominant shape.
///
/// Safe on BOTH bench corpora: the SecretBench mirror's `negatives.py` plants
/// hex hash-decoys ONLY at length 40 (sha1 / git-commit-sha) and 64 (sha256 /
/// docker-image-digest) — never 32 or 48 — and the decision-tree's v18 bare-hex
/// FP regression (3304 FPs) was entirely len-40/64. So hex32/48 carry no
/// hash-shaped negative twin; lifting them cannot reproduce the v31 `TOKEN=<hex>`
/// catastrophe (which was the len-64 sha256 class).
///
/// Soundness vs the truncated-sha256-prefix that the gate's len-48 entry exists
/// to catch: that truncation is produced by the weak-anchor NAMED path's
/// `[a-f0-9]{32,48}` detector regexes capping mid-span. The keyword bridge's
/// [`GENERIC_RE`] captures group 2 with `{8,128}` (NOT 48), so a length-48
/// capture here is the COMPLETE hex run, terminated by a non-charclass byte —
/// provably not a 64-hex sha256 prefix (which would capture as 64, a non-exempt
/// length). hex40/hex64 are deliberately NOT exempted.
///
/// Only the bare-hex-digest arm is skipped; the repetitive / fake-sequence /
/// placeholder / prefixed-`sha256:` arms in `should_suppress_inner` still run,
/// so `deadbeef…`-style decoys and `0123456789abcdef…` sequences are unaffected.
fn is_strong_keyword_anchored_hex_key(keyword: &str, value: &str) -> bool {
    if !matches!(value.len(), 32 | 48) {
        return false;
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    // Canonicalize the captured keyword: case-fold and drop `_`/`-`/`.` so
    // `API_KEY`, `api-key`, `encryption_key`, `clientSecret` all normalize to a
    // single token, then match the STRONG cryptographic-key family ONLY.
    // Deliberately EXCLUDES the weaker / more ambiguous bridge anchors
    // (`token`, `pass*`, `auth*`, `credential`, `license_key`, `passphrase`),
    // whose hex captures are not as cleanly real on CredData.
    let canon: String = keyword
        .bytes()
        .filter(|b| !matches!(b, b'_' | b'-' | b'.'))
        .map(|b| b.to_ascii_lowercase() as char)
        .collect();
    matches!(
        canon.as_str(),
        "secret"
            | "apikey"
            | "privatekey"
            | "encryptionkey"
            | "signingkey"
            | "accesskey"
            | "clientsecret"
            | "appsecret"
            | "masterkey"
    )
}

thread_local! {
    /// Per-thread pool for the `lines_with_keyword` scratch buffer.
    ///
    /// `scan_generic_assignments` runs on every chunk and previously did a
    /// fresh `Vec::new()` + grow per chunk. Across a 100k-file scan on rayon
    /// workers that is a flood of tiny allocations. Pool one buffer per worker:
    /// take it out, fill it, drain it, hand it back - resized once, resliced
    /// thereafter. Mirrors `ACTIVE_PATTERNS_POOL` / `TRIGGER_POOL`.
    static KEYWORD_LINES_POOL: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

impl CompiledScanner {
    /// Scan for generic `SECRET_NAME = "high_entropy_value"` patterns.
    /// This is the precision-gated equivalent of Gitleaks's `generic-api-key`.
    /// Only fires when:
    ///   1. The variable name contains a secret-related keyword
    ///   2. The value has entropy >= 3.5 (random-looking)
    ///   3. No named detector already matched the same line
    ///   4. The value is not a known placeholder/example
    pub(crate) fn scan_generic_assignments(
        &self,
        code_lines: &[&str],
        line_offsets: &[usize],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        let Some(generic_re) = GENERIC_RE.as_ref() else {
            return;
        };

        // Short-circuit: for the ~95% of chunks with zero prior matches there
        // is nothing to dedup against, so skip both allocations (the temporary
        // `Vec<usize>` and the `HashSet`) and use an empty set. Only build the
        // covered-line set when there is at least one existing match.
        let covered_lines: std::collections::HashSet<usize> = if scan_state.matches.is_empty() {
            std::collections::HashSet::new()
        } else {
            scan_state
                .matches
                .iter()
                .filter_map(|m| m.0.location.line)
                .collect()
        };

        // Single-pass case-insensitive Aho-Corasick over all 16 keywords.
        // Replaces the previous 16 × O(line_len) byte-window scans per line
        // (one per keyword) with one O(line_len) automaton walk that catches
        // every keyword simultaneously. On an 8 MiB no-hit corpus this drops
        // the scan_generic_assignments pre-filter from ~16 × 240 ms of
        // window-scan to a single AC pass.
        // `None` here means the keyword AC failed to build; the `KEYWORD_AC`
        // initializer already emitted the loud one-shot Law-10 warning, so this
        // per-chunk path just returns (the named-detector pass still ran).
        let Some(keyword_ac) = KEYWORD_AC.as_ref() else {
            return;
        };

        // ONE chunk-level AC scan instead of N per-line scans.
        // Profile showed scan_generic_assignments at ~500 µs/chunk -
        // dominant non-ML cost - and most of that was the per-line
        // KEYWORD_AC.find overhead (per-call AC setup × N lines).
        // One contiguous find_iter over the whole chunk is the same
        // total bytes scanned but with a single overhead point and
        // way better cache behavior. Map each match offset back to
        // its line via the existing `line_offsets` binary search;
        // dedup so we visit each line once even if multiple
        // keywords land on it.
        let chunk_bytes = chunk.data.as_bytes();
        // Borrow the pooled scratch buffer for the duration of this scan.
        // `take` leaves an empty Vec in the cell so the heavy consume loop
        // below does not hold a live RefCell borrow (which would conflict
        // with any re-entrant pool use); the buffer is returned at function
        // exit, preserving its capacity for the next chunk on this worker.
        let mut lines_with_keyword = KEYWORD_LINES_POOL.with(|cell| cell.take());
        lines_with_keyword.clear();
        let mut last_line_idx: Option<usize> = None;
        for mat in keyword_ac.find_iter(chunk_bytes) {
            // `partition_point` returns the 1-based line number;
            // subtract 1 for the 0-based code_lines index. Same
            // idiom as `match_line_number`.
            let line_num_1b = line_offsets.partition_point(|&lo| lo <= mat.start());
            let line_idx = line_num_1b.saturating_sub(1);
            if Some(line_idx) == last_line_idx {
                continue;
            }
            last_line_idx = Some(line_idx);
            lines_with_keyword.push(line_idx);
        }
        if lines_with_keyword.is_empty() {
            // Return the (now-empty) buffer to the pool before bailing so its
            // capacity survives for the next chunk.
            KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
            return;
        }

        for &line_idx in &lines_with_keyword {
            let line_num = line_idx + 1;
            if covered_lines.contains(&line_num) {
                continue;
            }
            let Some(&raw_line) = code_lines.get(line_idx) else {
                continue;
            };
            // The chunk-level AC told us this line has a keyword;
            // proceed straight to the heavy regex extraction.
            //
            // Evasion-resistant extraction: the named-detector path matches on
            // the homoglyph/zero-width-normalized chunk text, but this generic
            // fallback historically captured from the raw line, so a soft hyphen
            // (U+00AD) or other zero-width byte planted *inside* a value
            // truncated the capture (`abcde12345abcde<U+00AD>12345` ->
            // `abcde12345abcde`). Normalize the candidate line the same way
            // before extraction so an evaded secret is recovered whole. The Cow
            // borrows for pure-ASCII lines (the 99% case), so there is no alloc
            // and no behavior change off the evasion path. Line indexing, the
            // keyword AC prefilter, context inference and the reported offset all
            // remain in raw coordinates; only the captured value is de-evaded,
            // and an in-value zero-width never shifts the value's start offset.
            let normalized_line = crate::unicode_hardening::normalize_homoglyphs(raw_line);
            let line: &str = &normalized_line;

            for caps in generic_re.captures_iter(line) {
                let Some(keyword_match) = caps.get(1) else {
                    continue;
                };
                let Some(value_match) = caps.get(2) else {
                    continue;
                };
                // Whole-word left boundary, enforced ONLY for the short,
                // substring-ambiguous abbreviation `pass` (the tail of
                // `bypass`/`compass`/`surpass`/...). The longer keywords
                // (`password`, `token`, `secret`, `api_key`, ...) deliberately
                // keep substring matching so concatenated no-separator keys like
                // `DBPASSWORD=` / `apitoken=` still bridge — measured on CredData,
                // enforcing the boundary on every keyword cost ~36 real positives
                // for no precision gain. `pass` alone needs the guard because its
                // false-substring family (`bypass=`/`compass=`) is common.
                if keyword_match.as_str().eq_ignore_ascii_case("pass")
                    && !keyword_has_word_boundary(line, keyword_match.start())
                {
                    continue;
                }
                let value = value_match.as_str();
                // Entropy gate: reject low-entropy values (variable names, prose).
                // Routed through the SINGLE threshold-aware
                // `generic_entropy_floor` helper (engine/scan_filters.rs) — the
                // same source of truth the named-detector generic path uses — so
                // the per-length base floor (2.8 / 3.2 / 3.5 at the default) is
                // identical AND the operator's Tier-A `--entropy-threshold`
                // tightens this gate too. Raising the knob above its 4.5 default
                // lifts the floor to that bits/byte value, suppressing values
                // below it.
                let entropy = crate::pipeline::match_entropy(value.as_bytes());
                // KH-L-0110: a complete pure-hex value of canonical key length
                // (32/48) under a STRONG credential keyword is a real key, not a
                // hash digest — exempt it from the bare-hex-digest shape gate
                // (every other gate still applies). See the helper for the
                // CredData/mirror soundness argument.
                let allow_canonical_hex_key =
                    is_strong_keyword_anchored_hex_key(keyword_match.as_str(), value);
                if self.generic_value_shape_rejected(value, entropy, chunk, allow_canonical_hex_key)
                {
                    continue;
                }

                // Context suppression: test files get lower confidence
                let context = crate::context::infer_context(
                    code_lines,
                    line_idx,
                    chunk.metadata.path.as_deref(),
                );
                // The test/docs base-confidence haircut is the SAME path-keyed
                // policy `--no-suppress-test-fixtures` (penalize_test_paths)
                // governs everywhere else (scan_postprocess.rs:787, fallback.rs:2090).
                // This generic-secret fallback historically baked 0.25/0.30 into
                // `base_conf` UNCONDITIONALLY, so the opt-out could not clear it:
                // MC-15 proved on the bench that the same byte-identical corpus
                // scored ~600 fewer findings under a `fixtures/`-named scan dir
                // than under `corpus/` even with the flag set, because TestCode
                // values landed at 0.25 and fell below the 0.40 floor. Gating the
                // haircut on `penalize_test_paths` (mirroring the canonical policy)
                // makes the opt-out actually clear the path penalty here too; with
                // the flag UNSET (default) behaviour is byte-identical to before.
                let base_conf = match context {
                    crate::context::CodeContext::TestCode if self.config.penalize_test_paths => {
                        0.25
                    }
                    // `--scan-comments` (see ScannerConfig.scan_comments)
                    // promotes comment-context credentials to the
                    // ordinary-source base confidence so a real secret
                    // pasted into a TODO/debug-trace comment surfaces
                    // instead of getting silently filtered. Documentation
                    // context stays downgraded - it's a different (and
                    // far noisier) signal class than inline comments - but it
                    // too is cleared by the fixture opt-out, matching the
                    // canonical TestCode|Documentation policy.
                    crate::context::CodeContext::Comment if self.config.scan_comments => 0.60,
                    crate::context::CodeContext::Documentation
                        if self.config.penalize_test_paths =>
                    {
                        0.30
                    }
                    crate::context::CodeContext::Comment => 0.30,
                    _ => 0.60,
                };

                // Boost confidence for longer, higher-entropy values
                let entropy_boost = ((entropy - 3.5) * 0.1).min(0.25);
                let length_boost = ((value.len() as f64 - 16.0) * 0.005).clamp(0.0, 0.15);
                let confidence = (base_conf + entropy_boost + length_boost).min(0.95);

                // Route through the SAME canonical post-ML penalty pipeline the
                // ML / named-detector emit path uses (scan_postprocess.rs). The
                // generic-secret fallback historically emitted via `push_match`
                // and BYPASSED it, so the random-base64 / encoded-binary /
                // placeholder blob penalties (×0.02) never reached this path -
                // that bypass IS the base64-protobuf FP class (the lost
                // separation pipeline closed exactly this wiring gap). `is_named
                // = false`: generic-secret is an unanchored fallback, so the
                // shape penalties (char-diversity / repeat-run / uniform-base64
                // -blob / encoded-binary) all apply. A real short/base62 secret
                // clears every check unchanged; only a 44+ char raw-base64-blob
                // or encoded-binary value (the decoy class) is slammed ×0.02
                // below the floor. Applied BEFORE the checksum floor so a valid
                // embedded CRC still overrides shape and surfaces the token, and
                // a user can recover the penalized blob with `--min-confidence`.
                let confidence =
                    crate::confidence::apply_post_ml_penalties(confidence, value, false);

                // Single checksum policy on the generic-secret fallback emit path
                // (checksum/mod.rs documents EVERY emission path routes through
                // this): a prefix-bearing token (`ghp_`/`npm_`/…) with an Invalid
                // embedded CRC is dropped, and a Valid one is floored to
                // CHECKSUM_VALID_FLOOR BEFORE the min-confidence gate so a
                // confirmed token clears the bar even on the fallback path.
                let Some(confidence) =
                    crate::checksum::checksum_adjusted_confidence(confidence, value)
                else {
                    continue;
                };

                if confidence < self.config.min_confidence {
                    continue;
                }

                // Defect #80: this branch hard-coded `offset: 0` for every
                // generic-secret finding, so a `KEY = <secret>` on line 845
                // of a 137 KiB file reported offset 0 - the start of the
                // file - making the JSON impossible to navigate or grep.
                // The real offset is the start of the value within the
                // line, plus the line's start in the chunk, plus the
                // chunk's base offset in the original file (non-zero on
                // windowed >64 MiB scans).
                let chunk_line_offset = line_offsets.get(line_idx).copied().unwrap_or(0);
                let absolute_offset =
                    chunk.metadata.base_offset + chunk_line_offset + value_match.start();
                let raw = keyhog_core::RawMatch {
                    credential_hash: crate::sha256_hash(value),
                    detector_id: Arc::from("generic-secret"),
                    detector_name: Arc::from("Generic Secret (Key=Value)"),
                    service: Arc::from("generic"),
                    severity: keyhog_core::Severity::Medium,
                    credential: Arc::from(value),
                    companions: HashMap::new(),
                    location: keyhog_core::MatchLocation {
                        source: Arc::from(chunk.metadata.source_type.as_str()),
                        file_path: chunk.metadata.path.as_deref().map(Arc::from),
                        // Window-local line + chunk base line = absolute file
                        // line, mirroring `absolute_offset`'s base_offset add
                        // above. base_line is 0 for non-windowed chunks.
                        line: Some(line_num + chunk.metadata.base_line),
                        offset: absolute_offset,
                        commit: chunk.metadata.commit.as_deref().map(Arc::from),
                        author: chunk.metadata.author.as_deref().map(Arc::from),
                        date: chunk.metadata.date.as_deref().map(Arc::from),
                    },
                    entropy: Some(entropy),
                    confidence: Some(confidence),
                };
                scan_state.push_match(raw, self.config.max_matches_per_chunk);
            }
        }
        // Return the scratch buffer to the pool, preserving its capacity for
        // the next chunk this worker handles.
        KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
    }
}
