//! PERF TRIPWIRE — suppression / allowlist per-finding cost.
//!
//! HOT PATH: `keyhog_core::allowlist::Allowlist::is_path_ignored`
//! (crates/core/src/allowlist.rs:267) and its sibling `is_allowed`
//! (line 215). Both are called once **per finding** in the scanner
//! post-filter:
//!   - crates/cli/src/subcommands/scan.rs:401  `allowlist.is_path_ignored(path)`
//!   - crates/cli/src/orchestrator/postprocess.rs:165 `allowlist.is_path_ignored(path)`
//! so the suppression cost is O(findings · ignored_paths).
//!
//! THE DEFECT (two compounding inefficiencies, both hardware-independent):
//!
//!   1. LINEAR RULE WALK. `is_path_ignored` (allowlist.rs:269-271) is a raw
//!      `self.ignored_paths.iter().any(|pattern| glob_match_normalized(...))`.
//!      Every finding is tested against *every* glob with no prefix bucket,
//!      literal set, or automaton. Cost grows linearly in rule count: a
//!      `.keyhogignore` copied from a monorepo `.gitignore` (hundreds of
//!      globs — the bare-glob fallback at allowlist.rs:163-174 means every
//!      copied `.gitignore` line becomes a path rule) makes each finding pay
//!      the full O(rules) sweep.
//!
//!   2. PER-FINDING PATTERN RECOMPILE. Inside the walk,
//!      `glob_match_normalized` (allowlist.rs:286-308) recomputes, for the
//!      SAME fixed pattern, on EVERY finding:
//!         - `normalize_path(pattern)`           (line 287)  — heap String
//!         - `split_segments(&normalized_pattern)`(line 288) — heap Vec<&str>
//!         - the two oversize segment scans       (lines 291-306)
//!      None of this depends on the finding; the pattern segments are fixed
//!      at parse time yet are rebuilt findings×rules times. A precompiled
//!      `Vec<Vec<segment>>` (or a literal-prefix index / glob automaton)
//!      built once in `Allowlist::parse` removes both costs.
//!
//! MEASURED (release-fast characteristics: opt-level=3, thin LTO; this test's
//! timing logic mirrors that — run it `--release`; the bound is a *ratio* so
//! it is hardware-independent regardless of profile):
//!   Standalone -O probe, 2000 findings, all non-matching (worst case = full
//!   sweep), .keyhogignore of monorepo-style path globs:
//!       rules=200 -> 67.5 ms,  rules=400 -> 133.3 ms,  rules=800 -> 264.3 ms
//!       ratio(2N/N) = 1.97   ratio(4N/N) = 3.91   ->  PURELY LINEAR in rules.
//!   A sub-linear structure (prefix bucket / literal set / automaton) keeps
//!   the 4x-rules workload well under 2.0x; the recompile removal alone is a
//!   measured ~3.2x constant-factor win on top.
//!
//! TRIPWIRE: build the SAME allowlist at N and 4N rules, run the SAME set of
//! findings through `is_path_ignored`, and assert the wall-time ratio is
//! sub-linear. A correct O(1)/O(log rules) suppression index gives ratio
//! near 1; the current linear walk gives ~3.9. We trip at >= 3.0, which
//! leaves >5x headroom over the optimized target (ratio < 2.0 is the upper
//! bound on "sub-linear"; the real target is ~1.0-1.5) while sitting clearly
//! below the measured 3.91 so only the genuine linear blowup fails.
//!
//! RECALL GUARD: the optimizer must keep `is_path_ignored` byte-for-byte
//! equivalent. The `recall` test below pins the exact match/no-match decision
//! on representative globs so a faster index cannot silently drop or add a
//! suppression. keyhog-core lib doctests on `Allowlist` (allowlist.rs:88-92,
//! 264-266) plus `crates/core/tests/*` allowlist coverage must stay green.

use keyhog_core::allowlist::Allowlist;
use std::time::Instant;

/// Monorepo-style path globs — the kind a user gets by copying a big
/// `.gitignore` into `.keyhogignore` (bare globs become path rules, see
/// allowlist.rs:163-174). `count` rules, deterministic, all `path:`-form.
fn build_allowlist(count: usize) -> Allowlist {
    let base = [
        "**/*.md",
        "**/*.log",
        "node_modules/**",
        "vendor/**/*.json",
        "target/**",
        "**/test/fixtures/**",
        "docs/**/*.png",
        "**/.env.example",
        "build/**",
        "dist/**/*.js",
        "**/*.lock",
        "coverage/**",
        "**/snapshots/*.snap",
        "tmp/**",
        "**/*.min.js",
    ];
    let mut content = String::new();
    let mut dir = 0usize;
    'outer: loop {
        for b in &base {
            // count lines, then stop exactly at `count`.
            if content.lines().count() >= count {
                break 'outer;
            }
            content.push_str("path:dir");
            content.push_str(&dir.to_string());
            content.push('/');
            content.push_str(b);
            content.push('\n');
        }
        dir += 1;
    }
    let al = Allowlist::parse(&content);
    assert_eq!(
        al.ignored_paths.len(),
        count,
        "fixture must produce exactly {count} path rules (got {})",
        al.ignored_paths.len()
    );
    al
}

/// Findings whose paths do NOT match any rule — the worst case that forces
/// the full per-finding sweep over all rules (an early match would mask the
/// linear cost). 2000 distinct source paths.
fn build_findings() -> Vec<String> {
    (0..2000)
        .map(|i| format!("src/app/m{}/handler_{}.rs", i % 50, i))
        .collect()
}

/// Best-of-K min wall time (ns) of running every finding through
/// `is_path_ignored` against `al`. Best-of-K kills scheduler noise.
fn best_of_k(al: &Allowlist, findings: &[String], k: usize) -> u128 {
    let mut best = u128::MAX;
    for _ in 0..k {
        let start = Instant::now();
        let mut hits = 0u64;
        for f in findings {
            if al.is_path_ignored(f) {
                hits += 1;
            }
        }
        let elapsed = start.elapsed().as_nanos();
        std::hint::black_box(hits);
        if elapsed < best {
            best = elapsed;
        }
    }
    best
}

#[test]
fn suppression_path_walk_must_scale_sublinearly_in_rule_count() {
    const N: usize = 200;
    const FACTOR: usize = 4; // 4N
    const K: usize = 5; // best-of-K, keep the min

    let findings = build_findings();
    let small = build_allowlist(N);
    let large = build_allowlist(N * FACTOR);

    // Warmup so first-touch page faults / branch predictor state do not skew
    // the first measured run.
    let _ = best_of_k(&small, &findings, 2);
    let _ = best_of_k(&large, &findings, 2);

    let t_small = best_of_k(&small, &findings, K);
    let t_large = best_of_k(&large, &findings, K);

    // Defend against a degenerate near-zero small-time on a very fast box,
    // which would make the ratio meaningless. With N=200 rules × 2000
    // findings the small workload is hundreds of microseconds minimum.
    assert!(
        t_small > 0,
        "small workload measured 0 ns — timer resolution too coarse to form a ratio"
    );

    let ratio = t_large as f64 / t_small as f64;

    // Linear in rules => quadrupling rules ~quadruples time (measured 3.91).
    // A sub-linear suppression index (precompiled segments + literal-prefix
    // bucket / set / automaton built once in `Allowlist::parse`) keeps this
    // near 1.0 and certainly under 2.0. Trip at >= 3.0: >5x clear of the
    // optimized target (~1.0-1.5), below the measured 3.91 so only the real
    // O(findings·rules) blowup fails.
    const MAX_RATIO: f64 = 3.0;

    assert!(
        ratio < MAX_RATIO,
        "PERF REGRESSION (suppression rule walk is O(findings·rules)):\n\
         4x-rules / 1x-rules wall-time ratio = {ratio:.3} (>= {MAX_RATIO} trips)\n\
           rules={N}   ({K}x best) = {:.3} ms\n\
           rules={}   ({K}x best) = {:.3} ms\n\
           findings = {}\n\
         current behavior: is_path_ignored (allowlist.rs:267-272) does\n\
         `ignored_paths.iter().any(|p| glob_match_normalized(p, ..))` with NO\n\
         prefix/set/automaton, and glob_match_normalized (allowlist.rs:287-288)\n\
         re-runs normalize_path(pattern)+split_segments(pattern) PER finding.\n\
         target: precompile pattern segments once in Allowlist::parse and index\n\
         globs by literal prefix/set so per-finding cost is sub-linear in rule\n\
         count -> ratio < 2.0 (ideal ~1.0-1.5).",
        t_small as f64 / 1e6,
        N * FACTOR,
        t_large as f64 / 1e6,
        findings.len(),
    );
}

/// RECALL GUARD: pins the exact suppression decision so any future
/// sub-linear index proves it loses no findings (and adds none). If the
/// optimizer changes match semantics, this fails before the perf test is
/// even reached.
#[test]
fn suppression_recall_guard_exact_decisions() {
    let al = Allowlist::parse(
        "path:**/*.md\n\
         path:node_modules/**\n\
         path:vendor/**/*.json\n\
         path:**/.env.example\n\
         path:src/secrets/*.rs\n",
    );

    // MUST be suppressed. These pin the EXACT current (correct) glob
    // semantics so any future sub-linear index reproduces them bit-for-bit:
    //   - `**/*.md`  => `**` matches any prefix, `*.md` the basename.
    //   - `node_modules/**` => path must START with `node_modules/`.
    //   - `vendor/**/*.json` => path must START with `vendor/`; the `**`
    //     between is zero-or-more middle segments, then a `*.json` basename.
    //   - `**/.env.example` => `**` (incl. empty) prefix, exact basename.
    //   - `src/secrets/*.rs` => single-segment `*`, NOT `**` (one level only).
    for p in [
        "docs/README.md",
        "a/b/c/CHANGELOG.md",
        "node_modules/left-pad/index.js",
        "vendor/aws/creds.json", // starts with vendor/, **/*.json ok
        "vendor/creds.json",     // `**` matches zero middle segments
        "app/.env.example",
        ".env.example",
        "src/secrets/keys.rs",
    ] {
        assert!(
            al.is_path_ignored(p),
            "recall guard: '{p}' must stay suppressed under any optimized index"
        );
    }

    // MUST NOT be suppressed. The optimizer must not over-suppress either.
    for p in [
        "src/main.rs",
        "README.mdx",
        "node_modules_real/index.js",
        "vendor/aws/creds.yaml",   // wrong extension
        "deep/vendor/x/y/z.json",  // `vendor/**` is anchored at the root, no leading `**`
        "src/secrets/sub/keys.rs", // single-segment glob, not `**`
        "app/.env",
    ] {
        assert!(
            !al.is_path_ignored(p),
            "recall guard: '{p}' must NOT be suppressed under any optimized index"
        );
    }
}
