//! Comment-embed runner — the `scan_comments` toggle is a sound, wired,
//! monotone behavior switch.
//!
//! `# api_key = "ghp_…"` in Python, `// AWS_SECRET="…"` in JS, `/* token=… */`
//! in Rust, `<!-- … -->` in HTML. A non-trivial fraction of real leaks live in
//! comments. keyhog treats comment-bodied secrets as INTENTIONAL policy: by
//! default (`scan_comments=false`) it applies a 0.4 confidence multiplier and
//! hard-suppresses comment matches below 0.5; `--scan-comments` opts the Comment
//! context out of that penalty so the credential surfaces at full weight.
//!
//! BEHAVIOR contract, not an accuracy rate
//! ---------------------------------------
//! Because comment suppression is a deliberate, config-gated choice, "what
//! fraction of comment-bodied secrets surface" is an accuracy RATE that belongs
//! to the differential bench (`benchmarks/bench`), NOT `cargo test` (T-01). What
//! IS a sound, rate-free TOOL-BEHAVIOR contract is the toggle itself, asserted
//! all-or-nothing over the credential-sufficient set:
//!
//!   1. **Monotonicity** — enabling `scan_comments` can only ADD comment
//!      findings, never remove one. For every credential-sufficient positive in
//!      every comment style, `default-surfaces ⟹ enabled-surfaces`. A single
//!      counterexample is a real suppression-ordering bug.
//!   2. **The flag is wired** — there is at least one credential-sufficient
//!      positive that the default scanner suppresses in a comment and the
//!      `scan_comments=true` scanner surfaces. A zero-effect flag is a dead-knob
//!      wiring bug (CLAUDE.md WIRING / Law 11), caught here rather than shipped.

mod support;
use support::contracts::{
    load_contracts, make_chunk, primaries, scanner, scanner_with, sufficiency_mask, surfaces,
    Primary,
};

use std::collections::BTreeMap;

use keyhog_core::config::ScanConfig;

const SOURCE_TYPE: &str = "comment-embed";

#[derive(Debug, Clone, Copy)]
enum Comment {
    HashLine,       // # ...
    SlashSlash,     // // ...
    SlashStarBlock, // /* ... */
    HtmlBlock,      // <!-- ... -->
    SemiLine,       // ; ... (Lisp, INI)
    DashDashLine,   // -- ... (SQL, Haskell)
    PercentLine,    // % ... (Erlang, MATLAB)
}

impl Comment {
    const ALL: &'static [Comment] = &[
        Comment::HashLine,
        Comment::SlashSlash,
        Comment::SlashStarBlock,
        Comment::HtmlBlock,
        Comment::SemiLine,
        Comment::DashDashLine,
        Comment::PercentLine,
    ];

    fn label(self) -> &'static str {
        match self {
            Comment::HashLine => "hash-line",
            Comment::SlashSlash => "slash-slash",
            Comment::SlashStarBlock => "slash-star-block",
            Comment::HtmlBlock => "html-block",
            Comment::SemiLine => "semi-line",
            Comment::DashDashLine => "dash-dash-line",
            Comment::PercentLine => "percent-line",
        }
    }

    fn wrap(self, text: &str) -> String {
        let line_prefix = |prefix: &str| {
            text.lines()
                .map(|l| format!("{prefix} {l}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        match self {
            Comment::HashLine => line_prefix("#"),
            Comment::SlashSlash => line_prefix("//"),
            Comment::SlashStarBlock => format!("/* {text} */"),
            Comment::HtmlBlock => format!("<!-- {text} -->"),
            Comment::SemiLine => line_prefix(";"),
            Comment::DashDashLine => line_prefix("--"),
            Comment::PercentLine => line_prefix("%"),
        }
    }
}

#[test]
fn scan_comments_toggle_is_wired_and_monotone() {
    let default_scanner = scanner();
    let enabled_scanner = scanner_with(ScanConfig {
        scan_comments: true,
        ..ScanConfig::default()
    });

    let contracts = load_contracts();
    let primaries: Vec<Primary> = primaries(&contracts);
    // Sufficiency is a property of the credential bytes, probed with the
    // default scanner in plain (non-comment) context.
    let sufficient = sufficiency_mask(&default_scanner, SOURCE_TYPE, &primaries);
    let n_sufficient = sufficient.iter().filter(|b| **b).count();

    // Per style: (default_hits, enabled_hits, gated_runs) over the
    // credential-sufficient set — informational shape of the toggle's effect.
    let mut per_style: BTreeMap<&'static str, (usize, usize, usize)> = BTreeMap::new();
    let mut monotonicity_violations: Vec<String> = Vec::new();
    let mut flag_effect_cases = 0usize;

    for (idx, p) in primaries.iter().enumerate() {
        if !sufficient[idx] {
            continue; // companion-required survival is a bench rate, not gated
        }
        for style in Comment::ALL {
            let text = style.wrap(&p.text);
            let chunk = make_chunk(&text, SOURCE_TYPE, "source.txt");
            let default_hit = surfaces(&default_scanner, &chunk, &p.credential);
            let enabled_hit = surfaces(&enabled_scanner, &chunk, &p.credential);

            let bucket = per_style.entry(style.label()).or_insert((0, 0, 0));
            bucket.2 += 1;
            if default_hit {
                bucket.0 += 1;
            }
            if enabled_hit {
                bucket.1 += 1;
            }

            // (1) Monotonicity: enabling the flag must never remove a finding.
            if default_hit && !enabled_hit {
                monotonicity_violations.push(format!(
                    "{detector} :: style={style} :: credential {cred:?} surfaced with \
                     scan_comments=false but VANISHED with scan_comments=true",
                    detector = p.detector_id,
                    style = style.label(),
                    cred = p.credential,
                ));
            }
            // (2) Flag wired: enabling surfaces something the default suppressed.
            if enabled_hit && !default_hit {
                flag_effect_cases += 1;
            }
        }
    }

    let mut summary = format!(
        "comment-embed scan_comments toggle: {n_sufficient}/{} primaries fire standalone; \
         per-style credential-sufficient hits (default → enabled), informational:\n",
        primaries.len(),
    );
    for (style, (d, e, runs)) in &per_style {
        summary.push_str(&format!("    {style:<17} {d:>4} → {e:<4} / {runs}\n"));
    }
    summary.push_str(&format!(
        "  flag-effect cases (enabled surfaced what default suppressed): {flag_effect_cases}\n"
    ));
    eprintln!("{summary}");

    assert!(
        monotonicity_violations.is_empty(),
        "scan_comments monotonicity violated ({} cases): enabling --scan-comments REMOVED a \
         comment finding it should only ever add — a suppression-ordering bug:\n  - {}",
        monotonicity_violations.len(),
        monotonicity_violations.join("\n  - "),
    );
    assert!(
        flag_effect_cases > 0,
        "scan_comments had ZERO effect across the entire credential-sufficient corpus in every \
         comment style: no credential-sufficient secret that the default scanner suppressed in a \
         comment was surfaced by scan_comments=true. The flag is dead-wired (CLAUDE.md WIRING / \
         Law 11) — either the config no longer reaches the Comment-context penalty, or comment \
         context detection broke."
    );
}
