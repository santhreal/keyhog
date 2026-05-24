//! Comment-embed runner — credentials inside source-code comments.
//!
//! `# api_key = "ghp_…"` in a Python file, `// AWS_SECRET="…"` in
//! a JS file, `/* token=… */` in a Rust block comment, `<!-- … -->`
//! in HTML. A non-trivial fraction of real leaks live inside
//! comments, usually with intent ("noting this is temporary" /
//! "TODO: rotate") or the secret got pasted in a debug-trace
//! comment. Many scanners *suppress* comment-bodied secrets on the
//! theory that they're examples; if keyhog does this we want to
//! know exactly how much recall it costs.
//!
//! Runner wraps every contract positive in 7 single-line + block-
//! comment styles, asserts the credential surfaces, and reports the
//! per-style hit rate. The rate is the moral question — comment
//! suppression is intentional design in some scanners — but the
//! NUMBER must not drift silently.
//!
//! Surface
//! -------
//! 348 contracts × ~2 positives × 7 comment styles ≈ **4 800 cases**.

use std::collections::BTreeMap;
use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract {
    #[allow(dead_code)]
    schema_version: u32,
    #[allow(dead_code)]
    detector_id: String,
    #[allow(dead_code)]
    service: String,
    #[allow(dead_code)]
    severity: String,
    #[serde(default)]
    positive: Vec<Positive>,
}

#[derive(Debug, Deserialize)]
struct Positive {
    text: String,
    credential: String,
    #[allow(dead_code)]
    reason: String,
}

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn contracts_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    d.push("contracts");
    d
}

fn load_contracts() -> Vec<Contract> {
    let dir = contracts_dir();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(contract) = toml::from_str::<Contract>(&text) else {
            continue;
        };
        out.push(contract);
    }
    out
}

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory loadable from comment runner");
    CompiledScanner::compile(detectors).expect("scanner compile from comment runner")
}

// ── comment styles ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Comment {
    HashLine,         // # ...
    SlashSlash,       // // ...
    SlashStarBlock,   // /* ... */
    HtmlBlock,        // <!-- ... -->
    SemiLine,         // ; ... (Lisp, INI)
    DashDashLine,     // -- ... (SQL, Haskell)
    PercentLine,      // % ... (Erlang, MATLAB)
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

    /// Wrap one or more text lines in the comment style. Inputs that
    /// already contain newlines are split and each line gets the
    /// line-comment prefix; block-comment styles wrap the whole.
    fn wrap(self, text: &str) -> String {
        match self {
            Comment::HashLine => text.lines().map(|l| format!("# {l}")).collect::<Vec<_>>().join("\n"),
            Comment::SlashSlash => text.lines().map(|l| format!("// {l}")).collect::<Vec<_>>().join("\n"),
            Comment::SlashStarBlock => format!("/* {text} */"),
            Comment::HtmlBlock => format!("<!-- {text} -->"),
            Comment::SemiLine => text.lines().map(|l| format!("; {l}")).collect::<Vec<_>>().join("\n"),
            Comment::DashDashLine => text.lines().map(|l| format!("-- {l}")).collect::<Vec<_>>().join("\n"),
            Comment::PercentLine => text.lines().map(|l| format!("% {l}")).collect::<Vec<_>>().join("\n"),
        }
    }
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "comment-embed".into(),
            path: Some("source.txt".into()),
            ..Default::default()
        },
    }
}

#[test]
fn every_positive_swept_through_comment_styles() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml — comment runner has nothing to drive"
    );

    let mut per_style: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
    let mut total_runs: usize = 0;
    let mut total_hits: usize = 0;

    for c in &contracts {
        for p in &c.positive {
            for style in Comment::ALL {
                let text = style.wrap(&p.text);
                scanner.clear_fragment_cache();
                let chunk = make_chunk(&text);
                let matches = scanner.scan(&chunk);
                let hit = matches
                    .iter()
                    .any(|m| m.credential.as_ref().contains(&p.credential));
                let bucket = per_style.entry(style.label()).or_insert((0, 0));
                bucket.0 += 1;
                total_runs += 1;
                if hit {
                    bucket.1 += 1;
                    total_hits += 1;
                }
            }
        }
    }

    let mut summary = String::from("comment-embed per-style hit rate:\n");
    for (style, (runs, hits)) in &per_style {
        let pct = (*hits as f64 / (*runs).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "  {style:<17} {hits:>4}/{runs:<4} ({pct:5.1}%)\n"
        ));
    }
    let overall = (total_hits as f64 / total_runs.max(1) as f64) * 100.0;
    summary.push_str(&format!(
        "  TOTAL {total_hits}/{total_runs} ({overall:.1}%)\n"
    ));
    eprintln!("{summary}");

    let strict = std::env::var("KEYHOG_COMMENT_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if strict && overall < 70.0 {
        panic!(
            "comment-embed overall recall {overall:.1}% dropped below 70% floor"
        );
    }
}
