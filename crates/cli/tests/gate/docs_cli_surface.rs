//! Every `keyhog` command shown in the canonical docs must name a subcommand
//! and flags the shipped binary actually has.
//!
//! `tests/docs/cli_claims_check.sh` is a denylist of four flags confirmed not
//! to exist, and its own header says the exhaustive cross-check "belongs in a
//! binary-driven test where `--help` is ground truth". This is that test. A
//! denylist only catches the mistakes someone already made; a reader who runs a
//! documented command that was renamed gets `error: unexpected argument` and no
//! denylist entry ever mentioned it.
//!
//! Scope is deliberately names, not values. Checking values would mean running
//! every documented value parser against placeholders such as `<PATH>` and
//! `MAJOR.MINOR.PATCH`, which fails on correct documentation. Names are the
//! part that goes stale on a rename and the part a reader types.
//!
//! Only fenced code blocks are read. Prose mentions a flag to say it does NOT
//! exist, and the surrounding text is where that nuance lives.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Every canonical Markdown page a reader is pointed at.
fn documentation_pages() -> Vec<PathBuf> {
    let root = repo_root();
    let mut pages = vec![root.join("README.md")];
    let mut stack = vec![root.join("docs/src")];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()));
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                pages.push(path);
            }
        }
    }
    pages.sort();
    pages
}

/// One documented invocation: the page and line it came from, and its argv.
struct Invocation {
    page: String,
    line: usize,
    argv: Vec<String>,
}

/// Split a shell-ish command line into tokens, honouring single and double
/// quotes. Documented commands are simple; anything with substitution is
/// skipped by the caller before it gets here.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for ch in line.chars() {
        match quote {
            Some(active) if ch == active => quote = None,
            Some(_) => current.push(ch),
            None if ch == '\'' || ch == '"' => {
                quote = Some(ch);
                started = true;
            }
            None if ch.is_whitespace() => {
                if started || !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            None => current.push(ch),
        }
    }
    if started || !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Collect every `keyhog …` invocation inside fenced shell blocks.
fn collect_invocations(page: &Path) -> Vec<Invocation> {
    let text = std::fs::read_to_string(page)
        .unwrap_or_else(|error| panic!("read {}: {error}", page.display()));
    let label = page
        .strip_prefix(repo_root())
        .unwrap_or(page)
        .display()
        .to_string()
        .replace('\\', "/");
    let mut found = Vec::new();
    let mut in_fence = false;
    let mut fence_is_shell = false;
    let mut pending: Option<(usize, String)> = None;

    for (index, raw) in text.lines().enumerate() {
        let trimmed = raw.trim();
        if let Some(info) = trimmed.strip_prefix("```") {
            if in_fence {
                in_fence = false;
                pending = None;
            } else {
                in_fence = true;
                let lang = info.trim();
                fence_is_shell = matches!(lang, "" | "sh" | "bash" | "shell" | "console" | "zsh");
            }
            continue;
        }
        if !in_fence || !fence_is_shell {
            continue;
        }

        // Join backslash line continuations before deciding anything.
        let (start_line, joined) = match pending.take() {
            Some((start, mut acc)) => {
                acc.push(' ');
                acc.push_str(trimmed);
                (start, acc)
            }
            None => (index + 1, trimmed.to_string()),
        };
        if let Some(head) = joined.strip_suffix('\\') {
            pending = Some((start_line, head.trim_end().to_string()));
            continue;
        }
        if joined.starts_with('#') || joined.is_empty() {
            continue;
        }
        // Command substitution and expansion produce argv this test cannot
        // reconstruct; the shell, not the docs, owns those.
        if joined.contains("$(") || joined.contains('`') {
            continue;
        }
        // Take the first stage of a pipeline and drop redirections.
        let command = joined
            .split('|')
            .next()
            .unwrap_or_default()
            .split('>')
            .next()
            .unwrap_or_default();
        let mut tokens = tokenize(command);
        // Strip leading prompt markers and `VAR=value` environment prefixes.
        while let Some(first) = tokens.first() {
            if first == "$" || first == "sudo" || (first.contains('=') && !first.starts_with('-')) {
                tokens.remove(0);
            } else {
                break;
            }
        }
        let Some(program) = tokens.first() else {
            continue;
        };
        if program != "keyhog" && program != "./keyhog" && program != "keyhog.exe" {
            continue;
        }
        found.push(Invocation {
            page: label.clone(),
            line: start_line,
            argv: tokens,
        });
    }
    found
}

/// Long flags accepted at each command path, keyed by the space-joined path
/// (`""` for the top level, `"scan"`, `"hook install"`, …).
fn long_flags_by_path() -> BTreeMap<String, BTreeSet<String>> {
    fn walk(command: &clap::Command, path: &str, out: &mut BTreeMap<String, BTreeSet<String>>) {
        let flags: BTreeSet<String> = command
            .get_arguments()
            .filter_map(|arg| arg.get_long().map(str::to_owned))
            .chain(
                command
                    .get_arguments()
                    .flat_map(|arg| arg.get_all_aliases().unwrap_or_default())
                    .map(|alias| alias.to_owned()),
            )
            .chain(["help".to_owned()])
            .collect();
        out.insert(path.to_owned(), flags);
        for sub in command.get_subcommands() {
            let child = if path.is_empty() {
                sub.get_name().to_owned()
            } else {
                format!("{path} {}", sub.get_name())
            };
            walk(sub, &child, out);
        }
    }
    let mut out = BTreeMap::new();
    let command = keyhog::args::command();
    walk(&command, "", &mut out);
    out
}

/// Resolve the deepest command path an invocation selects, and report the
/// first token that is not a known subcommand at that depth.
fn resolve_path(argv: &[String], known: &BTreeMap<String, BTreeSet<String>>) -> String {
    let mut path = String::new();
    for token in argv.iter().skip(1) {
        if token.starts_with('-') {
            break;
        }
        let candidate = if path.is_empty() {
            token.clone()
        } else {
            format!("{path} {token}")
        };
        if known.contains_key(&candidate) {
            path = candidate;
        } else {
            break;
        }
    }
    path
}

/// Every documented invocation names a real subcommand path.
#[test]
fn documented_commands_name_real_subcommands() {
    let known = long_flags_by_path();
    let top_level: BTreeSet<&str> = known
        .keys()
        .filter(|path| !path.is_empty() && !path.contains(' '))
        .map(String::as_str)
        .collect();
    let mut problems = Vec::new();
    for page in documentation_pages() {
        for invocation in collect_invocations(&page) {
            let Some(first) = invocation
                .argv
                .iter()
                .skip(1)
                .find(|token| !token.starts_with('-'))
            else {
                continue;
            };
            if !top_level.contains(first.as_str()) {
                problems.push(format!(
                    "{}:{} documents `keyhog {first}`, which is not a subcommand",
                    invocation.page, invocation.line
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "documentation names subcommands the binary does not have:\n{}",
        problems.join("\n")
    );
}

/// Every long flag in a documented invocation exists on the command it is
/// written under. This is the check the denylist gate defers to a binary-driven
/// test: a renamed or removed flag stays correct-looking in prose until a
/// reader runs it.
#[test]
fn documented_long_flags_exist_on_their_command() {
    let known = long_flags_by_path();
    let mut problems = Vec::new();
    for page in documentation_pages() {
        for invocation in collect_invocations(&page) {
            let path = resolve_path(&invocation.argv, &known);
            let Some(flags) = known.get(&path) else {
                continue;
            };
            for token in invocation.argv.iter().skip(1) {
                let Some(flag) = token.strip_prefix("--") else {
                    continue;
                };
                if flag.is_empty() {
                    // A bare `--` ends flag parsing; everything after is a value.
                    break;
                }
                let name = flag.split('=').next().unwrap_or(flag);
                if !flags.contains(name) {
                    let where_ = if path.is_empty() {
                        "keyhog".to_owned()
                    } else {
                        format!("keyhog {path}")
                    };
                    problems.push(format!(
                        "{}:{} documents `--{name}` on `{where_}`, which has no such flag",
                        invocation.page, invocation.line
                    ));
                }
            }
        }
    }
    problems.sort();
    problems.dedup();
    assert!(
        problems.is_empty(),
        "documentation names flags the binary does not have:\n{}",
        problems.join("\n")
    );
}

/// The extractor must actually be finding commands. Without this, a change that
/// silently stops matching fenced blocks would make both gates above pass by
/// examining nothing.
#[test]
fn the_extractor_reads_a_substantial_number_of_documented_commands() {
    let total: usize = documentation_pages()
        .iter()
        .map(|page| collect_invocations(page).len())
        .sum();
    assert!(
        total >= 150,
        "expected the canonical docs to contain at least 150 `keyhog` invocations, found {total}; \
         the extractor has probably stopped matching fenced blocks"
    );
}
