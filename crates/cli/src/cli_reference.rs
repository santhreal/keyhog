//! Generate the CLI reference markdown from the live `clap` command model.
//!
//! This module is compiled only for the crate's path-included coherence tests;
//! it is not part of the supported `keyhog` library API.

use std::ffi::OsStr;
use clap::{Arg, ArgAction, Command};

/// Opening marker for a generated block in `docs/src/reference/cli.md`.
///
/// The `command` attribute names the command path; an empty string means the
/// root command options. Nested subcommands use `/` as a separator, e.g.
/// `daemon/start`.
pub(crate) const MARKER_OPEN: &str = "<!-- keyhog-generated: cli-reference command=\"";

/// Closing portion of an opening marker.
pub(crate) const MARKER_CLOSE: &str = "\" -->";

/// Opening portion of an end marker.
pub(crate) const MARKER_END_OPEN: &str = "<!-- /keyhog-generated: cli-reference command=\"";

/// Closing portion of an end marker.
pub(crate) const MARKER_END_CLOSE: &str = "\" -->";

/// Regenerate a markdown source by replacing every generated block marker with
/// the output of [`generate_for`].
///
/// The input is expected to contain paired markers like:
///
/// ```text
/// <!-- keyhog-generated: cli-reference command="scan" -->
/// ...old generated content...
/// <!-- /keyhog-generated: cli-reference command="scan" -->
/// ```
///
/// Unknown markup outside the markers is preserved unchanged.
pub(crate) fn regenerate(source: &str, root: &Command) -> String {
    let mut built = root.clone();
    built.build();
    let mut out = String::with_capacity(source.len());
    let mut rest = source;

    while let Some(start) = rest.find(MARKER_OPEN) {
        out.push_str(&rest[..start]);

        let after_open = &rest[start + MARKER_OPEN.len()..];
        let close_pos = after_open
            .find(MARKER_CLOSE)
            .expect("unclosed generated block opening marker");
        let command = &after_open[..close_pos];

        let after_close = &after_open[close_pos + MARKER_CLOSE.len()..];
        let after_close = if after_close.starts_with('\n') {
            &after_close[1..]
        } else {
            after_close
        };

        let end_marker = format!("{MARKER_END_OPEN}{command}{MARKER_END_CLOSE}");
        let end_pos = after_close
            .find(&end_marker)
            .expect("missing generated block end marker");

        let generated = generate_for_built(&built, command);

        out.push_str(MARKER_OPEN);
        out.push_str(command);
        out.push_str(MARKER_CLOSE);
        out.push('\n');
        out.push_str(&generated);
        if !generated.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&end_marker);

        rest = &after_close[end_pos + end_marker.len()..];
    }

    out.push_str(rest);
    out
}

/// Generate the markdown fragment for a command path.
///
/// `command` is either an empty string (root options) or a `/`-separated path
/// of subcommand names. For commands with nested subcommands, a summary table
/// is emitted followed by a flag table for each nested command.
pub(crate) fn generate_for(root: &Command, command: &str) -> String {
    // Clap derives value arities, names, default help flags, and other display
    // metadata while building a command. Render a private clone so callers do
    // not need to pre-build (or mutate) the production command tree.
    let mut built = root.clone();
    built.build();
    generate_for_built(&built, command)
}

fn generate_for_built(root: &Command, command: &str) -> String {
    if command.is_empty() {
        return arguments_table(root, true);
    }

    let cmd = resolve(root, command);
    let subcommands: Vec<&Command> = cmd
        .get_subcommands()
        .filter(|c| !c.is_hide_set())
        .collect();

    if subcommands.is_empty() {
        arguments_table(cmd, false)
    } else {
        nested_command_block(command, &subcommands)
    }
}

/// Resolve a `/`-separated subcommand path from `root`.
fn resolve<'a>(root: &'a Command, path: &str) -> &'a Command {
    if path.is_empty() {
        return root;
    }
    let mut cmd = root;
    for segment in path.split('/') {
        let Some(next) = cmd.find_subcommand(segment) else {
            panic!("unknown subcommand {segment} in path {path:?}");
        };
        cmd = next;
    }
    cmd
}

/// Render the summary table and per-subcommand flag tables for a command that
/// has nested subcommands.
fn nested_command_block(parent_path: &str, subcommands: &[&Command]) -> String {
    let mut out = String::new();

    out.push_str("| Subcommand | Aliases | Description |\n");
    out.push_str("|------------|---------|-------------|\n");
    for sub in sort_commands(subcommands) {
        let names = sub.get_name_and_visible_aliases();
        let primary = names[0];
        let aliases = if names.len() > 1 {
            names[1..].join(", ")
        } else {
            String::new()
        };
        let desc = about_text(sub.get_long_about().or(sub.get_about()));
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            primary,
            code_or_empty(&aliases),
            md_cell(&desc)
        ));
    }
    out.push('\n');

    for sub in sort_commands(subcommands) {
        let sub_name = sub.get_name();
        let full = full_command_path(parent_path, sub_name);
        out.push_str(&format!("### `{}`\n\n", full));
        out.push_str(&arguments_table(sub, false));
        out.push('\n');
    }

    out
}

/// Generate the argument table for a leaf command.
fn arguments_table(cmd: &Command, is_root: bool) -> String {
    let mut args: Vec<&Arg> = cmd
        .get_arguments()
        .filter(|a| {
            // Every subcommand auto-generates `--help`; keep it only for the
            // root options table because root help is part of the operator
            // contract, while per-subcommand `--help` is clap convention.
            if !is_root && is_auto_help(a) {
                return false;
            }
            true
        })
        .collect();
    args.sort_by_key(|a| sort_key(a));

    if args.is_empty() {
        return "*No arguments.*\n".to_string();
    }

    let mut out = String::new();
    out.push_str("| Argument | Value | Default | Description |\n");
    out.push_str("|----------|-------|---------|-------------|\n");
    for arg in args {
        let argument = argument_cell(arg);
        let value = value_cell(arg);
        let default = default_cell(arg);
        let desc = description(arg);
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            argument, value, default, md_cell(&desc)
        ));
    }
    out
}

/// Sort key: positionals by index, then flags alphabetically by long/short/id.
fn sort_key(arg: &Arg) -> (usize, String) {
    let index = match arg.get_index() {
        Some(index) => index,
        None => usize::MAX,
    };
    let name = if let Some(long) = arg.get_long() {
        long.to_string()
    } else if let Some(short) = arg.get_short() {
        format!("-{short}")
    } else {
        arg.get_id().as_str().to_string()
    };
    (index, name)
}

/// True when `arg` is the auto-generated `--help` flag.
fn is_auto_help(arg: &Arg) -> bool {
    arg.get_id().as_str() == "help"
        && arg.get_long() == Some("help")
        && arg.get_short() == Some('h')
        && matches!(arg.get_action(), ArgAction::Help)
}

/// Build the `Argument` table cell.
fn argument_cell(arg: &Arg) -> String {
    if arg.is_positional() {
        return positional_cell(arg);
    }

    let mut parts: Vec<String> = Vec::new();

    if let Some(short) = arg.get_short() {
        parts.push(format!("`-{short}`"));
    }
    if let Some(long) = arg.get_long() {
        parts.push(format!("`--{long}`"));
    }

    if let Some(shorts) = arg.get_visible_short_aliases() {
        for c in shorts {
            if Some(c) != arg.get_short() {
                parts.push(format!("`-{c}`"));
            }
        }
    }

    if let Some(aliases) = arg.get_visible_aliases() {
        for alias in aliases {
            if Some(alias) != arg.get_long() {
                parts.push(format!("`--{alias}`"));
            }
        }
    }

    let mut cell = parts.join(", ");
    if arg.is_required_set() {
        cell.push_str(" *(required)*");
    }
    if arg.is_hide_set() {
        cell.push_str(" *(hidden)*");
    }
    cell
}

/// Build the `Argument` cell for a positional argument.
fn positional_cell(arg: &Arg) -> String {
    let name = value_placeholder(arg);
    let mut cell = format!("`<{name}>`");
    if arg.is_required_set() {
        cell.push_str(" *(required)*");
    }
    if arg.is_hide_set() {
        cell.push_str(" *(hidden)*");
    }
    cell
}

/// Build the `Value` table cell.
fn value_cell(arg: &Arg) -> String {
    let action = arg.get_action();
    if !action.takes_values() || matches!(action, ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Count) {
        return String::new();
    }

    let Some(num) = arg.get_num_args() else {
        return String::new();
    };

    let min = num.min_values();
    let max = num.max_values();

    if min == 0 && max == 1 {
        // Optional single value: --daemon [auto|on|off]
        let ph = value_placeholder(arg);
        return code_or_empty(&format!("[{ph}]"));
    }

    if max > 1 || min != max {
        let ph = value_placeholder(arg);
        return code_or_empty(&format!("{ph}..."));
    }

    code_or_empty(&value_placeholder(arg))
}

/// Build the `Default` table cell.
fn default_cell(arg: &Arg) -> String {
    let action = arg.get_action();

    // Boolean flags default to false; stating it adds noise and the help text
    // already says "Off by default" where relevant.
    if matches!(action, ArgAction::SetTrue | ArgAction::SetFalse) {
        if let Some(first) = arg.get_default_values().first() {
            if parse_bool(first.as_os_str()) == Some(true) {
                return "`true`".to_string();
            }
        }
        return String::new();
    }

    if matches!(action, ArgAction::Count) {
        let vals: Vec<String> = arg.get_default_values().iter().map(os_to_str).collect();
        if !vals.is_empty() && vals != ["0"] {
            return code_or_empty(&vals.join(", "));
        }
        return String::new();
    }

    let vals: Vec<String> = arg.get_default_values().iter().map(os_to_str).collect();
    if vals.is_empty() {
        return String::new();
    }
    code_or_empty(&vals.join(", "))
}

/// Build the `Description` table cell.
fn description(arg: &Arg) -> String {
    let mut parts = Vec::new();

    if let Some(styled) = arg.get_long_help().or_else(|| arg.get_help()) {
        parts.push(styled.to_string());
    }

    if let Some(num) = arg.get_num_args() {
        if num.min_values() == 0 && num.max_values() >= 1 && arg.get_action().takes_values() {
            parts.push("Optional value.".to_string());
        }
    }

    let possible = possible_values(arg);
    if !possible.is_empty() {
        parts.push(format!("Possible values: {}.", possible.join(", ")));
    }

    let mut text = parts.join(" ");
    if text.is_empty() {
        text = "*No description.*".to_string();
    }
    text
}

/// Return possible values as backtick-wrapped markdown strings.
fn possible_values(arg: &Arg) -> Vec<String> {
    arg.get_possible_values()
        .into_iter()
        .map(|pv| {
            let mut s = format!("`{}`", pv.get_name());
            if pv.is_hide_set() {
                s.push_str(" *(hidden)*");
            }
            s
        })
        .collect()
}

/// Return the value placeholder for an argument.
fn value_placeholder(arg: &Arg) -> String {
    if let Some(names) = arg.get_value_names() {
        if !names.is_empty() {
            return names[0].as_str().to_string();
        }
    }
    arg.get_id().as_str().to_ascii_uppercase()
}

/// Human-readable command path for a nested subcommand heading.
fn full_command_path(parent: &str, sub_name: &str) -> String {
    if parent.is_empty() {
        format!("keyhog {sub_name}")
    } else {
        format!("keyhog {} {sub_name}", parent.replace('/', " "))
    }
}

/// Extract plain text from a command about string.
fn about_text(about: Option<&clap::builder::StyledStr>) -> String {
    let text = match about {
        Some(about) => about.to_string(),
        None => String::new(),
    };
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Wrap text in backticks if non-empty; otherwise return an empty string.
///
/// Pipes still need escaping inside inline code when that code is a Markdown
/// table cell; mdBook otherwise treats them as column delimiters.
fn code_or_empty(text: &str) -> String {
    if text.is_empty() {
        String::new()
    } else {
        format!("`{}`", text.replace('|', "\\|"))
    }
}

/// Escape a markdown table cell that is *not* wrapped in backticks.
///
/// Pipes are escaped, HTML-significant characters are escaped, and whitespace
/// is collapsed to a single space so multi-line clap help strings do not break
/// the table layout.
fn md_cell(text: &str) -> String {
    let collapsed = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let mut out = String::with_capacity(collapsed.len());
    let mut in_code = false;
    for c in collapsed.chars() {
        if c == '`' {
            in_code = !in_code;
            out.push(c);
            continue;
        }

        match c {
            // Markdown table parsers treat pipes as delimiters even inside an
            // inline-code span, so this escape is unconditional.
            '|' => out.push_str("\\|"),
            '<' if !in_code => out.push_str("&lt;"),
            '>' if !in_code => out.push_str("&gt;"),
            '&' if !in_code => out.push_str("&amp;"),
            _ => out.push(c),
        }
    }
    out
}

/// Convert an `OsStr` to a `String` lossily.
fn os_to_str(os: &clap::builder::OsStr) -> String {
    os.as_os_str().to_string_lossy().into_owned()
}

/// Parse an `OsStr` as a bool for default-value filtering.
fn parse_bool(os: &OsStr) -> Option<bool> {
    match os.to_string_lossy().as_ref() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Return a consistently sorted copy of a command slice.
fn sort_commands<'a>(commands: &[&'a Command]) -> Vec<&'a Command> {
    let mut v = commands.to_vec();
    v.sort_by_key(|c| c.get_name());
    v
}
