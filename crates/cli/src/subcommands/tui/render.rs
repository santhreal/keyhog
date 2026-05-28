//! All ratatui rendering for the `keyhog tui` subcommand.
//!
//! Split out of `mod.rs` to keep individual files under the 500-line
//! cap. The three pure-presentation fns (banner, feed, stats) are the
//! bulk of the line count; mod.rs is now ~280 lines focused on
//! orchestration, args plumbing, and the keyboard event loop.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

use keyhog_core::Severity;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use super::{Counters, FindingEvent};

#[allow(clippy::too_many_arguments)]
pub(super) fn render(
    frame: &mut ratatui::Frame<'_>,
    target: &Path,
    backend_label: &str,
    preferred_backend: &str,
    pattern_count: usize,
    counters: &Counters,
    findings_feed: &std::collections::VecDeque<FindingEvent>,
    elapsed: Duration,
    done: bool,
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(5),
            Constraint::Length(8),
        ])
        .split(area);

    let current_file = counters
        .current_file
        .read()
        .map(|s| s.clone())
        .unwrap_or_default();
    render_banner(frame, chunks[0], target, done, &current_file);
    render_feed(frame, chunks[1], findings_feed);
    render_stats(
        frame,
        chunks[2],
        counters,
        elapsed,
        backend_label,
        preferred_backend,
        pattern_count,
    );
}

fn render_banner(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    target: &Path,
    done: bool,
    current_file: &str,
) {
    // Same rationale as format_finding_row: explicit RGB to bypass
    // theme remapping of the named ANSI palette. The "scan complete"
    // pill needs a green saturated enough to read at a glance even
    // under aggressive theme desaturation; the "scanning" pill needs
    // an amber that can't be confused with the white text around it.
    let title = if done {
        Span::styled(
            " scan complete ",
            Style::default()
                .fg(Color::Rgb(0x0c, 0x0c, 0x0c))
                .bg(Color::Rgb(0x30, 0xd1, 0x58))
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " scanning ",
            Style::default()
                .fg(Color::Rgb(0x0c, 0x0c, 0x0c))
                .bg(Color::Rgb(0xff, 0xd6, 0x0a))
                .add_modifier(Modifier::BOLD),
        )
    };

    let line1 = Line::from(vec![
        Span::styled(
            "keyhog",
            Style::default()
                .fg(Color::Rgb(0x64, 0xd2, 0xff))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  v"),
        Span::raw(env!("CARGO_PKG_VERSION")),
        Span::raw("  ·  "),
        title,
        Span::raw("  "),
        Span::styled(
            target.display().to_string(),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let current_display = if done {
        "done. press any key to exit".to_string()
    } else if current_file.is_empty() {
        "scanning ...".to_string()
    } else {
        let trimmed = abbreviate_path(current_file, 90);
        format!("→ {trimmed}")
    };
    let line2 = Line::from(vec![Span::styled(
        current_display,
        Style::default().fg(Color::DarkGray),
    )]);

    let paragraph = Paragraph::new(vec![line1, line2])
        .block(Block::default().borders(Borders::ALL).title(" keyhog "));
    frame.render_widget(paragraph, area);
}

/// Trim a path to fit in `max_chars` columns by keeping the head plus
/// the tail and ellipsizing the middle. Matches the behaviour the
/// scan stream uses to avoid the banner wrapping when a deeply
/// nested target file path overflows the terminal width.
fn abbreviate_path(path: &str, max_chars: usize) -> String {
    if path.chars().count() <= max_chars {
        return path.to_string();
    }
    let take = max_chars.saturating_sub(3);
    let head = take / 2;
    let tail = take - head;
    let chars: Vec<char> = path.chars().collect();
    let mut out = String::with_capacity(max_chars);
    out.extend(chars.iter().take(head));
    out.push_str("...");
    out.extend(chars.iter().skip(chars.len().saturating_sub(tail)));
    out
}

fn render_feed(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    findings_feed: &std::collections::VecDeque<FindingEvent>,
) {
    let items: Vec<ListItem<'_>> = findings_feed
        .iter()
        .rev()
        .take(area.height.saturating_sub(2) as usize)
        .map(format_finding_row)
        .collect();
    let title = if findings_feed.is_empty() {
        " findings  (no leaks detected yet) ".to_string()
    } else {
        format!(" findings  ({} shown) ", findings_feed.len())
    };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .style(Style::default());
    frame.render_widget(list, area);
}

fn format_finding_row(f: &FindingEvent) -> ListItem<'_> {
    // Severity colors use explicit RGB rather than the named ANSI
    // palette (Color::Red etc) because terminal themes routinely
    // remap the 16-color palette to muted variants. Catppuccin
    // Mocha's "red" is a soft pink (#f38ba8); the resulting demo
    // gif showed five CRITICAL findings stacked with no visible
    // severity distinction. Explicit sRGB byte triples render at
    // full saturation regardless of theme, which is what users
    // expect from a SECURITY tool's severity badges. The values
    // are tuned for high contrast on a dark background AND legible
    // on a light one (the latter via VS Code's terminal panel).
    let (sev_label, sev_color) = match f.severity {
        Severity::Critical => ("CRITICAL", Color::Rgb(0xff, 0x3b, 0x30)),
        Severity::High => ("HIGH    ", Color::Rgb(0xff, 0x9f, 0x0a)),
        Severity::Medium => ("MEDIUM  ", Color::Rgb(0xff, 0xd6, 0x0a)),
        Severity::Low => ("LOW     ", Color::Rgb(0x64, 0xd2, 0xff)),
        Severity::ClientSafe => ("CLIENT  ", Color::Rgb(0x5a, 0xc8, 0xfa)),
        _ => ("INFO    ", Color::Rgb(0x8e, 0x8e, 0x93)),
    };
    let loc = match f.line {
        Some(n) => format!("{}:{n}", f.path),
        None => f.path.clone(),
    };
    ListItem::new(Line::from(vec![
        Span::styled(
            sev_label,
            Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{:<24}", f.detector_id),
            Style::default().fg(Color::White),
        ),
        Span::raw(" "),
        Span::styled(loc, Style::default().fg(Color::Gray)),
        Span::raw("  "),
        Span::styled(
            f.redacted.clone(),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        ),
        Span::raw("  ["),
        Span::styled(f.service.clone(), Style::default().fg(Color::Magenta)),
        Span::raw("]"),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn render_stats(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    counters: &Counters,
    elapsed: Duration,
    backend_label: &str,
    preferred_backend: &str,
    pattern_count: usize,
) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let files_done = counters.files_done.load(Ordering::Relaxed);
    let files_total = counters.files_total.load(Ordering::Relaxed);
    let bytes_done = counters.bytes_done.load(Ordering::Relaxed);
    let findings_total = counters.findings_total.load(Ordering::Relaxed);
    let secs = elapsed.as_secs_f64();
    let throughput_text = if bytes_done == 0 {
        if files_total == 0 {
            "discovering ...".to_string()
        } else {
            "warming up ...".to_string()
        }
    } else {
        let rate = bytes_done as f64 / secs.max(0.05);
        format!("{}/s", format_bytes(rate as u64))
    };
    let files_text = if files_total == 0 {
        "discovering ...".to_string()
    } else {
        format!("{files_done} / {files_total}")
    };

    let stats_lines = vec![
        Line::from(vec![stat_label("files"), Span::raw(files_text)]),
        Line::from(vec![
            stat_label("bytes"),
            Span::raw(format_bytes(bytes_done)),
        ]),
        Line::from(vec![
            stat_label("findings"),
            Span::styled(
                format!("{findings_total}"),
                Style::default()
                    .fg(if findings_total > 0 {
                        Color::Rgb(0xff, 0x3b, 0x30)
                    } else {
                        Color::Rgb(0x30, 0xd1, 0x58)
                    })
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            stat_label("elapsed"),
            Span::raw(format!("{:.2}s", secs)),
        ]),
        Line::from(vec![
            stat_label("throughput"),
            Span::styled(
                throughput_text,
                Style::default().fg(Color::Rgb(0x30, 0xd1, 0x58)),
            ),
        ]),
    ];

    let backend_lines = vec![
        Line::from(vec![
            stat_label("engine"),
            Span::styled(
                preferred_backend.to_string(),
                Style::default().fg(Color::Rgb(0xbf, 0x5a, 0xf2)),
            ),
        ]),
        Line::from(vec![
            stat_label("gpu-stack"),
            Span::styled(
                if backend_label.is_empty() {
                    "(none compiled)".to_string()
                } else {
                    backend_label.to_string()
                },
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            stat_label("patterns"),
            Span::raw(pattern_count.to_string()),
        ]),
        Line::from(vec![Span::styled(
            "  q to quit · any key after scan completes",
            Style::default().fg(Color::DarkGray),
        )]),
    ];

    frame.render_widget(
        Paragraph::new(stats_lines).block(Block::default().borders(Borders::ALL).title(" stats ")),
        columns[0],
    );
    frame.render_widget(
        Paragraph::new(backend_lines)
            .block(Block::default().borders(Borders::ALL).title(" backend ")),
        columns[1],
    );
}

fn stat_label(label: &str) -> Span<'_> {
    Span::styled(
        format!("  {label:<11}"),
        Style::default().fg(Color::DarkGray),
    )
}

use crate::format::format_bytes;
