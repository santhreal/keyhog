use std::io::Write;

/// Print the KeyHog ASCII banner and version info.
pub fn print_banner<W: Write>(
    w: &mut W,
    colors: bool,
    ascii: bool,
    detector_count: usize,
) -> std::io::Result<()> {
    if ascii {
        let banner = r#"
    ⠀⣠⣶⣿⣿⣿⣿⣶⣄⠀
    ⠀⣿⣿⠉⠛⠛⠉⣿⣿⠀
    ⠀⢿⣿⣶⣿⣿⣶⣿⡿⠀
    ⠀⠀⠙⣿⣦⣴⣿⠋⠀⠀
    ⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀
    ⠀⠀⠀⣼⣿⣿⣧⠀⠀⠀
"#;
        if colors {
            writeln!(w, "\x1b[38;5;208m{}\x1b[0m", banner)?;
        } else {
            writeln!(w, "{}", banner)?;
        }
    }

    if colors {
        writeln!(w, "    \x1b[1mK E Y H O G\x1b[0m")?;
        writeln!(w, "    \x1b[2m───────────\x1b[0m")?;
        writeln!(
            w,
            "    \x1b[32mv{} · secret scanner · {} detectors\x1b[0m",
            env!("CARGO_PKG_VERSION"),
            detector_count
        )?;
        writeln!(w, "    \x1b[2mby santh\x1b[0m")?;
    } else {
        writeln!(w, "    K E Y H O G")?;
        writeln!(w, "    ───────────")?;
        writeln!(
            w,
            "    v{} · secret scanner · {} detectors",
            env!("CARGO_PKG_VERSION"),
            detector_count
        )?;
        writeln!(w, "    by santh")?;
    }
    writeln!(w)?;
    Ok(())
}
