use clap::{Parser, Subcommand, ValueEnum};
use keyhog_profile::{compare_profiles, RunProfile, PROFILE_SCHEMA, RUN_PROFILE_VERSION};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_PROFILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "keyhog-profile",
    about = "Inspect and compare versioned KeyHog profile records"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate and render one profile record.
    Inspect {
        /// Profile JSON file to inspect.
        profile: PathBuf,
        /// Output representation.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Compare two profiles after checking workload compatibility.
    Compare {
        /// Control profile JSON file.
        baseline: PathBuf,
        /// Candidate profile JSON file.
        candidate: PathBuf,
        /// Output representation.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Markdown,
}

fn read_profile(path: &Path) -> Result<RunProfile, String> {
    let file = File::open(path)
        .map_err(|error| format!("cannot open profile {}: {error}", path.display()))?;
    let declared_len = file
        .metadata()
        .map_err(|error| format!("cannot read profile metadata {}: {error}", path.display()))?
        .len();
    if declared_len > MAX_PROFILE_BYTES {
        return Err(format!(
            "profile {} is {declared_len} bytes; the limit is {MAX_PROFILE_BYTES} bytes",
            path.display()
        ));
    }

    let mut bytes = Vec::with_capacity(usize::try_from(declared_len).unwrap_or(0));
    Read::take(file, MAX_PROFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read profile {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_PROFILE_BYTES {
        return Err(format!(
            "profile {} grew beyond the {MAX_PROFILE_BYTES}-byte limit while reading",
            path.display()
        ));
    }

    let profile: RunProfile = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid profile JSON in {}: {error}", path.display()))?;
    if profile.schema != PROFILE_SCHEMA {
        return Err(format!(
            "unsupported profile schema {:?} in {}; expected {PROFILE_SCHEMA}",
            profile.schema,
            path.display()
        ));
    }
    if profile.version > RUN_PROFILE_VERSION {
        return Err(format!(
            "profile version {} in {} is newer than supported version {RUN_PROFILE_VERSION}; update keyhog-profile",
            profile.version,
            path.display()
        ));
    }
    Ok(profile)
}

fn write_stdout(text: &str) -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .map_err(|error| format!("cannot write output: {error}"))
}

fn run(cli: Cli) -> Result<u8, String> {
    match cli.command {
        Command::Inspect { profile, format } => {
            let profile = read_profile(&profile)?;
            let output = match format {
                OutputFormat::Text => profile.render_text(),
                OutputFormat::Json => profile
                    .to_json_pretty()
                    .map_err(|error| format!("cannot serialize profile: {error}"))?,
                OutputFormat::Markdown => profile.render_markdown(),
            };
            write_stdout(output.trim_end())?;
            Ok(0)
        }
        Command::Compare {
            baseline,
            candidate,
            format,
        } => {
            let baseline = read_profile(&baseline)?;
            let candidate = read_profile(&candidate)?;
            let comparison = compare_profiles(&baseline, &candidate);
            let output = match format {
                OutputFormat::Text => comparison.render_text(),
                OutputFormat::Json => serde_json::to_string_pretty(&comparison)
                    .map_err(|error| format!("cannot serialize comparison: {error}"))?,
                OutputFormat::Markdown => comparison.render_markdown(),
            };
            write_stdout(output.trim_end())?;
            Ok(if comparison.comparable { 0 } else { 3 })
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("keyhog-profile: {error}");
            ExitCode::from(2)
        }
    }
}
