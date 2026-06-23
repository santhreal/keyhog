use clap::Parser;

use super::ScanArgs;

#[derive(Parser)]
pub struct ConfigArgs {
    /// Print the resolved scan configuration and exit without scanning.
    ///
    /// Accepts the same config-affecting flags as `keyhog scan`, so operators
    /// can prove the compiled defaults, TOML config, and CLI overrides that
    /// would reach the scanner for the same scan invocation.
    #[arg(long, required = true)]
    pub effective: bool,

    #[command(flatten)]
    pub scan: ScanArgs,
}
