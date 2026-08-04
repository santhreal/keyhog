//! `keyhog config` surfaces resolved runtime configuration without scanning.

use crate::args::ConfigArgs;
use crate::orchestrator_config::{render_effective_config, resolve_scan_config};
use anyhow::Result;
use std::process::ExitCode;

pub(crate) fn run(mut args: ConfigArgs) -> Result<ExitCode> {
    if !args.effective {
        anyhow::bail!(
            "`keyhog config` requires --effective. Fix: run `keyhog config --effective [scan flags]`."
        );
    }

    // Resolution (config merge) then publication of the rendered config.
    let resolved = {
        let _resolve_span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
        resolve_scan_config(&mut args.scan)?
    };
    let _report_span = keyhog_profile::span(keyhog_profile::Stage::Reporting);
    print!("{}", render_effective_config(&resolved));
    Ok(ExitCode::SUCCESS)
}
