//! `keyhog completion <shell>` — print a shell completion script to stdout.
//!
//! Standard tooling for any clap-based CLI. Pipe to a shell-specific
//! location:
//!
//! ```text
//! keyhog completion bash > /usr/share/bash-completion/completions/keyhog
//! keyhog completion zsh  > "${fpath[1]}/_keyhog"
//! keyhog completion fish > ~/.config/fish/completions/keyhog.fish
//! ```

use crate::args::{Cli, CompletionArgs};
use clap::CommandFactory;

pub fn run(args: CompletionArgs) {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    clap_complete::generate(args.shell, &mut cmd, bin_name, &mut std::io::stdout());
}
