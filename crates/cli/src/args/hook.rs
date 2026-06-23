#[derive(clap::Subcommand, Debug, Clone)]
pub enum HookCommand {
    /// Install a git pre-commit hook in the current repository
    Install {
        /// Replace an existing non-KeyHog pre-commit hook.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Remove the KeyHog pre-commit hook from the current repository
    Uninstall,
}
