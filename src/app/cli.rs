use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "mcaifee",
    version,
    about = "Pre-install npm, pnpm, Yarn, and Bun malware gate.",
    after_help = "Compatibility: `mcaifee <package-spec>` and `mcaifee --lockfile <path>` still run scan mode. Package-manager wrappers use `mcaifee npm|pnpm|yarn|bun ...`."
)]
pub(super) struct TopLevelCli {
    #[command(subcommand)]
    pub(super) command: Option<TopLevelCommand>,
}

#[derive(Subcommand, Debug)]
pub(super) enum TopLevelCommand {
    #[command(about = "Scan package specs, package.json manifests, and lockfiles")]
    Scan,
    #[command(about = "Generate a full dependency risk report")]
    Report,
    #[command(about = "Alias of report")]
    Audit,
    #[command(about = "Update or inspect the local malicious package source database")]
    Db,
    #[command(about = "Create or inspect user policy configuration")]
    Config,
    #[command(about = "Inspect, tail, or prune invocation logs")]
    Logs,
    #[command(about = "Check local config, cache, logs, source DB, and tool availability")]
    Doctor,
    #[command(about = "Print shell functions that wrap package managers")]
    ShellInit,
    #[command(about = "Print shell commands that disable wrapper functions")]
    ShellDisable,
    #[command(about = "Show whether the current shell has the Mcaifee marker")]
    ShellStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NamedCliCommand {
    Scan,
    ShellInit,
    ShellDisable,
    ShellStatus,
    Db,
    Config,
    Doctor,
    Logs,
    Report,
}

pub(super) fn should_render_top_level_cli(raw_args: &[String]) -> bool {
    raw_args.is_empty()
        || raw_args.first().is_some_and(|arg| {
            matches!(arg.as_str(), "-h" | "--help" | "-V" | "--version" | "help")
        })
}

pub(super) fn named_cli_command(command: &str) -> Option<NamedCliCommand> {
    match command {
        "scan" => Some(NamedCliCommand::Scan),
        "shell-init" => Some(NamedCliCommand::ShellInit),
        "shell-disable" => Some(NamedCliCommand::ShellDisable),
        "shell-status" => Some(NamedCliCommand::ShellStatus),
        "db" => Some(NamedCliCommand::Db),
        "config" => Some(NamedCliCommand::Config),
        "doctor" => Some(NamedCliCommand::Doctor),
        "logs" => Some(NamedCliCommand::Logs),
        "report" | "audit" => Some(NamedCliCommand::Report),
        _ => None,
    }
}

pub(super) fn args_with_program(program: &str, args: &[String]) -> Vec<String> {
    let mut parsed_args = Vec::with_capacity(args.len() + 1);
    parsed_args.push(program.to_string());
    parsed_args.extend(args.iter().cloned());
    parsed_args
}
