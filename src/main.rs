mod audit;
mod fs_util;
mod guards;
mod hook;
mod init;
mod project;
mod state;

use clap::{Parser, Subcommand};
use guards::Block;
use project::ProjectConfig;
use state::GuardState;

#[derive(Parser)]
#[command(name = "guardctl", about = "Blast-radius guard for Claude Code")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enable guards (defaults to current directory; use --global for global)
    On {
        /// Enable only a specific guard
        #[arg(long)]
        only: Option<String>,
        /// Override target directory (default: $PWD)
        #[arg(long)]
        dir: Option<String>,
        /// Apply globally instead of to a directory
        #[arg(long)]
        global: bool,
    },
    /// Disable guards (defaults to current directory; use --global for global)
    Off {
        /// Disable only a specific guard
        #[arg(long)]
        only: Option<String>,
        /// Override target directory (default: $PWD)
        #[arg(long)]
        dir: Option<String>,
        /// Apply globally instead of to a directory
        #[arg(long)]
        global: bool,
    },
    /// Show guard status (defaults to current directory; use --global for global)
    Status {
        /// Override target directory (default: $PWD)
        #[arg(long)]
        dir: Option<String>,
        /// Show global status instead of directory-resolved status
        #[arg(long)]
        global: bool,
    },
    /// List available guards
    List,
    /// Remove all directory-specific overrides for a directory
    ClearDir {
        /// The directory to clear overrides for
        dir: String,
    },
    /// Install guardctl hooks into ~/.claude/settings.json
    Init,
    /// Dry-run a command/path/tool against guards
    Test {
        /// Test against the bash guard
        #[arg(long)]
        bash: Option<String>,
        /// Test against the file-write guard
        #[arg(long, name = "file-write")]
        file_write: Option<String>,
        /// Test against the mcp guard
        #[arg(long)]
        mcp: Option<String>,
    },
    /// Show recent blocks from the audit log
    Log {
        /// Number of entries to show (default: 20)
        #[arg(short, long, default_value = "20")]
        count: usize,
        /// Output as raw JSONL
        #[arg(long)]
        json: bool,
    },
    /// Run a guard check (called by hook shims, reads JSON from stdin)
    Check {
        /// Guard name: "bash", "file-write", or "mcp"
        guard: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::On { only, dir, global } => cmd_toggle(true, only, resolve_dir(dir, global)),
        Command::Off { only, dir, global } => cmd_toggle(false, only, resolve_dir(dir, global)),
        Command::Status { dir, global } => cmd_status(resolve_dir(dir, global)),
        Command::List => cmd_list(),
        Command::ClearDir { dir } => cmd_clear_dir(&dir),
        Command::Init => cmd_init(),
        Command::Test { bash, file_write, mcp } => cmd_test(bash, file_write, mcp),
        Command::Log { count, json } => cmd_log(count, json),
        Command::Check { guard } => cmd_check(&guard),
    }
}

/// Resolve the target directory for on/off/status commands.
/// --global → None (global config). Otherwise, --dir → current_dir → $PWD.
/// We prefer `current_dir()` over `$PWD` because `$PWD` can be stale in
/// non-interactive contexts (CI, systemd, nohup), while `current_dir()`
/// reflects the actual process state.
fn resolve_dir(dir: Option<String>, global: bool) -> Option<String> {
    if global {
        return None;
    }
    dir.or_else(|| std::env::current_dir().ok().and_then(|p| p.to_str().map(String::from)))
        .or_else(|| std::env::var("PWD").ok())
}

fn cmd_toggle(enable: bool, only: Option<String>, dir: Option<String>) {
    let mut st = GuardState::load();
    let verb = if enable { "enabled" } else { "disabled" };
    match (only, dir) {
        (Some(name), Some(dir)) => {
            if !guards::exists(&name) {
                eprintln!("Unknown guard: {name}. Run 'guardctl list' to see available guards.");
                std::process::exit(1);
            }
            st.set_for_dir(&dir, &name, enable);
            st.save();
            eprintln!("{name}: {verb} (dir: {dir})");
        }
        (Some(name), None) => {
            if !guards::exists(&name) {
                eprintln!("Unknown guard: {name}. Run 'guardctl list' to see available guards.");
                std::process::exit(1);
            }
            st.set(&name, enable);
            st.save();
            eprintln!("{name}: {verb}");
        }
        (None, Some(dir)) => {
            for name in guards::all_names() {
                st.set_for_dir(&dir, name, enable);
            }
            st.save();
            eprintln!("All guards {verb} (dir: {dir}).");
        }
        (None, None) => {
            for name in guards::all_names() {
                st.set(name, enable);
            }
            st.save();
            eprintln!("All guards {verb} (global).");
        }
    }
}

fn cmd_status(dir: Option<String>) {
    let st = GuardState::load();

    if let Some(ref dir) = dir {
        eprintln!("Guards for: {dir}");
    } else {
        eprintln!("Global guards:");
    }

    for name in guards::all_names() {
        let enabled = match dir {
            Some(ref d) => st.is_enabled_for_dir(name, d),
            None => st.is_enabled(name),
        };
        let marker = if enabled { "ON " } else { "OFF" };
        let desc = guards::description(name);
        eprintln!("  [{marker}]  {name:16} {desc}");
    }

    if !st.directories.is_empty() && dir.is_none() {
        eprintln!();
        eprintln!("Directory overrides:");
        for (dir_path, overrides) in &st.directories {
            let summary: Vec<String> = overrides
                .iter()
                .map(|(k, v)| format!("{k}={}", if *v { "on" } else { "off" }))
                .collect();
            eprintln!("  {dir_path}: {}", summary.join(", "));
        }
    }
}

fn cmd_list() {
    for name in guards::all_names() {
        let desc = guards::description(name);
        eprintln!("  {name:16} {desc}");
    }
}

fn cmd_clear_dir(dir: &str) {
    let mut st = GuardState::load();
    st.clear_dir(dir);
    st.save();
    eprintln!("Cleared all overrides for: {dir}");
}

fn cmd_init() {
    if let Err(e) = init::install() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn cmd_test(bash: Option<String>, file_write: Option<String>, mcp: Option<String>) {
    let checks: Vec<(&str, serde_json::Value)> = vec![
        bash.map(|cmd| ("bash", serde_json::json!({"tool_input": {"command": cmd}}))),
        file_write.map(|path| ("file-write", serde_json::json!({"tool_input": {"file_path": path}}))),
        mcp.map(|tool| ("mcp", serde_json::json!({"tool_name": tool}))),
    ]
    .into_iter()
    .flatten()
    .collect();

    if checks.is_empty() {
        eprintln!("Specify at least one: --bash <cmd>, --file-write <path>, or --mcp <tool>");
        std::process::exit(1);
    }

    // `guardctl test` also honours the project `.guardctl.toml` in the cwd
    // so that users can sanity-check custom rules and allowlists.
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from));
    let project = ProjectConfig::discover(cwd.as_deref());
    if let Some(src) = project.source() {
        eprintln!("Using project config: {}", src.display());
    }

    for (guard_name, input) in &checks {
        if project.is_allowed(guard_name, input) {
            eprintln!("ALLOWED by {guard_name} (project allowlist)");
            continue;
        }
        let block = guards::check(guard_name, input)
            .or_else(|| project.check_extras(guard_name, input));
        match block {
            Some(b) => {
                let label = match b.decision {
                    guards::Decision::Deny => "DENY",
                    guards::Decision::Ask => "ASK ",
                };
                eprintln!("{label} by {guard_name}: {}", b.reason);
            }
            None => eprintln!("ALLOWED by {guard_name}"),
        }
    }
}

fn cmd_log(count: usize, json: bool) {
    let entries = audit::read_recent(count);
    if entries.is_empty() {
        eprintln!("No blocks recorded yet.");
        return;
    }
    for entry in &entries {
        if json {
            println!("{entry}");
        } else {
            let ts = entry.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
            let guard = entry.get("guard").and_then(|v| v.as_str()).unwrap_or("?");
            // decision was added in a later version; older entries default to "deny".
            let decision = entry
                .get("decision")
                .and_then(|v| v.as_str())
                .unwrap_or("deny");
            let blocked = entry.get("blocked").and_then(|v| v.as_str()).unwrap_or("?");
            let reason = entry.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            let cwd = entry.get("cwd").and_then(|v| v.as_str()).unwrap_or("");

            let time = format_ts(ts);
            eprintln!("{time}  [{guard}/{decision}]  {blocked}");
            if !cwd.is_empty() {
                eprintln!("  cwd: {cwd}");
            }
            eprintln!("  {reason}");
            eprintln!();
        }
    }
}

fn format_ts(epoch: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let time = UNIX_EPOCH + Duration::from_secs(epoch);
    let elapsed = SystemTime::now()
        .duration_since(time)
        .unwrap_or_default();
    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

fn cmd_check(guard_name: &str) {
    if !guards::exists(guard_name) {
        std::process::exit(0);
    }

    let input = match hook::read_stdin() {
        Some(v) => v,
        None => std::process::exit(0),
    };

    let st = GuardState::load();

    // Resolve working directory: prefer the hook input's `cwd` field (Claude
    // Code passes the session's actual working directory here), then fall
    // back to the process current_dir, then $PWD.
    let cwd = input
        .pointer("/cwd")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| std::env::current_dir().ok().and_then(|p| p.to_str().map(String::from)))
        .or_else(|| std::env::var("PWD").ok());

    // Per-project config: walk up from cwd to find a `.guardctl.toml`.
    let project = ProjectConfig::discover(cwd.as_deref());

    // Guard enable precedence: project [guards] > state directory > state global.
    let enabled = match project.guard_enabled(guard_name) {
        Some(v) => v,
        None => match cwd {
            Some(ref dir) => st.is_enabled_for_dir(guard_name, dir),
            None => st.is_enabled(guard_name),
        },
    };

    if !enabled {
        std::process::exit(0);
    }

    // Project allowlist short-circuits everything else.
    if project.is_allowed(guard_name, &input) {
        std::process::exit(0);
    }

    // Built-in rules first, then project [[rules]] extras.
    let block: Option<Block> = guards::check(guard_name, &input)
        .or_else(|| project.check_extras(guard_name, &input));

    if let Some(block) = block {
        audit::record(
            guard_name,
            &block.reason,
            block.decision,
            cwd.as_deref(),
            &input,
        );
        print!("{}", hook::decision_json(block.decision, &block.reason));
    }
    std::process::exit(0);
}
