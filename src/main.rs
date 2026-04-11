mod guards;
mod hook;
mod state;

use clap::{Parser, Subcommand};
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
        Command::Check { guard } => cmd_check(&guard),
    }
}

/// Resolve the target directory for on/off/status commands.
/// --global → None (global config). Otherwise, --dir or $PWD.
fn resolve_dir(dir: Option<String>, global: bool) -> Option<String> {
    if global {
        return None;
    }
    dir.or_else(|| std::env::var("PWD").ok())
        .or_else(|| std::env::current_dir().ok().and_then(|p| p.to_str().map(String::from)))
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

fn cmd_check(guard_name: &str) {
    if !guards::exists(guard_name) {
        std::process::exit(0);
    }

    let input = match hook::read_stdin() {
        Some(v) => v,
        None => std::process::exit(0),
    };

    let st = GuardState::load();

    // Resolve working directory: check hook input for cwd, then fall back to $PWD
    let cwd = input
        .pointer("/cwd")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| std::env::var("PWD").ok())
        .or_else(|| std::env::current_dir().ok().and_then(|p| p.to_str().map(String::from)));

    let enabled = match cwd {
        Some(ref dir) => st.is_enabled_for_dir(guard_name, dir),
        None => st.is_enabled(guard_name),
    };

    if !enabled {
        std::process::exit(0);
    }

    match guards::check(guard_name, &input) {
        Some(reason) => {
            print!("{}", hook::deny_json(&reason));
            std::process::exit(0);
        }
        None => std::process::exit(0),
    }
}
