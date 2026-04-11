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
    /// Enable guards
    On {
        /// Enable only a specific guard
        #[arg(long)]
        only: Option<String>,
    },
    /// Disable guards
    Off {
        /// Disable only a specific guard
        #[arg(long)]
        only: Option<String>,
    },
    /// Show guard status
    Status,
    /// List available guards
    List,
    /// Run a guard check (called by hook shims, reads JSON from stdin)
    Check {
        /// Guard name: "bash" or "file-write"
        guard: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::On { only } => cmd_toggle(true, only),
        Command::Off { only } => cmd_toggle(false, only),
        Command::Status => cmd_status(),
        Command::List => cmd_list(),
        Command::Check { guard } => cmd_check(&guard),
    }
}

fn cmd_toggle(enable: bool, only: Option<String>) {
    let mut st = GuardState::load();
    let verb = if enable { "enabled" } else { "disabled" };

    match only {
        Some(name) => {
            if !guards::exists(&name) {
                eprintln!("Unknown guard: {name}. Run 'guardctl list' to see available guards.");
                std::process::exit(1);
            }
            st.set(&name, enable);
            st.save();
            eprintln!("{name}: {verb}");
        }
        None => {
            for name in guards::all_names() {
                st.set(name, enable);
            }
            st.save();
            eprintln!("All guards {verb}.");
        }
    }
}

fn cmd_status() {
    let st = GuardState::load();
    for name in guards::all_names() {
        let enabled = st.is_enabled(name);
        let marker = if enabled { "ON " } else { "OFF" };
        let desc = guards::description(name);
        eprintln!("  [{marker}]  {name:16} {desc}");
    }
}

fn cmd_list() {
    for name in guards::all_names() {
        let desc = guards::description(name);
        eprintln!("  {name:16} {desc}");
    }
}

fn cmd_check(guard_name: &str) {
    if !guards::exists(guard_name) {
        std::process::exit(0);
    }

    let st = GuardState::load();
    if !st.is_enabled(guard_name) {
        std::process::exit(0);
    }

    let input = match hook::read_stdin() {
        Some(v) => v,
        None => std::process::exit(0),
    };

    match guards::check(guard_name, &input) {
        Some(reason) => {
            print!("{}", hook::deny_json(&reason));
            std::process::exit(0);
        }
        None => std::process::exit(0),
    }
}
