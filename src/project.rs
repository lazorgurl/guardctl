//! Per-project `.guardctl.toml` config.
//!
//! A project config is discovered by walking up from the resolved cwd. The
//! walk stops at `$HOME` (exclusive) so that a user-global config isn't
//! mistakenly picked up as project config.
//!
//! The config layers over the built-in guard rules in three ways:
//!
//! 1. `[guards]` — on/off override for this project, takes precedence over
//!    the state file's per-directory and global settings.
//! 2. `[[allow]]` — regex allowlist that short-circuits built-in rules. If
//!    a matching allow rule fires, the guard never runs.
//! 3. `[[rules]]` — project-specific extra rules, consulted *after* the
//!    built-in rules. Useful for per-repo tripwires like "never run `make
//!    deploy-prod`".
//!
//! Example `.guardctl.toml`:
//!
//! ```toml
//! [guards]
//! bash = true
//! file-write = true
//! mcp = false
//!
//! [[rules]]
//! guard = "bash"
//! pattern = "make deploy"
//! decision = "ask"
//! message = "Production deploy needs human confirmation"
//!
//! [[allow]]
//! guard = "bash"
//! pattern = "^git push --force origin experiment"
//! ```

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::guards::{Block, Decision};

/// The file name guardctl looks for in each ancestor directory.
pub const CONFIG_FILENAME: &str = ".guardctl.toml";

#[derive(Debug, Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    guards: HashMap<String, bool>,
    #[serde(default)]
    rules: Vec<RawRule>,
    #[serde(default)]
    allow: Vec<RawAllow>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    guard: String,
    pattern: String,
    decision: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct RawAllow {
    guard: String,
    pattern: String,
}

struct CompiledRule {
    guard: String,
    pattern: Regex,
    decision: Decision,
    message: String,
}

struct CompiledAllow {
    guard: String,
    pattern: Regex,
}

pub struct ProjectConfig {
    guards: HashMap<String, bool>,
    rules: Vec<CompiledRule>,
    allow: Vec<CompiledAllow>,
    /// Path to the `.guardctl.toml` this config was loaded from, if any.
    source: Option<PathBuf>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            guards: HashMap::new(),
            rules: Vec::new(),
            allow: Vec::new(),
            source: None,
        }
    }
}

impl ProjectConfig {
    /// Walk up from `cwd` looking for a `.guardctl.toml`. Returns the first
    /// one found, or a default (empty) config if none exists.
    ///
    /// The walk stops at `$HOME` (exclusive) — we never pick up a
    /// `$HOME/.guardctl.toml` via project discovery, since that would
    /// conflate per-user and per-project config.
    pub fn discover(cwd: Option<&str>) -> Self {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok();
        Self::discover_with_home(cwd, home.as_deref())
    }

    /// Explicit-home version of `discover` for testability. Takes the home
    /// directory as a parameter instead of reading `$HOME` so tests don't
    /// need to mutate shared process state.
    pub fn discover_with_home(cwd: Option<&str>, home: Option<&str>) -> Self {
        let Some(cwd) = cwd else {
            return Self::default();
        };

        let home = home.map(PathBuf::from);
        let mut dir = PathBuf::from(cwd);

        loop {
            // Stop before checking at $HOME — don't read user-global config as project config.
            if home.as_ref().map(|h| &dir == h).unwrap_or(false) {
                break;
            }

            let candidate = dir.join(CONFIG_FILENAME);
            if candidate.is_file() {
                match Self::load(&candidate) {
                    Ok(cfg) => return cfg,
                    Err(e) => {
                        eprintln!(
                            "guardctl: failed to load {}: {e} (falling back to defaults)",
                            candidate.display()
                        );
                        return Self::default();
                    }
                }
            }

            if !dir.pop() {
                break;
            }
        }

        Self::default()
    }

    /// Load a config from a specific path, compiling all regexes up front.
    /// Invalid individual rules are warned-about and skipped; syntactic TOML
    /// errors propagate.
    pub fn load(path: &Path) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let raw: RawConfig = toml::from_str(&contents)
            .map_err(|e| format!("{}: {e}", path.display()))?;

        let mut rules = Vec::with_capacity(raw.rules.len());
        for (i, r) in raw.rules.into_iter().enumerate() {
            match compile_rule(r) {
                Ok(c) => rules.push(c),
                Err(e) => eprintln!(
                    "guardctl: {}: skipping [[rules]] #{}: {e}",
                    path.display(),
                    i
                ),
            }
        }

        let mut allow = Vec::with_capacity(raw.allow.len());
        for (i, a) in raw.allow.into_iter().enumerate() {
            match compile_allow(a) {
                Ok(c) => allow.push(c),
                Err(e) => eprintln!(
                    "guardctl: {}: skipping [[allow]] #{}: {e}",
                    path.display(),
                    i
                ),
            }
        }

        Ok(Self {
            guards: raw.guards,
            rules,
            allow,
            source: Some(path.to_path_buf()),
        })
    }

    /// Where this config was loaded from, if any.
    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    /// Project-level on/off override for a guard. Returns `None` if the
    /// project config does not mention this guard — in that case the caller
    /// should fall back to the state file.
    pub fn guard_enabled(&self, name: &str) -> Option<bool> {
        self.guards.get(name).copied()
    }

    /// Does a `[[allow]]` rule match this input? If so, the guard should
    /// short-circuit and allow the tool call even if a built-in rule would
    /// have caught it.
    pub fn is_allowed(&self, guard_name: &str, input: &Value) -> bool {
        let Some(target) = extract_target(guard_name, input) else {
            return false;
        };
        self.allow
            .iter()
            .any(|a| a.guard == guard_name && a.pattern.is_match(&target))
    }

    /// Consult the project's `[[rules]]` for a match. Returned after the
    /// built-in rules are consulted, so custom project rules never override
    /// the project's own built-ins — they only *add* tripwires.
    pub fn check_extras(&self, guard_name: &str, input: &Value) -> Option<Block> {
        let target = extract_target(guard_name, input)?;
        for rule in &self.rules {
            if rule.guard == guard_name && rule.pattern.is_match(&target) {
                return Some(Block {
                    decision: rule.decision,
                    reason: rule.message.clone(),
                });
            }
        }
        None
    }
}

fn compile_rule(r: RawRule) -> Result<CompiledRule, String> {
    validate_guard_name(&r.guard)?;
    let pattern = Regex::new(&r.pattern)
        .map_err(|e| format!("invalid pattern {:?}: {e}", r.pattern))?;
    let decision = parse_decision(&r.decision)?;
    Ok(CompiledRule {
        guard: r.guard,
        pattern,
        decision,
        message: r.message,
    })
}

fn compile_allow(a: RawAllow) -> Result<CompiledAllow, String> {
    validate_guard_name(&a.guard)?;
    let pattern = Regex::new(&a.pattern)
        .map_err(|e| format!("invalid pattern {:?}: {e}", a.pattern))?;
    Ok(CompiledAllow {
        guard: a.guard,
        pattern,
    })
}

fn parse_decision(s: &str) -> Result<Decision, String> {
    match s {
        "deny" => Ok(Decision::Deny),
        "ask" => Ok(Decision::Ask),
        other => Err(format!(
            "unknown decision {other:?} (expected \"ask\" or \"deny\")"
        )),
    }
}

fn validate_guard_name(name: &str) -> Result<(), String> {
    match name {
        "bash" | "file-write" | "mcp" => Ok(()),
        other => Err(format!(
            "unknown guard {other:?} (expected \"bash\", \"file-write\", or \"mcp\")"
        )),
    }
}

/// Extract the command/path/tool-name from a hook input for matching against
/// a project rule. Bash commands are whitespace-normalized the same way the
/// built-in bash guard normalizes them.
fn extract_target(guard_name: &str, input: &Value) -> Option<String> {
    match guard_name {
        "bash" => {
            let cmd = input.pointer("/tool_input/command")?.as_str()?;
            Some(cmd.split_whitespace().collect::<Vec<_>>().join(" "))
        }
        "file-write" => input
            .pointer("/tool_input/file_path")?
            .as_str()
            .map(String::from),
        "mcp" => input.pointer("/tool_name")?.as_str().map(String::from),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn bash_input(cmd: &str) -> Value {
        json!({"tool_input": {"command": cmd}})
    }

    fn file_input(path: &str) -> Value {
        json!({"tool_input": {"file_path": path}})
    }

    fn mcp_input(tool: &str) -> Value {
        json!({"tool_name": tool})
    }

    /// Allocate a unique temporary directory for a test. No cleanup — /tmp
    /// handles it.
    fn make_tmp_dir() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "guardctl-project-test-{}-{}-{}",
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn default_config_is_empty() {
        let cfg = ProjectConfig::default();
        assert!(cfg.guard_enabled("bash").is_none());
        assert!(!cfg.is_allowed("bash", &bash_input("rm -rf /")));
        assert!(cfg.check_extras("bash", &bash_input("rm -rf /")).is_none());
    }

    #[test]
    fn guard_enabled_override() {
        let toml = r#"
[guards]
bash = false
mcp = true
"#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let cfg = ProjectConfig {
            guards: raw.guards,
            rules: vec![],
            allow: vec![],
            source: None,
        };
        assert_eq!(cfg.guard_enabled("bash"), Some(false));
        assert_eq!(cfg.guard_enabled("mcp"), Some(true));
        assert_eq!(cfg.guard_enabled("file-write"), None);
    }

    #[test]
    fn extras_match_bash_command() {
        let rule = compile_rule(RawRule {
            guard: "bash".into(),
            pattern: r"^make deploy-prod\b".into(),
            decision: "ask".into(),
            message: "prod deploy needs human sign-off".into(),
        })
        .unwrap();
        let cfg = ProjectConfig {
            guards: HashMap::new(),
            rules: vec![rule],
            allow: vec![],
            source: None,
        };

        let block = cfg
            .check_extras("bash", &bash_input("make deploy-prod --verbose"))
            .expect("should match");
        assert_eq!(block.decision, Decision::Ask);
        assert!(block.reason.contains("prod deploy"));

        assert!(cfg.check_extras("bash", &bash_input("make test")).is_none());
    }

    #[test]
    fn extras_match_file_path() {
        let rule = compile_rule(RawRule {
            guard: "file-write".into(),
            pattern: r"^/srv/app/dist/".into(),
            decision: "deny".into(),
            message: "dist/ is build output".into(),
        })
        .unwrap();
        let cfg = ProjectConfig {
            guards: HashMap::new(),
            rules: vec![rule],
            allow: vec![],
            source: None,
        };

        let block = cfg
            .check_extras("file-write", &file_input("/srv/app/dist/main.js"))
            .unwrap();
        assert_eq!(block.decision, Decision::Deny);
    }

    #[test]
    fn extras_match_mcp_tool() {
        let rule = compile_rule(RawRule {
            guard: "mcp".into(),
            pattern: r"delete".into(),
            decision: "ask".into(),
            message: "custom mcp rule".into(),
        })
        .unwrap();
        let cfg = ProjectConfig {
            guards: HashMap::new(),
            rules: vec![rule],
            allow: vec![],
            source: None,
        };

        assert!(cfg
            .check_extras("mcp", &mcp_input("mcp__foo__delete_thing"))
            .is_some());
        assert!(cfg
            .check_extras("mcp", &mcp_input("mcp__foo__read_thing"))
            .is_none());
    }

    #[test]
    fn allow_short_circuits_bash() {
        let allow = compile_allow(RawAllow {
            guard: "bash".into(),
            pattern: r"git push --force origin experiment".into(),
        })
        .unwrap();
        let cfg = ProjectConfig {
            guards: HashMap::new(),
            rules: vec![],
            allow: vec![allow],
            source: None,
        };

        assert!(cfg.is_allowed("bash", &bash_input("git push --force origin experiment")));
        assert!(!cfg.is_allowed("bash", &bash_input("git push --force origin main")));
    }

    #[test]
    fn compile_rejects_unknown_guard() {
        let err = compile_rule(RawRule {
            guard: "nope".into(),
            pattern: "foo".into(),
            decision: "ask".into(),
            message: "x".into(),
        });
        assert!(err.is_err());
    }

    #[test]
    fn compile_rejects_unknown_decision() {
        let err = compile_rule(RawRule {
            guard: "bash".into(),
            pattern: "foo".into(),
            decision: "perhaps".into(),
            message: "x".into(),
        });
        assert!(err.is_err());
    }

    #[test]
    fn compile_rejects_invalid_regex() {
        let err = compile_rule(RawRule {
            guard: "bash".into(),
            pattern: "[unclosed".into(),
            decision: "ask".into(),
            message: "x".into(),
        });
        assert!(err.is_err());
    }

    #[test]
    fn discover_walks_upward() {
        let root = make_tmp_dir();
        let nested = root.join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();

        // Put a .guardctl.toml at root/a
        let cfg_path = root.join("a").join(CONFIG_FILENAME);
        std::fs::write(
            &cfg_path,
            r#"
[guards]
bash = false
"#,
        )
        .unwrap();

        // HOME is set to an unrelated path so the walk doesn't terminate early.
        let cfg = ProjectConfig::discover_with_home(nested.to_str(), Some("/nonexistent-home"));
        assert_eq!(cfg.guard_enabled("bash"), Some(false));
        assert_eq!(cfg.source(), Some(cfg_path.as_path()));
    }

    #[test]
    fn discover_returns_default_when_nothing_found() {
        let dir = make_tmp_dir();
        let cfg = ProjectConfig::discover_with_home(dir.to_str(), Some("/nonexistent-home"));
        assert!(cfg.source().is_none());
        assert!(cfg.guard_enabled("bash").is_none());
    }

    #[test]
    fn discover_stops_at_home() {
        let root = make_tmp_dir();
        let home = root.join("home/julia");
        let project = home.join("Code/project");
        std::fs::create_dir_all(&project).unwrap();

        // Place a .guardctl.toml AT HOME — discovery must NOT pick this up.
        std::fs::write(
            home.join(CONFIG_FILENAME),
            r#"
[guards]
bash = false
"#,
        )
        .unwrap();

        let cfg = ProjectConfig::discover_with_home(project.to_str(), home.to_str());
        assert!(
            cfg.source().is_none(),
            "discover should not cross into HOME, but found {:?}",
            cfg.source()
        );
    }

    #[test]
    fn discover_loads_config_below_home() {
        // Analogous to the "stops at home" test but the config lives BELOW home,
        // which should be found.
        let root = make_tmp_dir();
        let home = root.join("home/julia");
        let project = home.join("Code/project");
        std::fs::create_dir_all(&project).unwrap();

        let cfg_path = project.join(CONFIG_FILENAME);
        std::fs::write(
            &cfg_path,
            r#"
[guards]
bash = false
"#,
        )
        .unwrap();

        let cfg = ProjectConfig::discover_with_home(project.to_str(), home.to_str());
        assert_eq!(cfg.source(), Some(cfg_path.as_path()));
    }

    #[test]
    fn load_parses_full_example() {
        let root = make_tmp_dir();
        let cfg_path = root.join(CONFIG_FILENAME);
        std::fs::write(
            &cfg_path,
            r#"
[guards]
bash = true
mcp = false

[[rules]]
guard = "bash"
pattern = "make deploy-prod"
decision = "ask"
message = "Prod deploy needs human confirmation"

[[rules]]
guard = "file-write"
pattern = "^/srv/app/dist/"
decision = "deny"
message = "dist/ is build output"

[[allow]]
guard = "bash"
pattern = "git push --force origin experiment"
"#,
        )
        .unwrap();

        let cfg = ProjectConfig::load(&cfg_path).unwrap();
        assert_eq!(cfg.guard_enabled("bash"), Some(true));
        assert_eq!(cfg.guard_enabled("mcp"), Some(false));

        // Extras: bash prod deploy should ask
        let b = cfg
            .check_extras("bash", &bash_input("make deploy-prod"))
            .unwrap();
        assert_eq!(b.decision, Decision::Ask);

        // Extras: file-write to dist should deny
        let b = cfg
            .check_extras("file-write", &file_input("/srv/app/dist/main.js"))
            .unwrap();
        assert_eq!(b.decision, Decision::Deny);

        // Allow: force push to experiment is whitelisted
        assert!(cfg.is_allowed("bash", &bash_input("git push --force origin experiment")));
        assert!(!cfg.is_allowed("bash", &bash_input("git push --force origin main")));
    }

    #[test]
    fn load_rejects_syntactic_errors() {
        let root = make_tmp_dir();
        let cfg_path = root.join(CONFIG_FILENAME);
        std::fs::write(&cfg_path, "this = is not [valid toml").unwrap();
        assert!(ProjectConfig::load(&cfg_path).is_err());
    }
}
