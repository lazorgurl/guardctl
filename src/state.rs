use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default)]
pub struct GuardState {
    pub guards: HashMap<String, bool>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub directories: HashMap<String, HashMap<String, bool>>,
    #[serde(skip)]
    path: PathBuf,
}

impl GuardState {
    fn state_path() -> PathBuf {
        if let Ok(p) = std::env::var("GUARDCTL_STATE") {
            return PathBuf::from(p);
        }
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| {
                eprintln!(
                    "guardctl: HOME not set; falling back to current directory for state storage"
                );
                ".".into()
            });
        PathBuf::from(home)
            .join(".claude")
            .join("hooks")
            .join(".guard-state.json")
    }

    pub fn load() -> Self {
        let path = Self::state_path();
        let mut st = match std::fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        };
        st.path = path;
        st
    }

    pub fn save(&self) {
        if let Some(parent) = self.path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("guardctl: failed to create state dir {}: {e}", parent.display());
                return;
            }
        }
        let json = serde_json::to_string_pretty(&self).unwrap_or_default();
        if let Err(e) = crate::fs_util::atomic_write(&self.path, json.as_bytes()) {
            eprintln!(
                "guardctl: failed to save state to {}: {e}",
                self.path.display()
            );
        }
    }

    /// Check if a guard is enabled globally (no directory context).
    pub fn is_enabled(&self, name: &str) -> bool {
        self.guards.get(name).copied().unwrap_or(true)
    }

    /// Check if a guard is enabled for a specific directory.
    /// Uses longest-prefix matching: the most specific directory config wins.
    /// Falls back to global config if no directory matches.
    pub fn is_enabled_for_dir(&self, name: &str, dir: &str) -> bool {
        if let Some(overrides) = self.find_dir_overrides(dir) {
            if let Some(&enabled) = overrides.get(name) {
                return enabled;
            }
        }
        self.is_enabled(name)
    }

    /// Find the most specific directory overrides for a given path
    /// using longest-prefix matching.
    fn find_dir_overrides(&self, dir: &str) -> Option<&HashMap<String, bool>> {
        let normalized = dir.trim_end_matches('/');
        self.directories
            .iter()
            .filter(|(prefix, _)| {
                let p = prefix.trim_end_matches('/');
                normalized == p || normalized.starts_with(&format!("{p}/"))
            })
            .max_by_key(|(prefix, _)| prefix.trim_end_matches('/').len())
            .map(|(_, overrides)| overrides)
    }

    pub fn set(&mut self, name: &str, enabled: bool) {
        self.guards.insert(name.to_string(), enabled);
    }

    /// Set a guard for a specific directory.
    pub fn set_for_dir(&mut self, dir: &str, name: &str, enabled: bool) {
        let normalized = dir.trim_end_matches('/').to_string();
        self.directories
            .entry(normalized)
            .or_default()
            .insert(name.to_string(), enabled);
    }

    /// Remove all overrides for a specific directory.
    pub fn clear_dir(&mut self, dir: &str) {
        let normalized = dir.trim_end_matches('/');
        self.directories.remove(normalized);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_default_is_enabled() {
        let st = GuardState::default();
        assert!(st.is_enabled("bash"));
    }

    #[test]
    fn global_override() {
        let mut st = GuardState::default();
        st.set("bash", false);
        assert!(!st.is_enabled("bash"));
    }

    #[test]
    fn dir_override_takes_precedence() {
        let mut st = GuardState::default();
        st.set("bash", true);
        st.set_for_dir("/Users/julia/Code/personal", "bash", false);

        assert!(st.is_enabled_for_dir("bash", "/Users/julia/Code/hytale"));
        assert!(!st.is_enabled_for_dir("bash", "/Users/julia/Code/personal"));
        assert!(!st.is_enabled_for_dir("bash", "/Users/julia/Code/personal/sub/dir"));
    }

    #[test]
    fn longest_prefix_wins() {
        let mut st = GuardState::default();
        st.set_for_dir("/Users/julia/Code", "bash", false);
        st.set_for_dir("/Users/julia/Code/hytale", "bash", true);

        assert!(!st.is_enabled_for_dir("bash", "/Users/julia/Code/other"));
        assert!(st.is_enabled_for_dir("bash", "/Users/julia/Code/hytale"));
        assert!(st.is_enabled_for_dir("bash", "/Users/julia/Code/hytale/src"));
    }

    #[test]
    fn dir_falls_back_to_global() {
        let mut st = GuardState::default();
        st.set("mcp", false);
        st.set_for_dir("/Users/julia/Code/hytale", "bash", true);

        // mcp not overridden for this dir, falls back to global (false)
        assert!(!st.is_enabled_for_dir("mcp", "/Users/julia/Code/hytale"));
        // bash is overridden
        assert!(st.is_enabled_for_dir("bash", "/Users/julia/Code/hytale"));
    }

    #[test]
    fn no_matching_dir_uses_global() {
        let mut st = GuardState::default();
        st.set("bash", false);
        st.set_for_dir("/Users/julia/Code/hytale", "bash", true);

        // Unrelated directory falls back to global
        assert!(!st.is_enabled_for_dir("bash", "/tmp/random"));
    }

    #[test]
    fn trailing_slash_normalized() {
        let mut st = GuardState::default();
        st.set_for_dir("/Users/julia/Code/hytale/", "bash", false);

        assert!(!st.is_enabled_for_dir("bash", "/Users/julia/Code/hytale"));
        assert!(!st.is_enabled_for_dir("bash", "/Users/julia/Code/hytale/"));
        assert!(!st.is_enabled_for_dir("bash", "/Users/julia/Code/hytale/src"));
    }

    #[test]
    fn clear_dir_removes_overrides() {
        let mut st = GuardState::default();
        st.set_for_dir("/Users/julia/Code/hytale", "bash", false);
        assert!(!st.is_enabled_for_dir("bash", "/Users/julia/Code/hytale"));

        st.clear_dir("/Users/julia/Code/hytale");
        // Falls back to global default (true)
        assert!(st.is_enabled_for_dir("bash", "/Users/julia/Code/hytale"));
    }

    #[test]
    fn partial_prefix_does_not_match() {
        let mut st = GuardState::default();
        st.set_for_dir("/Users/julia/Code/hy", "bash", false);

        // "/Users/julia/Code/hytale" should NOT match "/Users/julia/Code/hy"
        // because "hytale" doesn't start with "hy/"
        assert!(st.is_enabled_for_dir("bash", "/Users/julia/Code/hytale"));
        // But a true subdirectory does match
        assert!(!st.is_enabled_for_dir("bash", "/Users/julia/Code/hy/sub"));
    }
}
