use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default)]
pub struct GuardState {
    pub guards: HashMap<String, bool>,
    #[serde(skip)]
    path: PathBuf,
}

impl GuardState {
    fn state_path() -> PathBuf {
        if let Ok(p) = std::env::var("GUARDCTL_STATE") {
            return PathBuf::from(p);
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
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
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(&self).unwrap_or_default();
        let _ = std::fs::write(&self.path, json);
    }

    pub fn is_enabled(&self, name: &str) -> bool {
        // Default to enabled if not explicitly set
        self.guards.get(name).copied().unwrap_or(true)
    }

    pub fn set(&mut self, name: &str, enabled: bool) {
        self.guards.insert(name.to_string(), enabled);
    }
}
