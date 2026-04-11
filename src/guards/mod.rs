mod bash;
mod file_write;

use serde_json::Value;

struct Guard {
    name: &'static str,
    description: &'static str,
    check_fn: fn(&Value) -> Option<String>,
}

const GUARDS: &[Guard] = &[
    Guard {
        name: "bash",
        description: "Blocks destructive shell commands (rm -rf, force push, reset --hard, etc.)",
        check_fn: bash::check,
    },
    Guard {
        name: "file-write",
        description: "Blocks writes to generated files, secrets, lock files, and Claude config",
        check_fn: file_write::check,
    },
];

pub fn all_names() -> Vec<&'static str> {
    GUARDS.iter().map(|g| g.name).collect()
}

pub fn exists(name: &str) -> bool {
    GUARDS.iter().any(|g| g.name == name)
}

pub fn description(name: &str) -> &'static str {
    GUARDS
        .iter()
        .find(|g| g.name == name)
        .map(|g| g.description)
        .unwrap_or("")
}

pub fn check(name: &str, input: &Value) -> Option<String> {
    GUARDS
        .iter()
        .find(|g| g.name == name)
        .and_then(|g| (g.check_fn)(input))
}
