use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

use crate::fs_util::atomic_write;

/// The (matcher, subcommand) pairs guardctl installs into PreToolUse.
const DESIRED: &[(&str, &str)] = &[
    ("Bash", "check bash"),
    ("Write|Edit", "check file-write"),
    ("mcp__.*", "check mcp"),
];

fn settings_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".claude").join("settings.json")
}

fn guardctl_binary() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "guardctl".into())
}

/// Build the nested Claude Code hook entry for a single (matcher, subcommand) pair.
///
/// Canonical Claude Code schema:
/// ```json
/// {
///   "matcher": "Bash",
///   "hooks": [
///     { "type": "command", "command": "guardctl check bash" }
///   ]
/// }
/// ```
fn build_hook_entry(matcher: &str, subcmd: &str, bin: &str) -> Value {
    json!({
        "matcher": matcher,
        "hooks": [
            {
                "type": "command",
                "command": format!("{bin} {subcmd}"),
            }
        ]
    })
}

/// Classify a PreToolUse entry with respect to a given matcher.
/// Returns `(is_guardctl_for_matcher, is_nested_shape)`.
///
/// * nested shape: modern Claude Code schema — `{ matcher, hooks: [{ type, command }] }`
/// * flat shape: legacy/buggy — `{ matcher, command }` (silently ignored by Claude Code)
fn classify_entry(entry: &Value, matcher: &str) -> (bool, bool) {
    let entry_matcher = entry.get("matcher").and_then(|v| v.as_str()).unwrap_or("");
    if entry_matcher != matcher {
        return (false, false);
    }

    // Nested form: any inner hook whose command references guardctl.
    if let Some(arr) = entry.get("hooks").and_then(|v| v.as_array()) {
        for h in arr {
            let c = h.get("command").and_then(|v| v.as_str()).unwrap_or("");
            if c.contains("guardctl check") {
                return (true, true);
            }
        }
    }

    // Flat (legacy) form: top-level command referencing guardctl.
    let cmd = entry.get("command").and_then(|v| v.as_str()).unwrap_or("");
    if cmd.contains("guardctl check") {
        return (true, false);
    }

    (false, false)
}

/// Pure merge: mutate `settings` to contain guardctl's desired hooks in the
/// nested Claude Code schema, migrating any legacy flat-shape entries.
/// Returns `(migrated, added)` where `migrated` counts flat-shape entries
/// rewritten and `added` counts missing entries appended.
pub(crate) fn merge_hooks(
    settings: &mut Map<String, Value>,
    bin: &str,
) -> Result<(usize, usize), String> {
    let hooks = settings.entry("hooks").or_insert_with(|| json!({}));
    let pre_tool_use = hooks
        .as_object_mut()
        .ok_or("hooks is not an object")?
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));
    let arr = pre_tool_use
        .as_array_mut()
        .ok_or("PreToolUse is not an array")?;

    // Pass 1: drop legacy flat-shape guardctl entries so we can replace them
    // with correct nested entries below.
    let mut migrated = 0usize;
    for (matcher, _) in DESIRED {
        let before = arr.len();
        arr.retain(|entry| {
            let (is_guardctl, is_nested) = classify_entry(entry, matcher);
            !(is_guardctl && !is_nested)
        });
        migrated += before - arr.len();
    }

    // Pass 2: which correctly-nested entries already exist?
    let mut present: Vec<bool> = Vec::with_capacity(DESIRED.len());
    for (matcher, _) in DESIRED {
        let found = arr.iter().any(|entry| {
            let (is_guardctl, is_nested) = classify_entry(entry, matcher);
            is_guardctl && is_nested
        });
        present.push(found);
    }

    // Pass 3: append any missing entries in nested shape.
    let mut added = 0usize;
    for (i, (matcher, subcmd)) in DESIRED.iter().enumerate() {
        if !present[i] {
            arr.push(build_hook_entry(matcher, subcmd, bin));
            added += 1;
        }
    }

    Ok((migrated, added))
}

fn load_settings(path: &Path) -> Result<Map<String, Value>, String> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    if contents.trim().is_empty() {
        return Ok(Map::new());
    }
    serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))
}

fn write_settings(path: &Path, settings: &Map<String, Value>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("Failed to serialize settings: {e}"))?;
    atomic_write(path, json.as_bytes())
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

pub fn install() -> Result<(), String> {
    let path = settings_path();
    let bin = guardctl_binary();

    let mut settings = load_settings(&path)?;
    let (migrated, added) = merge_hooks(&mut settings, &bin)?;

    if migrated == 0 && added == 0 {
        eprintln!("guardctl hooks already installed in {}", path.display());
        return Ok(());
    }

    write_settings(&path, &settings)?;

    if migrated > 0 {
        eprintln!(
            "Migrated {migrated} legacy flat-shape guardctl hook(s) to nested schema in {}",
            path.display()
        );
    }
    if added > 0 {
        eprintln!(
            "Installed {added} guardctl hook(s) into {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn new_settings() -> Map<String, Value> {
        Map::new()
    }

    /// Extract the nested command string for a given matcher, if any.
    fn nested_command_for(settings: &Map<String, Value>, matcher: &str) -> Option<String> {
        let arr = settings
            .get("hooks")?
            .get("PreToolUse")?
            .as_array()?;
        for entry in arr {
            if entry.get("matcher")?.as_str()? != matcher {
                continue;
            }
            let inner = entry.get("hooks")?.as_array()?;
            for h in inner {
                if h.get("type")?.as_str()? == "command" {
                    return h.get("command")?.as_str().map(String::from);
                }
            }
        }
        None
    }

    #[test]
    fn install_into_empty_settings_uses_nested_schema() {
        let mut s = new_settings();
        let (migrated, added) = merge_hooks(&mut s, "guardctl").unwrap();
        assert_eq!(migrated, 0);
        assert_eq!(added, 3);

        // Every desired matcher must be present in nested shape.
        for (matcher, subcmd) in DESIRED {
            let cmd = nested_command_for(&s, matcher)
                .unwrap_or_else(|| panic!("missing nested entry for matcher {matcher}"));
            assert_eq!(cmd, format!("guardctl {subcmd}"));
        }

        // And crucially: no top-level `command` field should exist on the entries.
        let arr = s.get("hooks").unwrap().get("PreToolUse").unwrap().as_array().unwrap();
        for entry in arr {
            assert!(
                entry.get("command").is_none(),
                "entry has a top-level 'command' field, which is the broken legacy shape: {entry}"
            );
            assert!(entry.get("hooks").is_some(), "entry missing nested 'hooks' array: {entry}");
        }
    }

    #[test]
    fn install_is_idempotent() {
        let mut s = new_settings();
        let (_m1, a1) = merge_hooks(&mut s, "guardctl").unwrap();
        let (m2, a2) = merge_hooks(&mut s, "guardctl").unwrap();
        assert_eq!(a1, 3);
        assert_eq!(m2, 0);
        assert_eq!(a2, 0);

        // Second run should not duplicate.
        let arr = s.get("hooks").unwrap().get("PreToolUse").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn install_preserves_unrelated_hooks() {
        let mut s: Map<String, Value> = serde_json::from_value(json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Read",
                        "hooks": [
                            { "type": "command", "command": "some-other-tool --read" }
                        ]
                    }
                ],
                "Stop": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "echo done" }] }]
            },
            "other": "keepme"
        }))
        .unwrap();

        merge_hooks(&mut s, "guardctl").unwrap();

        // Unrelated top-level key preserved.
        assert_eq!(s.get("other").and_then(|v| v.as_str()), Some("keepme"));

        // Unrelated Stop hook preserved.
        assert!(s.get("hooks").unwrap().get("Stop").is_some());

        // Unrelated Read hook preserved alongside the new guardctl ones.
        let pre = s.get("hooks").unwrap().get("PreToolUse").unwrap().as_array().unwrap();
        assert_eq!(pre.len(), 4); // 1 pre-existing + 3 guardctl
        assert!(pre
            .iter()
            .any(|e| e.get("matcher").and_then(|v| v.as_str()) == Some("Read")));
    }

    #[test]
    fn migrates_legacy_flat_shape() {
        // Simulate the buggy shape earlier versions of guardctl init wrote.
        let mut s: Map<String, Value> = serde_json::from_value(json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "command": "/old/path/guardctl check bash" },
                    { "matcher": "Write|Edit", "command": "/old/path/guardctl check file-write" },
                    { "matcher": "mcp__.*", "command": "/old/path/guardctl check mcp" }
                ]
            }
        }))
        .unwrap();

        let (migrated, added) = merge_hooks(&mut s, "/new/path/guardctl").unwrap();
        assert_eq!(migrated, 3, "expected three legacy entries migrated");
        assert_eq!(added, 3, "expected three nested replacements appended");

        // After migration, every entry must be in the nested shape and point to the new binary.
        let arr = s.get("hooks").unwrap().get("PreToolUse").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 3);
        for entry in arr {
            assert!(entry.get("command").is_none());
            let inner = entry.get("hooks").unwrap().as_array().unwrap();
            assert_eq!(inner.len(), 1);
            let cmd = inner[0].get("command").unwrap().as_str().unwrap();
            assert!(cmd.starts_with("/new/path/guardctl "), "cmd = {cmd}");
        }
    }

    #[test]
    fn leaves_existing_nested_entries_alone_but_migrates_flat_siblings() {
        // Mixed state: nested Bash is correct, the other two matchers are legacy.
        let mut s: Map<String, Value> = serde_json::from_value(json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{ "type": "command", "command": "guardctl check bash" }]
                    },
                    { "matcher": "Write|Edit", "command": "guardctl check file-write" },
                    { "matcher": "mcp__.*", "command": "guardctl check mcp" }
                ]
            }
        }))
        .unwrap();

        let (migrated, added) = merge_hooks(&mut s, "guardctl").unwrap();
        assert_eq!(migrated, 2);
        assert_eq!(added, 2);

        let arr = s.get("hooks").unwrap().get("PreToolUse").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 3);
        // All three matchers now have valid nested entries.
        for (matcher, _) in DESIRED {
            assert!(
                nested_command_for(&s, matcher).is_some(),
                "missing nested entry for {matcher}"
            );
        }
    }

    #[test]
    fn creates_hooks_container_when_missing() {
        let mut s: Map<String, Value> = serde_json::from_value(json!({
            "model": "sonnet"
        }))
        .unwrap();

        merge_hooks(&mut s, "guardctl").unwrap();

        assert_eq!(s.get("model").and_then(|v| v.as_str()), Some("sonnet"));
        let arr = s.get("hooks").unwrap().get("PreToolUse").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn errors_when_hooks_field_is_not_object() {
        let mut s: Map<String, Value> = serde_json::from_value(json!({
            "hooks": "this is wrong"
        }))
        .unwrap();
        assert!(merge_hooks(&mut s, "guardctl").is_err());
    }

    #[test]
    fn errors_when_pre_tool_use_is_not_array() {
        let mut s: Map<String, Value> = serde_json::from_value(json!({
            "hooks": { "PreToolUse": "not an array" }
        }))
        .unwrap();
        assert!(merge_hooks(&mut s, "guardctl").is_err());
    }
}
